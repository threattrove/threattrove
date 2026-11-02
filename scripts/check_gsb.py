#!/usr/bin/env python3
"""Check the URL-side reputation sources: Google Safe Browsing and PhishTank.

Both sources answer the same question -- "has this URL been listed?" -- and both
used to turn a non-answer into a verdict. Safe Browsing called an unlisted URL
``CLEAN``, and PhishTank read its ``"y"``/``"n"`` strings for truthiness, so a
record it had explicitly marked invalid **and** unverified was reported as
verified phishing. These checks pin the corrected behaviour.

Run from the repository root::

    python3 scripts/check_gsb.py            # offline, no network
    python3 scripts/check_gsb.py --live     # also calls both real APIs

The live pass is opt-in and spends real quota (one Safe Browsing lookup per URL,
one PhishTank lookup). It never prints a key or a raw provider response; only
the status, verdict and note that the source itself produces.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove import core  # noqa: E402
from threattrove.sources import (  # noqa: E402
    ALL_SOURCES,
    PhishTank,
    SafeBrowsing,
    _phish_flag,
)

FAILED = []


def check(label, got, want):
    ok = got == want
    print(("  ok   " if ok else "  FAIL ") + f"{label}: {got!r}"
          + ("" if ok else f" (want {want!r})"))
    if not ok:
        FAILED.append(label)
    return ok


class FakeResponse:
    """Minimal stand-in for a ``requests.Response``."""

    def __init__(self, payload=None, status=200, text=None, headers=None):
        self._payload = payload
        self.status_code = status
        self.headers = headers or {}
        self._text = text

    @property
    def text(self):
        if self._text is not None:
            return self._text
        try:
            import json as _json
            return _json.dumps(self._payload)
        except (TypeError, ValueError):
            return str(self._payload)

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeSession:
    """Records the request a source would make, and answers with a payload."""

    def __init__(self, response):
        self.response = response
        self.calls = []
        self.headers = {}

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return self.response

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return self.response


def bound(source, response):
    """Give a source a recording session and hand the session back."""
    sess = FakeSession(response)
    source.session = lambda: sess  # type: ignore[method-assign]
    return sess


def phish_payload(valid, verified, in_database=True, phish_id=123456,
                  submitted_at="2026-10-30T11:22:33+00:00"):
    return {"results": {"in_database": in_database,
                        "valid": valid,
                        "verified": verified,
                        "phish_id": phish_id,
                        "submitted_at": submitted_at}}


def cf_page():
    return ("<!DOCTYPE html><html><head><title>Just a moment...</title></head>"
            "<body>Checking your browser before accessing phishtank.com.</body>"
            "</html>")


def main(argv):
    ind_url = core.parse_indicator("http://malware.testing.google.test/"
                                   "testing/malware/")
    ind_clean = core.parse_indicator("https://www.example.com/login")
    ind_domain = core.parse_indicator("example.com")

    # ------------------------------------------------------------------
    print("flag parsing")
    # ------------------------------------------------------------------
    for raw, want in (("y", True), ("Y", True), ("yes", True), ("true", True),
                      ("1", True), (1, True), (True, True),
                      ("n", False), ("N", False), ("no", False),
                      ("false", False), ("0", False), (0, False),
                      (False, False), ("", False), (None, False)):
        check(f"_phish_flag({raw!r})", _phish_flag(raw), want)
    check("an unreadable flag is not a yes", _phish_flag("maybe"), None)
    check("a missing flag is false, not None", _phish_flag(""), False)

    # ------------------------------------------------------------------
    print("\nPhishTank verdicts")
    # ------------------------------------------------------------------
    src = PhishTank()
    bound(src, FakeResponse(phish_payload("y", "y")))
    out = src.lookup(ind_url)
    check("verified phishing", (out.status, out.verdict),
          ("matched", core.VERDICT_MALICIOUS))
    check("verified note", out.note, "verified phishing URL")
    check("verified link", out.link,
          "https://phishtank.org/phish_detail.php?phish_id=123456")
    check("verified detail keeps the raw flags", out.detail.get("verified"), "y")
    check("verified detail carries valid", out.detail.get("valid"), "y")
    check("submission time from submitted_at", out.detail.get("submission_time"),
          "2026-10-30T11:22:33+00:00")

    # The regression: "n" is a truthy string, so the old code convicted here.
    bound(src, FakeResponse(phish_payload("n", "n")))
    out = src.lookup(ind_url)
    check("invalid and unverified is not phishing", out.verdict,
          core.VERDICT_UNKNOWN)
    check("invalid and unverified is still listed", out.status, "matched")
    check("invalid note", out.note, "listed but marked invalid or unverified")

    bound(src, FakeResponse(phish_payload("n", "y")))
    check("valid=n verified=y is not phishing", src.lookup(ind_url).verdict,
          core.VERDICT_UNKNOWN)

    bound(src, FakeResponse(phish_payload("y", "n")))
    out = src.lookup(ind_url)
    check("valid=y verified=n is not phishing", out.verdict,
          core.VERDICT_UNKNOWN)
    check("unverified note names both states", out.note,
          "listed but marked invalid or unverified")

    bound(src, FakeResponse(phish_payload(True, True)))
    check("real booleans still convict", src.lookup(ind_url).verdict,
          core.VERDICT_MALICIOUS)

    bound(src, FakeResponse(phish_payload(1, 1)))
    check("integer flags still convict", src.lookup(ind_url).verdict,
          core.VERDICT_MALICIOUS)

    bound(src, FakeResponse(phish_payload("?", "?")))
    out = src.lookup(ind_url)
    check("unreadable flags stay suspicious", out.verdict,
          core.VERDICT_SUSPICIOUS)
    check("unreadable note", out.note, "in database (unverified)")

    bound(src, FakeResponse(phish_payload("y", "y", in_database=False)))
    out = src.lookup(ind_url)
    check("not in the database", out.status, "no_match")
    check("not in the database has no verdict", out.verdict,
          core.VERDICT_UNKNOWN)

    bound(src, FakeResponse({"results": None}))
    check("empty results", src.lookup(ind_url).status, "no_match")

    # ------------------------------------------------------------------
    print("\nPhishTank refusals")
    # ------------------------------------------------------------------
    bound(src, FakeResponse(status=403, text=cf_page()))
    out = src.lookup(ind_url)
    check("Cloudflare challenge is an upstream error", out.status, "error")
    check("Cloudflare note", out.note, "upstream blocks API clients (Cloudflare)")

    bound(src, FakeResponse(status=403, text='{"error": "invalid app key"}'))
    out = src.lookup(ind_url)
    check("a real 403 is a bad key", out.status, "unauthorized")
    check("bad key note", out.note, "invalid app key")

    bound(src, FakeResponse(status=401, text="Unauthorized"))
    check("401", src.lookup(ind_url).status, "unauthorized")

    bound(src, FakeResponse(status=503, text="upstream down"))
    out = src.lookup(ind_url)
    check("503", out.status, "error")
    check("503 note", out.note, "HTTP 503")

    bound(src, FakeResponse(status=200, text="<html>maintenance</html>",
                            payload=ValueError("no json")))
    out = src.lookup(ind_url)
    check("HTML instead of JSON", out.status, "error")
    check("HTML note", out.note, "non-JSON response")

    # ------------------------------------------------------------------
    print("\nSafe Browsing verdicts")
    # ------------------------------------------------------------------
    src = SafeBrowsing()
    # The request only carries a key when one is configured, and the shape check
    # should not depend on a real credential. The placeholder is removed again
    # before the live pass so it can never be mistaken for a working key.
    _real_key = os.environ.get("GSB_API_KEY")
    os.environ["GSB_API_KEY"] = "offline-test-key"
    sess = bound(src, FakeResponse({"matches": [
        {"threatType": "MALWARE", "platformType": "ANY_PLATFORM",
         "threat": {"url": ind_url.value},
         "threatEntryType": "URL"}]}))
    out = src.lookup(ind_url)
    check("a listed URL", (out.status, out.verdict),
          ("matched", core.VERDICT_MALICIOUS))
    check("listed note is the threat type", out.note, "MALWARE")
    check("threat types in detail", out.detail.get("threat_types"), ["MALWARE"])
    check("Safe Browsing uses POST", sess.calls[-1][0], "POST")
    check("Safe Browsing endpoint", sess.calls[-1][1],
          "https://safebrowsing.googleapis.com/v4/threatMatches:find")
    check("key travels as a query parameter",
          sess.calls[-1][2].get("params", {}).get("key"), "offline-test-key")
    check("lookup body asks for every threat type",
          sess.calls[-1][2]["json"]["threatInfo"]["threatTypes"],
          list(SafeBrowsing.THREATS))

    bound(src, FakeResponse({"matches": [
        {"threatType": "SOCIAL_ENGINEERING"},
        {"threatType": "MALWARE"},
        {"threatType": "MALWARE"}]}))
    out = src.lookup(ind_url)
    check("several threat types are de-duplicated", out.note,
          "MALWARE, SOCIAL_ENGINEERING")

    # The regression: no match used to answer CLEAN.
    bound(src, FakeResponse({}))
    out = src.lookup(ind_clean)
    check("an unlisted URL is no_match", out.status, "no_match")
    check("an unlisted URL is not clean", out.verdict, core.VERDICT_UNKNOWN)
    check("unlisted note", out.note, "not on Google's lists")

    bound(src, FakeResponse({"matches": []}))
    check("an empty match list is also no_match", src.lookup(ind_clean).status,
          "no_match")

    sess = bound(src, FakeResponse({}))
    src.lookup(ind_domain)
    check("a domain is looked up as a URL",
          sess.calls[-1][2]["json"]["threatInfo"]["threatEntries"],
          [{"url": "http://example.com/"}])
    if _real_key is None:
        os.environ.pop("GSB_API_KEY", None)
    else:
        os.environ["GSB_API_KEY"] = _real_key

    # ------------------------------------------------------------------
    print("\nSafe Browsing refusals")
    # ------------------------------------------------------------------
    bound(src, FakeResponse(status=400,
                            text='{"error": {"code": 400, "message": '
                                 '"API key not valid. Please pass a valid API key.",'
                                 ' "status": "INVALID_ARGUMENT"}}'))
    out = src.lookup(ind_clean)
    check("400 is a bad key", out.status, "unauthorized")
    check("400 note", out.note, "invalid API key")

    bound(src, FakeResponse(
        status=403,
        text='{"error": {"code": 403, "message": "Safe Browsing API has not '
             'been used in project 12345 before or it is disabled. Enable it '
             'by visiting https://console.developers.google.com/apis/api/'
             'safebrowsing.googleapis.com/overview?project=12345 then retry.",'
             ' "status": "PERMISSION_DENIED"}}'))
    out = src.lookup(ind_clean)
    check("403 without the API enabled is not a bad key", out.status, "error")
    check("403 names the real problem", out.note,
          "API not enabled for this key's project")

    bound(src, FakeResponse(status=403,
                            text='{"error": {"status": "PERMISSION_DENIED"}}'))
    check("a plain 403 is a bad key", src.lookup(ind_clean).status,
          "unauthorized")

    bound(src, FakeResponse(status=429, text="rate limited",
                            headers={"Retry-After": "30"}))
    out = src.lookup(ind_clean)
    check("429", out.status, "error")
    check("429 names the daily allowance", "quota exceeded" in out.note, True)
    check("429 counts as a spent allowance",
          core.quota_exhausted_note(out.note), True)

    bound(src, FakeResponse(status=500, text="oops"))
    out = src.lookup(ind_url)
    check("500", out.status, "error")
    check("500 note", out.note, "HTTP 500")

    # ------------------------------------------------------------------
    print("\nverdict contribution")
    # ------------------------------------------------------------------
    # A blocklist that has no opinion must not push a URL towards clean.
    check("no_match alone is no verdict",
          core.combine([core.VERDICT_WEIGHT[core.VERDICT_UNKNOWN]]),
          (core.VERDICT_UNKNOWN, 0))
    check("both no_matches are still no verdict",
          core.combine([0, 0]), (core.VERDICT_UNKNOWN, 0))
    # One authority naming a URL malicious is a lead, not a conviction.
    check("one malicious list is suspicious",
          core.combine([core.VERDICT_WEIGHT[core.VERDICT_MALICIOUS]])[0],
          core.VERDICT_SUSPICIOUS)
    check("two malicious lists are malicious",
          core.combine([core.VERDICT_WEIGHT[core.VERDICT_MALICIOUS]] * 2)[0],
          core.VERDICT_MALICIOUS)
    # The old CLEAN answer used to drag this sum down; UNKNOWN leaves it alone.
    check("no_match does not offset a malicious list",
          core.combine([core.VERDICT_WEIGHT[core.VERDICT_MALICIOUS], 0])[0],
          core.VERDICT_SUSPICIOUS)

    results = [core.SourceResult(source="gsb", status="no_match",
                                 verdict=core.VERDICT_UNKNOWN,
                                 category="reputation"),
               core.SourceResult(source="phishtank", status="matched",
                                 verdict=core.VERDICT_MALICIOUS,
                                 category="reputation")]
    report = core.Report(indicator=ind_url)
    report.results = results
    check("a no_match scores nothing, the list scores 100",
          report._weights(),
          [0, core.VERDICT_WEIGHT[core.VERDICT_MALICIOUS]])
    check("a single list keeps the URL suspicious", report.verdict(),
          core.VERDICT_SUSPICIOUS)

    # ------------------------------------------------------------------
    print("\ncache invalidation")
    # ------------------------------------------------------------------
    check("Safe Browsing logic_version bumped past the cached rows",
          SafeBrowsing.logic_version, 2)
    check("PhishTank logic_version bumped past the cached rows",
          PhishTank.logic_version, 2)
    check("Safe Browsing is registered", "gsb" in
          {s.name for s in ALL_SOURCES}, True)
    check("PhishTank is registered", "phishtank" in
          {s.name for s in ALL_SOURCES}, True)
    check("Safe Browsing is a reputation source", SafeBrowsing().category,
          "reputation")
    check("Safe Browsing answers URLs and domains",
          tuple(SafeBrowsing.kinds), (core.KIND_URL, core.KIND_DOMAIN))
    check("PhishTank answers URLs only", tuple(PhishTank.kinds),
          (core.KIND_URL,))

    # ------------------------------------------------------------------
    if "--live" in argv:
        print("\nlive APIs")
        if not os.environ.get("GSB_API_KEY"):
            print("  skip  GSB_API_KEY is not set")
        else:
            for ind, label in ((ind_url, "google test malware URL"),
                               (ind_clean, "unlisted URL")):
                out = SafeBrowsing().lookup(ind)
                print(f"  gsb        {label:24s} {out.status:12s} "
                      f"{out.verdict:10s} {out.note[:48]}")
                want = "matched" if label.startswith("google") else "no_match"
                if out.status != want:
                    FAILED.append(f"live gsb {label}")
        if not os.environ.get("PHISHTANK_APPKEY"):
            print("  skip  PHISHTANK_APPKEY is not set")
        else:
            out = PhishTank().lookup(ind_url)
            print(f"  phishtank  {'live URL':24s} {out.status:12s} "
                  f"{out.verdict:10s} {out.note[:48]}")
            # Cloudflare blocking the API is recorded as an upstream error and
            # is not a reason to fail this suite.
            if out.status not in ("matched", "no_match", "error"):
                FAILED.append("live phishtank")

    print()
    if FAILED:
        print(f"{len(FAILED)} check(s) failed: {', '.join(FAILED)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
