#!/usr/bin/env python3
"""Check the MalShare source against the API contract it actually has.

MalShare answered every lookup with an empty body because the source asked for
``action=getdetails``. The documented action is ``details``, and the empty 200
looked exactly like "sample not in the corpus", so the source reported
``not_found`` for everything and never contributed a verdict. These checks pin
the real contract, which was measured against the live API:

    known hash    -> 200 + {MD5, SHA1, SHA256, SSDEEP, F_TYPE, SIZE, FILENAMES}
    unknown hash  -> 404 + {"ERROR": {"CODE": 404, "MESSAGE": "Sample not found"}}
    bad key       -> 400 + "User specified in `api_key` GET variable does not exist"
    no key        -> 400 + "No key specified in `api_key` GET variable"

Run from the repository root::

    python3 scripts/check_malshare.py           # offline, no network
    python3 scripts/check_malshare.py --live    # also asks the real API
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove import core  # noqa: E402
from threattrove.sources import ALL_SOURCES, MalShare  # noqa: E402

FAILED = []

SAMPLE = {
    "MD5": "f7ce88bd01e54bcf213ca082576e8701",
    "SHA1": "39f783cdb9163bce0f451519515323ce9c74a6b2",
    "SHA256": "96a3452b35774892f536e38503827988eb8c7d6ee0cfb9d0d25f4beddfa182ff",
    "SSDEEP": "24576:656F9O4Qd83c4fiEZ32cX98GC5uz+QZ6a:+6aTX4fBFz98Gcuz+ux",
    "F_TYPE": "PE32",
    "SIZE": 873984,
    "FILENAMES": ["payment advice.bat.exe"],
}


def check(label, got, want):
    ok = got == want
    print(("  ok   " if ok else "  FAIL ") + f"{label}: {got!r}"
          + ("" if ok else f" (want {want!r})"))
    if not ok:
        FAILED.append(label)
    return ok


class FakeResponse:
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
    sess = FakeSession(response)
    source.session = lambda: sess  # type: ignore[method-assign]
    return sess


def main(argv):
    ind = core.parse_indicator(
        "96a3452b35774892f536e38503827988eb8c7d6ee0cfb9d0d25f4beddfa182ff")
    src = MalShare()
    os.environ.setdefault("MALSHARE_API_KEY", "offline-test-key")

    print("request shape")
    sess = bound(src, FakeResponse(SAMPLE))
    out = src.lookup(ind)
    check("MalShare uses GET", sess.calls[-1][0], "GET")
    check("MalShare endpoint", sess.calls[-1][1],
          "https://malshare.com/api.php")
    params = sess.calls[-1][2].get("params", {})
    check("the action is `details`", params.get("action"), "details")
    check("the hash is sent", params.get("hash"), ind.preferred_hash())
    # MalShare's own error text names the parameter: "No key specified in
    # 'api_key' GET variable".
    # Compared against the configured key rather than a literal, so this passes
    # both offline and when a real key is exported; the value is not printed.
    check("the key is sent as api_key and is not empty",
          params.get("api_key") == src.key() and bool(params.get("api_key")),
          True)

    print("\na known sample")
    check("status", out.status, "found")
    check("a stored sample is malicious", out.verdict, core.VERDICT_MALICIOUS)
    check("note names the file type", out.note, "sample in MalShare (PE32)")
    check("link points at the sample page", out.link,
          "https://malshare.com/sample.php?action=detail"
          "&hash=96a3452b35774892f536e38503827988eb8c7d6ee0cfb9d0d25f4beddfa182ff")
    check("file type in detail", out.detail.get("type"), "PE32")
    check("size in detail", out.detail.get("size"), 873984)
    check("file names in detail", out.detail.get("filenames"),
          ["payment advice.bat.exe"])

    bound(src, FakeResponse({**SAMPLE, "F_TYPE": None, "FILENAMES": None}))
    out = src.lookup(ind)
    check("a sample with no type still convicts", out.verdict,
          core.VERDICT_MALICIOUS)
    check("a sample with no type still notes it", out.note, "sample in MalShare")
    check("missing names are None, not []", out.detail.get("filenames"), None)

    bound(src, FakeResponse({**SAMPLE, "FILENAMES": "a.exe"}))
    check("a single file name is wrapped", src.lookup(ind).detail.get("filenames"),
          ["a.exe"])

    bound(src, FakeResponse({**SAMPLE, "FILENAMES": ["1", "2", "3", "4", "5"]}))
    check("file names are capped at three",
          len(src.lookup(ind).detail.get("filenames") or []), 3)

    bound(src, FakeResponse([SAMPLE]))
    check("a one-element list is accepted", src.lookup(ind).status, "found")

    print("\nan unknown sample")
    bound(src, FakeResponse({"ERROR": {"CODE": 404, "MESSAGE": "Sample not found"}},
                            status=404))
    out = src.lookup(ind)
    check("404 with an error body is not_found", out.status, "not_found")
    check("404 carries no verdict", out.verdict, core.VERDICT_UNKNOWN)
    check("404 note", out.note, "not in MalShare")

    bound(src, FakeResponse({"ERROR": {"CODE": 404, "MESSAGE": "Sample not found"}}))
    check("the same body at 200 is also not_found", src.lookup(ind).status,
          "not_found")

    bound(src, FakeResponse({"ERROR": {"CODE": 500, "MESSAGE": "boom"}}))
    out = src.lookup(ind)
    check("a non-404 error is an error", out.status, "error")
    check("the error code is named", out.note, "MalShare error 500")

    print("\nrefusals")
    bound(src, FakeResponse(status=400,
                            text="User specified in `api_key` GET variable does "
                                 "not exist"))
    out = src.lookup(ind)
    check("400 with an api_key complaint is a bad key", out.status, "unauthorized")
    check("bad key note", out.note, "invalid API key")

    bound(src, FakeResponse(status=400,
                            text="No key specified in `api_key` GET variable"))
    check("a missing key is a bad key", src.lookup(ind).status, "unauthorized")

    bound(src, FakeResponse(status=400, text="something else went wrong"))
    out = src.lookup(ind)
    check("a plain 400 is an error", out.status, "error")
    check("plain 400 note", out.note, "HTTP 400")

    bound(src, FakeResponse(status=403, text="Forbidden"))
    check("403", src.lookup(ind).status, "unauthorized")

    bound(src, FakeResponse(status=429, text="slow down"))
    out = src.lookup(ind)
    check("429", out.status, "error")
    check("429 names the daily allowance", "quota exceeded" in out.note, True)

    bound(src, FakeResponse(status=502, text="bad gateway"))
    out = src.lookup(ind)
    check("502", out.status, "error")
    check("502 note", out.note, "HTTP 502")

    print("\nsilence is not a miss")
    # The regression: the withdrawn action answered 200 with an empty body.
    bound(src, FakeResponse(status=200, text="", payload=ValueError("no json")))
    out = src.lookup(ind)
    check("an empty 200 is an error, not not_found", out.status, "error")
    check("empty note", out.note, "empty or non-JSON response")
    check("an empty answer scores nothing", out.verdict, core.VERDICT_UNKNOWN)

    bound(src, FakeResponse(status=200, text="<html>maintenance</html>",
                            payload=ValueError("no json")))
    check("HTML is an error too", src.lookup(ind).status, "error")

    bound(src, FakeResponse({}))
    check("an empty object is an error", src.lookup(ind).status, "error")

    bound(src, FakeResponse([]))
    check("an empty list is an error", src.lookup(ind).status, "error")

    bound(src, FakeResponse("just a string"))
    check("a bare string is an error", src.lookup(ind).status, "error")

    print("\nverdict contribution")
    # A stored sample is a first-hand record of the file, so it is a direct
    # authority: it speaks to the file itself rather than to where a copy was
    # served from. Corroboration is still counted in authorities, not rows, so
    # a lone MalShare hit is suspicious; the source earns its keep as the
    # second voice beside an engine panel or the local corpus.
    check("malshare is a direct authority", "malshare" in core.DIRECT_SOURCES,
          True)
    check("a found sample is not an engine panel",
          core.evidence_authority("malshare") != core.ENGINE_PANEL_AUTHORITY,
          True)
    check("MalShare carries the malicious weight",
          core.VERDICT_WEIGHT[core.VERDICT_MALICIOUS], 100)

    mw = core.VERDICT_WEIGHT[core.VERDICT_MALICIOUS]
    check("a lone direct authority is suspicious", core.combine([mw])[0],
          core.VERDICT_SUSPICIOUS)
    check("MalShare with a second authority convicts", core.combine([mw, mw])[0],
          core.VERDICT_MALICIOUS)

    def report_with(*sources):
        rep = core.Report(indicator=ind)
        rep.results = [core.SourceResult(source=s, status="found",
                                        verdict=core.VERDICT_MALICIOUS,
                                        category="reputation")
                       for s in sources]
        return rep

    check("a lone MalShare row does not convict the report",
          report_with("malshare").verdict(), core.VERDICT_SUSPICIOUS)
    check("MalShare beside an engine panel convicts the report",
          report_with("virustotal", "malshare").verdict(),
          core.VERDICT_MALICIOUS)

    print("\ncache invalidation")
    check("logic_version bumped past the cached not_found rows",
          MalShare.logic_version, 2)
    check("MalShare is registered", "malshare" in {s.name for s in ALL_SOURCES},
          True)
    check("MalShare answers hashes only", tuple(MalShare.kinds),
          (core.KIND_HASH,))

    if "--live" in argv:
        print("\nlive API")
        if not os.environ.get("MALSHARE_API_KEY"):
            print("  skip  MALSHARE_API_KEY is not set")
        else:
            out = MalShare().lookup(ind)
            print(f"  malshare  known sample  {out.status:10s} "
                  f"{out.verdict:10s} {out.note[:48]}")
            check("a known sample is found live", out.status, "found")
            miss = core.parse_indicator("00" * 32)
            out = MalShare().lookup(miss)
            print(f"  malshare  unknown hash  {out.status:10s} "
                  f"{out.verdict:10s} {out.note[:48]}")
            check("an unknown hash is not_found live", out.status, "not_found")

    print()
    if FAILED:
        print(f"{len(FAILED)} check(s) failed: {', '.join(FAILED)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
