#!/usr/bin/env python3
"""Check the MetaDefender Cloud sources: parsing, floor, quota sharing, shape.

Run from the repository root::

    python3 scripts/check_metadefender.py            # offline, no network
    python3 scripts/check_metadefender.py --live     # also hits the real API

The live pass needs ``MD_API_KEY`` in the environment and spends real quota
(four calls, one per indicator kind), so it is opt-in. It prints pass/fail per
endpoint and never prints the key or any part of the API response.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove import core  # noqa: E402
from threattrove.sources import (  # noqa: E402
    ALL_SOURCES,
    MD_MIN_DETECTIONS,
    MetaDefenderDomain,
    MetaDefenderFile,
    MetaDefenderUrl,
    _md_floor,
    _md_hash_parse,
    _md_lookup_parse,
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
    """Minimal stand-in for a requests.Response."""

    def __init__(self, payload, status=200, headers=None):
        self._payload = payload
        self.status_code = status
        self.headers = headers or {}

    def json(self):
        return self._payload


class FakeSession:
    """Records the request a source would make, and answers with a payload."""

    def __init__(self, payload, status=200, headers=None):
        self.response = FakeResponse(payload, status, headers)
        self.calls = []
        self.headers = {}

    def get(self, url, **kw):
        self.calls.append(("GET", url, kw))
        return self.response

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        return self.response


def hash_payload(total=21, detected=17, verdict="Infected", family="eicar",
                 progress=100, threat="Unknown/Eicar!428cbHx5"):
    return {
        "scan_results": {"scan_all_result_a": verdict, "scan_all_result_i": 1,
                         "total_avs": total, "total_detected_avs": detected,
                         "progress_percentage": progress},
        "malware_family": family,
        "threat_name": threat,
        "file_info": {"file_size": 68, "file_type_description": "EICAR"},
    }


def lookup_payload(sources, detected_by=None):
    if detected_by is None:
        detected_by = sum(1 for s in sources
                          if s.get("assessment") == "malicious")
    return {"lookup_results": {"start_time": 1762000000,
                               "detected_by": detected_by,
                               "sources": sources}}


def main(argv):
    ind_hash = core.parse_indicator(
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    ind_url = core.parse_indicator("http://malware.testing.google.test/evil.exe")
    ind_domain = core.parse_indicator("webroot.com")
    ind_ip = core.parse_indicator("8.8.8.8")

    print("engine floor")
    check("floor of 21", _md_floor(21), MD_MIN_DETECTIONS)
    check("floor never below the minimum", _md_floor(4), MD_MIN_DETECTIONS)
    check("floor scales with a wide sweep", _md_floor(92), 5)

    print("\nfile verdicts")
    res = _md_hash_parse(MetaDefenderFile(), hash_payload(), ind_hash.value)
    check("EICAR verdict", res.verdict, core.VERDICT_MALICIOUS)
    check("EICAR detections", res.detections, 17)
    check("EICAR total", res.total, 21)
    check("EICAR note", res.note, "17/21 engines flagged")
    check("EICAR counts as engines", res.detail.get("engines"), True)
    check("EICAR family", res.detail.get("threat_label"), "eicar")
    check("signature kept out of the family", res.detail.get("family"), None)
    check("file link", res.link.startswith("https://metadefender.com/results/file/"),
          True)

    one = _md_hash_parse(MetaDefenderFile(), hash_payload(detected=1), ind_hash.value)
    check("a lone vendor flag is not a verdict", one.verdict, core.VERDICT_UNKNOWN)
    check("a lone vendor flag is marked low_signal", one.detail.get("low_signal"), True)
    check("a lone vendor flag still reports its ratio", one.detections, 1)

    clean = _md_hash_parse(MetaDefenderFile(),
                           hash_payload(detected=0, verdict="Clean", family=""),
                           ind_hash.value)
    check("clean sweep", clean.verdict, core.VERDICT_CLEAN)
    check("clean note", clean.note, "0/21 engines")

    unscanned = _md_hash_parse(MetaDefenderFile(),
                               hash_payload(total=0, detected=0,
                                            verdict="Not Scanned", progress=0),
                               ind_hash.value)
    check("not scanned", unscanned.verdict, core.VERDICT_UNKNOWN)
    check("not scanned note", unscanned.note, "not scanned by MetaDefender")

    partial = _md_hash_parse(MetaDefenderFile(),
                             hash_payload(detected=6, progress=40),
                             ind_hash.value)
    check("partial sweep still convicts", partial.verdict, core.VERDICT_MALICIOUS)
    check("partial sweep says so", partial.note.endswith("(40% analysed)"), True)

    generic = _md_hash_parse(MetaDefenderFile(), hash_payload(family="Malware"),
                             ind_hash.value)
    check("a category is not a family", generic.detail.get("threat_label"), None)

    print("\nurl / domain / ip verdicts")
    two = lookup_payload([{"provider": "A", "assessment": "malicious"},
                          {"provider": "B", "assessment": "malicious"},
                          {"provider": "C", "assessment": "benign"}])
    res = _md_lookup_parse(MetaDefenderUrl(), {"lookup_results": two["lookup_results"]},
                           ind_url)
    check("two providers convict", res.verdict, core.VERDICT_MALICIOUS)
    check("two providers note", res.note, "2/3 providers flagged")
    check("flagged providers named", res.detail.get("flagged_by"), ["A", "B"])
    check("providers do not pose as engines", res.detail.get("engines"), None)
    check("url link", res.link, f"https://metadefender.com/results/url/{ind_url.value}")

    one = _md_lookup_parse(MetaDefenderDomain(),
                           {"lookup_results": lookup_payload(
                               [{"provider": "A", "assessment": "malicious"},
                                {"provider": "B", "assessment": "no_threat"}])["lookup_results"]},
                           ind_domain)
    check("one provider is a lead", one.verdict, core.VERDICT_SUSPICIOUS)

    # webroot.com really answers like this: a provider that assessed nothing,
    # alongside providers that cleared it. The empty string is not an opinion.
    quiet = _md_lookup_parse(MetaDefenderDomain(),
                             {"lookup_results": lookup_payload(
                                 [{"provider": "A", "assessment": "benign"},
                                  {"provider": "B", "assessment": "no_threat"},
                                  {"provider": "C", "assessment": "", "status": 5}],
                                 detected_by=0)["lookup_results"]},
                             ind_domain)
    check("empty assessments are not flags", quiet.verdict, core.VERDICT_CLEAN)
    check("empty assessments are not flags (detail)", quiet.detail.get("flagged_by"), [])

    none = _md_lookup_parse(MetaDefenderDomain(),
                            {"lookup_results": lookup_payload([], detected_by=0)["lookup_results"]},
                            ind_ip)
    check("no assessments at all", none.status, "not_found")

    nolookup = _md_lookup_parse(MetaDefenderDomain(), {}, ind_ip)
    check("empty body", nolookup.status, "not_found")

    print("\nauthority and corroboration")
    check("MetaDefender is an engine panel",
          core.evidence_authority("metadefender"), core.ENGINE_PANEL_AUTHORITY)
    check("MetaDefender URL is the same panel",
          core.evidence_authority("metadefender_url"),
          core.ENGINE_PANEL_AUTHORITY)
    check("MetaDefender examines the file",
          "metadefender" in core.DIRECT_SOURCES, True)
    check("MetaDefender URL does not examine the file",
          "metadefender_url" in core.DIRECT_SOURCES, False)
    check("MetaDefender is an engine source",
          "metadefender" in core.ENGINE_SOURCES, True)
    check("MetaDefender URL is not an engine sweep",
          "metadefender_url" in core.ENGINE_SOURCES, False)
    check("MetaDefender evidence class",
          core.evidence_class("metadefender_url")[0], "sandbox")
    check("MetaDefender file evidence class",
          core.evidence_class("metadefender")[0], "sandbox")

    def report_with(*results):
        rep = core.Report(indicator=ind_hash)
        rep.results.extend(results)
        return rep

    def row(source, verdict=core.VERDICT_MALICIOUS, detections=1, total=1,
            detail=None):
        return core.SourceResult(source=source, status="found", verdict=verdict,
                                 detections=detections, total=total,
                                 category="reputation", detail=detail or {})

    md = row("metadefender", detections=17, total=21, detail={"engines": True})
    vt = row("virustotal", detections=40, total=70, detail={"engines": True})
    check("two panels are one authority", report_with(md, vt).corroboration(), 1)
    check("two panels alone stay a lead", report_with(md, vt).verdict(),
          core.VERDICT_SUSPICIOUS)
    check("a panel plus a feed convicts",
          report_with(md, row("malwarebazaar")).corroboration(), 2)
    check("a panel plus a feed is malicious",
          report_with(md, row("malwarebazaar")).verdict(), core.VERDICT_MALICIOUS)
    check("a panel alone is direct evidence",
          report_with(md).direct_evidence(), ["metadefender"])

    sandbox = core.SourceResult(source="hybridanalysis", status="found",
                                verdict=core.VERDICT_SUSPICIOUS,
                                note="sandbox score 60", category="reputation")
    cleared = _md_hash_parse(MetaDefenderFile(),
                             hash_payload(total=21, detected=0, verdict="Clean"),
                             ind_hash.value)
    check("a clean second sweep clears a heuristic hit",
          report_with(sandbox, cleared).engine_cleared(), True)
    flagged = _md_hash_parse(MetaDefenderFile(), hash_payload(), ind_hash.value)
    check("a flagged second sweep does not clear it",
          report_with(sandbox, flagged).engine_cleared(), False)

    print("\nregistry and quota")
    md_sources = [s for s in ALL_SOURCES if s.name.startswith("metadefender")]
    check("three MetaDefender sources", [s.name for s in md_sources],
          ["metadefender", "metadefender_url", "metadefender_domain"])
    check("one shared quota key", {s.quota_key for s in md_sources},
          {"metadefender"})
    check("one shared allowance", {s.daily_budget for s in md_sources}, {800})
    check("one shared pace slot", {s.quota_key for s in md_sources}, {"metadefender"})
    check("kinds covered",
          sorted({k for s in md_sources for k in s.kinds}),
          ["domain", "hash", "ip", "url"])
    check("names are unique", len({s.name for s in ALL_SOURCES}), len(ALL_SOURCES))
    check("pace is one call per 7.2s", MetaDefenderFile().min_interval, 7.2)
    os.environ["TT_MD_MIN_INTERVAL"] = "0"
    check("pace can be lifted by env", MetaDefenderFile().min_interval, 0.0)
    del os.environ["TT_MD_MIN_INTERVAL"]

    def bound(source, payload=None, status=200, headers=None):
        """Give a source a recording session and hand the session back."""
        sess = FakeSession(payload if payload is not None else {}, status, headers)
        source.session = lambda: sess  # type: ignore[method-assign]
        return sess

    print("\nrequest shapes")
    src = MetaDefenderFile()
    sess = bound(src, hash_payload())
    out = src.lookup(ind_hash)
    call = sess.calls[-1]
    check("file uses GET", call[0], "GET")
    check("file path", call[1], f"https://api.metadefender.com/v4/hash/{ind_hash.value}")
    check("file sends the key header", "apikey" in call[2].get("headers", {}), True)
    check("file parses", out.verdict, core.VERDICT_MALICIOUS)

    src = MetaDefenderUrl()
    sess = bound(src, {"data": [{"address": ind_url.value, "lookup_results": lookup_payload(
        [{"provider": "A", "assessment": "malicious"},
         {"provider": "B", "assessment": "malicious"}])["lookup_results"]}]})
    out = src.lookup(ind_url)
    call = sess.calls[-1]
    check("url uses POST", call[0], "POST")
    check("url path", call[1], "https://api.metadefender.com/v4/url")
    check("url body is a one-element array", call[2].get("json"),
          {"url": [ind_url.value]})
    check("url parses the data row", out.verdict, core.VERDICT_MALICIOUS)

    src = MetaDefenderDomain()
    sess = bound(src, lookup_payload([]))
    src.lookup(ind_ip)
    check("ip path", sess.calls[-1][1],
          f"https://api.metadefender.com/v4/ip/{ind_ip.value}")
    src = MetaDefenderDomain()
    sess = bound(src, lookup_payload([]))
    src.lookup(ind_domain)
    check("domain path", sess.calls[-1][1],
          f"https://api.metadefender.com/v4/domain/{ind_domain.value}")

    print("\nrefusals")
    for status, want in ((401, "unauthorized"), (403, "unauthorized"),
                         (404, "not_found"), (500, "error")):
        src = MetaDefenderFile()
        bound(src, {}, status=status)
        check(f"HTTP {status}", src.lookup(ind_hash).status, want)

    src = MetaDefenderFile()
    bound(src, {}, status=429, headers={"Retry-After": "12"})
    out = src.lookup(ind_hash)
    check("429 status", out.status, "error")
    check("429 says rate limited", "rate limited" in out.note, True)
    check("429 holds the shared slot back",
          core.pace_wait_hint("metadefender") > 5, True)

    if "--live" in argv:
        print("\nlive API")
        if not os.environ.get("MD_API_KEY"):
            print("  skip  MD_API_KEY is not set")
        else:
            for source, ind in ((MetaDefenderFile(), ind_hash),
                                (MetaDefenderUrl(), ind_url),
                                (MetaDefenderDomain(), ind_domain),
                                (MetaDefenderDomain(), ind_ip)):
                out = source.lookup(ind)
                print(f"  {source.name:20s} {ind.value[:34]:34s} "
                      f"{out.status:12s} {out.verdict:10s} {out.note[:48]}")
                if out.status not in ("found", "not_found"):
                    FAILED.append(f"live {source.name} {ind.value}")

    print()
    if FAILED:
        print(f"{len(FAILED)} check(s) failed: {', '.join(FAILED)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
