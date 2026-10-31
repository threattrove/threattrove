#!/usr/bin/env python3
"""Manual smoke test: parsing, verdict math, and live keyless lookups.

    python scripts/smoke.py            # offline checks + live lookups
    python scripts/smoke.py --offline  # parsing/verdict only
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threattrove import core  # noqa: E402


def check(cond: bool, msg: str) -> None:
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        raise SystemExit(f"failed: {msg}")


def parsing() -> None:
    print("\n[parsing]")
    cases = [
        ("44D88612FEA8A8F36DE82E1278ABB02F", core.KIND_HASH),
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", core.KIND_HASH),
        ("https://example.com/path?x=1#frag", core.KIND_URL),
        ("example.com/login", core.KIND_URL),
        ("example.com", core.KIND_DOMAIN),
        ("sub.example.co.uk", core.KIND_DOMAIN),
        ("8.8.8.8", core.KIND_IP),
        ("2001:4860:4860::8888", core.KIND_IP),
        ("http://user@evil.example.com:8080/a", core.KIND_URL),
    ]
    for raw, kind in cases:
        ind = core.parse_indicator(raw)
        check(ind is not None and ind.kind == kind, f"{raw!r} -> {kind}")
    check(core.parse_indicator("hello world") is None, "garbage rejected")
    check(core.parse_indicator("") is None, "empty rejected")

    ind = core.parse_indicator("HTTPS://Example.COM/A?b=1#c")
    check(ind.value == "https://example.com/A?b=1", f"url normalised: {ind.value}")
    check(ind.domain == "example.com", "registrable domain")
    check(core.registrable_domain("a.b.example.co.uk") == "example.co.uk",
          "multi-label suffix")


def verdicts() -> None:
    print("\n[verdicts]")
    # A single malicious source is not enough evidence to convict anything.
    check(core.combine([100])[0] == core.VERDICT_SUSPICIOUS,
          "single malicious -> suspicious (needs corroboration)")
    check(core.combine([100])[1] <= 50, "single malicious keeps low confidence")
    check(core.combine([100, 100])[0] == core.VERDICT_MALICIOUS, "two malicious")
    check(core.combine([100, 100])[1] >= 75, "two malicious -> high confidence")
    check(core.combine([100, 100, 100])[1] > core.combine([100, 100])[1],
          "more corroboration, more confidence")
    check(core.combine([100, -100])[0] == core.VERDICT_UNKNOWN, "conflict -> unknown")
    check(core.combine([-100])[0] == core.VERDICT_KNOWN_GOOD, "known good")
    check(core.combine([-20])[0] == core.VERDICT_CLEAN, "clean")
    check(core.combine([])[0] == core.VERDICT_UNKNOWN, "empty -> unknown")
    check(core.combine([60, 60])[0] == core.VERDICT_SUSPICIOUS,
          "two suspicious never escalate to malicious")
    check(core.combine([100])[1] < core.combine([100, 100])[1],
          "corroboration beats a lone feed")


def report_view() -> None:
    print("\n[report]")
    ind = core.parse_indicator(
        "bdd1a33de78618d16ee4ce148b849932c05d0015491c34887846d431d29f308e")

    # two independent feeds agree -> malicious, and the family is named
    rep = core.Report(indicator=ind)
    rep.results = [
        core.SourceResult(source="malwarebazaar", status="found",
                          verdict=core.VERDICT_MALICIOUS, note="Emotet",
                          detail={"signature": "Emotet", "file_type": "exe"}),
        core.SourceResult(source="urlhaus", status="found",
                          verdict=core.VERDICT_MALICIOUS, note="payload",
                          detail={"file_type": "exe"}),
        core.SourceResult(source="circl", status="not_found"),
        core.SourceResult(source="hybridanalysis", status="error"),
    ]
    check(rep.corroboration() == 2, f"corroboration counted ({rep.corroboration()})")
    check(rep.verdict() == core.VERDICT_MALICIOUS, "two agreeing feeds -> malicious")
    classes = {c["key"]: c for c in rep.evidence()}
    check(classes["blocklist"]["hit"] == 2, "blocklist class counts 2 hits")
    check(classes["blocklist"]["answered"] == 3,
          "blocklist class counts every source that answered")
    check("sandbox" not in classes, "errored source is not evidence")
    check(rep.families() == ["Emotet"], f"families: {rep.families()}")
    check("emotet" in rep.headline().lower(),
          f"headline names the family: {rep.headline()}")

    # one feed alone is a lead, and says so
    lead = core.Report(indicator=ind)
    lead.results = [core.SourceResult(source="malwarebazaar", status="found",
                                      verdict=core.VERDICT_MALICIOUS)]
    check(lead.verdict() == core.VERDICT_SUSPICIOUS, "lone feed -> suspicious")
    check("1 source" in lead.headline(),
          f"headline flags the lone source: {lead.headline()}")

    # NSRL identity: a known Windows binary is named, not accused
    good = core.Report(indicator=ind)
    good.results = [core.SourceResult(
        source="circl", status="found", verdict=core.VERDICT_KNOWN_GOOD,
        note="cmd.exe",
        detail={"FileName": "cmd.exe",
                "ProductName": "Microsoft Windows Operating System",
                "OpSystemName": "Windows", "FileSize": 311296})]
    ident = good.file_identity()
    check(ident.get("name") == "cmd.exe", f"file identity name ({ident})")
    check(ident.get("size") == "304.0 KB", f"file size rendered ({ident.get('size')})")
    check(good.verdict() == core.VERDICT_KNOWN_GOOD, "known good kept")
    check("cmd.exe" in good.headline(),
          f"known-good headline names the file: {good.headline()}")

    payload = rep.to_dict()
    for key in ("corroboration", "families", "evidence", "file_identity", "headline"):
        check(key in payload, f"json has {key}")


def sandbox_ha() -> None:
    """Hybrid Analysis verdict logic, driven by recorded API shapes."""
    print("\n[sandbox]")
    from threattrove.sources import HybridAnalysis
    ha = HybridAnalysis()
    sha = "0" * 64

    def entry(verdict, score=None, family=None, **scanners):
        return {"sha256": sha, "verdict": verdict, "threat_score": score,
                "vx_family": family, "last_file_name": "x.exe",
                "type": "PE32 executable (GUI) Intel 80386", "size": 1234,
                "analysis_start_time": "2025-01-02 03:04:05",
                "whitelisted": False, "scanners_v2": scanners}

    clean_md = {"metadefender": {"status": "clean"}}
    bad_md = {"metadefender": {"status": "malicious"}}
    err_cs = {"crowdstrike_ml": {"status": "error"}}

    # Authentic PuTTY: the sandbox found nothing and one scanner says clean.
    res = ha._judge(entry("no specific threat", None, None,
                          **{**clean_md, **err_cs}), sha)
    check(res.verdict == core.VERDICT_CLEAN, f"clean sample -> clean ({res.verdict})")
    check(res.detections == 0 and res.total == 1,
          f"errored scanner excluded from the denominator ({res.detections}/{res.total})")
    check(res.detail["engines"] is True, "detail advertises engine results")

    # Authentic 7-Zip installer: behavioural score with zero scanner agreement.
    res = ha._judge(entry("malicious", 75, None, **{**clean_md, **err_cs}), sha)
    check(res.verdict == core.VERDICT_SUSPICIOUS,
          f"score without engine agreement -> suspicious ({res.verdict})")
    check("0/1" in res.note, f"note admits the disagreement: {res.note}")

    # EICAR: a scanner flagged and the family is named.
    res = ha._judge(entry("malicious", 100, "EICAR", **{**bad_md, **err_cs}), sha)
    check(res.verdict == core.VERDICT_MALICIOUS, "flagged scanner -> malicious")
    check(res.detections == 1 and res.total == 1, f"engine ratio {res.detections}/{res.total}")
    check(res.detail["family"] == "EICAR", "family surfaced in detail")

    # A named family alone, with no scanner data, is still a determination.
    res = ha._judge(entry("malicious", None, "Emotet", **err_cs), sha)
    check(res.verdict == core.VERDICT_MALICIOUS, "named family -> malicious")

    # No usable scanner at all -> engines flag off, nothing to compare.
    res = ha._judge(entry("suspicious", None, None, **err_cs), sha)
    check(res.verdict == core.VERDICT_SUSPICIOUS, "suspicious verdict kept")
    check(res.detail["engines"] is False, "no usable scanners -> engines False")

    rep = core.Report(indicator=core.parse_indicator(sha))
    rep.results = [
        ha._judge(entry("malicious", 100, "EICAR", **{**bad_md, **err_cs}), sha),
        core.SourceResult(source="otx", status="found",
                          verdict=core.VERDICT_MALICIOUS, note="2 pulse(s)"),
    ]
    check(rep.verdict() == core.VERDICT_MALICIOUS, "sandbox + community -> malicious")
    check(rep.engine_ratio() == (1, 1), f"engine_ratio {rep.engine_ratio()}")
    ident = rep.file_identity()
    check(ident.get("name") == "x.exe", f"sandbox names the file ({ident.get('name')})")
    check(ident.get("size") == "1.2 KB", f"sandbox size rendered ({ident.get('size')})")
    classes = {c["key"]: c for c in rep.evidence()}
    check(classes.get("sandbox", {}).get("hit") == 1, "HA lands in the sandbox class")


def live(skip: bool) -> None:
    from threattrove import Engine, Store, ALL_SOURCES
    import tempfile
    if skip:
        print("\n[live] skipped")
        return
    print("\n[live]")
    store = Store(Path(tempfile.mkdtemp()) / "smoke.db")
    eng = Engine(store=store, deadline=40)

    eicar = core.parse_indicator(
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    rep = eng.lookup(eicar)
    print(f"  eicar hash verdict={rep.verdict()} conf={rep.confidence()} "
          f"in {rep.elapsed:.1f}s")
    for r in rep.results:
        print(f"    {r.source:<16} {r.status:<12} {r.verdict:<12} {r.note[:50]}")
    # With two or more keyed sources this is malicious; a keyless-only box may
    # only reach suspicious, which is the honest answer for one feed.
    check(rep.verdict() in (core.VERDICT_MALICIOUS, core.VERDICT_SUSPICIOUS),
          f"EICAR flagged ({rep.verdict()}, {rep.corroboration()} source(s) agree)")

    rep2 = eng.lookup(eicar)
    cached = sum(1 for r in rep2.results if r.detail.get("_cached"))
    check(cached > 0, f"cache hit on second lookup ({cached} sources)")

    url = core.parse_indicator("https://example.com/")
    rep3 = eng.lookup(url)
    print(f"  url verdict={rep3.verdict()} in {rep3.elapsed:.1f}s")
    for r in rep3.results:
        print(f"    {r.source:<16} {r.status:<12} {r.verdict:<12} {r.note[:50]}")
    check(any(r.source == "urlscan" for r in rep3.results), "urlscan ran")

    dom = core.parse_indicator("example.com")
    rep4 = eng.lookup(dom)
    print(f"  domain verdict={rep4.verdict()} in {rep4.elapsed:.1f}s")
    for r in rep4.results:
        print(f"    {r.source:<16} {r.status:<12} {r.verdict:<12} {r.note[:50]}")
    dns = [r for r in rep4.results if r.source == "dns"]
    check(bool(dns) and dns[0].status == "found", "dns resolved")


if __name__ == "__main__":
    parsing()
    verdicts()
    report_view()
    sandbox_ha()
    live("--offline" in sys.argv)
    print("\nall checks passed")
