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
    for key in ("corroboration", "direct_sources", "campaign_only", "families",
                "evidence", "file_identity", "headline"):
        check(key in payload, f"json has {key}")

    # Distribution feeds alone cannot convict: this is the authentic-PuTTY case,
    # listed by URLhaus and named in OTX because attackers re-hosted it.
    campaign = core.Report(indicator=ind)
    campaign.results = [
        core.SourceResult(source="urlhaus", status="found",
                          verdict=core.VERDICT_MALICIOUS,
                          note="payload seen in URLhaus"),
        core.SourceResult(source="otx", status="found",
                          verdict=core.VERDICT_MALICIOUS, note="5 pulse(s)"),
        core.SourceResult(source="hybridanalysis", status="found",
                          verdict=core.VERDICT_CLEAN, detections=0, total=2,
                          note="0/2 scanner(s) flagged - putty.exe",
                          detail={"engines": True, "file_name": "putty.exe"}),
    ]
    check(campaign.corroboration() == 2, "two distribution feeds agree")
    check(campaign.verdict() == core.VERDICT_SUSPICIOUS,
          f"campaign listing without a file look -> suspicious ({campaign.verdict()})")
    check(campaign.campaign_only() is True, "campaign_only flagged")
    check(campaign.confidence() <= 45,
          f"campaign-only confidence capped ({campaign.confidence()})")
    check("none examined the file" in campaign.headline(),
          f"headline says nobody looked at the file: {campaign.headline()}")

    # The same feeds plus one source that actually looked -> malicious again.
    campaign.results.append(core.SourceResult(
        source="malwarebazaar", status="found", verdict=core.VERDICT_MALICIOUS,
        note="Emotet", detail={"signature": "Emotet"}))
    check(campaign.verdict() == core.VERDICT_MALICIOUS,
          "a direct determination restores the malicious verdict")

    # A single partial flag is not a disagreement between sources.
    partial = core.Report(indicator=ind)
    partial.results = [core.SourceResult(source="otx", status="found",
                                         verdict=core.VERDICT_SUSPICIOUS,
                                         note="1 pulse(s)")]
    check("Only 1 source flags this as suspicious" in partial.headline(),
          f"single partial flag described honestly: {partial.headline()}")
    check("disagree" not in partial.headline().lower(),
          "no 'sources disagree' when only one source spoke")


def decision_view() -> None:
    """The "what decided this" panel: weights, counterfactuals, caveats."""
    print("\n[decision]")
    ind = core.parse_indicator(
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    mb = core.SourceResult(source="malwarebazaar", status="found",
                           verdict=core.VERDICT_MALICIOUS, note="EICAR")
    uh = core.SourceResult(source="urlhaus", status="found",
                           verdict=core.VERDICT_MALICIOUS)
    vt = core.SourceResult(source="virustotal", status="found",
                           verdict=core.VERDICT_MALICIOUS, detections=58,
                           total=72, detail={"engines": True})

    rep = core.Report(indicator=ind)
    rep.results = [mb, uh, vt,
                   core.SourceResult(source="circl", status="not_found"),
                   core.SourceResult(source="dns", status="found",
                                     verdict=core.VERDICT_UNKNOWN,
                                     category="intel")]
    dec = rep.decision()
    check(dec["verdict"] == rep.verdict() and
          dec["confidence"] == rep.confidence(),
          "panel repeats the aggregate verdict and confidence")
    check([r["label"] for r in dec["rows"]][0] == "Blocklists",
          f"heaviest evidence class first ({[r['label'] for r in dec['rows']]})")
    check(dec["rows"][0]["width"] == 100, "leading bar is drawn full width")
    check(all(0 < row["width"] <= 100 for row in dec["rows"]),
          "every bar stays inside its track")
    check(dec["rows"][0]["tone"] == "bad", "malicious weight renders hot")
    check(all(row["key"] != "other" for row in dec["rows"]),
          "intel rows never count as votes")
    # The lead must say how wide the agreement is, not just how many sources:
    # three sources spread over two classes is a different claim from three
    # blocklists echoing one another.
    check(dec["summary"] ==
          "3 sources across 2 evidence classes agree it is malicious",
          f"lead quantifies breadth, not just the count ({dec['summary']})")

    # Two feeds are a conviction on their own; losing either must be modelled as
    # a downgrade, and that number has to come from the real verdict rules.
    pair = core.Report(indicator=ind)
    pair.results = [mb, uh]
    check(pair.verdict() == core.VERDICT_MALICIOUS, "two feeds convict")
    piv = pair.decision()["pivots"]
    check(bool(piv) and piv[0]["verdict"] == core.VERDICT_SUSPICIOUS,
          f"losing one of two feeds is predicted as a lead ({piv})")
    check(piv[0]["confidence"] < pair.confidence(),
          "the predicted confidence is lower than today's")
    pair_dec = pair.decision()
    check("2 sources across 1 evidence class " in pair_dec["summary"],
          f"two feeds in one class read as narrow ({pair_dec['summary']})")
    check("classess" not in pair_dec["summary"], "singular plural is spelled")

    # PuTTY: distribution feeds plus a clean engine sweep stay a lead, and the
    # panel says why instead of pretending the feeds disagreed.
    putty = core.Report(indicator=ind)
    putty.results = [
        core.SourceResult(source="urlhaus", status="found",
                          verdict=core.VERDICT_MALICIOUS),
        core.SourceResult(source="otx", status="found",
                          verdict=core.VERDICT_MALICIOUS, note="5 pulse(s)"),
        core.SourceResult(source="hybridanalysis", status="found",
                          verdict=core.VERDICT_CLEAN, detections=0, total=2,
                          detail={"engines": True}),
    ]
    putty_dec = putty.decision()
    check(any("engines found nothing" in i for i in putty_dec["insights"]),
          f"panel flags the heuristic-only suspicion ({putty_dec['insights']})")
    check(any("lead, not a conviction" in i for i in putty_dec["insights"]),
          "panel says agreeing feeds are still a lead")
    clean_row = [r for r in putty_dec["rows"] if r["key"] == "sandbox"][0]
    check(clean_row["tone"] == "good" and clean_row["flagged"] == 0,
          "a clean engine sweep is drawn as counter-evidence")

    # The operator's own corpus does not need to borrow credibility.
    mine = core.Report(indicator=ind)
    mine.results = [core.SourceResult(source="local", status="found",
                                      verdict=core.VERDICT_MALICIOUS,
                                      note="block")]
    mine_dec = mine.decision()
    check("blocklist decides this on its own" in mine_dec["summary"],
          f"local verdict explained as a first-hand decision ({mine_dec['summary']})")
    check("1 independent sources" not in mine_dec["summary"],
          "no broken plural in the local summary")

    # A clean report must not borrow the false-positive caveat.
    quiet = core.Report(indicator=ind)
    quiet.results = [
        core.SourceResult(source="hybridanalysis", status="found",
                          verdict=core.VERDICT_CLEAN, detections=0, total=2,
                          detail={"engines": True}),
        core.SourceResult(source="circl", status="not_found"),
    ]
    quiet_dec = quiet.decision()
    check(not any("false-positive" in i for i in quiet_dec["insights"]),
          f"no false-positive caveat on a clean result ({quiet_dec['insights']})")

    payload = rep.to_dict()
    check(isinstance(payload.get("decision"), dict), "decision shipped in the JSON")
    check(payload["decision"]["rows"] == dec["rows"], "JSON rows match the panel")


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


def engine_clearance() -> None:
    """A clean engine sweep must outrank heuristic-only suspicion."""
    print("\n[engine clearance]")
    from threattrove.sources import HybridAnalysis
    ha = HybridAnalysis()
    sha = "0" * 64

    def ha_result(verdict, score=None, **scanners):
        entry = {"sha256": sha, "verdict": verdict, "threat_score": score,
                 "vx_family": "", "last_file_name": "7z2501-x64.exe",
                 "type": "PE32 executable (GUI) Intel 80386", "size": 1234,
                 "analysis_start_time": "2025-01-02 03:04:05",
                 "whitelisted": False, "scanners_v2": scanners}
        return ha._judge(entry, sha)

    def otx(verdict, pulses=1):
        return core.SourceResult(source="otx", status="found", verdict=verdict,
                                 note=f"{pulses} pulse(s)",
                                 detail={"pulses": pulses})

    def urlhaus(verdict):
        return core.SourceResult(source="urlhaus", status="found",
                                 verdict=verdict, note="payload seen in URLhaus")

    two_clean = {"metadefender": {"status": "clean"},
                 "crowdstrike_ml": {"status": "clean"}}
    one_clean = {"metadefender": {"status": "clean"}}
    one_bad = {"metadefender": {"status": "malicious"}}

    def report(*results):
        rep = core.Report(indicator=core.parse_indicator(sha))
        rep.results = list(results)
        return rep

    # Authentic 7-Zip: behavioural score plus one pulse, zero engine agreement.
    rep = report(ha_result("suspicious", 75, **two_clean),
                 otx(core.VERDICT_SUSPICIOUS))
    check(rep.engine_cleared(), "0/2 engines -> cleared")
    check(rep.verdict() == core.VERDICT_CLEAN,
          f"engine sweep outranks heuristics ({rep.verdict()})")
    check(rep.confidence() <= core.ENGINE_CLEARED_CONFIDENCE,
          f"cleared file keeps a low confidence ({rep.confidence()})")
    check("0/2 engines flagged this" in rep.headline(),
          f"headline cites the sweep: {rep.headline()}")
    check("hybridanalysis" in rep.headline() and "otx" in rep.headline(),
          f"headline names the weak flags: {rep.headline()}")

    # Authentic PuTTY: two feeds call it malicious without scanning it. The
    # engines agree there is nothing wrong, yet a conviction is not erased.
    putty = report(ha_result("no specific threat", None, **two_clean),
                   otx(core.VERDICT_MALICIOUS, pulses=5),
                   urlhaus(core.VERDICT_MALICIOUS))
    check(putty.engine_cleared(), "putty engines cleared too")
    check(putty.verdict() == core.VERDICT_SUSPICIOUS,
          f"feed consensus is not downgraded by engines ({putty.verdict()})")
    check(putty.confidence() == core.CAMPAIGN_ONLY_CONFIDENCE,
          f"campaign-only confidence kept ({putty.confidence()})")

    # A real determination survives a clean sweep next to it.
    eicar = report(ha_result("malicious", 100, **one_bad),
                   core.SourceResult(source="malwarebazaar", status="found",
                                     verdict=core.VERDICT_MALICIOUS,
                                     note="EICAR-Test-File"))
    check(eicar.verdict() == core.VERDICT_MALICIOUS,
          f"direct determination stays malicious ({eicar.verdict()})")

    # One scanner is not enough to call a sweep; the suspicion stands.
    weak = report(ha_result("suspicious", 60, **one_clean),
                  otx(core.VERDICT_SUSPICIOUS))
    check(not weak.engine_cleared(), "0/1 scanner does not clear")
    check(weak.verdict() == core.VERDICT_SUSPICIOUS,
          f"thin engine evidence keeps suspicion ({weak.verdict()})")

    # A sandbox that never produced scanner data cannot clear anything.
    blind = report(ha_result("suspicious", 60), otx(core.VERDICT_SUSPICIOUS))
    check(not blind.engine_cleared(), "no scanners -> not cleared")
    check(blind.verdict() == core.VERDICT_SUSPICIOUS,
          f"no scanner data keeps suspicion ({blind.verdict()})")


def family_labels() -> None:
    """A category word is not a family name."""
    print("\n[family labels]")
    from threattrove.sources import HybridAnalysis
    ha = HybridAnalysis()
    sha = "0" * 64

    def entry(verdict, score, family, **scanners):
        return {"sha256": sha, "verdict": verdict, "threat_score": score,
                "vx_family": family, "last_file_name": "7zr.exe",
                "type": "PE32 executable (console) Intel 80386", "size": 602624,
                "analysis_start_time": "2025-01-02 03:04:05",
                "whitelisted": False, "scanners_v2": scanners}

    err = {"crowdstrike_ml": {"status": "error"}}

    # The observed 7zr case: HA tags a 7-Zip binary "Malware" with every
    # scanner silent. A category word must not convict the file.
    res = ha._judge(entry("suspicious", 52, "Malware", **err), sha)
    check(res.verdict == core.VERDICT_SUSPICIOUS,
          f"generic family does not convict ({res.verdict})")
    check(res.detail["family"] is None, "generic family dropped from detail")
    check(res.detail["family_raw"] == "Malware", "raw family kept for display")

    # A real family name still convicts without scanner support.
    res = ha._judge(entry("malicious", None, "Emotet", **err), sha)
    check(res.verdict == core.VERDICT_MALICIOUS, "specific family still convicts")
    check(res.detail["family"] == "Emotet", "specific family kept")

    # And the headline never reads "(Malware)".
    rep = core.Report(indicator=core.parse_indicator(sha))
    rep.results = [core.SourceResult(source="virustotal", status="found",
                                     verdict=core.VERDICT_MALICIOUS,
                                     note="12/70 engines flagged",
                                     detail={"threat_label": "malware"})]
    check(rep.families() == [], f"generic label filtered ({rep.families()})")
    check("Malware" not in rep.headline(), f"headline clean: {rep.headline()}")


def otx_pulses() -> None:
    """A pulse tagged as not-a-threat must not convict anything."""
    print("\n[otx pulses]")
    from threattrove import sources as src

    # The real response behind the all-f hash: a lab-issues pulse whose only
    # verdict-ish tag is "no problems".
    junk = {"pulse_info": {"count": 1, "pulses": [
        {"name": "UAlberta Computer Lab Issues",
         "tags": ["drive", "problems1", "data", "no problems"]}]}}
    convicting, raw, ignored, names = src._otx_pulse_count(junk)
    check((convicting, raw, ignored) == (0, 1, 1),
          f"no-threat pulse ignored ({convicting} of {raw}, {ignored} ignored)")
    check(bool(names) and "UAlberta" in names[0], f"ignored pulse named ({names})")
    verdict, note = src._otx_verdict(convicting, [], core.KIND_HASH)
    check(verdict == core.VERDICT_UNKNOWN, f"junk pulse does not convict ({verdict})")
    check("ignored" in src._note_ignored(note, ignored),
          f"note stays honest: {src._note_ignored(note, ignored)}")

    # A genuinely pulsed hash keeps its other pulses and still convicts.
    mixed = {"pulse_info": {"count": 5, "pulses": [
        {"name": "Emotet campaign", "tags": ["emotet", "loader"]},
        {"name": "Lab test", "tags": ["No Problems"]},
        {"name": "Qakbot", "tags": ["qakbot"]}]}}
    convicting, raw, ignored, _ = src._otx_pulse_count(mixed)
    check((convicting, raw, ignored) == (4, 5, 1),
          f"real pulses survive ({convicting} of {raw})")
    verdict, _ = src._otx_verdict(convicting, [], core.KIND_HASH)
    check(verdict == core.VERDICT_MALICIOUS, f"real pulses still convict ({verdict})")

    # Only the benign pulses we can actually see are discounted.
    paged = {"pulse_info": {"count": 40,
                            "pulses": [{"name": "x", "tags": ["benign"]}]}}
    check(src._otx_pulse_count(paged)[0] == 39, "paged count reduced only by visible pulses")

    # Older responses carry a count with no pulse list; leave it untouched.
    check(src._otx_pulse_count({"pulse_info": {"count": 3}})[0] == 3,
          "count without pulse list is untouched")


def local_corpus() -> None:
    """Bulk-imported blocklists convict on their own, and parse by shape."""
    print("\n[local import]")
    import tempfile
    from threattrove import bulk

    sha_a = "a" * 64
    sha_b = "b" * 64
    sha_c = "c" * 64
    md5_a = "d" * 32
    sha1_a = "e" * 40

    # A MalwareBazaar-style export: header row, quoted fields, extra columns,
    # a duplicate, and hashes of two different widths.
    raw = (
        '"sha256_hash","firstseen_utc","file_name","file_type_guess"\n'
        f'"{sha_a}","2025-01-02 03:04:05","invoice.exe","exe"\n'
        f'"{md5_a}","2025-01-02 03:04:06","invoice.exe","exe"\n'
        f'"{sha1_a}","2025-01-02 03:04:07","loader.dll","dll"\n'
        f'"{sha_a}","2025-01-03 00:00:00","invoice.exe","exe"\n'
        "not-a-hash,whatever\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        csv_path = Path(tmp) / "full.csv"
        csv_path.write_text(raw, encoding="utf-8")

        parsed = list(bulk.iter_hash_tokens(csv_path))
        algos = sorted(a for a, _ in parsed)
        check(len(parsed) == 3, f"header skipped and duplicate dropped ({len(parsed)})")
        check(algos == ["md5", "sha1", "sha256"], f"widths detected ({algos})")
        check(len(list(bulk.iter_hash_tokens(csv_path, limit=2))) == 2,
              "limit honoured")

        # Import twice: the first pass inserts, the second only relabels.
        store = core.Store(Path(tmp) / "t.db")
        inserted, updated = store.add_local_many(
            [("hash", h) for _, h in parsed], label="malware",
            note="imported from full.csv")
        check((inserted, updated) == (3, 0), f"first import inserts ({inserted}/{updated})")

        inserted, updated = store.add_local_many(
            [("hash", sha_a)], label="malware", note="re-import")
        check((inserted, updated) == (0, 1), f"re-import updates ({inserted}/{updated})")
        check(store.count_local_in("hash", [sha_a, sha_b]) == 1,
              "count_local_in counts only stored values")

        # The operator's own verdict needs no second source.
        eng = core.Engine(sources=[], store=store)
        rep = eng.lookup(core.parse_indicator(sha_a))
        check(rep.verdict() == core.VERDICT_MALICIOUS,
              f"local row convicts alone ({rep.verdict()})")
        check(rep.confidence() >= core.LOCAL_TRUST_CONFIDENCE,
              f"confidence lifted ({rep.confidence()})")
        head = rep.headline()
        check("local blocklist" in head, f"headline names the corpus: {head}")
        check("0/0" not in head, f"no empty engine ratio: {head}")

        # A hash that is not in the corpus stays unknown.
        rep = eng.lookup(core.parse_indicator(sha_b))
        check(rep.verdict() == core.VERDICT_UNKNOWN, f"miss stays {rep.verdict()}")

        # An allowlist row outranks a feed hit rather than being overruled.
        store.add_local("hash", sha_c, "clean", "vendor binary")
        rep = core.Report(indicator=core.parse_indicator(sha_c))
        rep.results = [core.SourceResult(source="virustotal", status="found",
                                         verdict=core.VERDICT_MALICIOUS,
                                         note="1/70 engines flagged")]
        check(rep.verdict() != core.VERDICT_MALICIOUS,
              f"allowlist still wins ({rep.verdict()})")
        store.close()


def cache_logic() -> None:
    print("\n[cache logic version]")
    import dataclasses
    import json
    import sqlite3
    import tempfile
    import time

    h = "ab" * 32
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "old.db"

        # A cache written before 2.1.7 has no logic_version column at all.
        stale = core.SourceResult(source="otx", status="found",
                                  verdict=core.VERDICT_SUSPICIOUS,
                                  note="pulses counted the old way")
        conn = sqlite3.connect(db)
        conn.executescript(
            "CREATE TABLE cache (kind TEXT NOT NULL, value TEXT NOT NULL,"
            " source TEXT NOT NULL, payload TEXT NOT NULL,"
            " fetched_at REAL NOT NULL,"
            " PRIMARY KEY (kind, value, source));")
        conn.execute("INSERT INTO cache VALUES (?,?,?,?,?)",
                     ("hash", h, "otx",
                      json.dumps(dataclasses.asdict(stale)), time.time()))
        conn.commit()
        conn.close()

        store = core.Store(db)
        cols = {row[1] for row in store.conn.execute("PRAGMA table_info(cache)")}
        check("logic_version" in cols, "old database gained the column")
        check(store.get_cached("hash", h, "otx", logic_version=2) is None,
              "row written by the old rule is not served")
        check(store.get_cached("hash", h, "otx", logic_version=0) is not None,
              "it is kept, tagged 0, until the next lookup replaces it")

        # A write only comes back to the code version that made it.
        fresh = core.SourceResult(source="otx", status="found",
                                  verdict=core.VERDICT_UNKNOWN,
                                  note="no-threat pulses ignored")
        store.put_cached("hash", h, fresh, logic_version=2)
        got = store.get_cached("hash", h, "otx", logic_version=2)
        check(got is not None and got.verdict == core.VERDICT_UNKNOWN,
              "matching logic version -> served")
        check(bool(got and got.detail.get("_cached")), "marked as cached")
        check(store.get_cached("hash", h, "otx", logic_version=1) is None,
              "older logic version -> miss")

        # The engine re-queries only the source that moved.
        class _Counter(core.Source):
            name = "counter"
            display = "Counter"
            env_key = None
            kinds = (core.KIND_HASH,)
            calls = 0

            def lookup(self, ind):
                type(self).calls += 1
                return self.result(status="found",
                                   verdict=core.VERDICT_CLEAN,
                                   note=f"call {type(self).calls}")

        class _Other(_Counter):
            name = "other"
            calls = 0

        eng = core.Engine(sources=[_Counter()], store=store)
        ind = core.parse_indicator(h)
        first = eng.lookup(ind).results[0]
        check(_Counter.calls == 1 and not first.detail.get("_cached"),
              "first lookup queries the source")
        second = eng.lookup(ind).results[0]
        check(_Counter.calls == 1 and second.detail.get("_cached"),
              "second lookup is served from cache")

        _Counter.logic_version = 2
        third = eng.lookup(ind).results[0]
        check(_Counter.calls == 2 and not third.detail.get("_cached"),
              "bumping logic_version forces a re-query")
        check(third.verdict == core.VERDICT_CLEAN,
              f"the fresh verdict is what is served ({third.verdict})")
        eng.lookup(ind)
        check(_Counter.calls == 2, "and the new row caches at the new version")

        # Bumping one source must not throw away another source's cache.
        _Counter.logic_version = 1
        _Counter.calls = 0
        h2 = "cd" * 32
        eng2 = core.Engine(sources=[_Counter(), _Other()], store=store)
        ind2 = core.parse_indicator(h2)
        eng2.lookup(ind2)
        check((_Counter.calls, _Other.calls) == (1, 1),
              f"two sources, each queried once ({_Counter.calls}, {_Other.calls})")
        _Other.logic_version = 2
        res = {r.source: r for r in eng2.lookup(ind2).results}
        check(_Other.calls == 2, "the bumped source re-queried")
        check(_Counter.calls == 1 and res["counter"].detail.get("_cached"),
              "the untouched source stayed cached")
        store.close()

    # The shipped sources say which of them changed their rules.
    from threattrove.sources import ALL_SOURCES
    bumped = sorted(s.name for s in ALL_SOURCES if s.logic_version > 1)
    check(bumped == ["hybridanalysis", "otx", "otx_domain", "otx_url",
                     "virustotal", "virustotal_domain", "virustotal_url"],
          f"sources with corrected verdict logic: {bumped}")


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
    decision_view()
    sandbox_ha()
    engine_clearance()
    family_labels()
    otx_pulses()
    local_corpus()
    cache_logic()
    live("--offline" in sys.argv)
    print("\nall checks passed")
