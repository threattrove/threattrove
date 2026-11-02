#!/usr/bin/env python3
"""Check that corroboration counts authorities, and that pacing is shared.

    python scripts/check_corroboration.py

Three rules are under test.

0. The weighted score stays on the -100..100 scale the pages report. Summed
   weights are unbounded, and an unbounded sum used to render as "score
   600/100".

1. Corroboration counts *authorities*, not rows. Rows published by one
   authority -- two engine panels, or a feed answering for a payload and for a
   URL -- are one opinion, so they cannot convict each other. Two genuinely
   separate authorities still convict, and the operator's own corpus still
   convicts alone.

2. A provider rate limit belongs to the key, so one web process must spend one
   body of it. The pacer is keyed by ``quota_key``, shared across threads and
   Engine instances, and it refuses rather than blocks once the queue is long.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threattrove import core  # noqa: E402


def check(cond: bool, msg: str) -> None:
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        raise SystemExit(f"failed: {msg}")


H = "44d88612fea8a8f36de82e1278abb02f"   # EICAR, for the report view


def row(source: str, verdict: str = core.VERDICT_MALICIOUS, **kw):
    return core.SourceResult(source=source, status="found", verdict=verdict,
                             category="reputation", **kw)


def report(*rows) -> core.Report:
    rep = core.Report(indicator=core.parse_indicator(H))
    rep.results = list(rows)
    return rep


def score_is_bounded() -> None:
    print("\n[score bounds]")
    check(report(row("circl")).score() == 100,
          "one malicious source scores 100")
    check(report(row("circl"), row("otx")).score() == 100,
          "two malicious sources score 100, not 200")
    check(report(row("circl", core.VERDICT_CLEAN),
                row("otx", core.VERDICT_CLEAN)).score() == -40,
          "ordinary sums are not flattened by the clamp")
    check(report(row("circl", core.VERDICT_KNOWN_GOOD),
                row("otx", core.VERDICT_KNOWN_GOOD)).score() == -100,
          "two known-good sources score -100, not -200")


def authorities() -> None:
    print("\n[authorities]")
    check(core.evidence_authority("virustotal") == core.ENGINE_PANEL_AUTHORITY,
          "virustotal is the engine panel")
    check(core.evidence_authority("virustotal_url") == core.ENGINE_PANEL_AUTHORITY,
          "the URL endpoint is the same panel")
    check(core.evidence_authority("hybridanalysis") == core.ENGINE_PANEL_AUTHORITY,
          "a second panel is still the panel")
    check(core.evidence_authority("urlhaus") == core.evidence_authority("urlhaus_url"),
          "urlhaus answers once, whatever it was asked about")
    check(core.evidence_authority("gsb") == "gsb", "a plain source stands alone")
    check(core.evidence_authority("phishtank") != core.evidence_authority("gsb"),
          "two reputation services are two authorities")


def two_panels_do_not_convict() -> None:
    print("\n[engine panels]")
    # Both panels call the file malicious. Two rows, one authority: the honest
    # reading is a lead, not a conviction.
    rep = report(row("virustotal", detections=9, total=70,
                     detail={"engines": True}),
                 row("hybridanalysis", detections=4, total=20,
                     detail={"engines": True}))
    check(rep.corroboration() == 1,
          f"two panels are one authority ({rep.corroboration()})")
    check(rep.verdict() == core.VERDICT_SUSPICIOUS,
          f"panels alone stay suspicious ({rep.verdict()})")
    check(rep.verdict() != core.VERDICT_MALICIOUS,
          "and never reach malicious")
    dec = rep.decision()
    check(dec["verdict"] == core.VERDICT_SUSPICIOUS,
          f"decision view agrees ({dec['verdict']})")
    head = rep.headline()
    check("independent sources" not in head,
          f"headline does not claim agreement that does not exist: {head}")

    # One panel plus one blocklist is two authorities, so it convicts.
    rep = report(row("virustotal", detections=9, total=70,
                     detail={"engines": True}),
                 row("urlhaus"))
    check(rep.corroboration() == 2,
          f"panel + feed are two authorities ({rep.corroboration()})")
    check(rep.verdict() == core.VERDICT_MALICIOUS,
          f"panel + feed convict ({rep.verdict()})")
    check(rep.corroboration_classes() == 2,
          f"and span two classes ({rep.corroboration_classes()})")


def duplicate_rows_do_not_convict() -> None:
    print("\n[same source twice]")
    # A URL and a payload answer from one feed. Two rows, one opinion.
    rep = report(row("urlhaus"), row("urlhaus_url"))
    check(rep.corroboration() == 1, f"one feed is one authority ({rep.corroboration()})")
    check(rep.verdict() == core.VERDICT_SUSPICIOUS,
          f"a feed agreeing with itself stays suspicious ({rep.verdict()})")


def independent_services_still_convict() -> None:
    print("\n[independent services]")
    # Google and OpenPhish are different authorities in the same evidence
    # class; the class count must not be allowed to hide that.
    rep = report(row("gsb"), row("phishtank"))
    check(rep.corroboration() == 2,
          f"two services are two authorities ({rep.corroboration()})")
    check(rep.corroboration_classes() == 1,
          f"even inside one class ({rep.corroboration_classes()})")
    # Neither service examined the artifact, so the older rule still holds it
    # to suspicious -- independent authorities are necessary, not sufficient.
    check(rep.verdict() == core.VERDICT_SUSPICIOUS,
          f"but nothing looked at it, so it stays a lead ({rep.verdict()})")

    # Two authorities inside one class, one of which examined the file, are a
    # conviction: distinct providers must not be lost in the class count.
    rep = report(row("malwarebazaar"), row("malshare"))
    check((rep.corroboration(), rep.corroboration_classes()) == (2, 1),
          f"two repos, one class ({rep.corroboration()}, "
          f"{rep.corroboration_classes()})")
    check(rep.verdict() == core.VERDICT_MALICIOUS,
          f"and together they convict ({rep.verdict()})")

    # The operator's own decision never needed a second source.
    rep = report(row("local"))
    check(rep.corroboration() == 1, "a local row is one authority")
    check(rep.verdict() == core.VERDICT_MALICIOUS,
          f"local still convicts alone ({rep.verdict()})")
    check(rep.confidence() >= core.LOCAL_TRUST_CONFIDENCE,
          f"with trusted confidence ({rep.confidence()})")


def breadth_wording() -> None:
    print("\n[wording]")
    rep = report(row("malwarebazaar"), row("urlhaus"), row("virustotal",
                                                          detail={"engines": True}))
    dec = rep.decision()
    check(dec["summary"] == "3 independent authorities across 2 evidence "
                            "classes agree it is malicious",
          f"breadth is stated in authorities: {dec['summary']}")


def pacer() -> None:
    print("\n[pacer]")
    core._PACE_NEXT.clear()
    key = "check-pacer"
    check(core.pace_slot(key, 0) is True, "no interval -> no wait")
    check(core.pace_slot(key, 5, max_wait=0) is True, "first call takes the slot")
    check(core.pace_slot(key, 5, max_wait=0) is False,
          "the next call is refused, not blocked")
    check(core.pace_wait_hint(key) > 0, "and the wait is reported")
    core.pace_defer(key, 30)
    check(core.pace_wait_hint(key) >= 29, "a 429 defers the whole key")
    core._PACE_NEXT.clear()

    # The slot is shared between threads and between Engine instances, so two
    # lookups served at once cannot each think they have the key to themselves.
    core._PACE_NEXT.clear()
    shared = "shared-key"
    results: list[bool] = []
    lock = threading.Lock()

    class _Src(core.Source):
        name = "paced"
        display = "Paced"
        quota_key = shared
        min_interval = 5.0

        def lookup(self, ind):
            return self.result(status="found", verdict=core.VERDICT_UNKNOWN)

    src = _Src()

    def one() -> None:
        got = core.Engine(sources=[src])._pace(src)
        with lock:
            results.append(got)

    threads = [threading.Thread(target=one) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check(results.count(True) == 1 and results.count(False) == 3,
          f"one slot per key per interval ({results})")
    core._PACE_NEXT.clear()

    # A held-back source says so instead of spending quota on a 429.
    class _Quota(core.Source):
        name = "quota-check"
        display = "Quota"
        keyless = True
        quota_key = "quota-check-key"
        min_interval = 60.0
        calls = 0

        def lookup(self, ind):
            type(self).calls += 1
            return self.result(status="found", verdict=core.VERDICT_UNKNOWN)

    q = _Quota()
    eng = core.Engine(sources=[q], use_cache=False)
    ind = core.parse_indicator(H)
    first = eng.lookup(ind).results[0]
    second = eng.lookup(ind).results[0]
    check(first.status == "found" and _Quota.calls == 1,
          f"first call went out ({first.status})")
    check(second.status == "skipped" and _Quota.calls == 1,
          f"second call held back, not sent ({second.status}, {_Quota.calls} call)")
    check("rate limit" in second.note, f"and says why: {second.note}")
    core._PACE_NEXT.clear()


def virus_total_interval() -> None:
    print("\n[virustotal interval]")
    from threattrove.sources import (VT_MIN_INTERVAL, VT_MIN_INTERVAL_ENV,
                                     VirusTotalDomain, VirusTotalFile,
                                     VirusTotalUrl)

    saved = os.environ.pop(VT_MIN_INTERVAL_ENV, None)
    try:
        check(VirusTotalFile().min_interval == VT_MIN_INTERVAL,
              f"default spacing ({VT_MIN_INTERVAL}s)")
        check(VirusTotalUrl().min_interval == VT_MIN_INTERVAL
              and VirusTotalDomain().min_interval == VT_MIN_INTERVAL,
              "all three endpoints share the key's spacing")
        os.environ[VT_MIN_INTERVAL_ENV] = "0.1"
        check(VirusTotalFile().min_interval == 0.1,
              "a premium key can raise it through the env")
        os.environ[VT_MIN_INTERVAL_ENV] = "not a number"
        check(VirusTotalFile().min_interval == VT_MIN_INTERVAL,
              "garbage falls back to the default")
    finally:
        os.environ.pop(VT_MIN_INTERVAL_ENV, None)
        if saved is not None:
            os.environ[VT_MIN_INTERVAL_ENV] = saved

    check(VirusTotalFile.quota_key == "virustotal"
          and VirusTotalUrl.quota_key == "virustotal",
          "the quota key is what the pacer is keyed on")


def retry_after() -> None:
    print("\n[retry-after]")
    from threattrove.sources import _retry_after

    class _R:
        def __init__(self, headers):
            self.headers = headers

    check(_retry_after(_R({"Retry-After": "12"})) == 12.0, "reads the header")
    check(_retry_after(_R({})) == 60.0, "falls back to a minute")
    check(_retry_after(_R({"Retry-After": "soon"})) == 60.0, "ignores rubbish")
    check(_retry_after(_R({"Retry-After": "0"})) == 1.0, "never zero")


if __name__ == "__main__":
    score_is_bounded()
    authorities()
    two_panels_do_not_convict()
    duplicate_rows_do_not_convict()
    independent_services_still_convict()
    breadth_wording()
    pacer()
    virus_total_interval()
    retry_after()
    print("\nall checks passed")
