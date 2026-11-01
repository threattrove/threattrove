#!/usr/bin/env python3
"""Check the VirusTotal engine-ratio floor and its effect on engine clearance.

Run from the repository root::

    python3 scripts/check_vt_floor.py

Exits non-zero on the first failed expectation.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove import core  # noqa: E402
from threattrove.sources import (  # noqa: E402
    VirusTotalFile,
    _vt_floor,
    _vt_parse,
)

FAILED = []


class FakeResponse:
    """Minimal stand-in for a requests.Response carrying VT stats."""

    def __init__(self, mal=0, susp=0, harmless=0, undetected=0, total=None):
        self.status_code = 200
        self._stats = {"malicious": mal, "suspicious": susp,
                       "harmless": harmless, "undetected": undetected}
        if total is not None:  # explicit denominator, e.g. a partial sweep
            self._stats = {"malicious": mal, "suspicious": susp,
                           "harmless": harmless,
                           "undetected": total - mal - susp - harmless}

    def json(self):
        return {"data": {"attributes": {"last_analysis_stats": self._stats}}}


def check(label, got, want):
    ok = got == want
    print(("  ok   " if ok else "  FAIL ") + f"{label}: {got!r}"
          + ("" if ok else f" (want {want!r})"))
    if not ok:
        FAILED.append(label)


def parse(resp):
    return _vt_parse(VirusTotalFile(), resp, file_hash="0" * 64)


def main() -> int:
    print("floor maths")
    check("floor(0)", _vt_floor(0), 3)
    check("floor(70)", _vt_floor(70), 3)
    check("floor(92)", _vt_floor(92), 3)
    check("floor(200)", _vt_floor(200), 6)

    print("engine sweeps")
    # 8.8.8.8: one vendor out of 92 -- noise, not a verdict.
    r = parse(FakeResponse(mal=1, harmless=60, undetected=31, total=92))
    check("1/92 verdict", r.verdict, core.VERDICT_UNKNOWN)
    check("1/92 low_signal", r.detail.get("low_signal"), True)
    check("1/92 detections kept for display", (r.detections, r.total), (1, 92))
    check("1/92 note", r.note, "1/92 engines flagged, below the 3 needed to call it")

    # Two vendors of ninety-two is still a coin flip, not a call.
    check("2/92 verdict", parse(FakeResponse(mal=2, undetected=90)).verdict,
          core.VERDICT_UNKNOWN)

    # Three is the floor.
    check("3/92 verdict", parse(FakeResponse(mal=3, undetected=89)).verdict,
          core.VERDICT_MALICIOUS)

    # EICAR-sized consensus.
    check("65/75 verdict", parse(FakeResponse(mal=65, undetected=10)).verdict,
          core.VERDICT_MALICIOUS)
    check("65/75 note", parse(FakeResponse(mal=65, undetected=10)).note,
          "65/75 engines flagged")

    # A real sample flagged by a minority of engines still convicts.
    check("12/68 verdict", parse(FakeResponse(mal=12, undetected=56)).verdict,
          core.VERDICT_MALICIOUS)

    # Suspicion needs the same agreement.
    check("1 suspicious/70 verdict",
          parse(FakeResponse(susp=1, undetected=69)).verdict, core.VERDICT_UNKNOWN)
    check("4 suspicious/70 verdict",
          parse(FakeResponse(susp=4, undetected=66)).verdict,
          core.VERDICT_SUSPICIOUS)
    check("1 suspicious/70 note",
          parse(FakeResponse(susp=1, undetected=69)).note,
          "1/70 suspicious, below the 3 needed to call it")
    # Two vendors out of ninety-two, one each side of the line, must not read as
    # "3 flagged, below the 3 needed".
    check("1 malicious + 2 suspicious/92 note",
          parse(FakeResponse(mal=1, susp=2, undetected=89)).note,
          "1/92 engines flagged, below the 3 needed to call it")

    # Nobody had an opinion, or nobody liked it.
    check("0/70 verdict", parse(FakeResponse(undetected=70)).verdict,
          core.VERDICT_CLEAN)
    check("0/0 verdict", parse(FakeResponse(total=0)).verdict, core.VERDICT_UNKNOWN)
    check("0/0 has no low_signal", parse(FakeResponse(total=0)).detail.get("low_signal"),
          None)

    print("engine clearance")
    ind = core.parse_indicator("d41d8cd98f00b204e9800998ecf8427e")

    def report_with(*results):
        rep = core.Report(indicator=ind)
        rep.results.extend(results)
        return rep

    sandbox = core.SourceResult(source="hybridanalysis", status="found",
                                verdict=core.VERDICT_SUSPICIOUS,
                                note="sandbox score 60")
    noisy = parse(FakeResponse(mal=1, harmless=60, undetected=31, total=92))
    noisy.source = "virustotal"
    agreed = parse(FakeResponse(mal=20, undetected=72))
    agreed.source = "virustotal"

    check("lone vendor flag leaves the file cleared",
          report_with(sandbox, noisy).engine_cleared(), True)
    check("a real sweep keeps it unclearable",
          report_with(sandbox, agreed).engine_cleared(), False)

    print()
    if FAILED:
        print(f"{len(FAILED)} check(s) failed: {', '.join(FAILED)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
