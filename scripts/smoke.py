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
    check(core.combine([100])[0] == core.VERDICT_MALICIOUS, "single malicious")
    check(core.combine([100, 100])[0] == core.VERDICT_MALICIOUS, "two malicious")
    check(core.combine([100, -100])[0] == core.VERDICT_UNKNOWN, "conflict -> unknown")
    check(core.combine([-100])[0] == core.VERDICT_KNOWN_GOOD, "known good")
    check(core.combine([-20])[0] == core.VERDICT_CLEAN, "clean")
    check(core.combine([])[0] == core.VERDICT_UNKNOWN, "empty -> unknown")


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
    check(rep.verdict() == core.VERDICT_MALICIOUS, "EICAR is malicious")

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
    live("--offline" in sys.argv)
    print("\nall checks passed")
