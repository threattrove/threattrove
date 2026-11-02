#!/usr/bin/env python3
"""Source-health canary: ask every active source about a known indicator.

Run from the repository root, with the same environment the service gets::

    set -a; . /etc/threattrove/threattrove.env; set +a
    .venv/bin/python scripts/source_canary.py

``--dry-run`` prints what each source answered without writing anything, which
is the way to look at a failing feed without changing its recorded health.

The canary exists because the failures that matter are silent. Two releases
shipped a source that answered HTTP 200 with a document that parsed to "not
found": nothing raised, no status code changed, and only a sample whose answer
was already known showed the difference. So every run bypasses the cache,
records the status each source returned for an indicator it cannot plausibly be
neutral about, and compares that with what the source said when it was last
healthy.

One probe per source per run, on the first canary indicator the source
supports, keeps the cost at one live request per active source. Sources that
support several indicator types are therefore checked on the type listed first
below; the canary is a liveness and agreement check, not a per-endpoint test.

Exit status is 1 when any active source is failing, so the timer leaves a
failed unit behind for whoever watches ``systemctl --failed``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from threattrove.core import (  # noqa: E402
    HEALTH_BAD,
    Engine,
    Store,
    health_state,
    pace_wait_hint,
    parse_indicator,
)

#: Failures worth a second try. One request that timed out is not evidence that
#: a feed is down, and crt.sh alone has answered in 12s and in 26s on the same
#: afternoon; a source that fails twice in a row is.
RETRY_STATUSES = frozenset({"error", "timeout"})

#: Longest the canary will wait out its own pacing window before giving up and
#: recording a skip. metadefender's shared allowance needs about 6s.
MAX_PACING_WAIT = 15.0

#: Indicators whose answer does not change. EICAR is the standard test file,
#: the malware.testing.google.test URL is Google's documented Safe Browsing
#: sample, and example.com and 8.8.8.8 are the two most stable neutral
#: indicators there are: a "found" for either is itself worth seeing.
CANARY = (
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
     "eicar"),
    ("http://malware.testing.google.test/testing/malware/", "gsb-sample"),
    ("example.com", "example-domain"),
    ("8.8.8.8", "public-resolver"),
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ask every active source about a known indicator.")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the answers, store nothing")
    parser.add_argument("--json", action="store_true",
                        help="print one JSON document instead of lines")
    parser.add_argument("--deadline", type=float, default=60.0,
                        help="seconds to wait for the slowest source")
    args = parser.parse_args()

    store = Store()
    engine = Engine(store=store, max_workers=6, deadline=args.deadline)
    if not args.json:
        print(f"database: {store.path}")

    checks = []
    seen = set()
    bad = 0
    for text, sample in CANARY:
        ind = parse_indicator(text)
        if ind is None:
            print(f"canary indicator did not parse: {text}", file=sys.stderr)
            bad += 1
            continue
        for source in engine.sources_for(ind.kind):
            if source.name in seen:
                continue
            seen.add(source.name)
            result, latency = engine.probe(source, ind)
            paced = (result.detail or {}).get("paced")
            if paced:
                # The canary tripped the pacing window it shares with the rest
                # of the site; asking a provider "too soon" is not a fault, so
                # wait the window out and ask again.
                time.sleep(min(MAX_PACING_WAIT, max(0.0, pace_wait_hint(paced))))
                result, latency = engine.probe(source, ind)
            elif result.status in RETRY_STATUSES:
                time.sleep(1.5)
                result, latency = engine.probe(source, ind)
            row = {
                "source": source.name,
                "display": source.display or source.name,
                "kind": ind.kind,
                "indicator": ind.value,
                "sample": sample,
                "status": result.status,
                "verdict": result.verdict,
                "note": result.note,
                "latency_ms": int(latency),
            }
            if args.dry_run:
                row["state"] = health_state(result.status)
                row["expected"] = ""
                row["drift"] = None
            else:
                stored = store.record_health(
                    source.name, result.status, kind=ind.kind,
                    indicator=ind.value, verdict=result.verdict,
                    note=result.note, latency_ms=int(latency))
                row["state"] = stored["state"]
                row["expected"] = stored["expected"]
                row["drift"] = stored["drift"]
            if row["state"] == HEALTH_BAD:
                bad += 1
            checks.append(row)
            if not args.json:
                drift = row.get("drift")
                suffix = f" {drift:.1f}x" if drift and drift >= 1.5 else ""
                note = f"  {result.note[:70]}" if result.note else ""
                print(f"  {row['state']:<4} {source.name:<24}"
                      f"{result.status:<12}{row['latency_ms']:>6} ms{suffix}{note}")

    counts = {state: sum(1 for c in checks if c["state"] == state)
              for state in ("ok", "warn", "bad")}
    summary = {"checked": len(checks), "failed": bad, "states": counts,
               "dry_run": bool(args.dry_run)}
    if args.json:
        print(json.dumps({"summary": summary, "checks": checks}, indent=2))
    else:
        print(f"\n{counts['ok']} ok, {counts['warn']} warn, {counts['bad']} bad"
              f" of {len(checks)} source(s) checked")
        if bad:
            print("failing sources: "
                  + ", ".join(c["source"] for c in checks
                              if c["state"] == HEALTH_BAD))
    store.close()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
