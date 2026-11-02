#!/usr/bin/env python3
"""Check the pager contract of ``/api/v1/status?strict=...``.

Run from the repository root::

    python3 scripts/check_monitor.py

``strict=1`` is meant to be the URL an uptime monitor polls, so it has to fail
for the reasons that make a lookup wrong and stay quiet for the reasons that
only make it slow. This check pins that down: a broken source fails, stale
canary data fails (the timer may be dead), a fresh warning does not fail unless
the caller asked for ``strict=warn``, and no ``strict`` argument never fails.

Nothing here touches the network or the production database: the rows are
written straight into a temporary SQLite file and the app is driven through
Flask's test client. Exits non-zero if any expectation fails.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

# The module-level ``app`` opens the store named by TT_DB at import time, so the
# throwaway path has to be in place before the import.
_TMP = tempfile.mkdtemp(prefix="tt-monitor-check-")
os.environ["TT_DB"] = os.path.join(_TMP, "check.db")

from threattrove.core import Store  # noqa: E402
from threattrove.web import (  # noqa: E402
    HEALTH_STALE_SECONDS,
    _source_rows,
    app,
)

FAILED = []


def check(cond: bool, msg: str) -> None:
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        FAILED.append(msg)


def runtime() -> Store:
    return app.extensions["threattrove"].store


def active_names() -> list:
    return [r["name"] for r in _source_rows(app.extensions["threattrove"])
            if r["active"]]


def put(row: str, status: str = "found", *, age: float = 60.0,
        latency: int = 100, drift: float | None = None,
        note: str = "") -> None:
    """Write one canary row, ``age`` seconds old, without running a canary."""
    store = runtime()
    now = time.time()
    with store._lock:                       # noqa: SLF001 - a check may be direct
        store.conn.execute(
            "INSERT INTO source_health (source, kind, indicator, status,"
            " verdict, note, latency_ms, checked_at, expected, baseline_ms,"
            " baseline_at, drift) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(source) DO UPDATE SET status=excluded.status,"
            " note=excluded.note, latency_ms=excluded.latency_ms,"
            " checked_at=excluded.checked_at, expected=excluded.expected,"
            " baseline_ms=excluded.baseline_ms, baseline_at=excluded.baseline_at,"
            " drift=excluded.drift",
            (row, "hash", "44d88612fea8a8f36de82e1278abb02f", status, "",
             note, latency, now - age, "found", 100.0, now - age, drift))
        store.conn.commit()


def drop_all() -> None:
    store = runtime()
    with store._lock:                       # noqa: SLF001 - a check may be direct
        store.conn.execute("DELETE FROM source_health")
        store.conn.commit()


def get(client, query: str = ""):
    resp = client.get("/api/v1/status" + query)
    return resp, resp.get_json()


def main() -> int:
    client = app.test_client()
    names = active_names()
    check(bool(names), "at least one source is active in this environment")
    if not names:
        print("\ncannot exercise the monitor contract with every source off")
        return 1
    first = names[0]

    print("payload: shape")
    drop_all()
    for name in names:
        put(name)
    resp, data = get(client)
    check(resp.status_code == 200, "the plain payload is 200")
    check("stale_count" in data, "the payload carries a stale_count")
    check(data["stale_count"] == 0, "fresh rows are not stale")
    check(all(("stale" in row) for row in data["sources"]),
          "every source row carries its own stale flag")
    check(all(not row["stale"] for row in data["sources"]),
          "no source is stale after a fresh canary run")
    off = [r for r in data["sources"] if not r["active"]]
    check(all(r["state"] == "off" and not r["stale"] for r in off),
          "a source that is turned off is not stale")
    check(data["counts"]["off"] == len(off),
          "off sources are counted, not treated as failures")
    check(resp.headers.get("Cache-Control") == "no-store",
          "a monitor is never handed a cached answer")

    print("strict=1: broken source")
    put(first, "error", note="upstream 500")
    resp, data = get(client, "?strict=1")
    check(resp.status_code == 503, "a bad source fails strict=1")
    check(data["counts"]["bad"] == 1, "exactly the broken source is counted bad")
    check(data["stale_count"] == 0, "a fresh failure is not reported as stale")

    print("strict=1: stale canary, healthy-looking rows")
    drop_all()
    for name in names:
        put(name, age=HEALTH_STALE_SECONDS + 3600)
    resp, data = get(client, "?strict=1")
    check(resp.status_code == 503, "stale canary data fails strict=1")
    check(data["counts"]["bad"] == 0,
          "and it fails although nothing is bad")
    check(data["counts"]["warn"] == len(names),
          "stale rows surface as warnings on /status")
    check(data["stale_count"] == len(names), "they are all counted as stale")
    check(data["sources"][0]["stale"] is True, "the row says why")
    check(data["status"] == "warn", "the overall state is warn, not ok")
    resp = client.get("/status")
    body = resp.get_data(as_text=True)
    check(resp.status_code == 200, "the /status page renders with stale rows")
    check("are stale" in body, "and it names the stale rows as the cause")

    print("strict=1: one stale source among fresh ones")
    drop_all()
    for name in names:
        put(name)
    put(first, age=HEALTH_STALE_SECONDS + 60)
    resp, data = get(client, "?strict=1")
    check(resp.status_code == 503, "one stale source is enough to fail")
    check(data["stale_count"] == 1, "only that source is counted")
    stale_rows = [r["name"] for r in data["sources"] if r["stale"]]
    check(stale_rows == [first], "the stale flag names the right source")

    print("strict=1: one ok source, the rest never checked")
    drop_all()
    put(names[0])
    resp, data = get(client, "?strict=1")
    check(data["status"] == "ok",
          "the rollup is ok when the checked source is healthy")
    check(data["stale_count"] == len(names) - 1,
          "the sources with no row are stale")
    check(resp.status_code == 503, "unproven sources still fail the pager")
    body = client.get("/status").get_data(as_text=True)
    check("unproven rather than healthy" in body,
          "and the page says so instead of claiming everything is fine")

    print("strict=1: drift-only warning stays green")
    drop_all()
    for name in names:
        put(name)
    put(first, "found", latency=1070, drift=10.7)
    resp, data = get(client, "?strict=1")
    check(resp.status_code == 200, "a slow but answering source does not page")
    check(data["counts"]["warn"] == 1, "it is still a warning on the payload")
    check(data["stale_count"] == 0, "and it is not stale")

    print("strict=warn: drift is loud when asked for")
    resp, data = get(client, "?strict=warn")
    check(resp.status_code == 503, "strict=warn fails on that same drift")
    resp, _ = get(client, "?strict=all")
    check(resp.status_code == 503, "strict=all is the same setting")

    print("no canary row at all")
    drop_all()
    resp, data = get(client, "?strict=1")
    check(resp.status_code == 503, "unproven sources are not called healthy")
    check(data["status"] == "unknown", "the payload says unknown")
    check(data["counts"]["unchecked"] == len(names),
          "every active source is unchecked")
    check(data["stale_count"] == len(names), "unchecked counts as stale")

    print("skip is not a failure")
    drop_all()
    for name in names:
        put(name)
    put(first, "skipped", note="daily allowance is spent")
    resp, data = get(client, "?strict=1")
    check(resp.status_code == 200, "a spent allowance does not page")
    check(data["counts"]["skip"] == 1, "it is reported as skip")
    check(data["sources"][0]["stale"] is False, "a fresh skip is not stale")

    print("strict aliases and opt-out")
    drop_all()
    for name in names:
        put(name)
    put(first, "error")
    for arg, code in (("?strict=1", 503), ("?strict=true", 503),
                      ("?strict=yes", 503), ("?strict=TRUE", 503),
                      ("?strict=warn", 503), ("?strict=all", 503),
                      ("", 200), ("?strict=", 200), ("?strict=0", 200),
                      ("?strict=no", 200), ("?strict=off", 200),
                      ("?strict=1x", 200)):
        resp, _ = get(client, arg)
        check(resp.status_code == code,
              f"GET /api/v1/status{arg or ' (no argument)'} is {code}")

    print("strict=1 with sources deliberately off")
    drop_all()
    for name in names:
        put(name)
    resp, data = get(client, "?strict=1")
    check(resp.status_code == 200,
          "a source that is off on purpose never pages")
    check(data["counts"]["off"] > 0, "the off sources are still visible")

    runtime().close()
    print()
    if FAILED:
        print(f"{len(FAILED)} check(s) failed")
        return 1
    print("all monitor checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
