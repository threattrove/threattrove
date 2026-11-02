#!/usr/bin/env python3
"""Check the paged local list and the source-health plumbing.

Run from the repository root::

    python3 scripts/check_status.py

Nothing here touches the network or the production database: a temporary SQLite
file holds a few hundred rows and the app is exercised through Flask's test
client. Exits non-zero on the first failed expectation, like the other checks.
"""
from __future__ import annotations

import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

# threattrove.web builds an app at import time and that app opens the store
# named by TT_DB, so the throwaway path has to be in place before the import.
_TMP = tempfile.mkdtemp(prefix="tt-status-check-")
os.environ["TT_DB"] = os.path.join(_TMP, "check.db")

from threattrove.core import (  # noqa: E402
    HEALTH_BAD,
    HEALTH_OK,
    HEALTH_SKIP,
    HEALTH_WARN,
    Store,
    health_state,
)
from threattrove.web import _source_rows, app  # noqa: E402

FAILED = []
TOTAL = 120


def check(cond: bool, msg: str) -> None:
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        FAILED.append(msg)


def seed(store: Store) -> None:
    """Insert TOTAL rows with distinct timestamps, newest last."""
    base = 1_700_000_000.0
    with store._lock:                      # noqa: SLF001 - a check may be direct
        for i in range(TOTAL):
            store.conn.execute(
                "INSERT OR REPLACE INTO local (kind, value, label, note,"
                " added_at) VALUES (?,?,?,?,?)",
                ("hash", f"{i:06d}" + "a" * 58, "malware",
                 f"ticket {i}", base + i))
        store.conn.commit()


def main() -> int:
    store = Store()
    seed(store)

    print("local list: paging")
    check(store.count_local() == TOTAL, f"count_local sees {TOTAL} rows")
    first = store.list_local(limit=10)
    check(len(first) == 10, "limit 10 returns 10 rows")
    check(first[0]["value"].startswith("000119"),
          "the newest row comes first")
    check(first[-1]["value"].startswith("000110"), "the page is contiguous")

    seen = []
    for offset in range(0, TOTAL, 50):
        seen.extend(r["value"] for r in store.list_local(limit=50, offset=offset))
    check(len(seen) == TOTAL, "paging over the whole table visits every row")
    check(len(set(seen)) == TOTAL, "no row is visited twice")
    check(seen[0].startswith("000119") and seen[-1].startswith("000000"),
          "the whole walk is newest to oldest")

    tail = store.list_local(limit=10, offset=TOTAL - 10)
    check(len(tail) == 10 and tail[-1]["value"].startswith("000000"),
          "the last page ends on the oldest row")
    check(store.list_local(limit=10, offset=10_000) == [],
          "an offset past the end is empty, not an error")
    check(len(store.list_local(limit=0)) == 1, "a limit of 0 is raised to 1")

    print("local list: filters")
    check(store.count_local(kind="hash") == TOTAL, "kind=hash counts everything")
    check(store.count_local(kind="url") == 0, "kind=url counts nothing")
    check(store.count_local(kind="url") == len(store.list_local(kind="url")),
          "the count and the list agree on an empty filter")
    check(store.count_local(query="00001") == 10, "a prefix filter counts 10 rows")
    check(len(store.list_local(query="00001")) == 10,
          "a prefix filter lists 10 rows")
    check(store.count_local(query="00001", kind="hash") == 10,
          "prefix and kind combine")
    check(store.count_local(query="00001", kind="url") == 0,
          "prefix and a wrong kind count nothing")
    check(store.count_local(query="00001".upper()) == 10,
          "the prefix filter lowercases its argument")
    check(store.count_local(query="ffff") == 0, "an unmatched prefix counts 0")
    check(store.list_local(query="000010")[0]["value"].startswith("000010"),
          "an exact prefix returns that row first")

    print("health: classification")
    check(health_state("found") == HEALTH_OK, "found is ok")
    check(health_state("not_found") == HEALTH_OK, "not_found is ok")
    check(health_state("error") == HEALTH_BAD, "error is bad")
    check(health_state("timeout") == HEALTH_BAD, "timeout is bad")
    check(health_state("") == HEALTH_BAD, "an empty status is bad")
    check(health_state("skipped") == HEALTH_SKIP,
          "a source that was not asked is neither ok nor a warning")
    check(health_state("deferred") == HEALTH_SKIP, "so is a deferred check")
    check(health_state("weird") == HEALTH_WARN,
          "an answer nobody can classify still is a warning")
    check(health_state("found", expected="not_found") == HEALTH_WARN,
          "answering differently than before is a warning")
    check(health_state("found", 5.0, "found") == HEALTH_WARN,
          "5x the baseline latency is a warning")
    check(health_state("found", 2.0, "found") == HEALTH_OK,
          "2x the baseline latency is not")

    print("health: recording")
    one = store.record_health("canary_a", "found", kind="hash",
                             indicator="x", latency_ms=100)
    check(one["state"] == HEALTH_OK, "the first healthy answer is ok")
    check(one["expected"] == "found", "the first answer becomes the expectation")
    check(one["baseline_ms"] == 100.0, "the first latency becomes the baseline")

    two = store.record_health("canary_a", "not_found", latency_ms=110)
    check(two["state"] == HEALTH_WARN, "a changed answer is a warning")
    check(two["expected"] == "found", "the expectation is not rewritten")
    check(two["baseline_ms"] == 100.0, "the baseline survives a warning")

    three = store.record_health("canary_a", "found", latency_ms=300)
    check(three["state"] == HEALTH_OK, "the expected answer is ok again")
    check(three["drift"] == 3.0, "drift is measured against the baseline")
    check(three["baseline_ms"] == 140.0, "the baseline follows a slow run")

    four = store.record_health("canary_a", "error", note="boom")
    check(three["baseline_ms"] is not None and four["baseline_ms"] == 140.0,
          "a failure keeps the baseline")

    store.record_health("canary_b", "no_match", latency_ms=50)
    rows = store.health_rows()
    check(len(rows) == 2, "one row per source, updated in place")
    check(rows[0]["source"] == "canary_a", "the worst state sorts first")
    check(store.health_for()["canary_a"]["status"] == "error",
          "health_for is keyed by source")

    skipped = store.record_health("canary_skip", "skipped", note="allowance")
    check(skipped["state"] == HEALTH_SKIP, "a skip is recorded as a skip")
    check(skipped["expected"] == "", "a skip never becomes the expectation")
    check(store.health_for()["canary_skip"]["state"] == HEALTH_SKIP,
          "and it stays a skip when read back")

    print("web: /local")
    client = app.test_client()
    resp = client.get("/local")
    body = resp.get_data(as_text=True)
    check(resp.status_code == 200, "GET /local is 200")
    check(f"Entries ({TOTAL})" in body, "the page shows the total")
    check("page 1 / 3" in body, "50 rows a page makes three pages")
    check(len(resp.data) < 60_000, "a page of 50 rows stays under 60 KB")
    check('rel="next"' in body, "page 1 links to the next page")

    resp = client.get("/local?page=3")
    body = resp.get_data(as_text=True)
    check(resp.status_code == 200 and "page 3 / 3" in body,
          "the last page renders")
    check('rel="next"' not in body, "the last page has no next link")
    check('rel="prev"' in body, "the last page links back")

    resp = client.get("/local?page=99")
    check("page 3 / 3" in resp.get_data(as_text=True),
          "a page past the end is clamped to the last page")

    resp = client.get("/local?per_page=999")
    check("page 1 / 1" in resp.get_data(as_text=True),
          "per_page is clamped to 200")

    resp = client.get("/local?page=abc&per_page=-4&kind=bogus")
    check(resp.status_code == 200, "nonsense query arguments still render")
    check("Entries (120)" in resp.get_data(as_text=True),
          "a bogus kind filter is ignored")

    resp = client.get("/local?q=00001")
    check("Entries (10)" in resp.get_data(as_text=True),
          "a prefix filter is reflected in the total")

    resp = client.get("/local?q=00001&kind=url")
    check("Nothing matches that filter." in resp.get_data(as_text=True),
          "an empty result says so instead of rendering an empty table")

    resp = client.post("/local", data={
        "action": "add", "value": "f" * 64, "label": "clean", "note": "paging"})
    check(resp.status_code == 302, "adding an entry redirects")
    check(store.count_local() == TOTAL + 1, "the added entry is stored")

    print("web: /status")
    # Give a source that really exists a failing health row: the page is
    # drawn from the configured source list, so a made-up name would test
    # nothing that renders.
    live = next(r["name"] for r in _source_rows(app.extensions["threattrove"])
                if r["active"])
    store.record_health(live, "error", note="check suite")
    resp = client.get("/status")
    body = resp.get_data(as_text=True)
    check(resp.status_code == 200, "GET /status is 200")
    check("Source health" in body, "the page has its heading")
    check("canary_a" not in body, "an unknown source is not drawn from thin air")
    check("failing" in body, "the counters are rendered")

    resp = client.get("/api/v1/status")
    data = resp.get_json()
    check(resp.status_code == 200, "GET /api/v1/status is 200")
    check(data["status"] == "bad", "the overall state follows the worst row")
    check(data["counts"]["off"] >= 1, "sources that are off are counted")
    check(isinstance(data["sources"], list) and data["sources"],
          "every source is listed")
    check({"name", "state", "status", "latency_ms"} <= set(data["sources"][0]),
          "a source row carries what the page needs")
    check(data["sources"][0]["state"] == "bad", "the worst source sorts first")

    resp = client.get("/api/v1/status?strict=1")
    check(resp.status_code == 503, "strict mode fails while a source is failing")

    resp = client.get("/health")
    check(resp.status_code == 200 and resp.get_json()["status"] == "ok",
          "/health still answers")

    store.close()
    print()
    if FAILED:
        print(f"{len(FAILED)} check(s) failed")
        return 1
    print("all status checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
