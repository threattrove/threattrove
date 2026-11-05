#!/usr/bin/env python3
"""Check the paged local list, the lookup feed pager and source health.

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
from threattrove.web import _source_rows, app, short_value  # noqa: E402

FAILED = []
TOTAL = 120
HISTORY_ROWS = 130


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


def seed_history(store: Store) -> None:
    """History rows for the /recent pager: HISTORY_ROWS, newest last.

    Every fifth row is a 64-character digest so the feed carries both the long
    values that need shortening on a phone and the short ones that must not be
    touched.
    """
    base = 1_700_000_000.0
    with store._lock:                      # noqa: SLF001 - a check may be direct
        for i in range(HISTORY_ROWS):
            kind, value = (("hash", f"{i:064x}") if i % 5 == 0
                           else ("domain", f"recent{i:03d}.example"))
            store.conn.execute(
                "INSERT INTO history (kind, value, verdict, score, ts)"
                " VALUES (?,?,?,?,?)",
                (kind, value, "clean", 0, base + i))
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

    print("display: long values")
    digest = "d41d8cd98f00b204e9800998ecf8427e"
    check(short_value(digest) == "d41d8cd\u2026ecf8427e",
          "a 32-char digest keeps its first 7 and last 8 characters")
    check(short_value("a" * 64) == "a" * 7 + "\u2026" + "a" * 8,
          "a 64-char digest shortens the same way")
    check(len(short_value("A" * 64)) == 16, "uppercase hex shortens too")
    check(short_value("recent042.example") == "",
          "a domain is left whole: its middle is the identifying part")
    check(short_value("a" * 31) == "", "31 characters is not a digest")
    check(short_value("z" * 64) == "", "a non-hex 64-character value is not one")
    check(short_value("") == "", "an empty value stays empty")

    # The two spans are only useful together with the rule that swaps them, so
    # the stylesheet is part of the contract rather than decoration.
    css_path = os.path.join(os.path.dirname(HERE), "threattrove", "static",
                            "style.css")
    with open(css_path, encoding="utf-8") as fh:
        css = fh.read()
    check(".short-val { display: none; }" in css,
          "the shortened value is hidden on a wide screen")
    phone = css.find("@media (max-width: 720px)")
    check(phone != -1 and css.find(".short-val { display: inline;", phone) != -1,
          "the phone breakpoint swaps it in")
    check(phone != -1 and css.find(".full-val { display: none; }", phone) != -1,
          "and hides the full value at the same width")

    print("web: /local")
    client = app.test_client()
    resp = client.get("/local")
    body = resp.get_data(as_text=True)
    check(resp.status_code == 200, "GET /local is 200")
    check(f"Entries ({TOTAL})" in body, "the page shows the total")
    check("page 1 / 3" in body, "50 rows a page makes three pages")
    check(len(resp.data) < 60_000, "a page of 50 rows stays under 60 KB")
    check('rel="next"' in body, "page 1 links to the next page")
    check(body.count('class="full-val"') == 50,
          "every 64-char hash also carries its whole value")
    check(body.count('class="short-val"') == 50,
          "and a shortened copy for a phone")
    check('<span class="short-val">000119a\u2026aaaaaaaa</span>' in body,
          "the newest hash shows first7…last8 on a narrow screen")
    check('title="000119' + "a" * 58 + '"' in body,
          "the link still carries the full digest as its title")

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

    seed_history(store)

    print("web: /recent")
    resp = client.get("/recent")
    body = resp.get_data(as_text=True)
    check(resp.status_code == 200, "GET /recent is 200")
    check(f"1–50 of {HISTORY_ROWS}" in body, "the pager counts the whole history")
    check("page 1 / 3" in body, "50 rows a page makes three pages")
    check(body.count('class="mono wrap-cell"') == 50,
          "the page renders 50 rows")
    check(body.count('class="full-val"') == 10,
          "the ten digest rows carry their whole value")
    check(body.count('class="short-val"') == 10,
          "and a shortened copy each")
    check('<span class="short-val">0000000\u20260000007d</span>' in body,
          "a feed digest is shortened to first7…last8")
    check('class="short-val">recent' not in body,
          "domains in the feed are never truncated")
    check(len(resp.data) < 60_000, "a page of 50 lookups stays under 60 KB")
    check(resp.headers.get("Cache-Control") == "no-store",
          "the feed is not cached")
    check("X-Robots-Tag" not in resp.headers,
          "the newest page stays indexable")

    resp = client.get("/recent?page=2")
    body = resp.get_data(as_text=True)
    check(f"51–100 of {HISTORY_ROWS}" in body, "page 2 starts at the 51st lookup")
    check("noindex" in resp.headers.get("X-Robots-Tag", ""),
          "deeper pages are noindex")

    resp = client.get("/recent?page=3")
    body = resp.get_data(as_text=True)
    check(f"101–{HISTORY_ROWS} of {HISTORY_ROWS}" in body,
          "the last page ends on the last lookup")
    check('rel="next"' not in body, "the last page has no Older link")
    check('rel="prev"' in body, "the last page links back")

    resp = client.get("/recent?page=99")
    check("page 3 / 3" in resp.get_data(as_text=True),
          "a page past the end is clamped to the last page")

    resp = client.get("/recent?page=abc")
    check(resp.status_code == 200 and "page 1 / 3" in resp.get_data(as_text=True),
          "nonsense paging still renders the first page")

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
