#!/usr/bin/env python3
"""Check the shared daily allowance: the ledger, the engine hook, the sources page.

Run from the repository root::

    python3 scripts/check_quota.py

Exits non-zero on the first failed expectation. Nothing here touches the
network: every upstream call is replaced by a recording stub.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove import core  # noqa: E402
from threattrove.sources import (  # noqa: E402
    VT_DAILY_BUDGET,
    VirusTotalDomain,
    VirusTotalFile,
    VirusTotalUrl,
    _vt_parse,
)

FAILED = []


def check(cond: bool, msg: str) -> None:
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        FAILED.append(msg)


class Calls:
    """Counts how often a stub source actually reached upstream."""

    def __init__(self) -> None:
        self.n = 0


class Counting(core.Source):
    """A source that spends a shared allowance and answers instantly."""

    name = "counting"
    display = "Counting"
    kinds = (core.KIND_HASH,)
    quota_key = "stub"
    daily_budget = 3

    def __init__(self, calls: Calls, note: str = "listed") -> None:
        self.calls = calls
        self.note = note

    def lookup(self, ind: core.Indicator) -> core.SourceResult:
        self.calls.n += 1
        if self.note.startswith("error:"):
            return self.result(status="error", note=self.note[6:])
        return self.result(status="found", verdict=core.VERDICT_MALICIOUS,
                           note=self.note)


def new_store(tmp: str) -> core.Store:
    return core.Store(Path(tmp) / "quota.db")


def ledger() -> None:
    print("\n[ledger]")
    with tempfile.TemporaryDirectory() as tmp:
        store = new_store(tmp)
        state = store.quota_state("virustotal")
        check(state["used"] == 0 and not state["exhausted"],
              "a quota nobody used reads 0, not exhausted")
        check(state["day"] == core._utc_day(), "counters are attributed to a UTC day")

        check(store.take_quota("virustotal", 2), "first call allowed")
        check(store.take_quota("virustotal", 2), "second call allowed")
        check(not store.take_quota("virustotal", 2), "third call refused at the limit")
        check(store.quota_state("virustotal")["used"] == 2,
              "a refused call is not counted (no phantom spend)")
        check(store.take_quota("virustotal", None), "no limit -> always allowed")
        check(store.quota_state("virustotal")["used"] == 3, "and it is counted")

        check(store.take_quota("other", 1), "a different quota has its own budget")
        check(not store.take_quota("other", 1), "and its own limit")
        check(store.quota_state("virustotal")["used"] == 3,
              "spending one quota does not touch another")

        store.exhaust_quota("virustotal", 500)
        state = store.quota_state("virustotal")
        check(state["exhausted"], "exhaust_quota marks the day spent")
        check(state["used"] == 500, "and records the allowance as used")
        check(not store.take_quota("virustotal", None),
              "an exhausted quota refuses even without a limit")
        check(store.take_quota("other", 10) is not None, "other quotas still work")

        # Yesterday's counter must not eat today's allowance.
        store.conn.execute("UPDATE quota SET exhausted=1, used=999, day='1999-01-01'")
        store.conn.commit()
        check(store.take_quota("virustotal", 1),
              "an old day's exhaustion does not block today")
        store.close()


def engine() -> None:
    print("\n[engine]")
    with tempfile.TemporaryDirectory() as tmp:
        store = new_store(tmp)
        calls = Calls()
        src = Counting(calls)
        eng = core.Engine(sources=[src], store=store)
        ind = core.parse_indicator("ab" * 32)

        first = eng.lookup(ind)
        check(calls.n == 1, "a cold lookup asks upstream once")
        check(store.quota_state("stub")["used"] == 1, "and spends one unit")
        row = first.results[0]
        check(row.status == "found" and row.verdict == core.VERDICT_MALICIOUS,
              "the answer comes back unchanged")

        second = eng.lookup(ind)
        check(calls.n == 1, "a cached lookup asks nothing")
        check(store.quota_state("stub")["used"] == 1,
              "a cached answer spends no allowance")
        check(second.results[0].detail.get("_cached"), "and is served from the cache")

        eng.lookup(core.parse_indicator("cd" * 32))
        check(store.quota_state("stub")["used"] == 2, "a new indicator spends a unit")

        eng.lookup(core.parse_indicator("ef" * 32))
        check(store.quota_state("stub")["used"] == 3, "the budget counts up to the limit")

        spent = eng.lookup(core.parse_indicator("12" * 32))
        row = spent.results[0]
        check(calls.n == 3, "past the budget upstream is not called")
        check(row.status == "skipped", "the source reports skipped")
        check(row.verdict == core.VERDICT_UNKNOWN, "and asserts no verdict")
        check("3/3" in row.note and "stub" in row.note,
              f"the note names the counter: {row.note!r}")
        check(spent.verdict() == core.VERDICT_UNKNOWN,
              "a skipped source does not drag the report to malicious")
        check(store.get_cached("hash", "12" * 32, "counting") is None,
              "the skipped answer is not cached, so it is retried tomorrow")

        # A provider that says the day is over is believed the first time.
        with tempfile.TemporaryDirectory() as tmp2:
            store2 = new_store(tmp2)
            ltd = Calls()
            src2 = Counting(ltd, note="error:daily quota exceeded (free key: 500/day)")
            eng2 = core.Engine(sources=[src2], store=store2)
            res = eng2.lookup(core.parse_indicator("aa" * 32))
            check(res.results[0].status == "error", "the provider's refusal is reported")
            check(store2.quota_state("stub")["exhausted"],
                  "a daily-quota error marks the allowance spent")
            eng2.lookup(core.parse_indicator("bb" * 32))
            check(ltd.n == 1, "and nothing is asked upstream afterwards")

            # A per-minute 429 is not a spent day and must keep being retried.
            store3 = new_store(tmp2 + "/second")
            burst = Calls()
            src3 = Counting(burst, note="error:rate limited (free tier: 4/min)")
            eng3 = core.Engine(sources=[src3], store=store3)
            eng3.lookup(core.parse_indicator("cc" * 32))
            check(not store3.quota_state("stub")["exhausted"],
                  "a per-minute rate limit does not spend the day")
            eng3.lookup(core.parse_indicator("dd" * 32))
            check(burst.n == 2, "a burst-limited source is asked again")
            store2.close()
            store3.close()
        store.close()


class StatusOnly:
    """Minimal stand-in for a requests.Response, status and body only."""

    def __init__(self, status: int, body: dict | None = None, text: str = "") -> None:
        self.status_code = status
        self._body = body
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


def virus_total() -> None:
    print("\n[virustotal]")
    src = VirusTotalFile()
    check(src.quota_key == VirusTotalUrl().quota_key == VirusTotalDomain().quota_key
          == "virustotal", "all three sources draw on one allowance")
    check(VirusTotalUrl().budget() == VT_DAILY_BUDGET,
          f"the default budget is {VT_DAILY_BUDGET}, under the free key's 500")
    os.environ["TT_VT_DAILY_BUDGET"] = "120"
    check(VirusTotalUrl().budget() == 120, "TT_VT_DAILY_BUDGET overrides it")
    os.environ["TT_VT_DAILY_BUDGET"] = "not a number"
    check(VirusTotalUrl().budget() == VT_DAILY_BUDGET, "a bad override is ignored")
    os.environ.pop("TT_VT_DAILY_BUDGET", None)

    old_key = os.environ.get("VT_API_KEY")
    old_opt = os.environ.get("TT_VT_DOMAINS")
    os.environ["VT_API_KEY"] = "0" * 64
    os.environ.pop("TT_VT_DOMAINS", None)
    check(VirusTotalFile().available(), "files are on with a key")
    check(VirusTotalUrl().available(), "URLs are on with a key")
    check(not VirusTotalDomain().available(),
          "domain/IP lookups are off until TT_VT_DOMAINS is set")
    check(VirusTotalDomain().opt_in_missing() == "TT_VT_DOMAINS",
          "and the page can say which variable to set")
    os.environ["TT_VT_DOMAINS"] = "1"
    check(VirusTotalDomain().available(), "TT_VT_DOMAINS=1 turns them on")
    os.environ["TT_VT_DOMAINS"] = "0"
    check(not VirusTotalDomain().available(), "TT_VT_DOMAINS=0 leaves them off")
    os.environ.pop("VT_API_KEY")
    check(not VirusTotalFile().available(), "no key -> the source stays off")
    if old_key is not None:
        os.environ["VT_API_KEY"] = old_key
    if old_opt is not None:
        os.environ["TT_VT_DOMAINS"] = old_opt
    else:
        os.environ.pop("TT_VT_DOMAINS", None)

    # A 429 body decides whether the day or the minute was exceeded.
    quota = _vt_parse(src, StatusOnly(429, {"error": {
        "code": "QuotaExceededError", "message": "Quota exceeded"}}))
    check(quota.status == "error" and "daily quota" in quota.note,
          f"a quota 429 reads as a spent day: {quota.note!r}")
    check(core.quota_exhausted_note(quota.note), "and the engine recognises it")
    burst = _vt_parse(src, StatusOnly(429, {"error": {
        "code": "TooManyRequestsError",
        "message": "Too many requests per minute"}}))
    check("rate limited" in burst.note, f"a burst 429 stays a burst: {burst.note!r}")
    check(not core.quota_exhausted_note(burst.note),
          "and does not stop the source for the day")
    check(not core.quota_exhausted_note("HTTP 503"), "other errors change nothing")


def pacing() -> None:
    print("\n[pacing]")
    with tempfile.TemporaryDirectory() as tmp:
        store = new_store(tmp)
        calls = Calls()
        src = Counting(calls)
        src.min_interval = 60.0      # one call a minute on this key
        eng = core.Engine(sources=[src], store=store)

        first = eng.lookup(core.parse_indicator("ab" * 32))
        check(first.results[0].status == "found" and calls.n == 1,
              "the first call on a paced key is allowed through")
        check(store.quota_state("stub")["used"] == 1, "and charged once")

        saved = core.PACE_MAX_WAIT
        core.PACE_MAX_WAIT = 0.0     # never wait: report the hold-back
        try:
            held = eng.lookup(core.parse_indicator("cd" * 32))
        finally:
            core.PACE_MAX_WAIT = saved
        row = held.results[0]
        check(calls.n == 1, "a paced lookup does not reach upstream")
        check(row.status == "skipped" and row.detail.get("paced") == "stub",
              f"and says it was held back: {row.note!r}")
        check(store.quota_state("stub")["used"] == 1,
              "a held-back call is refunded, not charged")
        check(store.get_cached("hash", "cd" * 32, "counting") is None,
              "and nothing is cached for it")

        # This is what the canary does: wait the window out, then ask again.
        core._PACE_NEXT.pop("stub", None)
        again = eng.lookup(core.parse_indicator("cd" * 32))
        check(again.results[0].status == "found" and calls.n == 2,
              "the retry after the window reaches upstream")
        check(store.quota_state("stub")["used"] == 2,
              "and the paused-and-retried source costs one credit, not two")

        # A refund can never push the counter below zero.
        store.refund_quota("stub")
        store.refund_quota("stub")
        store.refund_quota("stub")
        check(store.quota_state("stub")["used"] == 0,
              "refunds stop at zero rather than going negative")
        store.close()


def sources_page() -> None:
    print("\n[sources page]")
    with tempfile.TemporaryDirectory() as tmp:
        store = new_store(tmp)
        store.take_quota("virustotal", 10)
        store.take_quota("virustotal", 10)
        from threattrove.web import Runtime, _source_rows

        rows = _source_rows(Runtime(store=store))
        by_name = {r["name"]: r for r in rows}
        vt = by_name["virustotal"]["quota"]
        check(vt is not None and vt["used"] == 2 and vt["limit"] == VT_DAILY_BUDGET,
              f"the page shows 2/{VT_DAILY_BUDGET} used today")
        check(vt["shared"] == 3, "and says the allowance is shared by three sources")
        check(by_name["circl"]["quota"] is None,
              "a source without an allowance shows no counter")
        check(by_name["reverseip"]["opt_in"] == "TT_ENABLE_REVERSE_IP",
              "an opt-in source names its variable")
        check(by_name["virustotal_domain"]["opt_in"] == "TT_VT_DOMAINS",
              "so does the VirusTotal domain source")
        store.close()


def main() -> int:
    ledger()
    engine()
    pacing()
    virus_total()
    sources_page()
    print()
    if FAILED:
        print(f"{len(FAILED)} check(s) failed:")
        for msg in FAILED:
            print(f"  - {msg}")
        return 1
    print("all quota checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
