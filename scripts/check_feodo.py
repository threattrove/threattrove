#!/usr/bin/env python3
"""Offline checks for the Feodo import and the corpus path it feeds.

Nothing here touches the network: the fixture is a real blocklist excerpt with
its comment header, a duplicate address on a second port, and a row with no IP.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove.core import KIND_IP, Engine, Indicator, Store, VERDICT_MALICIOUS
from threattrove.feeds import feodo_note, feodo_rows, parse_feodo_csv

FIXTURE = """\
################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)          #
# Terms Of Use: https://feodotracker.abuse.ch/blocklist/       #
################################################################
#
"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
"2022-06-04 21:24:53","162.243.103.246","8080","offline","2026-03-07","Emotet"
"2025-12-30 13:56:31","50.16.16.211","443","online","2026-03-12","QakBot"
"2025-12-30 13:56:31","50.16.16.211","8443","online","2026-03-12","QakBot"
"2026-01-13 21:41:15","","443","offline","2026-03-01","QakBot"
# END 3 entries
"""

failures = []


def check(name, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{(' - ' + detail) if detail and not ok else ''}")
    if not ok:
        failures.append(name)


def main() -> int:
    print("feodo parsing")
    entries = parse_feodo_csv(FIXTURE)
    check("comment header is not the CSV header", len(entries) == 2,
          f"got {len(entries)} entries")
    check("IPs parsed in order",
          [e["ip"] for e in entries] == ["162.243.103.246", "50.16.16.211"])
    check("a repeated address is kept once", entries[1]["ip"] == "50.16.16.211")
    check("empty address dropped", all(e["ip"] for e in entries))
    check("family survives parsing", entries[1]["malware"] == "QakBot",
          str(entries[1]))
    note = feodo_note(entries[1])
    check("note names the family, port and status",
          "QakBot" in note and "port 443" in note and "online" in note, note)
    check("note is bounded", len(note) <= 160)
    check("a non-Feodo CSV is refused",
          _raises(lambda: parse_feodo_csv('"a","b"\n"1","2"\n')))
    check("an empty body yields no rows", parse_feodo_csv("# nothing here\n") == [])

    rows = feodo_rows(FIXTURE)
    check("rows are kind=ip triples",
          all(r[0] == KIND_IP for r in rows) and len(rows) == 2)

    print("corpus sync")
    tmp = tempfile.mkdtemp(prefix="tt-feodo-")
    store = Store(os.path.join(tmp, "check.db"))
    try:
        # An address the analyst labelled by hand, long ago.
        store.add_local(KIND_IP, "50.16.16.211", "suspicious", "watch this host")
        old = store.get_local(KIND_IP, "50.16.16.211")["added_at"]
        time.sleep(0.05)
        written = store.sync_local_many(rows, label="malware")
        check("both rows written", written == 2, str(written))
        after = store.get_local(KIND_IP, "50.16.16.211")
        check("the existing row keeps its first-seen date",
              after["added_at"] == old, f"{old} -> {after['added_at']}")
        check("the existing row is relabelled to the feed's label",
              after["label"] == "malware", after["label"])
        check("the feed's note replaces the hand note",
              "Feodo Tracker C2" in after["note"], after["note"])
        new = store.get_local(KIND_IP, "162.243.103.246")
        check("a new address is inserted", new is not None and new["label"] == "malware")

        # A second run changes nothing but must not re-date anything either.
        store.sync_local_many(rows, label="malware")
        again = store.get_local(KIND_IP, "50.16.16.211")["added_at"]
        check("re-import is stable", again == old, f"{old} -> {again}")
        check("no duplicate rows", store.count_local("", KIND_IP) == 2,
              str(store.count_local("", KIND_IP)))

        print("verdict path")
        ind = Indicator(kind=KIND_IP, value="50.16.16.211", raw="50.16.16.211",
                        ip="50.16.16.211")
        report = Engine(sources=[], store=store).lookup(ind, use_cache=False)
        check("the corpus answers before any upstream",
              report.results and report.results[0].source == "local",
              str([r.source for r in report.results]))
        check("the local row convicts", report.verdict() == VERDICT_MALICIOUS,
              report.verdict())
        check("the note is shown", "Feodo Tracker C2" in report.results[0].note,
              report.results[0].note)
    finally:
        store.close()

    print()
    if failures:
        print(f"FAILED {len(failures)}: {', '.join(failures)}")
        return 1
    print("all feodo checks passed")
    return 0


def _raises(fn) -> bool:
    try:
        fn()
    except ValueError:
        return True
    return False


if __name__ == "__main__":
    sys.exit(main())
