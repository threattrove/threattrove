#!/usr/bin/env python3
"""Fold the Feodo Tracker C2 IP blocklist into the local corpus.

abuse.ch publishes this list without a key, so the job runs even on an install
that has no Auth-Key. An imported address is an ordinary local-corpus row: a
lookup answers from SQLite before any upstream is asked, and the note says which
botnet family was seen serving it.

    python scripts/import_feodo.py                 # download and sync
    python scripts/import_feodo.py --dry-run       # parse and print, write nothing
    python scripts/import_feodo.py --file list.csv # import a saved copy
"""
from __future__ import annotations

import argparse
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove.core import Store                    # noqa: E402
from threattrove.feeds import FEODO_URL, feodo_rows   # noqa: E402

USER_AGENT = "threattrove-feodo/1.0"


def fetch(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--file", help="read a saved copy instead of downloading")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--timeout", type=float, default=45.0)
    args = ap.parse_args()

    try:
        if args.file:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        else:
            text = fetch(FEODO_URL, args.timeout)
    except (urllib.error.URLError, OSError) as exc:
        print(f"download failed: {exc}", file=sys.stderr)
        return 1
    try:
        rows = feodo_rows(text)
    except ValueError as exc:
        print(f"unusable feed: {exc}", file=sys.stderr)
        return 1
    if not rows:
        # An emptied feed is not news. Say so and change nothing rather than
        # importing an empty list as if the blocklist had been withdrawn.
        print("no C2 addresses in the feed; nothing imported", file=sys.stderr)
        return 1

    online = sum(1 for _k, _v, note in rows if "online" in note
                 and "offline" not in note)
    print(f"parsed {len(rows)} address(es), {online} online")
    if args.dry_run:
        for kind, value, note in rows[:5]:
            print(f"  {kind} {value}  {note}")
        print("dry run: nothing written")
        return 0

    store = Store(os.environ.get("TT_DB") or None)
    try:
        written = store.sync_local_many(rows, label="malware")
    finally:
        store.close()
    print(f"synced {written} row(s) into the local corpus")
    return 0


if __name__ == "__main__":
    sys.exit(main())
