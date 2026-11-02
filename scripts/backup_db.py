#!/usr/bin/env python3
"""Nightly consistent backup of the ThreatTrove SQLite database.

`cp` of a live SQLite file can catch a page mid-checkpoint, and a database that
fails to open is worse than no backup at all because it looks like one. The
backup API copies a consistent snapshot while the web workers keep reading and
writing, so what lands in /var/backups is a database. Each snapshot is checked,
gzipped and pruned; a snapshot that fails its check is kept as `.part` and the
run exits non-zero, so a broken backup is loud instead of missing.

Run from the repository root::

    python3 scripts/backup_db.py            # TT_DB, TT_BACKUP_DIR, TT_BACKUP_KEEP
    python3 scripts/backup_db.py --keep 3   # keep fewer snapshots
"""
from __future__ import annotations

import argparse
import gzip
import os
import pathlib
import sqlite3
import sys
import time

DEFAULT_DB = os.environ.get("TT_DB", "/var/lib/threattrove/threattrove.db")
DEFAULT_DIR = os.environ.get("TT_BACKUP_DIR", "/var/backups/threattrove")
DEFAULT_KEEP = int(os.environ.get("TT_BACKUP_KEEP", "7"))
CHUNK = 1 << 20


def snapshot(db_path: str, dest_path: str) -> int:
    """Copy a consistent snapshot of *db_path* to *dest_path*."""
    src = sqlite3.connect(db_path)
    try:
        dst = sqlite3.connect(dest_path)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    return os.path.getsize(dest_path)


def verify(path: str) -> tuple:
    """Cheap structural check plus the row count that matters most."""
    conn = sqlite3.connect(path)
    try:
        row = conn.execute("PRAGMA quick_check").fetchone()
        local = conn.execute("SELECT COUNT(*) FROM local").fetchone()[0]
    finally:
        conn.close()
    return (str(row[0]) if row else "unknown"), int(local)


def pack(src_path: str, dest_path: str) -> int:
    with open(src_path, "rb") as fh, gzip.open(dest_path, "wb",
                                               compresslevel=6) as gz:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            gz.write(chunk)
    return os.path.getsize(dest_path)


def prune(directory: pathlib.Path, keep: int) -> list:
    """Delete all but the newest *keep* snapshots; return what went."""
    old = sorted(directory.glob("threattrove-*.db.gz"), reverse=True)
    gone = []
    for path in old[max(1, keep):]:
        path.unlink()
        gone.append(path.name)
    return gone


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--out", default=DEFAULT_DIR)
    ap.add_argument("--keep", type=int, default=DEFAULT_KEEP)
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print("backup: no database at %s" % args.db, file=sys.stderr)
        return 2

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M")
    raw = out / (".threattrove-%s.db.part" % stamp)
    packed = out / (".threattrove-%s.db.gz.part" % stamp)
    final = out / ("threattrove-%s.db.gz" % stamp)

    size = snapshot(args.db, str(raw))
    status, rows = verify(str(raw))
    if status != "ok":
        print("backup: snapshot failed %r; left at %s" % (status, raw),
              file=sys.stderr)
        return 1

    try:
        csize = pack(str(raw), str(packed))
        os.replace(str(packed), str(final))
    finally:
        if raw.exists():
            raw.unlink()

    gone = prune(out, args.keep)
    print("backup: %s %.1f MiB (from %.1f MiB, %d local rows, %s), "
          "removed %d old" % (final.name, csize / 1048576.0, size / 1048576.0,
                              rows, status, len(gone)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
