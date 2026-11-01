"""Bulk ingestion: CSV / newline / JSON feeds of hashes, URLs and domains.

Jobs are persisted in SQLite so a long run survives a page reload and can be
polled from the web UI or resumed from the CLI.
"""

from __future__ import annotations

import concurrent.futures
import csv
import io
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .core import (
    Engine,
    Indicator,
    Report,
    Store,
    hash_type,
    parse_indicator,
)

MAX_ROWS = int(os.environ.get("TT_BULK_MAX", "5000"))

#: characters that separate fields in a feed export
_FIELD_SPLIT = re.compile(r"[,\;\t\s\"']+")


def iter_hash_tokens(path: str | Path, limit: int = 0) -> Iterator[Tuple[str, str]]:
    """Stream ``(algo, hash)`` pairs from a fetch or blocklist dump.

    Deliberately schema-agnostic: every field of every line is scanned and any
    md5/sha1/sha256-shaped token is taken, so a header row (which contains no
    hash), a ``sha256_hash,md5_hash,first_seen`` export, a CSV quoted one value
    per line, and a plain newline list all parse without a column map. Lines are
    read one at a time so a multi-million-row file costs no memory.
    """
    seen = set()
    emitted = 0
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            if not line or line[0] == "#":
                continue
            for token in _FIELD_SPLIT.split(line.strip()):
                algo = hash_type(token)
                if not algo:
                    continue
                value = token.strip().lower()
                if value in seen:
                    continue
                seen.add(value)
                yield algo, value
                emitted += 1
                if limit and emitted >= limit:
                    break
            if limit and emitted >= limit:
                break

#: header names we recognise, mapped to the indicator kind they imply
_HASH_HEADERS = {
    "hash", "hashes", "sha256", "sha256_hash", "sha1", "sha1_hash", "md5",
    "md5_hash", "file_hash", "sample_hash", "imphash",
}
_URL_HEADERS = {"url", "urls", "uri", "link", "ioc_url"}
_DOMAIN_HEADERS = {"domain", "host", "hostname", "fqdn", "domain_name"}
_ANY_HEADERS = _HASH_HEADERS | _URL_HEADERS | _DOMAIN_HEADERS | {
    "indicator", "value", "ioc", "indicator_value", "observable",
}

JOB_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id         TEXT PRIMARY KEY,
    created    REAL NOT NULL,
    finished   REAL,
    status     TEXT NOT NULL,
    label      TEXT,
    total      INTEGER NOT NULL DEFAULT 0,
    done       INTEGER NOT NULL DEFAULT 0,
    skipped    INTEGER NOT NULL DEFAULT 0,
    error      TEXT
);
CREATE TABLE IF NOT EXISTS job_items (
    job_id   TEXT NOT NULL,
    idx      INTEGER NOT NULL,
    kind     TEXT NOT NULL,
    value    TEXT NOT NULL,
    verdict  TEXT,
    score    INTEGER,
    status   TEXT NOT NULL,
    headline TEXT,
    flagged  TEXT,
    detail   TEXT,
    PRIMARY KEY (job_id, idx)
);
CREATE INDEX IF NOT EXISTS job_items_job ON job_items(job_id, idx);
"""


# --------------------------------------------------------------------------
# Parsing input
# --------------------------------------------------------------------------

def _dedupe(items: Iterable[Indicator]) -> List[Indicator]:
    seen, out = set(), []
    for ind in items:
        key = (ind.kind, ind.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(ind)
    return out


def parse_text(text: str, limit: int = MAX_ROWS) -> Tuple[List[Indicator], int]:
    """Parse pasted text: one indicator per line, '#' comments ignored."""
    items: List[Indicator] = []
    skipped = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # allow "value,note" rows too
        candidate = line.split(",")[0].strip() if line.count(",") == 1 else line
        ind = parse_indicator(candidate) or parse_indicator(line)
        if ind:
            items.append(ind)
        else:
            skipped += 1
        if len(items) >= limit:
            break
    return _dedupe(items), skipped


def parse_csv_bytes(data: bytes, limit: int = MAX_ROWS,
                    filename: str = "") -> Tuple[List[Indicator], int]:
    """Parse a CSV export from any TI platform, plus JSON/plain-text lists."""
    text = data.decode("utf-8-sig", errors="replace")

    # JSON array / object
    stripped = text.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            payload = json.loads(text)
        except ValueError:
            payload = None
        if payload is not None:
            rows: List[str] = []
            if isinstance(payload, dict):
                for key in ("indicators", "iocs", "data", "results", "hashes"):
                    if isinstance(payload.get(key), list):
                        payload = payload[key]
                        break
                else:
                    payload = list(payload.values())
            for entry in payload if isinstance(payload, list) else []:
                if isinstance(entry, str):
                    rows.append(entry)
                elif isinstance(entry, dict):
                    for key in ("hash", "sha256", "value", "indicator", "url",
                                "domain", "ioc"):
                        if entry.get(key):
                            rows.append(str(entry[key]))
                            break
            items = [parse_indicator(r) for r in rows[:limit]]
            good = [i for i in items if i]
            return _dedupe(good), len(items) - len(good)

    # CSV with a header we recognise
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    rows = list(reader)
    if not rows:
        return [], 0

    header = [c.strip().lower() for c in rows[0]]
    col = None
    for i, name in enumerate(header):
        if name in _ANY_HEADERS:
            col = i
            break
    if col is None:
        return parse_text(text, limit)

    items: List[Indicator] = []
    skipped = 0
    for row in rows[1:]:
        if col >= len(row):
            skipped += 1
            continue
        ind = parse_indicator(row[col])
        if ind:
            items.append(ind)
        else:
            skipped += 1
        if len(items) >= limit:
            break
    return _dedupe(items), skipped


def parse_any(data: bytes, filename: str = "",
              limit: int = MAX_ROWS) -> Tuple[List[Indicator], int]:
    name = (filename or "").lower()
    if name.endswith((".csv", ".tsv", ".json", ".txt", ".list", ".ioc")):
        return parse_csv_bytes(data, limit, filename)
    try:
        return parse_csv_bytes(data, limit, filename)
    except Exception:  # noqa: BLE001
        return parse_text(data.decode("utf-8", errors="replace"), limit)


def read_source(path: str | Path, limit: int = MAX_ROWS) -> Tuple[List[Indicator], int]:
    p = Path(path)
    return parse_any(p.read_bytes(), p.name, limit)


# --------------------------------------------------------------------------
# Job storage
# --------------------------------------------------------------------------

class BulkJobs:
    """SQLite-backed job state shared by the CLI and the web app."""

    def __init__(self, store: Store):
        self.store = store
        self.conn = store.conn
        self.lock = store._lock
        with self.lock:
            self.conn.executescript(JOB_SCHEMA)
            self.conn.commit()

    # -- lifecycle --------------------------------------------------------
    def create(self, indicators: Sequence[Indicator], label: str = "",
               skipped: int = 0) -> str:
        job_id = uuid.uuid4().hex[:12]
        with self.lock:
            self.conn.execute(
                "INSERT INTO jobs (id, created, status, label, total, skipped)"
                " VALUES (?,?,?,?,?,?)",
                (job_id, time.time(), "queued", label,
                 len(indicators), skipped))
            for idx, ind in enumerate(indicators):
                self.conn.execute(
                    "INSERT INTO job_items (job_id, idx, kind, value, status)"
                    " VALUES (?,?,?,?,?)",
                    (job_id, idx, ind.kind, ind.value, "pending"))
            self.conn.commit()
        return job_id

    def set_status(self, job_id: str, status: str, error: str = "") -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE jobs SET status=?, error=? WHERE id=?",
                (status, error or None, job_id))
            self.conn.commit()

    def finish(self, job_id: str, error: str = "") -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE jobs SET status=?, finished=?, error=? WHERE id=?",
                ("error" if error else "done", time.time(), error or None,
                 job_id))
            self.conn.commit()

    def record_error(self, job_id: str, idx: int, error: str) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE job_items SET status='error', headline=?, verdict=?,"
                " score=0 WHERE job_id=? AND idx=?",
                (error, "error", job_id, idx))
            self.conn.execute("UPDATE jobs SET done = done + 1 WHERE id=?",
                              (job_id,))
            self.conn.commit()

    def record(self, job_id: str, idx: int, report: Report) -> None:
        d = report.to_dict(include_results=False)
        flagged = ",".join(report.flagged_by()[:6])
        with self.lock:
            self.conn.execute(
                "UPDATE job_items SET verdict=?, score=?, status='done',"
                " headline=?, flagged=?, detail=? WHERE job_id=? AND idx=?",
                (d["verdict"], d["score"], d["headline"], flagged,
                 json.dumps({"confidence": d["confidence"],
                             "elapsed": d["elapsed_seconds"]}),
                 job_id, idx))
            self.conn.execute(
                "UPDATE jobs SET done = done + 1 WHERE id=?", (job_id,))
            self.conn.commit()

    # -- reads ------------------------------------------------------------
    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            row = self.conn.execute(
                "SELECT id, created, finished, status, label, total, done,"
                " skipped, error FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return None
        return {"id": row[0], "created": row[1], "finished": row[2],
                "status": row[3], "label": row[4], "total": row[5],
                "done": row[6], "skipped": row[7], "error": row[8]}

    def items(self, job_id: str, offset: int = 0,
              limit: int = 1000) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT idx, kind, value, verdict, score, status, headline,"
                " flagged FROM job_items WHERE job_id=? ORDER BY idx"
                " LIMIT ? OFFSET ?", (job_id, limit, offset)).fetchall()
        return [{"idx": r[0], "kind": r[1], "value": r[2], "verdict": r[3],
                 "score": r[4], "status": r[5], "headline": r[6],
                 "flagged": r[7]} for r in rows]

    def all_items(self, job_id: str) -> List[Dict[str, Any]]:
        job = self.get(job_id)
        if not job:
            return []
        return self.items(job_id, 0, max(1, job["total"]))

    def summary(self, job_id: str) -> Dict[str, int]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT verdict, COUNT(*) FROM job_items WHERE job_id=?"
                " GROUP BY verdict", (job_id,)).fetchall()
        out = {r[0] or "pending": r[1] for r in rows}
        return out

    def recent(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self.lock:
            ids = [r[0] for r in self.conn.execute(
                "SELECT id FROM jobs ORDER BY created DESC LIMIT ?",
                (limit,)).fetchall()]
        return [j for j in (self.get(i) for i in ids) if j]

    def pending(self, job_id: str) -> List[Tuple[int, Indicator]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT idx, kind, value FROM job_items"
                " WHERE job_id=? AND status='pending' ORDER BY idx",
                (job_id,)).fetchall()
        out = []
        for idx, kind, value in rows:
            ind = parse_indicator(value)
            if ind:
                out.append((idx, ind))
        return out

    def delete(self, job_id: str) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM job_items WHERE job_id=?", (job_id,))
            self.conn.execute("DELETE FROM jobs WHERE id=?", (job_id,))
            self.conn.commit()


# --------------------------------------------------------------------------
# Running a job
# --------------------------------------------------------------------------

class BulkRunner:
    """Runs job items through an Engine with bounded concurrency."""

    def __init__(self, engine: Engine, jobs: BulkJobs,
                 workers: int = 3, use_cache: bool = True):
        self.engine = engine
        self.jobs = jobs
        self.workers = max(1, int(workers))
        self.use_cache = use_cache

    def run(self, job_id: str) -> None:
        job = self.jobs.get(job_id)
        if not job:
            return
        self.jobs.set_status(job_id, "running")
        pending = self.jobs.pending(job_id)
        try:
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.workers) as ex:
                futures = {
                    ex.submit(self.engine.lookup, ind, self.use_cache): idx
                    for idx, ind in pending
                }
                for fut in concurrent.futures.as_completed(futures):
                    idx = futures[fut]
                    try:
                        report = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        self.jobs.record_error(job_id, idx, str(exc)[:200])
                        continue
                    self.jobs.record(job_id, idx, report)
        except Exception as exc:  # noqa: BLE001
            self.jobs.finish(job_id, error=str(exc)[:300])
            return
        self.jobs.finish(job_id)

    def run_async(self, job_id: str, on_done: Optional[Any] = None) -> threading.Thread:
        def _target() -> None:
            try:
                self.run(job_id)
            finally:
                if on_done:
                    try:
                        on_done(job_id)
                    except Exception:  # noqa: BLE001
                        pass

        t = threading.Thread(target=_target, name=f"bulk-{job_id}", daemon=True)
        t.start()
        return t


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------

def to_csv(items: Sequence[Dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["indicator", "kind", "verdict", "score", "status",
                     "flagged_by", "headline"])
    for it in items:
        writer.writerow([it.get("value"), it.get("kind"), it.get("verdict"),
                         it.get("score"), it.get("status"),
                         it.get("flagged") or "", it.get("headline") or ""])
    return buf.getvalue()


def to_json(items: Sequence[Dict[str, Any]]) -> str:
    return json.dumps(items, indent=2, default=str)
