"""Blocklist parsers for the feeds that are folded into the local corpus.

These providers do not answer queries about an indicator: their lists are
downloaded on a timer and written into the ``local`` table, where a hit outranks
every live source. The parsing lives here rather than in the import script so
the same code that runs on the timer can be exercised by an offline check.
"""
from __future__ import annotations

import csv
import io
from typing import Any, Dict, List, Tuple

from .core import KIND_IP

#: Feodo Tracker's botnet C2 list. Keyless, regenerated continuously.
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

#: SSLBL's certificate list is deliberately absent: its rows are certificate
#: SHA-1 fingerprints, and storing those as ``kind=hash`` would let a file-hash
#: lookup answer for something that was never a file.


def _data_lines(text: str) -> List[str]:
    """Lines that carry data.

    Feodo prefixes the file with ``#`` comments and ends it with
    ``# END n entries``; handing those to a CSV reader would make the first
    comment the header row.
    """
    return [line for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def parse_feodo_csv(text: str) -> List[Dict[str, Any]]:
    """Parse the Feodo Tracker C2 IP blocklist.

    Columns: ``first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware``.
    A row without a usable address is dropped rather than guessed at, and an
    address listed twice (two ports on one host) is kept once.
    """
    lines = _data_lines(text)
    if not lines:
        return []
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not reader.fieldnames or "dst_ip" not in reader.fieldnames:
        raise ValueError("not a Feodo Tracker CSV: no dst_ip column")
    seen = set()
    out: List[Dict[str, Any]] = []
    for row in reader:
        ip = (row.get("dst_ip") or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        out.append({
            "ip": ip,
            "port": (row.get("dst_port") or "").strip(),
            "status": (row.get("c2_status") or "").strip().lower(),
            "malware": (row.get("malware") or "").strip(),
            "last_online": (row.get("last_online") or "").strip(),
            "first_seen": (row.get("first_seen_utc") or "").strip(),
        })
    return out


def feodo_note(entry: Dict[str, Any]) -> str:
    """The one line that will be shown for this address on a result page."""
    parts = ["Feodo Tracker C2"]
    if entry.get("malware"):
        parts.append(str(entry["malware"]))
    if entry.get("port"):
        parts.append("port " + str(entry["port"]))
    if entry.get("status"):
        parts.append(str(entry["status"]))
    if entry.get("last_online"):
        parts.append("seen " + str(entry["last_online"]))
    return " · ".join(parts)[:160]


def feodo_rows(text: str) -> List[Tuple[str, str, str]]:
    """``(kind, value, note)`` triples ready for ``Store.sync_local_many``."""
    return [(KIND_IP, e["ip"], feodo_note(e)) for e in parse_feodo_csv(text)]
