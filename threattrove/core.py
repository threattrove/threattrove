"""Core models, indicator parsing, storage and the lookup engine.

Nothing in this module talks to the network directly; sources live in
``threattrove.sources``. This keeps the engine testable and lets the CLI and the
web app share exactly the same lookup behaviour.
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import requests

VERSION = "2.1.1"

DEFAULT_TIMEOUT = float(os.environ.get("TT_TIMEOUT", "20"))
CACHE_TTL_SECONDS = int(os.environ.get("TT_CACHE_TTL", str(7 * 24 * 3600)))
DEFAULT_DEADLINE = float(os.environ.get("TT_DEADLINE", "45"))
SITE_URL = os.environ.get("TT_SITE_URL", "https://threattrove.com")
USER_AGENT = f"threattrove/{VERSION} (+{SITE_URL})"

KIND_HASH = "hash"
KIND_URL = "url"
KIND_DOMAIN = "domain"
KIND_IP = "ip"
KINDS = (KIND_HASH, KIND_URL, KIND_DOMAIN, KIND_IP)

# --------------------------------------------------------------------------
# Verdicts
# --------------------------------------------------------------------------

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN = "clean"
VERDICT_KNOWN_GOOD = "known_good"
VERDICT_UNKNOWN = "unknown"
VERDICT_ERROR = "error"
VERDICT_SKIPPED = "skipped"

VERDICT_WEIGHT = {
    VERDICT_MALICIOUS: 100,
    VERDICT_SUSPICIOUS: 60,
    VERDICT_CLEAN: -20,
    VERDICT_KNOWN_GOOD: -100,
    VERDICT_UNKNOWN: 0,
    VERDICT_ERROR: 0,
    VERDICT_SKIPPED: 0,
}

VERDICT_LABEL = {
    VERDICT_MALICIOUS: "Malicious",
    VERDICT_SUSPICIOUS: "Suspicious",
    VERDICT_CLEAN: "Clean",
    VERDICT_KNOWN_GOOD: "Known good",
    VERDICT_UNKNOWN: "No verdict",
    VERDICT_ERROR: "Error",
    VERDICT_SKIPPED: "Skipped",
}

#: statuses that count towards the aggregate verdict
SCORED_STATUSES = {"found", "not_found", "matched", "no_match"}

#: independent sources that must list an indicator as malicious before it is
#: reported as malicious. A lone hit is a lead, not a conviction.
MIN_CORROBORATION = 2

#: confidence granted by N corroborating sources (5 or more -> MAX)
CORROBORATION_CONFIDENCE = {1: 45, 2: 75, 3: 88, 4: 93}
CORROBORATION_CONFIDENCE_MAX = 96
CONFIDENCE_CAP = 98
SUSPICIOUS_CONFIDENCE = 60


def combine(weights: Sequence[int]) -> Tuple[str, int]:
    """Combine per-source weights into (verdict, confidence).

    Malicious is gated on corroboration: at least ``MIN_CORROBORATION``
    independent sources must list the indicator as malicious. One feed alone is
    reported as suspicious with low confidence, because a single hit is often a
    stale entry, an over-broad feed, or a shared hosting address. Confidence is
    a grade of agreement between sources, not a sum of points.
    """
    if not weights:
        return VERDICT_UNKNOWN, 0

    malicious = sum(1 for w in weights
                    if w >= VERDICT_WEIGHT[VERDICT_MALICIOUS])
    suspicious = sum(1 for w in weights
                     if 0 < w < VERDICT_WEIGHT[VERDICT_MALICIOUS])
    trusted = sum(1 for w in weights
                  if w <= VERDICT_WEIGHT[VERDICT_KNOWN_GOOD])
    benign = sum(1 for w in weights
                 if VERDICT_WEIGHT[VERDICT_KNOWN_GOOD] < w < 0)

    # A malware feed and a curated allowlist disagreeing is not evidence of
    # anything in particular; refuse to guess instead of averaging them.
    if malicious and trusted:
        return VERDICT_UNKNOWN, 0

    if malicious >= MIN_CORROBORATION:
        base = CORROBORATION_CONFIDENCE.get(malicious,
                                            CORROBORATION_CONFIDENCE_MAX)
        return VERDICT_MALICIOUS, min(CONFIDENCE_CAP,
                                      base + 5 * suspicious)

    if malicious:
        return VERDICT_SUSPICIOUS, min(CONFIDENCE_CAP,
                                       CORROBORATION_CONFIDENCE[1]
                                       + 5 * suspicious)

    if suspicious:
        return VERDICT_SUSPICIOUS, min(CONFIDENCE_CAP,
                                       SUSPICIOUS_CONFIDENCE
                                       + 15 * (suspicious - 1))

    score = sum(weights)
    if trusted:
        return VERDICT_KNOWN_GOOD, min(100, abs(score))
    if benign:
        return VERDICT_CLEAN, min(99, abs(score))
    return VERDICT_UNKNOWN, 0


# --------------------------------------------------------------------------
# Evidence classes
# --------------------------------------------------------------------------

#: (key, label, description, sources). Ordered from strongest evidence to
#: weakest: a blocklist hit names this exact artifact, an engine verdict is an
#: opinion about it, community intel is chatter about it, and reputation lists
#: are usually about a host rather than a file.
EVIDENCE_CLASSES: Tuple[Tuple[str, str, str, Tuple[str, ...]], ...] = (
    ("blocklist", "Blocklists",
     "Malware sample and payload feeds that list this exact indicator",
     ("malwarebazaar", "urlhaus", "urlhaus_url", "threatfox", "malshare",
      "circl", "local")),
    ("sandbox", "Sandbox engines",
     "Automated analysis engines that detonated or scanned the artifact",
     ("virustotal", "virustotal_url", "virustotal_domain",
      "hybridanalysis", "triage")),
    ("community", "Community intel",
     "Analyst pulses and public scan reports that mention the indicator",
     ("otx", "otx_url", "otx_domain", "urlscan")),
    ("reputation", "Reputation",
     "Curated block/allow lists and site reputation services",
     ("gsb", "phishtank")),
)

EVIDENCE_OTHER = ("other", "Other",
                  "Other sources that returned data for this indicator")


def evidence_class(source: str) -> Tuple[str, str, str]:
    """Map a source name onto its (key, label, description) evidence class."""
    for key, label, description, sources in EVIDENCE_CLASSES:
        if source in sources:
            return key, label, description
    return EVIDENCE_OTHER


def human_size(value: Any) -> str:
    """Render a byte count as a short human string, or '' if it is not one."""
    try:
        size = float(value)
    except (TypeError, ValueError):
        return ""
    if size <= 0:
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return ""


# --------------------------------------------------------------------------
# Hash helpers
# --------------------------------------------------------------------------

_HEX = set("0123456789abcdef")


def hash_type(value: str) -> Optional[str]:
    """Return md5/sha1/sha256 if *value* looks like a hash of that type."""
    v = (value or "").strip().lower()
    if not v or any(c not in _HEX for c in v):
        return None
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(v))


def hashes_for_file(path: str | Path) -> Dict[str, str]:
    """Compute md5/sha1/sha256 for a file without loading it into memory."""
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest()}


def hashes_for_bytes(data: bytes) -> Dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# --------------------------------------------------------------------------
# Indicator parsing
# --------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9_\-]{1,63}(?:\.(?!-)[a-z0-9_\-]{1,63})+$",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

#: multi-label public suffixes worth handling without a full PSL dependency
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "co.za", "org.za", "co.jp", "or.jp",
    "ne.jp", "co.in", "net.in", "org.in", "co.kr", "or.kr", "com.br",
    "net.br", "org.br", "com.mx", "com.ar", "com.tr", "com.cn", "net.cn",
    "com.sg", "com.hk", "com.tw", "com.my", "co.il", "com.ua", "co.id",
    "com.pl", "com.es", "com.ph", "com.vn", "com.pk", "com.ng", "com.eg",
    "com.sa", "com.co", "com.pe", "com.ve",
}


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 (no full public-suffix list dependency)."""
    host = (host or "").strip().lower().strip(".")
    if not host or _IPV4_RE.match(host) or ":" in host:
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


@dataclasses.dataclass
class Indicator:
    """A normalised thing to look up."""

    kind: str
    value: str                      # canonical lookup key
    raw: str
    hashes: Dict[str, str] = dataclasses.field(default_factory=dict)
    url: str = ""                   # full normalised URL (kind == url)
    scheme: str = ""
    host: str = ""
    path: str = ""
    domain: str = ""                # registrable domain
    ip: str = ""

    # -- helpers ---------------------------------------------------------
    def preferred_hash(self) -> str:
        return (self.hashes.get("sha256") or self.hashes.get("sha1")
                or self.hashes.get("md5") or self.value)

    @property
    def label(self) -> str:
        return {"hash": "File hash", "url": "URL", "domain": "Domain",
                "ip": "IP address"}.get(self.kind, self.kind.title())

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["label"] = self.label
        return d


def parse_indicator(text: str) -> Optional[Indicator]:
    """Turn arbitrary user input into an Indicator, or None if unrecognised."""
    if not text:
        return None
    raw = text.strip().strip("<>\"'")
    if not raw or len(raw) > 2048:
        return None

    ht = hash_type(raw)
    if ht:
        v = raw.lower()
        return Indicator(kind=KIND_HASH, value=v, raw=raw, hashes={ht: v})

    # IP address (v4 or v6)
    try:
        ip = ipaddress.ip_address(raw.strip("[]"))
        return Indicator(kind=KIND_IP, value=str(ip), raw=raw, ip=str(ip))
    except ValueError:
        pass

    # URL, with or without a scheme
    candidate = raw
    if "://" not in candidate and ("/" in candidate or "?" in candidate):
        candidate = "http://" + candidate
    if candidate.lower().startswith(("http://", "https://")):
        try:
            from urllib.parse import urlsplit, urlunsplit
            sp = urlsplit(candidate)
        except ValueError:
            return None
        host = (sp.hostname or "").lower()
        if not host:
            return None
        scheme = sp.scheme.lower()
        netloc = host
        if sp.port and not ((scheme == "http" and sp.port == 80)
                            or (scheme == "https" and sp.port == 443)):
            netloc = f"{host}:{sp.port}"
        path = sp.path or ""
        norm = urlunsplit((scheme, netloc, path, sp.query, ""))
        return Indicator(
            kind=KIND_URL, value=norm, raw=raw, url=norm, scheme=scheme,
            host=host, path=path or "/", domain=registrable_domain(host),
        )

    # Bare hostname -> domain
    host = raw.lower().rstrip(".")
    if _HOSTNAME_RE.match(host) or _IPV4_RE.match(host):
        return Indicator(kind=KIND_DOMAIN, value=host, raw=raw, host=host,
                         domain=registrable_domain(host))
    return None


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------

@dataclasses.dataclass
class SourceResult:
    source: str
    status: str = "unknown"     # found | not_found | error | skipped | unauthorized | timeout
    verdict: str = VERDICT_UNKNOWN
    detections: int = 0
    total: int = 0
    note: str = ""
    link: str = ""
    category: str = "reputation"     # reputation | intel
    detail: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Report:
    indicator: Indicator
    results: List[SourceResult] = dataclasses.field(default_factory=list)
    created: float = dataclasses.field(default_factory=time.time)
    elapsed: float = 0.0

    # -- aggregation -----------------------------------------------------
    def _weights(self) -> List[int]:
        return [VERDICT_WEIGHT.get(r.verdict, 0)
                for r in self.results
                if r.category == "reputation" and r.status in SCORED_STATUSES]

    def score(self) -> int:
        return sum(self._weights())

    def verdict(self) -> str:
        return combine(self._weights())[0]

    def confidence(self) -> int:
        return combine(self._weights())[1]

    # -- presentation helpers -------------------------------------------
    def reputation(self) -> List[SourceResult]:
        return [r for r in self.results if r.category == "reputation"]

    def intel(self) -> List[SourceResult]:
        return [r for r in self.results if r.category == "intel"]

    def engine_ratio(self) -> Tuple[int, int]:
        """Sum of vendor-engine detections across sources that report them.

        Only sources that explicitly advertise engine results (VirusTotal-style
        ``x/y engines``) contribute; scan counts from urlscan or pulse counts
        from OTX are not comparable and would inflate the denominator.
        """
        engines = [r for r in self.results
                   if r.total and (r.detail or {}).get("engines")]
        return (sum(r.detections for r in engines),
                sum(r.total for r in engines))

    def flagged_by(self) -> List[str]:
        return [r.source for r in self.results
                if r.verdict in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS)]

    def corroboration(self) -> int:
        """How many independent sources list this indicator as malicious."""
        return len({r.source for r in self.results
                    if r.category == "reputation"
                    and r.status in SCORED_STATUSES
                    and r.verdict == VERDICT_MALICIOUS})

    def evidence(self) -> List[Dict[str, Any]]:
        """Group the sources that answered into evidence classes.

        The point is to show *what kind* of evidence backs the verdict, and how
        many sources inside each class agree, instead of one flat count.
        """
        classes = [tuple(c[:3]) for c in EVIDENCE_CLASSES] + [EVIDENCE_OTHER]
        groups: Dict[str, Dict[str, Any]] = {}
        for key, label, description in classes:
            groups[key] = {"key": key, "label": label,
                           "description": description,
                           "sources": [], "answered": 0, "hit": 0}
        for r in self.results:
            if r.category != "reputation" or r.status not in SCORED_STATUSES:
                continue
            key = evidence_class(r.source)[0]
            group = groups[key]
            group["sources"].append(r.source)
            group["answered"] += 1
            if r.verdict in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS):
                group["hit"] += 1
        return [g for g in groups.values() if g["answered"]]

    def families(self) -> List[str]:
        """Malware family / signature names reported by malicious sources."""
        names: List[str] = []
        seen = set()
        for r in self.results:
            if r.verdict not in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS):
                continue
            detail = r.detail or {}
            for key in ("signature", "malware", "threat_label", "family",
                        "threat"):
                value = detail.get(key)
                if not isinstance(value, str):
                    continue
                label = value.strip()
                if not label or label.lower() in seen:
                    continue
                seen.add(label.lower())
                names.append(label)
        return names[:4]

    def file_identity(self) -> Dict[str, str]:
        """Best-effort "what file is this" summary from sources that name it.

        Without a filename database of our own, the name/product/platform
        fields that NSRL (CIRCL) and VirusTotal already return are the only
        way to answer "which executable is this hash?" -- so surface them
        instead of hiding them in the raw detail blob.
        """
        ident: Dict[str, str] = {"name": "", "product": "", "platform": "",
                                 "type": "", "size": "", "first_seen": "",
                                 "source": ""}

        def take(field: str, *values: Any) -> None:
            if ident[field]:
                return
            for value in values:
                if field == "size":
                    text = human_size(value)
                elif isinstance(value, str):
                    text = value.strip()
                else:
                    text = ""
                if text:
                    ident[field] = text
                    return

        for r in self.results:
            detail = r.detail or {}
            if r.source == "circl":
                take("name", detail.get("FileName"))
                take("product", detail.get("ProductName"))
                take("platform", detail.get("OpSystemName"))
                take("size", detail.get("FileSize"))
            elif r.source == "virustotal":
                take("name", detail.get("meaningful_name"))
                take("type", detail.get("type_description"))
                take("size", detail.get("size"))
                take("first_seen", detail.get("first_submission"))
            elif r.source == "hybridanalysis":
                take("name", detail.get("file_name"))
                take("type", detail.get("type"))
                take("size", detail.get("size"))
                take("first_seen", detail.get("first_seen"))
            elif r.source == "malwarebazaar":
                take("type", detail.get("file_type"))
                take("first_seen", detail.get("first_seen"))
            elif r.source in ("urlhaus", "urlhaus_url"):
                take("type", detail.get("file_type"))
                take("first_seen", detail.get("firstseen"))
            if ident["name"] and not ident["source"]:
                ident["source"] = r.source
        return {k: v for k, v in ident.items() if v}

    def _conflict(self) -> bool:
        """True when a malware feed and a curated allowlist both match."""
        weights = self._weights()
        return (any(w >= VERDICT_WEIGHT[VERDICT_MALICIOUS] for w in weights)
                and any(w <= VERDICT_WEIGHT[VERDICT_KNOWN_GOOD]
                        for w in weights))

    def headline(self) -> str:
        """A one-line, calibrated summary of the evidence behind the verdict."""
        verdict = self.verdict()
        det, tot = self.engine_ratio()
        sources = self.corroboration()
        families = self.families()
        ident = self.file_identity()
        name = ident.get("name", "")

        if verdict == VERDICT_MALICIOUS:
            if sources >= MIN_CORROBORATION:
                text = f"Listed as malicious by {sources} independent sources"
                if det and tot:
                    text += f", and {det}/{tot} engines agree"
            else:
                text = f"{det}/{tot} engines flagged this as malicious"
            if families:
                text += f" ({families[0]})"
            return text

        if verdict == VERDICT_SUSPICIOUS:
            if sources == 1:
                who = next(iter({r.source for r in self.results
                                 if r.verdict == VERDICT_MALICIOUS}), "")
                where = f" ({who})" if who else ""
                return (f"Only 1 source lists this as malicious{where} - "
                        "a lead, not a conviction")
            flagged = len({r.source for r in self.results
                           if r.verdict == VERDICT_SUSPICIOUS})
            if sources >= MIN_CORROBORATION or flagged:
                return ("Sources disagree or only partially flag this - "
                        f"{self.confidence()}% confidence")
            return "Suspicious, but the evidence is thin"

        if verdict == VERDICT_KNOWN_GOOD:
            if name:
                text = f"Known good: {name}"
                if ident.get("product"):
                    text += f" ({ident['product']})"
                return text
            return "Matches a known-good record"

        if verdict == VERDICT_CLEAN:
            if det == 0 and tot:
                return f"0/{tot} engines flagged this and no feed lists it"
            return "No source that answered flagged this"

        if self._conflict():
            return ("Sources disagree: a malware feed and an allowlist both "
                    "match this indicator")
        if name:
            return f"No verdict for {name} - no source has data on it"
        return "No source returned a usable verdict for this indicator"

    def to_dict(self, include_results: bool = True) -> Dict[str, Any]:
        d = {
            "indicator": self.indicator.to_dict(),
            "verdict": self.verdict(),
            "confidence": self.confidence(),
            "headline": self.headline(),
            "score": self.score(),
            "corroboration": self.corroboration(),
            "families": self.families(),
            "evidence": self.evidence(),
            "file_identity": self.file_identity(),
            "elapsed_seconds": round(self.elapsed, 2),
            "created": self.created,
            "sources_checked": len(self.reputation()),
        }
        if include_results:
            d["results"] = [r.to_dict() for r in self.results]
        return d


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    kind       TEXT NOT NULL,
    value      TEXT NOT NULL,
    source     TEXT NOT NULL,
    payload    TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    PRIMARY KEY (kind, value, source)
);
CREATE TABLE IF NOT EXISTS local (
    kind     TEXT NOT NULL,
    value    TEXT NOT NULL,
    label    TEXT NOT NULL,
    note     TEXT,
    added_at REAL NOT NULL,
    PRIMARY KEY (kind, value)
);
CREATE TABLE IF NOT EXISTS history (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    kind    TEXT NOT NULL,
    value   TEXT NOT NULL,
    verdict TEXT NOT NULL,
    score   INTEGER NOT NULL,
    ts      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS history_ts ON history(ts DESC);
CREATE INDEX IF NOT EXISTS history_value ON history(kind, value);
"""


class Store:
    """SQLite-backed cache, custom local verdicts and lookup history."""

    def __init__(self, path: Optional[str | Path] = None):
        if path is None:
            path = os.environ.get("TT_DB") or os.environ.get("TT_CACHE_DB")
            path = Path(path) if path else Path.home() / ".threattrove" / "threattrove.db"
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False,
                                    timeout=30)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    # -- cache -----------------------------------------------------------
    def get_cached(self, kind: str, value: str, source: str,
                   ttl: Optional[int] = None) -> Optional[SourceResult]:
        ttl = CACHE_TTL_SECONDS if ttl is None else ttl
        if ttl <= 0:
            return None
        with self._lock:
            row = self.conn.execute(
                "SELECT payload, fetched_at FROM cache"
                " WHERE kind=? AND value=? AND source=?",
                (kind, value, source),
            ).fetchone()
        if not row:
            return None
        payload, fetched_at = row
        if time.time() - fetched_at > ttl:
            return None
        try:
            res = SourceResult(**json.loads(payload))
        except (TypeError, ValueError):
            return None
        res.detail = dict(res.detail or {})
        res.detail["_cached"] = True
        res.detail["_cached_at"] = fetched_at
        return res

    def put_cached(self, kind: str, value: str, res: SourceResult) -> None:
        payload = json.dumps(dataclasses.asdict(res))
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO cache (kind, value, source, payload, fetched_at)"
                " VALUES (?,?,?,?,?)",
                (kind, value, res.source, payload, time.time()),
            )
            self.conn.commit()

    def clear_cache(self, older_than: Optional[float] = None) -> int:
        with self._lock:
            cur = self.conn.execute(
                "DELETE FROM cache WHERE ? IS NULL OR fetched_at < ?",
                (older_than, older_than or 0),
            )
            self.conn.commit()
            return cur.rowcount

    # -- local custom verdicts -------------------------------------------
    def get_local(self, kind: str, value: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT label, note, added_at FROM local WHERE kind=? AND value=?",
                (kind, value.lower()),
            ).fetchone()
        if not row:
            return None
        return {"label": row[0], "note": row[1] or "", "added_at": row[2]}

    def add_local(self, kind: str, value: str, label: str, note: str = "") -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO local (kind, value, label, note, added_at)"
                " VALUES (?,?,?,?,?)",
                (kind, value.lower(), label, note, time.time()),
            )
            self.conn.commit()

    def delete_local(self, kind: str, value: str) -> int:
        with self._lock:
            cur = self.conn.execute(
                "DELETE FROM local WHERE kind=? AND value=?", (kind, value.lower()))
            self.conn.commit()
            return cur.rowcount

    def list_local(self, limit: int = 500) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT kind, value, label, note, added_at FROM local"
                " ORDER BY added_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{"kind": r[0], "value": r[1], "label": r[2], "note": r[3],
                 "added_at": r[4]} for r in rows]

    # -- history / stats -------------------------------------------------
    def record_lookup(self, report: "Report") -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO history (kind, value, verdict, score, ts)"
                " VALUES (?,?,?,?,?)",
                (report.indicator.kind, report.indicator.value,
                 report.verdict(), report.score(), time.time()),
            )
            self.conn.commit()

    def recent(self, limit: int = 12) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT kind, value, verdict, ts FROM history"
                " ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{"kind": r[0], "value": r[1], "verdict": r[2], "ts": r[3]}
                for r in rows]

    def close(self) -> None:
        with self._lock:
            try:
                self.conn.commit()
            finally:
                self.conn.close()

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self.conn.execute("SELECT COUNT(*) FROM history").fetchone()[0]
            recent = self.conn.execute(
                "SELECT COUNT(*) FROM history WHERE ts > ?",
                (time.time() - 86400,)).fetchone()[0]
            cached = self.conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            local = self.conn.execute("SELECT COUNT(*) FROM local").fetchone()[0]
            flagged = self.conn.execute(
                "SELECT COUNT(*) FROM history WHERE verdict=?",
                (VERDICT_MALICIOUS,)).fetchone()[0]
        return {"lookups_total": total, "lookups_24h": recent,
                "cached_entries": cached, "local_entries": local,
                "malicious_total": flagged}


# --------------------------------------------------------------------------
# Source base class
# --------------------------------------------------------------------------

class Source:
    """Base class for every data source.

    Subclasses set ``kinds`` to declare which indicator types they support.
    ``min_interval`` adds client-side pacing so a bulk run never hammers a
    free API.
    """

    name: str = "base"
    display: str = "base"
    env_key: Optional[str] = None
    keyless: bool = False
    homepage: str = ""
    kinds: Tuple[str, ...] = (KIND_HASH,)
    category: str = "reputation"
    min_interval: float = 0.0
    cache_ttl: Optional[int] = None

    def key(self) -> Optional[str]:
        if not self.env_key:
            return None
        return os.environ.get(self.env_key) or None

    def available(self) -> bool:
        return self.keyless or self.env_key is None or bool(self.key())

    def supports(self, kind: str) -> bool:
        return kind in self.kinds

    def lookup(self, ind: Indicator) -> SourceResult:  # pragma: no cover
        raise NotImplementedError

    # convenience ---------------------------------------------------------
    def session(self) -> requests.Session:
        s = getattr(_thread_local, "session", None)
        if s is None:
            s = requests.Session()
            s.headers.update({"User-Agent": USER_AGENT,
                              "Accept": "application/json, */*"})
            _thread_local.session = s
        return s

    def result(self, **kw: Any) -> SourceResult:
        kw.setdefault("source", self.name)
        kw.setdefault("category", self.category)
        return SourceResult(**kw)

    def fail(self, exc: Exception) -> SourceResult:
        msg = str(exc)[:180] or exc.__class__.__name__
        return self.result(status="error", note=msg)


_thread_local = threading.local()


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

class Engine:
    """Runs every applicable source for an indicator, in parallel."""

    def __init__(self, sources: Optional[Sequence[Source]] = None,
                 store: Optional[Store] = None, use_cache: bool = True,
                 max_workers: int = 6,
                 deadline: Optional[float] = None):
        if sources is None:
            from .sources import ALL_SOURCES
            sources = ALL_SOURCES
        self.sources: List[Source] = list(sources)
        self.store = store
        self.use_cache = use_cache
        self.max_workers = max(1, int(max_workers))
        self.deadline = DEFAULT_DEADLINE if deadline is None else deadline
        self._pace_lock = threading.Lock()
        self._last_call: Dict[str, float] = {}

    # -- source selection -------------------------------------------------
    def sources_for(self, kind: str) -> List[Source]:
        return [s for s in self.sources if s.supports(kind) and s.available()]

    def disabled_for(self, kind: str) -> List[Source]:
        return [s for s in self.sources
                if s.supports(kind) and not s.available()]

    # -- pacing -----------------------------------------------------------
    def _pace(self, source: Source) -> None:
        if source.min_interval <= 0:
            return
        while True:
            with self._pace_lock:
                last = self._last_call.get(source.name, 0.0)
                wait = source.min_interval - (time.time() - last)
                if wait <= 0:
                    self._last_call[source.name] = time.time()
                    return
            time.sleep(min(wait, 0.5))

    # -- the lookup -------------------------------------------------------
    def lookup(self, ind: Indicator, use_cache: Optional[bool] = None) -> Report:
        started = time.time()
        report = Report(indicator=ind)
        cache_on = self.use_cache if use_cache is None else use_cache

        # Local, user-defined verdicts always win and are shown first.
        if self.store:
            loc = self.store.get_local(ind.kind, ind.value)
            if loc:
                label = (loc["label"] or "").lower()
                verdict = (VERDICT_MALICIOUS
                           if label in ("malware", "malicious", "bad", "block")
                           else VERDICT_KNOWN_GOOD
                           if label in ("clean", "good", "allow", "whitelist")
                           else VERDICT_SUSPICIOUS
                           if label in ("suspicious", "watch")
                           else VERDICT_UNKNOWN)
                report.results.append(SourceResult(
                    source="local",
                    status="found",
                    verdict=verdict,
                    note=(f"{loc['label']}: {loc['note']}".strip(": ")
                          or loc["label"]),
                    link="/local",
                    category="reputation",
                    detail={"label": loc["label"], "note": loc["note"]},
                ))

        active = self.sources_for(ind.kind)
        if not active:
            report.elapsed = time.time() - started
            return report

        futures = {}
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(self.max_workers, len(active))) as ex:
            for src in active:
                futures[ex.submit(self._run, src, ind, cache_on)] = src
            try:
                for fut in concurrent.futures.as_completed(
                        futures, timeout=self.deadline):
                    src = futures[fut]
                    try:
                        report.results.append(fut.result())
                    except Exception as exc:  # noqa: BLE001 - never break a report
                        report.results.append(src.result(
                            status="error", note=str(exc)[:180]))
            except concurrent.futures.TimeoutError:
                for fut, src in futures.items():
                    if fut.done():
                        continue
                    report.results.append(src.result(
                        status="timeout",
                        note=f"no response within {self.deadline:.0f}s"))

        order = {s.name: i for i, s in enumerate(self.sources)}
        report.results.sort(key=lambda r: (order.get(r.source, 999), r.source))
        report.elapsed = time.time() - started

        if self.store:
            try:
                self.store.record_lookup(report)
            except sqlite3.Error:
                pass
        return report

    def _run(self, source: Source, ind: Indicator, use_cache: bool) -> SourceResult:
        if self.store and use_cache:
            cached = self.store.get_cached(
                ind.kind, ind.value, source.name,
                ttl=source.cache_ttl if source.cache_ttl is not None
                else CACHE_TTL_SECONDS)
            if cached:
                return cached
        self._pace(source)
        try:
            res = source.lookup(ind)
        except requests.RequestException as exc:
            return source.fail(exc)
        if self.store and res.status in ("found", "not_found", "matched",
                                         "no_match"):
            try:
                payload = dataclasses.asdict(res)
                payload["detail"] = {k: v for k, v in (payload["detail"] or {}).items()
                                     if not k.startswith("_")}
                self.store.put_cached(ind.kind, ind.value,
                                      SourceResult(**payload))
            except sqlite3.Error:
                pass
        return res

    # -- bulk -------------------------------------------------------------
    def lookup_many(self, indicators: Iterable[Indicator],
                    use_cache: Optional[bool] = None,
                    progress: Optional[Any] = None) -> List[Report]:
        reports = []
        for ind in indicators:
            reports.append(self.lookup(ind, use_cache=use_cache))
            if progress:
                progress(reports[-1])
        return reports


def default_engine(**kw: Any) -> Engine:
    """Engine wired to the shared store configured by the environment."""
    store = kw.pop("store", None) or Store()
    return Engine(store=store, **kw)
