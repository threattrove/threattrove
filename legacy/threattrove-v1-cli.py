#!/usr/bin/env python3
"""
threattrove - a self-hostable, multi-source hash reputation lookup tool.

An open "VirusTotal alternative" focused purely on file-hash reputation.
It aggregates results from several free / freemium threat-intelligence
sources, caches them locally, and produces a consolidated verdict.

Sources
=======
Keyless (work out of the box):
  * circl      - CIRCL hashlookup (NSRL known-good whitelist + known-malicious flag)
  * otx        - AlienVault OTX file reputation

Optional API key (set the matching environment variable to enable):
  * malwarebazaar   (ABUSECH_AUTH_KEY)   abuse.ch sample repository
  * threatfox       (ABUSECH_AUTH_KEY)   abuse.ch IOC database
  * urlhaus         (ABUSECH_AUTH_KEY)   abuse.ch malware URL/payload DB
  * virustotal      (VT_API_KEY)         60+ engine aggregation
  * hybridanalysis  (HA_API_KEY)         Falcon Sandbox reports
  * malshare        (MALSHARE_API_KEY)   malware sample sharing
  * triage          (TRIAGE_API_KEY)     Hatching Triage sandbox

Get a free abuse.ch Auth-Key at https://auth.abuse.ch/ (one key covers all
three abuse.ch APIs). VirusTotal's free tier key is at
https://www.virustotal.com/gui/my-apikey .

Usage
=====
    python3 threattrove.py 44d88612fea8a8f36de82e1278abb02f
    python3 threattrove.py --file suspicious.exe --file notes.doc
    python3 threattrove.py --json 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    python3 threattrove.py --list-sources
    python3 threattrove.py --add-local <hash> --label malware --note "confirmed C2 loader"
    python3 threattrove.py --json <hash>            # machine-readable report

Environment
===========
    ABUSECH_AUTH_KEY, VT_API_KEY, HA_API_KEY, MALSHARE_API_KEY, TRIAGE_API_KEY
    TT_CACHE_DB      override cache database path (default ~/.threattrove/cache.db)
    TT_TIMEOUT       per-request timeout seconds (default 20)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "This tool needs the 'requests' library:  pip install requests\n"
    )
    raise

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

VERSION = "1.0.0"
DEFAULT_TIMEOUT = float(os.environ.get("TT_TIMEOUT", "20"))
CACHE_TTL_SECONDS = int(os.environ.get("TT_CACHE_TTL", str(7 * 24 * 3600)))
USER_AGENT = f"threattrove/{VERSION} (+https://github.com/; hash reputation lookup)"

C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_DIM = "\033[2m"
C_BOLD = "\033[1m"
C_CYAN = "\033[96m"
C_RESET = "\033[0m"


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def color(text: str, code: str) -> str:
    if not _supports_color():
        return text
    return f"{code}{text}{C_RESET}"


# --------------------------------------------------------------------------
# Hash helpers
# --------------------------------------------------------------------------

HEXCHARS = set("0123456789abcdef")


def hash_type(value: str) -> Optional[str]:
    """Return md5/sha1/sha256 if value looks like that hash, else None."""
    v = value.strip().lower()
    if not v or any(c not in HEXCHARS for c in v):
        return None
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(v))


def hashes_for_file(path: Path) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


# --------------------------------------------------------------------------
# Result model
# --------------------------------------------------------------------------

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN = "clean"
VERDICT_KNOWN_GOOD = "known_good"
VERDICT_UNKNOWN = "unknown"
VERDICT_ERROR = "error"
VERDICT_SKIPPED = "skipped"

# weight used when combining source verdicts into an overall confidence
_VERDICT_WEIGHT = {
    VERDICT_MALICIOUS: 100,
    VERDICT_SUSPICIOUS: 60,
    VERDICT_KNOWN_GOOD: -100,
    VERDICT_CLEAN: -20,
    VERDICT_UNKNOWN: 0,
    VERDICT_ERROR: 0,
    VERDICT_SKIPPED: 0,
}


@dataclasses.dataclass
class SourceResult:
    source: str
    status: str = "unknown"          # found | not_found | error | skipped | unauthorized
    verdict: str = VERDICT_UNKNOWN
    detections: int = 0
    total: int = 0
    detail: Dict[str, Any] = dataclasses.field(default_factory=dict)
    link: str = ""
    note: str = ""


@dataclasses.dataclass
class HashReport:
    query: str
    hash_type: str
    results: List[SourceResult] = dataclasses.field(default_factory=list)
    cached_at: float = 0.0

    def verdict(self) -> str:
        weights = [
            _VERDICT_WEIGHT.get(r.verdict, 0)
            for r in self.results
            if r.status in ("found", "not_found", "ok")
        ]
        if not weights:
            return VERDICT_UNKNOWN
        score = sum(weights)
        if score >= 100:
            return VERDICT_MALICIOUS
        if score >= 40:
            return VERDICT_SUSPICIOUS
        if score <= -100:
            return VERDICT_KNOWN_GOOD
        if score <= -20:
            return VERDICT_CLEAN
        return VERDICT_UNKNOWN

    def confidence(self) -> int:
        """0-100 rough confidence derived from the combined source weights."""
        weights = [
            _VERDICT_WEIGHT.get(r.verdict, 0)
            for r in self.results
            if r.status in ("found", "not_found", "ok")
        ]
        if not weights:
            return 0
        score = sum(weights)
        return min(100, abs(score))


# --------------------------------------------------------------------------
# Source implementations
# --------------------------------------------------------------------------

class Source:
    name: str = "base"
    display: str = "base"
    env_key: Optional[str] = None
    keyless: bool = False   # works without a key (key still optional if set)
    homepage: str = ""

    def key(self) -> Optional[str]:
        if not self.env_key:
            return None
        return os.environ.get(self.env_key) or None

    def available(self) -> bool:
        return self.keyless or self.env_key is None or bool(self.key())

    def lookup(self, ht: "HashTarget") -> SourceResult:
        raise NotImplementedError


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


class CIRCLHashlookup(Source):
    name = "circl"
    display = "CIRCL hashlookup"
    keyless = True
    homepage = "https://hashlookup.circl.lu/"

    def lookup(self, ht: "HashTarget") -> SourceResult:
        res = SourceResult(source=self.name)
        for algo in ("sha256", "sha1", "md5"):
            val = ht.hashes.get(algo)
            if not val:
                continue
            url = f"https://hashlookup.circl.lu/lookup/{algo}/{val}"
            try:
                r = _session().get(url, timeout=DEFAULT_TIMEOUT)
            except requests.RequestException as e:
                return dataclasses.replace(res, status="error", note=str(e))
            if r.status_code == 400:
                continue
            if r.status_code == 404:
                continue
            if r.status_code != 200:
                return dataclasses.replace(
                    res, status="error", note=f"HTTP {r.status_code}")
            try:
                data = r.json()
            except ValueError:
                return dataclasses.replace(res, status="error", note="bad JSON")
            res.status = "found"
            res.detail = {
                "FileName": data.get("FileName"),
                "FileSize": data.get("FileSize"),
                "KnownMalicious": data.get("KnownMalicious"),
                "ProductName": (data.get("ProductCode") or {}).get("ProductName"),
                "OpSystemName": (data.get("OpSystemCode") or {}).get("OpSystemName"),
            }
            res.link = f"https://hashlookup.circl.lu/lookup/{algo}/{val}"
            known_mal = str(data.get("KnownMalicious", "")).strip()
            if known_mal and known_mal.lower() not in ("none", "false", "0"):
                res.verdict = VERDICT_MALICIOUS
                res.note = f"flag: {known_mal}"
            else:
                res.verdict = VERDICT_KNOWN_GOOD
                res.note = data.get("FileName", "NSRL known file")
            return res
        res.status = "not_found"
        res.verdict = VERDICT_UNKNOWN
        return res


class AlienVaultOTX(Source):
    name = "otx"
    display = "AlienVault OTX"
    env_key = "OTX_API_KEY"
    keyless = True
    homepage = "https://otx.alienvault.com/"

    def lookup(self, ht: "HashTarget") -> SourceResult:
        res = SourceResult(source=self.name)
        h = ht.preferred()
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{h}/general"
        headers = {}
        if self.key():
            headers["X-OTX-API-KEY"] = self.key()
        try:
            r = _session().get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        except requests.RequestException as e:
            return dataclasses.replace(res, status="error", note=str(e))
        if r.status_code == 404:
            return dataclasses.replace(res, status="not_found")
        if r.status_code != 200:
            return dataclasses.replace(
                res, status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return dataclasses.replace(res, status="error", note="bad JSON")
        res.status = "found"
        res.link = f"https://otx.alienvault.com/indicator/file/{h}"
        pulse_info = data.get("pulse_info", {}) or {}
        pulses = pulse_info.get("count", 0) or 0
        analysis = data.get("analysis", {}) or {}
        detections = int(analysis.get("detection", 0) or 0)
        res.detections = detections
        res.total = int(analysis.get("analysis", 0) or 0)
        res.detail = {
            "pulses": pulses,
            "detections": detections,
            "names": (data.get("base_indicator", {}) or {}).get("title", ""),
        }
        if detections > 0 or pulses > 0:
            res.verdict = VERDICT_MALICIOUS if pulses >= 1 else VERDICT_SUSPICIOUS
            res.note = f"{pulses} pulse(s)"
        else:
            res.verdict = VERDICT_UNKNOWN
            res.note = "no pulses"
        return res


class MalwareBazaar(Source):
    name = "malwarebazaar"
    display = "MalwareBazaar (abuse.ch)"
    env_key = "ABUSECH_AUTH_KEY"
    homepage = "https://bazaar.abuse.ch/"

    def lookup(self, ht: "HashTarget") -> SourceResult:
        res = SourceResult(source=self.name)
        h = ht.preferred()
        headers = {"Auth-Key": self.key() or ""}
        try:
            r = _session().post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": h},
                headers=headers,
                timeout=DEFAULT_TIMEOUT,
            )
        except requests.RequestException as e:
            return dataclasses.replace(res, status="error", note=str(e))
        if r.status_code in (401, 403):
            return dataclasses.replace(res, status="unauthorized",
                                      note="invalid/absent Auth-Key")
        if r.status_code != 200:
            return dataclasses.replace(
                res, status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return dataclasses.replace(res, status="error", note="bad JSON")
        status = data.get("query_status")
        if status == "hash_not_found":
            return dataclasses.replace(res, status="not_found")
        if status != "ok":
            return dataclasses.replace(res, status="error",
                                      note=str(data.get("query_status")))
        entry = (data.get("data") or [{}])[0]
        res.status = "found"
        res.verdict = VERDICT_MALICIOUS
        res.detail = {
            "signature": entry.get("signature"),
            "file_type": entry.get("file_type"),
            "first_seen": entry.get("first_seen"),
            "tags": entry.get("tags"),
            "reporter": entry.get("reporter"),
        }
        res.note = entry.get("signature") or "known malware sample"
        res.link = f"https://bazaar.abuse.ch/sample/{ht.hashes.get('sha256', h)}/"
        return res


class ThreatFox(Source):
    name = "threatfox"
    display = "ThreatFox (abuse.ch)"
    env_key = "ABUSECH_AUTH_KEY"
    homepage = "https://threatfox.abuse.ch/"

    def lookup(self, ht: "HashTarget") -> SourceResult:
        res = SourceResult(source=self.name)
        h = ht.hashes.get("sha256") or ht.preferred()
        headers = {"Auth-Key": self.key() or "", "Content-Type": "application/json"}
        try:
            r = _session().post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": h},
                headers=headers,
                timeout=DEFAULT_TIMEOUT,
            )
        except requests.RequestException as e:
            return dataclasses.replace(res, status="error", note=str(e))
        if r.status_code in (401, 403):
            return dataclasses.replace(res, status="unauthorized",
                                      note="invalid/absent Auth-Key")
        if r.status_code != 200:
            return dataclasses.replace(
                res, status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return dataclasses.replace(res, status="error", note="bad JSON")
        status = data.get("query_status")
        if status in ("no_result", "illegal_search_term"):
            return dataclasses.replace(res, status="not_found")
        if status != "ok":
            return dataclasses.replace(res, status="error", note=str(status))
        entries = data.get("data") or []
        if not entries:
            return dataclasses.replace(res, status="not_found")
        first = entries[0]
        res.status = "found"
        res.verdict = VERDICT_MALICIOUS
        res.detail = {
            "malware": first.get("malware_printable"),
            "threat_type": first.get("threat_type"),
            "confidence": first.get("confidence_level"),
            "first_seen": first.get("first_seen_utc"),
        }
        res.note = first.get("malware_printable") or "IOC match"
        res.link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{h}"
        return res


class URLhaus(Source):
    name = "urlhaus"
    display = "URLhaus (abuse.ch)"
    env_key = "ABUSECH_AUTH_KEY"
    homepage = "https://urlhaus.abuse.ch/"

    def lookup(self, ht: "HashTarget") -> SourceResult:
        res = SourceResult(source=self.name)
        md5 = ht.hashes.get("md5")
        if not md5:
            return dataclasses.replace(res, status="skipped",
                                      note="md5 required")
        headers = {"Auth-Key": self.key() or ""}
        try:
            r = _session().post(
                "https://urlhaus-api.abuse.ch/v1/payload/",
                data={"md5_hash": md5},
                headers=headers,
                timeout=DEFAULT_TIMEOUT,
            )
        except requests.RequestException as e:
            return dataclasses.replace(res, status="error", note=str(e))
        if r.status_code in (401, 403):
            return dataclasses.replace(res, status="unauthorized",
                                      note="invalid/absent Auth-Key")
        if r.status_code != 200:
            return dataclasses.replace(
                res, status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return dataclasses.replace(res, status="error", note="bad JSON")
        if data.get("query_status") != "ok":
            return dataclasses.replace(res, status="not_found")
        res.status = "found"
        res.verdict = VERDICT_MALICIOUS
        res.detail = {
            "file_type": data.get("file_type"),
            "signature": data.get("signature"),
            "url_count": data.get("url_count"),
            "firstseen": data.get("firstseen"),
        }
        res.note = data.get("signature") or "payload seen in URLhaus"
        res.link = f"https://urlhaus.abuse.ch/browse.php?search={md5}"
        return res


class VirusTotal(Source):
    name = "virustotal"
    display = "VirusTotal"
    env_key = "VT_API_KEY"
    homepage = "https://www.virustotal.com/"

    def lookup(self, ht: "HashTarget") -> SourceResult:
        res = SourceResult(source=self.name)
        h = ht.preferred()
        headers = {"x-apikey": self.key() or ""}
        url = f"https://www.virustotal.com/api/v3/files/{h}"
        try:
            r = _session().get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        except requests.RequestException as e:
            return dataclasses.replace(res, status="error", note=str(e))
        if r.status_code == 401:
            return dataclasses.replace(res, status="unauthorized",
                                      note="invalid API key")
        if r.status_code == 404:
            return dataclasses.replace(res, status="not_found")
        if r.status_code == 429:
            return dataclasses.replace(res, status="error",
                                      note="rate limited (4/min free tier)")
        if r.status_code != 200:
            return dataclasses.replace(
                res, status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return dataclasses.replace(res, status="error", note="bad JSON")
        attr = ((data.get("data") or {}).get("attributes") or {})
        stats = attr.get("last_analysis_stats") or {}
        mal = int(stats.get("malicious", 0) or 0)
        susp = int(stats.get("suspicious", 0) or 0)
        total = sum(int(v or 0) for v in stats.values()) or 0
        res.status = "found"
        res.detections = mal
        res.total = total
        res.detail = {
            "malicious": mal,
            "suspicious": susp,
            "total_engines": total,
            "meaningful_name": attr.get("meaningful_name"),
            "type_description": attr.get("type_description"),
            "threat_label": (attr.get("popular_threat_classification") or {})
            .get("suggested_threat_label"),
        }
        res.link = f"https://www.virustotal.com/gui/file/{h}"
        if mal > 0:
            res.verdict = VERDICT_MALICIOUS if mal >= 3 else VERDICT_SUSPICIOUS
            res.note = f"{mal}/{total} engines"
        elif susp > 0:
            res.verdict = VERDICT_SUSPICIOUS
            res.note = f"{susp} suspicious / {total}"
        else:
            res.verdict = VERDICT_CLEAN
            res.note = f"0/{total} engines"
        return res


class HybridAnalysis(Source):
    name = "hybridanalysis"
    display = "Hybrid Analysis"
    env_key = "HA_API_KEY"
    homepage = "https://www.hybrid-analysis.com/"

    def lookup(self, ht: "HashTarget") -> SourceResult:
        res = SourceResult(source=self.name)
        h = ht.hashes.get("sha256") or ht.preferred()
        headers = {"api-key": self.key() or "",
                   "User-Agent": "Falcon Sandbox"}
        url = f"https://www.hybrid-analysis.com/api/v2/search/hash"
        try:
            r = _session().post(url, data={"hash": h}, headers=headers,
                                timeout=DEFAULT_TIMEOUT)
        except requests.RequestException as e:
            return dataclasses.replace(res, status="error", note=str(e))
        if r.status_code in (401, 403):
            return dataclasses.replace(res, status="unauthorized",
                                      note="invalid API key")
        if r.status_code != 200:
            return dataclasses.replace(
                res, status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return dataclasses.replace(res, status="error", note="bad JSON")
        if not data:
            return dataclasses.replace(res, status="not_found")
        entry = data[0] if isinstance(data, list) else data
        res.status = "found"
        verdict_raw = (entry.get("verdict") or "").lower()
        threat_score = entry.get("threat_score") or 0
        res.detail = {
            "verdict": entry.get("verdict"),
            "threat_score": threat_score,
            "vx_family": entry.get("vx_family"),
            "av_detect": entry.get("av_detect"),
        }
        res.link = f"https://www.hybrid-analysis.com/search?query={h}"
        if verdict_raw in ("malicious", "suspicious") or (threat_score or 0) >= 50:
            res.verdict = (VERDICT_MALICIOUS if verdict_raw == "malicious"
                           or (threat_score or 0) >= 75 else VERDICT_SUSPICIOUS)
            res.note = f"{entry.get('verdict')} (score {threat_score})"
        else:
            res.verdict = VERDICT_UNKNOWN
            res.note = str(entry.get("verdict") or "no verdict")
        return res


class MalShare(Source):
    name = "malshare"
    display = "MalShare"
    env_key = "MALSHARE_API_KEY"
    homepage = "https://malshare.com/"

    def lookup(self, ht: "HashTarget") -> SourceResult:
        res = SourceResult(source=self.name)
        h = ht.preferred()
        params = {"api_key": self.key(), "action": "getdetails", "hash": h}
        try:
            r = _session().get("https://malshare.com/api.php", params=params,
                               timeout=DEFAULT_TIMEOUT)
        except requests.RequestException as e:
            return dataclasses.replace(res, status="error", note=str(e))
        if r.status_code == 403:
            return dataclasses.replace(res, status="unauthorized",
                                      note="invalid API key")
        if r.status_code != 200:
            return dataclasses.replace(
                res, status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return dataclasses.replace(res, status="not_found")
        if not data or (isinstance(data, dict) and data.get("ERROR")):
            return dataclasses.replace(res, status="not_found")
        res.status = "found"
        res.verdict = VERDICT_MALICIOUS
        entry = data[0] if isinstance(data, list) else data
        res.detail = {
            "type": entry.get("F_TYPE"),
            "sources": entry.get("SOURCES"),
            "sha256": entry.get("SHA256"),
        }
        res.note = "sample in MalShare"
        res.link = f"https://malshare.com/sample.php?action=detail&hash={h}"
        return res


class Triage(Source):
    name = "triage"
    display = "Hatching Triage"
    env_key = "TRIAGE_API_KEY"
    homepage = "https://tria.ge/"

    def lookup(self, ht: "HashTarget") -> SourceResult:
        res = SourceResult(source=self.name)
        h = ht.hashes.get("sha256") or ht.preferred()
        headers = {"Authorization": f"Bearer {self.key()}"}
        url = f"https://tria.ge/api/v0/search?query=sha256:{h}"
        try:
            r = _session().get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        except requests.RequestException as e:
            return dataclasses.replace(res, status="error", note=str(e))
        if r.status_code in (401, 403):
            return dataclasses.replace(res, status="unauthorized",
                                      note="invalid API key")
        if r.status_code != 200:
            return dataclasses.replace(
                res, status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return dataclasses.replace(res, status="error", note="bad JSON")
        entries = data.get("data") or []
        if not entries:
            return dataclasses.replace(res, status="not_found")
        entry = entries[0]
        res.status = "found"
        analysis = entry.get("analysis") or {}
        score = analysis.get("score")
        res.detail = {"status": entry.get("status"), "score": score,
                      "tags": entry.get("tags"), "sample_id": entry.get("id")}
        res.link = f"https://tria.ge/{entry.get('id')}"
        if analysis.get("verdict") and str(analysis.get("verdict")).lower() != "benign":
            res.verdict = VERDICT_MALICIOUS
            res.note = f"Triage verdict: {analysis.get('verdict')}"
        elif score is not None:
            try:
                score = float(score)
                res.verdict = (VERDICT_MALICIOUS if score >= 7 else
                               VERDICT_SUSPICIOUS if score >= 4 else VERDICT_CLEAN)
                res.note = f"Triage score {score}/10"
            except (TypeError, ValueError):
                res.verdict = VERDICT_UNKNOWN
        else:
            res.verdict = VERDICT_UNKNOWN
        return res


ALL_SOURCES: List[Source] = [
    CIRCLHashlookup(),
    AlienVaultOTX(),
    MalwareBazaar(),
    ThreatFox(),
    URLhaus(),
    VirusTotal(),
    HybridAnalysis(),
    MalShare(),
    Triage(),
]


# --------------------------------------------------------------------------
# Target wrapper
# --------------------------------------------------------------------------

class HashTarget:
    def __init__(self, hashes: Dict[str, str], original: str):
        self.hashes = {k: v for k, v in hashes.items() if v}
        self.original = original

    def preferred(self) -> str:
        return (self.hashes.get("sha256") or self.hashes.get("sha1")
                or self.hashes.get("md5") or self.original.lower())


# --------------------------------------------------------------------------
# Local cache + custom database (SQLite)
# --------------------------------------------------------------------------

class Store:
    def __init__(self, path: Optional[Path] = None):
        self.path = path or self._default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init()

    @staticmethod
    def _default_path() -> Path:
        override = os.environ.get("TT_CACHE_DB")
        if override:
            return Path(override)
        return Path.home() / ".threattrove" / "cache.db"

    def _init(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cache (
                hash TEXT NOT NULL,
                source TEXT NOT NULL,
                payload TEXT NOT NULL,
                fetched_at REAL NOT NULL,
                PRIMARY KEY (hash, source)
            );
            CREATE TABLE IF NOT EXISTS local (
                hash TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                note TEXT,
                added_at REAL NOT NULL
            );
            """
        )
        self.conn.commit()

    def get_cached(self, h: str, source: str) -> Optional[SourceResult]:
        with self._lock:
            row = self.conn.execute(
                "SELECT payload, fetched_at FROM cache WHERE hash=? AND source=?",
                (h, source),
            ).fetchone()
        if not row:
            return None
        payload, fetched_at = row
        if time.time() - fetched_at > CACHE_TTL_SECONDS:
            return None
        try:
            d = json.loads(payload)
            return SourceResult(**d)
        except (ValueError, TypeError):
            return None

    def put_cached(self, h: str, res: SourceResult) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO cache (hash, source, payload, fetched_at)"
                " VALUES (?,?,?,?)",
                (h, res.source, json.dumps(dataclasses.asdict(res)), time.time()),
            )
            self.conn.commit()

    def get_local(self, h: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT label, note, added_at FROM local WHERE hash=?",
            (h.lower(),),
        ).fetchone()
        if not row:
            return None
        return {"label": row[0], "note": row[1], "added_at": row[2]}

    def add_local(self, h: str, label: str, note: str = "") -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO local (hash, label, note, added_at)"
            " VALUES (?,?,?,?)",
            (h.lower(), label, note, time.time()),
        )
        self.conn.commit()

    def list_local(self) -> List[tuple]:
        return self.conn.execute(
            "SELECT hash, label, note, added_at FROM local ORDER BY added_at DESC"
        ).fetchall()


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

class Engine:
    def __init__(self, sources: List[Source], store: Optional[Store],
                 use_cache: bool = True):
        self.sources = sources
        self.store = store
        self.use_cache = use_cache

    def lookup(self, ht: HashTarget) -> HashReport:
        report = HashReport(query=ht.original, hash_type=hash_type(ht.original)
                            or "sha256")
        h = ht.preferred()

        # Local custom entries take precedence and short-circuit.
        if self.store:
            loc = self.store.get_local(h)
            if loc:
                report.results.append(SourceResult(
                    source="local-db", status="found",
                    verdict=(VERDICT_MALICIOUS if loc["label"].lower() in
                             ("malware", "malicious") else
                             VERDICT_KNOWN_GOOD if loc["label"].lower() in
                             ("clean", "good", "whitelist") else VERDICT_UNKNOWN),
                    note=f"{loc['label']} - {loc['note'] or ''}".strip(" -"),
                    link="local",
                ))

        active = [s for s in self.sources if s.available()]
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            futures = {ex.submit(self._one, s, ht): s for s in active}
            for fut in concurrent.futures.as_completed(futures):
                s = futures[fut]
                try:
                    report.results.append(fut.result())
                except Exception as e:  # noqa: BLE001
                    report.results.append(SourceResult(
                        source=s.name, status="error", note=f"unhandled: {e}"))

        # keep deterministic ordering
        order = {s.name: i for i, s in enumerate(ALL_SOURCES)}
        report.results.sort(key=lambda r: order.get(r.source, 999))
        report.cached_at = time.time()
        return report

    def _one(self, source: Source, ht: HashTarget) -> SourceResult:
        h = ht.preferred()
        if self.store and self.use_cache:
            cached = self.store.get_cached(h, source.name)
            if cached:
                cached.detail = dict(cached.detail)
                cached.detail["_cached"] = True
                return cached
        res = source.lookup(ht)
        if self.store and res.status in ("found", "not_found"):
            self.store.put_cached(h, res)
        return res


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

_VERDICT_STYLE = {
    VERDICT_MALICIOUS: (C_RED, "MALICIOUS"),
    VERDICT_SUSPICIOUS: (C_YELLOW, "SUSPICIOUS"),
    VERDICT_CLEAN: (C_GREEN, "CLEAN"),
    VERDICT_KNOWN_GOOD: (C_GREEN, "KNOWN-GOOD"),
    VERDICT_UNKNOWN: (C_DIM, "UNKNOWN"),
    VERDICT_ERROR: (C_DIM, "ERROR"),
    VERDICT_SKIPPED: (C_DIM, "SKIPPED"),
}


def render_text(report: HashReport) -> str:
    out: List[str] = []
    v = report.verdict()
    style, label = _VERDICT_STYLE.get(v, (C_DIM, v.upper()))
    out.append("")
    out.append(color(f"  Hash    : {report.query}", C_BOLD))
    out.append(f"  Type    : {report.hash_type}")
    out.append(color(f"  Verdict : {label}", style + C_BOLD)
               + color(f"   (confidence {report.confidence()}%)", C_DIM))
    out.append("")
    header = f"  {'SOURCE':<22} {'STATUS':<12} {'VERDICT':<12} DETAIL"
    out.append(color(header, C_BOLD))
    out.append(color("  " + "-" * 78, C_DIM))
    for r in report.results:
        _, vlabel = _VERDICT_STYLE.get(r.verdict, (C_DIM, r.verdict))
        vstyle, _ = _VERDICT_STYLE.get(r.verdict, (C_DIM, r.verdict))
        det = r.note or ""
        if r.detections and r.total:
            det = f"{r.detections}/{r.total} - {det}"
        cached = " [cached]" if r.detail.get("_cached") else ""
        out.append(
            f"  {r.source:<22} {r.status:<12} "
            + color(f"{vlabel:<12}", vstyle) + f" {det}{cached}"
        )
    return "\n".join(out)


def report_to_dict(report: HashReport) -> Dict[str, Any]:
    return {
        "query": report.query,
        "hash_type": report.hash_type,
        "verdict": report.verdict(),
        "confidence": report.confidence(),
        "sources": [
            {
                "source": r.source,
                "status": r.status,
                "verdict": r.verdict,
                "detections": r.detections,
                "total": r.total,
                "note": r.note,
                "link": r.link,
                "detail": r.detail,
            }
            for r in report.results
        ],
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threattrove",
        description="Multi-source file-hash reputation lookup (VirusTotal alternative).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("hashes", nargs="*", help="hash value(s) (md5/sha1/sha256)")
    p.add_argument("--file", "-f", action="append", default=[],
                   metavar="PATH", help="compute hashes of a file and look it up")
    p.add_argument("--json", "-j", action="store_true", help="emit JSON")
    p.add_argument("--sources", metavar="LIST",
                   help="comma-separated subset of sources to query")
    p.add_argument("--list-sources", action="store_true",
                   help="show configured sources and key status")
    p.add_argument("--no-cache", action="store_true",
                   help="bypass the local cache")
    p.add_argument("--add-local", metavar="HASH",
                   help="add a hash to the local custom database")
    p.add_argument("--label", default="malware",
                   help="label for --add-local (malware|clean|<custom>)")
    p.add_argument("--note", default="", help="note for --add-local")
    p.add_argument("--list-local", action="store_true",
                   help="list entries in the local database")
    p.add_argument("--version", "-V", action="version",
                   version=f"threattrove {VERSION}")
    return p


def cmd_list_sources() -> int:
    print(color(f"\n  threattrove {VERSION} - configured sources\n", C_BOLD))
    print(f"  {'NAME':<16} {'REQUIRED KEY':<18} {'STATUS':<12} HOME")
    print(color("  " + "-" * 78, C_DIM))
    for s in ALL_SOURCES:
        key_name = s.env_key or "(none - keyless)"
        if s.available():
            status = color(f"{'ready':<12}", C_GREEN)
        else:
            status = color(f"{'no key':<12}", C_YELLOW)
        print(f"  {s.name:<16} {key_name:<18} {status} {s.homepage}")
    print()
    print(color("  Set a key to enable a source, e.g.:", C_DIM))
    print(color("    export ABUSECH_AUTH_KEY=...   # one key for the 3 abuse.ch APIs",
                C_DIM))
    print(color("    export VT_API_KEY=...", C_DIM))
    print()
    return 0


def _hash_targets(args) -> List[HashTarget]:
    targets: List[HashTarget] = []
    for h in args.hashes:
        hv = hash_type(h)
        if not hv:
            sys.stderr.write(f"warning: '{h}' is not a valid md5/sha1/sha256, skipping\n")
            continue
        targets.append(HashTarget({hv: h.strip().lower()}, h.strip().lower()))
    for f in args.file:
        p = Path(f)
        if not p.is_file():
            sys.stderr.write(f"warning: file not found: {f}\n")
            continue
        hd = hashes_for_file(p)
        targets.append(HashTarget(hd, hd["sha256"]))
    return targets


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.list_sources:
        return cmd_list_sources()

    store = Store()

    if args.list_local:
        rows = store.list_local()
        if not rows:
            print("Local database is empty.")
            return 0
        print(color(f"\n  {len(rows)} local entr(ies):\n", C_BOLD))
        for h, label, note, ts in rows:
            when = _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
            print(f"  {h}  {label:<10} {when}  {note}")
        print()
        return 0

    if args.add_local:
        hv = hash_type(args.add_local)
        if not hv:
            sys.stderr.write("error: --add-local expects a valid md5/sha1/sha256\n")
            return 2
        store.add_local(args.add_local, args.label, args.note)
        print(f"Added {args.add_local} as '{args.label}' to the local database.")
        return 0

    targets = _hash_targets(args)
    if not targets:
        _build_parser().print_help()
        return 2

    sources = ALL_SOURCES
    if args.sources:
        wanted = {s.strip().lower() for s in args.sources.split(",")}
        sources = [s for s in ALL_SOURCES if s.name in wanted]
        if not sources:
            sys.stderr.write("error: no matching sources\n")
            return 2

    engine = Engine(sources, store, use_cache=not args.no_cache)
    reports = [engine.lookup(t) for t in targets]

    if args.json:
        payload = report_to_dict(reports[0]) if len(reports) == 1 \
            else [report_to_dict(r) for r in reports]
        print(json.dumps(payload, indent=2, default=str))
    else:
        for r in reports:
            print(render_text(r))
        print()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
