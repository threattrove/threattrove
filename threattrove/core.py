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

VERSION = "2.9.4"

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

#: Rows that come from the same authority are one opinion, however many rows
#: there are. Two VirusTotal or Hybrid Analysis panels reading the same vendor
#: corpus can agree all day without telling you more than one panel did, and
#: URLhaus answering for a payload and for a URL is one feed answering twice.
#: Corroboration therefore counts authorities, not rows: ``MIN_CORROBORATION``
#: authorities must name the indicator malicious before it is reported so.
ENGINE_PANEL_AUTHORITY = "engine-panel"

AUTHORITY_ALIASES: Dict[str, str] = {
    "virustotal": ENGINE_PANEL_AUTHORITY,
    "virustotal_url": ENGINE_PANEL_AUTHORITY,
    "virustotal_domain": ENGINE_PANEL_AUTHORITY,
    "hybridanalysis": ENGINE_PANEL_AUTHORITY,
    "triage": ENGINE_PANEL_AUTHORITY,
    # MetaDefender is a second engine panel, not a second authority: its URL,
    # domain and IP endpoints are the same vendor's sensors reporting on a
    # different object. Two panels are two opinions; two endpoints of one panel
    # are one opinion repeated, so they all collapse onto the same authority.
    "metadefender": ENGINE_PANEL_AUTHORITY,
    "metadefender_url": ENGINE_PANEL_AUTHORITY,
    "metadefender_domain": ENGINE_PANEL_AUTHORITY,
    "urlhaus": "urlhaus",
    "urlhaus_url": "urlhaus",
    "otx": "otx",
    "otx_url": "otx",
    "otx_domain": "otx",
}


def evidence_authority(source: str) -> str:
    """The authority behind a source row: who is actually making the claim.

    Rows published by one provider for different indicator kinds, or by one
    engine panel, collapse onto a single authority. Anything not listed stands
    for itself.
    """
    if source in ENGINE_SOURCES:
        return ENGINE_PANEL_AUTHORITY
    return AUTHORITY_ALIASES.get(source, source)

#: Sources whose "malicious" verdict means the file itself was examined: a
#: sample repository that has the artifact, an engine scan, a sandbox run, or a
#: local analyst. Feeds that record where a copy was *served from* (URLhaus,
#: ThreatFox) and analyst chatter (OTX) describe distribution, not the file, and
#: routinely accuse genuine vendor software that attackers re-hosted. They can
#: corroborate, but they cannot convict on their own.
DIRECT_SOURCES = frozenset({"malwarebazaar", "virustotal", "hybridanalysis",
                            "triage", "malshare", "local", "metadefender"})

#: family labels that name a category rather than a specific family. They are
#: dropped from ``families()`` so a headline never reads "(Malware)".
GENERIC_FAMILY_LABELS = frozenset({
    "malware", "malicious", "virus", "trojan", "worm", "backdoor",
    "dropper", "downloader", "ransomware", "stealer", "infostealer",
    "spyware", "adware", "pup", "pua", "riskware", "rootkit", "keylogger",
    "miner", "coinminer", "exploit", "phishing", "crimeware", "hacktool",
    "generic", "heuristic", "heur", "unknown", "unclassified", "other",
    "none", "n/a", "na", "bad",
})

#: confidence ceiling for a malicious consensus that no source examined
CAMPAIGN_ONLY_CONFIDENCE = 45

#: Sources whose ``x/y engines`` figure comes from antivirus engines that
#: actually scanned the artifact. OTX also reports an engine count, but it is
#: derived from community analysis, so it can corroborate without voting here.
ENGINE_SOURCES = frozenset({"virustotal", "hybridanalysis", "triage",
                           "metadefender"})

#: how many engine slots must have reported a clean sweep before that sweep is
#: allowed to overrule heuristic flags
ENGINE_CLEARANCE_MIN = 2

#: confidence for a file the engines cleared while heuristics kept flagging it
ENGINE_CLEARED_CONFIDENCE = 35

#: floor for a verdict that rests on the operator's own corpus, which is a
#: first-hand decision rather than an unconfirmed feed hit
LOCAL_TRUST_CONFIDENCE = 70

#: confidence granted by N corroborating sources (5 or more -> MAX)
CORROBORATION_CONFIDENCE = {1: 45, 2: 75, 3: 88, 4: 93}
CORROBORATION_CONFIDENCE_MAX = 96
CONFIDENCE_CAP = 98
SUSPICIOUS_CONFIDENCE = 60

#: words in a source's error note that mean the provider's daily allowance is
#: gone, not that one request came too soon. Only these stop a source for the
#: rest of the day; a plain per-minute 429 keeps being retried.
QUOTA_EXHAUSTED_MARKERS = (
    "daily quota", "quota exceeded", "quota exhausted", "daily limit",
    "50/day", "per day",
)


def _truthy(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _utc_day(ts: Optional[float] = None) -> str:
    """The UTC calendar day a quota counter belongs to (``YYYY-MM-DD``).

    A UTC day is used because every provider resets its free allowance on its
    own midnight, and the attribution is used for budgeting rather than
    billing.
    """
    return time.strftime("%Y-%m-%d", time.gmtime(time.time() if ts is None else ts))


def quota_exhausted_note(note: Optional[str]) -> bool:
    """True when an error note says the provider's daily quota ran out."""
    text = str(note or "").lower()
    return any(marker in text for marker in QUOTA_EXHAUSTED_MARKERS)


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
      "hybridanalysis", "triage", "metadefender", "metadefender_url",
      "metadefender_domain")),
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
# Defanging ("hxxp://evil[.]com")
# --------------------------------------------------------------------------

#: zero-width / soft-hyphen junk that survives paste from chat, PDF and email
_INVISIBLE_RE = re.compile("[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad]")

#: ordered rewrites; the scheme rule runs last so "hxxp[://]" works in one pass
_REFANG_SUBSTS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"\[\s*\.\s*\]|\[\s*dot\s*\]|\(\s*\.\s*\)|\(\s*dot\s*\)"
                r"|\{\s*\.\s*\}|<\s*dot\s*>|(?<=\w)\s+dot\s+(?=\w)", re.I), "."),
    (re.compile(r"\[\s*:\s*\]|\[\s*colon\s*\]|\(\s*:\s*\)", re.I), ":"),
    (re.compile(r"\[\s*/\s*\]|\(\s*/\s*\)|\[\s*slash\s*\]", re.I), "/"),
    (re.compile(r"\[\s*@\s*\]|\[\s*at\s*\]|\(\s*@\s*\)|\(\s*at\s*\)", re.I), "@"),
    (re.compile(r"\[\s*_\s*\]", re.I), "_"),
)
_REFANG_SCHEME_RE = re.compile(r"\bh(?:xx|\*\*)(p|ps)\b", re.I)


_DEFANG_SCHEME_RE = re.compile(r"^(https?)://", re.I)


def defang(value: str) -> str:
    """Render an indicator so it is safe to paste into chat, mail or a ticket.

    ``http://evil.com/x`` becomes ``hxxp://evil[.]com/x``. Used for share cards
    and anything the operator is likely to forward.
    """
    if not value:
        return ""
    out, scheme = value, ""
    m = _DEFANG_SCHEME_RE.match(out)
    if m:
        scheme = "hxxps://" if m.group(1).lower() == "https" else "hxxp://"
        out = out[m.end():]
    return scheme + out.replace(".", "[.]")


def refang(text: str) -> str:
    """Undo indicator defanging so analysts can paste what they actually have.

    Handles ``hxxp``/``hxxps``, ``[.]``, ``(.)``, ``[dot]``, ``evil dot com``,
    ``[:]``, ``[at]`` and zero-width characters. Idempotent and safe on plain
    text: nothing here can turn a non-indicator into one.
    """
    if not text:
        return ""
    out = _INVISIBLE_RE.sub("", text)
    for pattern, repl in _REFANG_SUBSTS:
        out = pattern.sub(repl, out)
    return _REFANG_SCHEME_RE.sub(
        lambda m: "https" if m.group(1).lower() == "ps" else "http", out)


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

    normalised = refang(raw)
    if normalised != raw:
        ind = parse_indicator(normalised)
        if ind is not None:
            ind.raw = raw          # keep what the user actually typed
        return ind

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


#: bodies of pasted reports: pull the indicators out of the sentences
_PROSE_URL_RE = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s<>\"')\]}]+", re.I)
_PROSE_HASH_RE = re.compile(
    r"(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])", re.I)
_PROSE_IPV4_RE = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d)")
_PROSE_DOMAIN_RE = re.compile(
    r"(?<![\w.\-])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![a-z0-9\-])",
    re.I)

#: "report.pdf" in prose is a file name, not a domain
_FILE_SUFFIXES = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "json",
    "csv", "exe", "dll", "sys", "dat", "log", "png", "jpg", "jpeg", "gif",
    "svg", "html", "htm", "php", "asp", "aspx", "ps1", "bat", "cmd", "vbs",
    "jar", "msi", "iso", "rtf", "md", "bak", "tmp",
}


def extract_indicators(text: str, limit: int = 200) -> List[Indicator]:
    """Pull every indicator out of prose: an email body, ticket or report.

    Refangs first, so a defanged paste works as well as a live one. Hosts that
    a URL already covers are not emitted a second time, so the number of
    lookups stays close to the number of distinct indicators.
    """
    if not text:
        return []
    body = refang(text)
    out: List[Indicator] = []
    seen = set()
    covered = set()

    def add(ind: Optional[Indicator]) -> None:
        if ind is None:
            return
        key = (ind.kind, ind.value)
        if key in seen:
            return
        seen.add(key)
        out.append(ind)

    for m in _PROSE_URL_RE.finditer(body):
        ind = parse_indicator(m.group(0).rstrip(".,;:!?'\""))
        if ind is not None and ind.kind == KIND_URL:
            add(ind)
            if ind.host:
                covered.add(ind.host.lower())
            if ind.domain:
                covered.add(ind.domain.lower())

    for m in _PROSE_HASH_RE.finditer(body):
        add(parse_indicator(m.group(0)))

    for m in _PROSE_IPV4_RE.finditer(body):
        # a sentence period is not part of the address
        add(parse_indicator(m.group(0).rstrip(".")))

    for m in _PROSE_DOMAIN_RE.finditer(body):
        host = m.group(0).lower().rstrip(".")
        if host.rsplit(".", 1)[-1] in _FILE_SUFFIXES:
            continue
        if host in covered or registrable_domain(host) in covered:
            continue
        add(parse_indicator(host))
        if len(out) >= limit:
            break

    return out[:limit]


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
        """Aggregate verdict, requiring one direct look at the file to convict.

        Malicious needs a direct determination and suspicious needs something
        that survived the engines: heuristic scores and community chatter about
        genuine vendor software are the classic false-positive pair, and an
        engine sweep that found nothing outranks both.
        """
        verdict = combine(self._weights())[0]
        if self.trusted_determination() and verdict in (VERDICT_SUSPICIOUS,
                                                        VERDICT_MALICIOUS):
            return VERDICT_MALICIOUS
        if (verdict == VERDICT_MALICIOUS
                and self.corroboration() < MIN_CORROBORATION):
            # Two rows from one authority are one opinion, however loud: a
            # second engine panel or a feed's own second endpoint does not
            # turn a lone hit into a conviction.
            return VERDICT_SUSPICIOUS
        if verdict == VERDICT_MALICIOUS and not self.direct_evidence():
            return VERDICT_SUSPICIOUS
        if (verdict == VERDICT_SUSPICIOUS and not self.has_malicious()
                and self.engine_cleared()):
            return VERDICT_CLEAN
        return verdict

    def confidence(self) -> int:
        verdict, confidence = combine(self._weights())
        if self.trusted_determination():
            return max(confidence, LOCAL_TRUST_CONFIDENCE)
        if verdict == VERDICT_MALICIOUS and not self.direct_evidence():
            return min(confidence, CAMPAIGN_ONLY_CONFIDENCE)
        if (verdict == VERDICT_SUSPICIOUS and not self.has_malicious()
                and self.engine_cleared()):
            return min(confidence, ENGINE_CLEARED_CONFIDENCE)
        return confidence

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
        """How many independent authorities list this indicator as malicious.

        Rows are collapsed onto the authority that published them, so a panel
        that answers for two endpoints, or a feed that answers for both a
        payload and a URL, counts once. Agreement between two rows of the same
        authority is one opinion repeated, not corroboration.
        """
        return len({evidence_authority(r.source) for r in self.results
                    if r.category == "reputation"
                    and r.status in SCORED_STATUSES
                    and r.verdict == VERDICT_MALICIOUS})

    def corroboration_classes(self) -> int:
        """How many evidence classes carry a malicious vote."""
        return len({evidence_class(r.source)[0] for r in self.results
                    if r.category == "reputation"
                    and r.status in SCORED_STATUSES
                    and r.verdict == VERDICT_MALICIOUS})

    def direct_evidence(self) -> List[str]:
        """Sources that examined the file itself and called it malicious."""
        return sorted({r.source for r in self.results
                       if r.category == "reputation"
                       and r.status in SCORED_STATUSES
                       and r.verdict == VERDICT_MALICIOUS
                       and r.source in DIRECT_SOURCES})

    def campaign_only(self) -> bool:
        """True when a malicious consensus rests purely on distribution data."""
        return (self.corroboration() >= MIN_CORROBORATION
                and not self.direct_evidence())

    def trusted_determination(self) -> bool:
        """True when the operator's own corpus lists this as malicious.

        A local row is a decision this instance's owner made about this exact
        file, not a third-party feed's guess, so it does not need a second
        source to corroborate it. An allowlist conflict still wins.
        """
        return any(r.source == "local" and r.status in SCORED_STATUSES
                   and r.verdict == VERDICT_MALICIOUS for r in self.results)

    def has_malicious(self) -> bool:
        """True when any source lists this indicator as malicious."""
        return any(r.verdict == VERDICT_MALICIOUS for r in self.results)

    def engine_cleared(self) -> bool:
        """True when every antivirus engine that scanned the file missed it.

        Only real scan results count (``ENGINE_SOURCES``), and every one of
        them must report zero detections over at least ``ENGINE_CLEARANCE_MIN``
        engine slots. This is the veto for heuristic-only suspicion: a sandbox
        score or a pulse says how a file behaved, an engine sweep says what the
        file is.
        """
        scans = [r for r in self.results
                 if r.source in ENGINE_SOURCES
                 and r.status in SCORED_STATUSES
                 and r.total and (r.detail or {}).get("engines")]
        if not scans:
            return False
        # A lone vendor flagging a file out of ninety is noise, not a detection,
        # and must not stop the rest of the sweep from clearing the file.
        noisy = any(r.detections and not (r.detail or {}).get("low_signal")
                    for r in scans)
        if noisy:
            return False
        return sum(r.total for r in scans) >= ENGINE_CLEARANCE_MIN

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
                key = label.lower().strip(".! ")
                if not label or key in seen or key in GENERIC_FAMILY_LABELS:
                    continue
                if len(label) < 3 or not any(c.isalpha() for c in label):
                    continue
                seen.add(key)
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

    # -- explanation ------------------------------------------------------
    def _derived(self, add: Sequence[SourceResult] = (),
                 drop: Sequence[str] = ()) -> "Report":
        """A copy of this report with some sources dropped or a result added.

        Exists so the "what would change it" lines can be produced by running
        ``verdict`` and ``confidence`` over a hypothetical result set, instead
        of restating what those rules are believed to do. If the rules change,
        the explanation changes with them.
        """
        kept = [r for r in self.results if r.source not in drop]
        return dataclasses.replace(self, results=kept + list(add))

    @staticmethod
    def _labels() -> Dict[str, str]:
        """Pretty source names, read from the source registry."""
        try:
            from .sources import SOURCE_MAP
        except Exception:                      # pragma: no cover
            return {}
        # Drop the operator suffix ("MalwareBazaar (abuse.ch)") so a pivot line
        # stays readable inside a sentence.
        return {name: str(getattr(src, "display", name)).split(" (")[0]
                for name, src in SOURCE_MAP.items()}

    def _untried(self) -> List[Tuple[str, str]]:
        """Reputation sources that could still answer for this indicator.

        Taken from the registry rather than a fixed list, so a domain lookup is
        never told to consult a hash-only sample repository, and a deployment
        without the key for a source is never given advice it cannot follow.
        """
        try:
            from .sources import SOURCE_MAP
        except Exception:                      # pragma: no cover
            return [(n, n) for n in sorted(DIRECT_SOURCES)]
        present = {r.source for r in self.results}
        out: List[Tuple[str, str]] = []
        for name, src in SOURCE_MAP.items():
            if name in present or src.category != "reputation":
                continue
            if self.indicator.kind not in getattr(src, "kinds", ()):
                continue
            if not getattr(src, "available", lambda: True)():
                continue
            out.append((name, str(getattr(src, "display", name)).split(" (")[0]))
        out.sort(key=lambda pair: (pair[0] not in DIRECT_SOURCES, pair[0]))
        return out

    def decision(self) -> Dict[str, Any]:
        """The argument behind the verdict, and what would overturn it.

        Three parts: the evidence classes that actually carried weight, the
        counterfactuals that would flip the result, and any structural caveat
        (distribution-only evidence, an engine sweep that found nothing, the
        operator's own corpus deciding it).
        """
        verdict = self.verdict()
        confidence = self.confidence()

        classes = [tuple(c[:3]) for c in EVIDENCE_CLASSES] + [EVIDENCE_OTHER]
        rows: List[Dict[str, Any]] = []
        for key, label, description in classes:
            members = [r for r in self.results
                       if r.category == "reputation"
                       and r.status in SCORED_STATUSES
                       and evidence_class(r.source)[0] == key]
            if not members:
                continue
            weight = sum(VERDICT_WEIGHT.get(r.verdict, 0) for r in members)
            flagged = sum(1 for r in members
                          if r.verdict in (VERDICT_MALICIOUS,
                                           VERDICT_SUSPICIOUS))
            rows.append({
                "key": key,
                "label": label,
                "description": description,
                "answered": len(members),
                "flagged": flagged,
                "weight": weight,
                "verdicts": [{"name": r.source, "verdict": r.verdict}
                             for r in members],
            })

        # What carried the verdict comes first; classes that abstained last.
        rows.sort(key=lambda row: (-row["flagged"], -abs(row["weight"]),
                                   row["label"]))
        peak = max((abs(row["weight"]) for row in rows), default=0) or 1
        for row in rows:
            row["width"] = max(3, round(100 * abs(row["weight"]) / peak))
            row["tone"] = ("bad" if row["weight"] > 0
                           else "good" if row["weight"] < 0 else "muted")

        pivots: List[Dict[str, Any]] = []
        labels = self._labels()

        # Dropping a source that voted malicious shows what the verdict leans on.
        losses: List[Dict[str, Any]] = []
        voters = sorted({r.source for r in self.results
                         if r.category == "reputation"
                         and r.status in SCORED_STATUSES
                         and r.verdict == VERDICT_MALICIOUS
                         and r.source != "local"})
        for src in voters:
            hyp = self._derived(drop=[src])
            hv, hc = hyp.verdict(), hyp.confidence()
            # A source that was holding the verdict up is worth naming even
            # when the verdict survives it: the confidence it was buying is
            # the part of the argument a reader cannot see.
            if hv == verdict and confidence - hc < 5:
                continue
            losses.append({"kind": "without", "source": src,
                           "label": f"If {labels.get(src, src)} had missed it",
                           "verdict": hv, "confidence": hc,
                           "changed": hv != verdict})
        losses.sort(key=lambda p: (not p["changed"], p["confidence"]))
        # Two feeds that prop the verdict up identically teach one lesson, so
        # they share a line: "If X or Y had missed it".
        grouped: List[Dict[str, Any]] = []
        index: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        for item in losses:
            key = (item["changed"], item["verdict"], item["confidence"])
            if key in index:
                slot = index[key]
                if len(slot["names"]) < 2:
                    slot["names"].append(item["label"])
                continue
            slot = dict(item, names=[item["label"]])
            index[key] = slot
            grouped.append(slot)
        for slot in grouped[:2]:
            joined = " or ".join(n[len("If "):-len(" had missed it")]
                               for n in slot["names"])
            pivots.append({"kind": slot["kind"], "source": slot["source"],
                           "label": f"If {joined} had missed it",
                           "verdict": slot["verdict"],
                           "confidence": slot["confidence"]})

        # What would raise it: one more source agreeing on the indicator.
        if verdict in (VERDICT_SUSPICIOUS, VERDICT_UNKNOWN, VERDICT_CLEAN):
            best: Optional[Tuple[str, str, int]] = None
            for cand, display in self._untried()[:14]:
                hyp = self._derived(add=[SourceResult(
                    source=cand, status="found", category="reputation",
                    verdict=VERDICT_MALICIOUS, note="hypothetical")])
                hv, hc = hyp.verdict(), hyp.confidence()
                if hv == VERDICT_MALICIOUS and (best is None or hc > best[2]):
                    best = (cand, display, hc)
            if best is not None:
                pivots.append({"kind": "with", "source": best[0],
                               "label": f"If {best[1]} flagged it too",
                               "verdict": VERDICT_MALICIOUS,
                               "confidence": best[2]})

        # The operator's own corpus outranks every feed; show what that does.
        has_local = any(r.source == "local" for r in self.results)
        if not has_local and verdict in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS):
            hyp = self._derived(add=[SourceResult(
                source="local", status="found", category="reputation",
                verdict=VERDICT_CLEAN, note="allowlisted")])
            hv, hc = hyp.verdict(), hyp.confidence()
            if hv != verdict:
                pivots.append({"kind": "own", "source": "local",
                               "label": "If you allowlist it",
                               "verdict": hv, "confidence": hc})

        insights: List[str] = []
        if (verdict == VERDICT_MALICIOUS and len(voters) > 1
                and not any(p["kind"] == "without" for p in pivots)):
            insights.append(f"No single source carries this: removing any one of "
                            f"the {len(voters)} would still convict.")
        direct = self.direct_evidence()
        if verdict == VERDICT_MALICIOUS and not direct:
            insights.append("No source examined the file itself; this rests on "
                            "where it was seen, not what it contains.")
        elif len(direct) == 1 and direct[0] != "local":
            insights.append(f"Only {labels.get(direct[0], direct[0])} examined "
                            "the file itself; the other sources know where it "
                            "was seen.")
        if verdict in (VERDICT_SUSPICIOUS, VERDICT_MALICIOUS) and self.engine_cleared():
            insights.append("The engines found nothing. The flags are "
                            "heuristic, which is the usual false-positive pair.")
        if (self.trusted_determination()
                and self.corroboration() < MIN_CORROBORATION):
            insights.append("Your local corpus is what makes this malicious; "
                            "no second source is required.")
        if self._conflict():
            insights.append("A feed and your allowlist both match this, so "
                            "ThreatTrove declines to average them.")
        if self.campaign_only() and verdict == VERDICT_SUSPICIOUS:
            insights.append("Nothing looked at the indicator itself, so "
                            "agreeing feeds remain a lead, not a conviction.")

        # Only classes that carried a malicious vote count toward the breadth
        # claim; a class that merely abstained or hedged did not agree to it.
        classes_hit = self.corroboration_classes()
        summary = {
            VERDICT_MALICIOUS: (
                f"{self.corroboration()} independent "
                f"{'authority' if self.corroboration() == 1 else 'authorities'} "
                f"across {classes_hit} evidence "
                f"class{'' if classes_hit == 1 else 'es'} agree it is malicious"
                if classes_hit else "Independent sources agree it is malicious"),
            VERDICT_SUSPICIOUS: "Flagged, but not enough to convict",
            VERDICT_CLEAN: "Nothing that answered found a problem",
            VERDICT_KNOWN_GOOD: "Matches a known-good record",
            VERDICT_UNKNOWN: "No source that answered could decide it",
        }.get(verdict, "No usable verdict")
        if (self.trusted_determination()
                and self.corroboration() < MIN_CORROBORATION):
            summary = ("Your own blocklist decides this on its own, without "
                       "asking another source to agree")

        return {"verdict": verdict, "confidence": confidence,
                "summary": summary, "rows": rows, "pivots": pivots,
                "insights": insights[:2]}

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
            if self.trusted_determination():
                text = "Listed in your local blocklist"
                other = sorted({r.source for r in self.results
                                if r.source != "local"
                                and r.status in SCORED_STATUSES
                                and r.verdict == VERDICT_MALICIOUS})
                if other:
                    text += f", also listed by {', '.join(other[:3])}"
                if det and tot:
                    text += f" ({det}/{tot} engines agree)"
            elif sources >= MIN_CORROBORATION:
                text = f"Listed as malicious by {sources} independent sources"
                if det and tot:
                    text += f", and {det}/{tot} engines agree"
            else:
                text = f"{det}/{tot} engines flagged this as malicious"
            if families:
                text += f" ({families[0]})"
            return text

        if verdict == VERDICT_SUSPICIOUS:
            if self.campaign_only():
                who = ", ".join(sorted({r.source for r in self.results
                                        if r.verdict == VERDICT_MALICIOUS}))
                text = (f"Listed in a malware campaign by {sources} sources "
                        f"({who}) but none examined the file")
                if tot and det == 0:
                    text += f" - {tot} engines found nothing"
                elif name:
                    text += f" - {name}"
                return text
            if sources == 1:
                who = next(iter({r.source for r in self.results
                                 if r.verdict == VERDICT_MALICIOUS}), "")
                where = f" ({who})" if who else ""
                return (f"Only 1 source lists this as malicious{where} - "
                        "a lead, not a conviction")
            flagged = sorted({r.source for r in self.results
                              if r.verdict == VERDICT_SUSPICIOUS})
            if len(flagged) == 1:
                return (f"Only 1 source flags this as suspicious "
                        f"({flagged[0]}) - unconfirmed")
            if flagged:
                return (f"{len(flagged)} sources flag this as suspicious "
                        f"({', '.join(flagged[:3])}) - no malware determination")
            return "Suspicious, but the evidence is thin"

        if verdict == VERDICT_KNOWN_GOOD:
            if name:
                text = f"Known good: {name}"
                if ident.get("product"):
                    text += f" ({ident['product']})"
                return text
            return "Matches a known-good record"

        if verdict == VERDICT_CLEAN:
            weak = sorted({r.source for r in self.results
                           if r.verdict in (VERDICT_SUSPICIOUS,
                                            VERDICT_MALICIOUS)})
            if weak and self.engine_cleared():
                return (f"0/{tot} engines flagged this - the flags from "
                        f"{', '.join(weak[:3])} are a weak lead, not a verdict")
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
            "direct_sources": self.direct_evidence(),
            "campaign_only": self.campaign_only(),
            "engine_cleared": self.engine_cleared(),
            "families": self.families(),
            "evidence": self.evidence(),
            "decision": self.decision(),
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

#: Health states a canary check can leave a source in.
HEALTH_OK = "ok"
HEALTH_WARN = "warn"
HEALTH_BAD = "bad"
#: Neither good nor bad: the source was not asked. Its allowance was spent, or
#: another endpoint of the same provider had just been called. A skip is a fact
#: about our budget and pacing, not about the source, so it is counted apart
#: from the answers and never decides the overall status.
HEALTH_SKIP = "skip"

#: Statuses in which a source answered the question it was asked. Anything
#: outside this set is either a failure (bad) or a check that never really ran
#: (warn), and the two must not be reported as the same thing.
ANSWERED_STATUSES = frozenset({"found", "not_found", "matched", "no_match"})
SKIPPED_STATUSES = frozenset({"skipped", "deferred", "quota"})
FAILED_STATUSES = frozenset({"error", "timeout", "unauthorized", "empty",
                             "blocked", "forbidden"})

#: Latency multiple over the source's baseline that is worth a warning.
HEALTH_DRIFT_LIMIT = 4.0


def health_state(status: str, drift: Optional[float] = None,
                 expected: str = "") -> str:
    """Classify one canary answer as ok, warn or bad.

    ``drift`` is the check's latency as a multiple of that source's baseline and
    ``expected`` is the status it answered with when it was last known healthy.

    The status comparison is the point of the whole exercise. Both silent
    breakages fixed in 2.6.0 and 2.7.0 returned HTTP 200 and a document that
    parsed to "not found": no error, no exception, just a different answer. A
    canary that only looks for failures would have called both of them healthy.
    """
    got = (status or "").strip().lower()
    if not got or got in FAILED_STATUSES:
        return HEALTH_BAD
    if got in SKIPPED_STATUSES:
        # not asked: the allowance was spent, or the provider was being paced,
        # so this says nothing either way about the source
        return HEALTH_SKIP
    if got not in ANSWERED_STATUSES:
        # an answer we cannot classify is worth a look, unlike a skip
        return HEALTH_WARN
    if expected and got != expected:
        return HEALTH_WARN
    if drift is not None and drift >= HEALTH_DRIFT_LIMIT:
        return HEALTH_WARN
    return HEALTH_OK


SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    kind          TEXT NOT NULL,
    value         TEXT NOT NULL,
    source        TEXT NOT NULL,
    payload       TEXT NOT NULL,
    fetched_at    REAL NOT NULL,
    logic_version INTEGER NOT NULL DEFAULT 0,
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
-- /local used to sort every row in this table on every page view because
-- nothing indexed added_at. It is paged now, and both orders have an index:
-- newest-first reads walk local_added, a filtered list seeks local_value.
CREATE INDEX IF NOT EXISTS local_added ON local(added_at DESC);
CREATE INDEX IF NOT EXISTS local_value ON local(value);
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
CREATE TABLE IF NOT EXISTS quota (
    quota     TEXT NOT NULL,
    day       TEXT NOT NULL,
    used      INTEGER NOT NULL DEFAULT 0,
    exhausted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (quota, day)
);
-- What the source-health canary last saw, one row per source. Kept apart from
-- the cache on purpose: a health row is an observation about the source, not a
-- verdict about a sample, and nothing in a lookup may ever read it.
CREATE TABLE IF NOT EXISTS source_health (
    source      TEXT PRIMARY KEY,
    kind        TEXT NOT NULL DEFAULT '',
    indicator   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT '',
    verdict     TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    latency_ms  INTEGER NOT NULL DEFAULT 0,
    checked_at  REAL NOT NULL DEFAULT 0,
    expected    TEXT NOT NULL DEFAULT '',
    baseline_ms REAL,
    baseline_at REAL,
    drift       REAL
);
"""


class Store:
    """SQLite-backed cache, custom local verdicts, lookup history and quotas."""

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
            self._migrate()
            self.conn.commit()

    def _migrate(self) -> None:
        """Bring a database written by an older version up to this schema.

        ``logic_version`` arrived in 2.1.7. Rows that predate it are given 0,
        which no source declares, so they are never served: an entry cached by
        an older parser may carry a verdict that logic has since corrected.
        They are replaced on the next lookup rather than deleted, so the cost is
        one re-fetch per indicator and the cache refills on its own.
        """
        cols = {row[1] for row in self.conn.execute("PRAGMA table_info(cache)")}
        if "logic_version" not in cols:
            self.conn.execute(
                "ALTER TABLE cache ADD COLUMN logic_version INTEGER NOT NULL"
                " DEFAULT 0")

    # -- cache -----------------------------------------------------------
    def get_cached(self, kind: str, value: str, source: str,
                   ttl: Optional[int] = None,
                   logic_version: int = 1) -> Optional[SourceResult]:
        """Return a cached result only if the source logic still matches.

        ``logic_version`` is the version of the code that produced the entry,
        as declared by the source. A mismatch means the parsing or verdict
        rules changed after the entry was written, so the entry is ignored and
        the source is queried again.
        """
        ttl = CACHE_TTL_SECONDS if ttl is None else ttl
        if ttl <= 0:
            return None
        with self._lock:
            row = self.conn.execute(
                "SELECT payload, fetched_at FROM cache"
                " WHERE kind=? AND value=? AND source=? AND logic_version=?",
                (kind, value, source, int(logic_version)),
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

    def put_cached(self, kind: str, value: str, res: SourceResult,
                   logic_version: int = 1) -> None:
        payload = json.dumps(dataclasses.asdict(res))
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO cache"
                " (kind, value, source, payload, fetched_at, logic_version)"
                " VALUES (?,?,?,?,?,?)",
                (kind, value, res.source, payload, time.time(),
                 int(logic_version)),
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

    # -- provider quotas --------------------------------------------------
    def quota_state(self, quota: str) -> Dict[str, Any]:
        """Today's usage for one provider quota."""
        day = _utc_day()
        with self._lock:
            row = self.conn.execute(
                "SELECT used, exhausted FROM quota WHERE quota=? AND day=?",
                (quota, day)).fetchone()
        used, exhausted = row if row else (0, 0)
        return {"quota": quota, "day": day, "used": int(used),
                "exhausted": bool(exhausted)}

    def take_quota(self, quota: str, limit: Optional[int]) -> bool:
        """Reserve one call against today's allowance for *quota*.

        Returns False when the allowance is spent or the provider already said
        no today, in which case the caller must not make the request. The
        increment happens before the call, in one guarded statement, so a
        crash mid-call can never let more requests through than the budget.
        """
        day = _utc_day()
        with self._lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO quota (quota, day, used, exhausted)"
                " VALUES (?,?,0,0)", (quota, day))
            sql = ("UPDATE quota SET used=used+1"
                   " WHERE quota=? AND day=? AND exhausted=0")
            params: List[Any] = [quota, day]
            if limit is not None:
                sql += " AND used<?"
                params.append(int(limit))
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur.rowcount > 0

    def exhaust_quota(self, quota: str, limit: Optional[int] = None) -> None:
        """Stop asking *quota* for the rest of the UTC day.

        Called when the provider itself refuses. A provider that has said no
        will keep saying no, so every later lookup of this kind is answered
        from what is already cached instead of burning retries.
        """
        day = _utc_day()
        with self._lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO quota (quota, day, used, exhausted)"
                " VALUES (?,?,0,0)", (quota, day))
            if limit is not None:
                self.conn.execute(
                    "UPDATE quota SET exhausted=1, used=MAX(used, ?)"
                    " WHERE quota=? AND day=?", (int(limit), quota, day))
            else:
                self.conn.execute(
                    "UPDATE quota SET exhausted=1 WHERE quota=? AND day=?",
                    (quota, day))
            self.conn.commit()

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

    def add_local_many(self, pairs: Iterable[Tuple[str, str]], label: str,
                       note: str = "", chunk_size: int = 20000) -> Tuple[int, int]:
        """Import many ``(kind, value)`` pairs, one transaction per chunk.

        Returns ``(inserted, updated)``. Chunked commits keep the write lock
        short so a running web instance stays responsive during a large import.
        """
        sql = ("INSERT OR REPLACE INTO local (kind, value, label, note, added_at)"
               " VALUES (?,?,?,?,?)")
        now = time.time()
        with self._lock:
            before = self.conn.execute("SELECT COUNT(*) FROM local").fetchone()[0]
        total = 0
        buf: List[Tuple[str, str, str, str, float]] = []
        for kind, value in pairs:
            buf.append((kind, (value or "").lower(), label, note, now))
            total += 1
            if len(buf) >= chunk_size:
                with self._lock:
                    self.conn.executemany(sql, buf)
                    self.conn.commit()
                buf = []
        if buf:
            with self._lock:
                self.conn.executemany(sql, buf)
                self.conn.commit()
        with self._lock:
            after = self.conn.execute("SELECT COUNT(*) FROM local").fetchone()[0]
        inserted = after - before
        return inserted, total - inserted

    def sync_local_many(self, rows: Iterable[Tuple[str, str, str]],
                        label: str, chunk_size: int = 2000) -> int:
        """Keep a feed's rows in the corpus without re-dating them.

        ``add_local_many`` replaces a row, which resets ``added_at``. For a
        feed refreshed every hour that would walk the same few hundred values
        back to the top of ``/local`` on every run and bury what an analyst
        entered by hand. A row that is already stored keeps its first-seen
        timestamp and only has its label and note refreshed; a new row is
        inserted now.

        *rows* are ``(kind, value, note)`` triples, so each indicator carries
        its own note. Returns the number of rows written.
        """
        sql = ("INSERT INTO local (kind, value, label, note, added_at)"
               " VALUES (?,?,?,?,?)"
               " ON CONFLICT(kind, value) DO UPDATE SET label=excluded.label,"
               " note=excluded.note")
        now = time.time()
        written = 0
        buf: List[Tuple[str, str, str, str, float]] = []
        for kind, value, note in rows:
            buf.append((kind, (value or "").lower(), label, note, now))
            written += 1
            if len(buf) >= chunk_size:
                with self._lock:
                    self.conn.executemany(sql, buf)
                    self.conn.commit()
                buf = []
        if buf:
            with self._lock:
                self.conn.executemany(sql, buf)
                self.conn.commit()
        return written

    def count_local_in(self, kind: str, values: Sequence[str]) -> int:
        """How many of *values* are already stored for *kind*."""
        found = 0
        vals = list(values)
        with self._lock:
            for i in range(0, len(vals), 400):
                chunk = vals[i:i + 400]
                marks = ",".join("?" * len(chunk))
                found += self.conn.execute(
                    f"SELECT COUNT(*) FROM local WHERE kind=? AND value IN ({marks})",
                    (kind, *chunk)).fetchone()[0]
        return found

    def delete_local(self, kind: str, value: str) -> int:
        with self._lock:
            cur = self.conn.execute(
                "DELETE FROM local WHERE kind=? AND value=?", (kind, value.lower()))
            self.conn.commit()
            return cur.rowcount

    def _local_filter(self, query: str = "",
                      kind: str = "") -> Tuple[str, tuple]:
        """The WHERE clause shared by the list and the count, plus its args.

        ``kind`` is matched exactly and ``query`` as a prefix of the stored
        value. The prefix is expressed as a range comparison rather than LIKE
        on purpose: SQLite's LIKE is case-insensitive, which makes it unable to
        use an index, and on a 3.5M-row table that difference is the whole page
        time. Values are stored lowercased, so lowering the query matches.
        """
        clauses: List[str] = []
        args: List[Any] = []
        if kind:
            clauses.append("kind = ?")
            args.append(kind)
        q = (query or "").strip().lower()
        if q:
            clauses.append("value >= ? AND value < ?")
            args.append(q)
            args.append(q + chr(0x10FFFF))   # everything that starts with q
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, tuple(args)

    def count_local(self, query: str = "", kind: str = "") -> int:
        """How many stored local verdicts match a filter."""
        where, args = self._local_filter(query, kind)
        with self._lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM local" + where, args).fetchone()[0]

    def list_local(self, limit: int = 500, offset: int = 0,
                   query: str = "", kind: str = "") -> List[Dict[str, Any]]:
        """One page of stored local verdicts, newest first."""
        where, args = self._local_filter(query, kind)
        limit = max(1, min(1000, int(limit)))
        offset = max(0, int(offset))
        with self._lock:
            rows = self.conn.execute(
                "SELECT kind, value, label, note, added_at FROM local" + where
                + " ORDER BY added_at DESC LIMIT ? OFFSET ?",
                (*args, limit, offset)).fetchall()
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

    def last_verdict(self, kind: str, value: str) -> Optional[Dict[str, Any]]:
        """The most recent verdict we recorded for one indicator.

        Used by the share-card route, which must never spend provider quota:
        it reports what a real lookup already decided and nothing else.
        """
        with self._lock:
            row = self.conn.execute(
                "SELECT verdict, score, ts FROM history"
                " WHERE kind=? AND value=? ORDER BY ts DESC LIMIT 1",
                (kind, value),
            ).fetchone()
        if not row:
            return None
        return {"verdict": row[0], "score": row[1], "ts": row[2]}

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

    # -- source health ---------------------------------------------------
    def record_health(self, source: str, status: str, *,
                      kind: str = "", indicator: str = "", verdict: str = "",
                      note: str = "", latency_ms: int = 0) -> Dict[str, Any]:
        """Store the outcome of one canary check and return the row.

        The first healthy answer for a source becomes the status it is expected
        to repeat, and its latency becomes a baseline. Later checks are compared
        with both, so a feed that starts saying "not found" where it used to say
        "found" is visible even though nothing returned an error.

        The baseline is an exponential average: a provider that has genuinely
        become slower moves the baseline within a few runs instead of alarming
        forever, while a sudden spike still stands out.
        """
        now = time.time()
        source = (source or "").strip()
        status = (status or "").strip().lower()
        latency_ms = max(0, int(latency_ms or 0))
        with self._lock:
            prev = self.conn.execute(
                "SELECT expected, baseline_ms, baseline_at FROM source_health"
                " WHERE source=?", (source,)).fetchone()
            expected = (prev[0] or "") if prev else ""
            baseline = prev[1] if prev and prev[1] else None
            baseline_at = prev[2] if prev else None
            drift = (round(latency_ms / baseline, 2)
                     if baseline and latency_ms else None)
            state = health_state(status, drift, expected)
            if state == HEALTH_OK:
                if not expected:
                    expected = status
                if latency_ms:
                    baseline = (round(baseline * 0.8 + latency_ms * 0.2, 1)
                                if baseline else float(latency_ms))
                    baseline_at = now
            note = (note or "")[:300]
            self.conn.execute(
                "INSERT INTO source_health (source, kind, indicator, status,"
                " verdict, note, latency_ms, checked_at, expected, baseline_ms,"
                " baseline_at, drift) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(source) DO UPDATE SET"
                " kind=excluded.kind, indicator=excluded.indicator,"
                " status=excluded.status, verdict=excluded.verdict,"
                " note=excluded.note, latency_ms=excluded.latency_ms,"
                " checked_at=excluded.checked_at, expected=excluded.expected,"
                " baseline_ms=excluded.baseline_ms,"
                " baseline_at=excluded.baseline_at, drift=excluded.drift",
                (source, kind, indicator, status, verdict, note, latency_ms,
                 now, expected, baseline, baseline_at, drift))
            self.conn.commit()
        return {"source": source, "state": state, "status": status,
                "kind": kind, "indicator": indicator, "verdict": verdict,
                "note": note, "latency_ms": latency_ms, "drift": drift,
                "expected": expected, "baseline_ms": baseline,
                "baseline_at": baseline_at, "checked_at": now}

    def health_rows(self) -> List[Dict[str, Any]]:
        """Every stored health observation, worst state first."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT source, kind, indicator, status, verdict, note,"
                " latency_ms, checked_at, expected, baseline_ms, baseline_at,"
                " drift FROM source_health").fetchall()
        out = []
        for r in rows:
            expected = r[8] or ""
            out.append({
                "source": r[0], "kind": r[1], "indicator": r[2],
                "status": r[3], "verdict": r[4], "note": r[5],
                "latency_ms": r[6], "checked_at": r[7], "expected": expected,
                "baseline_ms": r[9], "baseline_at": r[10], "drift": r[11],
                "state": health_state(r[3], r[11], expected),
            })
        order = {HEALTH_BAD: 0, HEALTH_WARN: 1, HEALTH_OK: 2}
        out.sort(key=lambda h: (order.get(h["state"], 3), h["source"]))
        return out

    def health_for(self) -> Dict[str, Dict[str, Any]]:
        """Health rows keyed by source name."""
        return {h["source"]: h for h in self.health_rows()}


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
    #: Env var that must be truthy before this source runs at all. Used for
    #: sources that cost quota or are rate limited per day without needing a
    #: key of their own, so they stay off until explicitly switched on.
    opt_in: Optional[str] = None
    #: Name of the provider quota this source draws on. Every source sharing
    #: the same value spends one shared daily budget, so a hash lookup, a URL
    #: lookup and a domain lookup are counted together rather than each
    #: getting its own allowance.
    quota_key: Optional[str] = None
    #: Calls per UTC day allowed on ``quota_key``. ``None`` means unlimited.
    daily_budget: Optional[int] = None
    #: Env var that overrides ``daily_budget`` at runtime.
    budget_env: Optional[str] = None
    #: Bump when the verdict or parsing rules of this source change. Cached
    #: entries carrying an older number are ignored, so a corrected verdict
    #: takes effect on the next lookup instead of up to ``cache_ttl`` later.
    logic_version: int = 1

    def key(self) -> Optional[str]:
        if not self.env_key:
            return None
        return os.environ.get(self.env_key) or None

    def opted_in(self) -> bool:
        """True when this source has no opt-in flag, or the flag is set."""
        if not self.opt_in:
            return True
        return _truthy(os.environ.get(self.opt_in, ""))

    def opt_in_missing(self) -> Optional[str]:
        """The opt-in variable still to be set, or ``None`` when it is set."""
        return None if self.opted_in() else (self.opt_in or None)

    def budget(self) -> Optional[int]:
        """Daily call allowance, honouring the ``budget_env`` override."""
        raw = os.environ.get(self.budget_env, "").strip() if self.budget_env else ""
        if raw:
            try:
                return max(0, int(raw))
            except ValueError:
                pass
        return self.daily_budget

    def available(self) -> bool:
        if not self.opted_in():
            return False
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
# Pacing
# --------------------------------------------------------------------------

#: A provider rate limit belongs to the API key, not to the source class that
#: spent it, and not to the Engine instance that happened to run it. One web
#: worker serving two lookups at once, or a hash lookup and a URL lookup in the
#: same minute, all draw on the same allowance, so the pacing state lives at
#: module level keyed by ``quota_key`` and is shared by every thread.
_PACE_LOCK = threading.Lock()
_PACE_NEXT: Dict[str, float] = {}

#: How long a caller will wait for its turn before giving up. Pacing is meant to
#: spread calls out, not to make somebody stare at a spinner: past this the
#: source reports that it was held back and the next lookup tries again.
PACE_MAX_WAIT = float(os.environ.get("TT_PACE_MAX_WAIT", "3"))


def pace_slot(key: str, interval: float,
              max_wait: Optional[float] = None) -> bool:
    """Claim the next call slot on ``key``, or refuse if the wait is too long.

    Returns ``True`` when the caller may make its request now, ``False`` when
    the provider would only be hammered. ``interval`` is the minimum spacing
    between calls on that key.
    """
    if interval <= 0:
        return True
    budget = PACE_MAX_WAIT if max_wait is None else max_wait
    while True:
        with _PACE_LOCK:
            now = time.time()
            ready = _PACE_NEXT.get(key, 0.0)
            if ready <= now:
                _PACE_NEXT[key] = now + interval
                return True
            wait = ready - now
        if wait > budget:
            return False
        time.sleep(min(wait, 0.25))


def pace_defer(key: str, seconds: float) -> None:
    """Hold every caller on ``key`` back for ``seconds`` (a 429 said so)."""
    if not key or seconds <= 0:
        return
    with _PACE_LOCK:
        _PACE_NEXT[key] = max(_PACE_NEXT.get(key, 0.0), time.time() + seconds)


def pace_wait_hint(key: str) -> float:
    """Seconds still to wait on ``key``, for an honest note to the user."""
    with _PACE_LOCK:
        return max(0.0, _PACE_NEXT.get(key, 0.0) - time.time())


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
    def _pace(self, source: Source) -> bool:
        """Claim this source's rate-limit slot; ``False`` means held back.

        The slot is keyed by provider quota, so the three VirusTotal endpoints
        spend one body of rate limit rather than three.
        """
        key = source.quota_key or source.name
        return pace_slot(key, source.min_interval)

    # -- the lookup -------------------------------------------------------
    def lookup(self, ind: Indicator, use_cache: Optional[bool] = None,
               record: bool = True) -> Report:
        """Run every applicable source for one indicator.

        ``record=False`` keeps the lookup out of the history table, so the
        canary's test indicators never show up in the public "recent" feed or
        in the lookup counters.
        """
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

        if self.store and record:
            try:
                self.store.record_lookup(report)
            except sqlite3.Error:
                pass
        return report

    def probe(self, source: Source, ind: Indicator,
              use_cache: bool = False) -> Tuple["SourceResult", float]:
        """Ask one source about one indicator, and time the answer.

        A single-source lookup, used by the health canary. Per-source timing is
        what makes a provider that has become slow, rather than wrong, visible;
        the report-wide elapsed time cannot attribute that to anyone.
        """
        started = time.time()
        try:
            result = self._run(source, ind, use_cache)
        except Exception as exc:  # noqa: BLE001 - a probe never raises
            result = source.result(status="error", note=str(exc)[:180])
        return result, (time.time() - started) * 1000.0

    def _run(self, source: Source, ind: Indicator, use_cache: bool) -> SourceResult:
        if self.store and use_cache:
            cached = self.store.get_cached(
                ind.kind, ind.value, source.name,
                ttl=source.cache_ttl if source.cache_ttl is not None
                else CACHE_TTL_SECONDS,
                logic_version=source.logic_version)
            if cached:
                return cached

        # A provider with a daily allowance is charged before the call, and the
        # lookup is simply not made once the allowance is gone: an answer that
        # says the budget is spent is more useful than a 429 or an empty report.
        limit = source.budget() if source.quota_key else None
        if source.quota_key and self.store:
            try:
                allowed = self.store.take_quota(source.quota_key, limit)
            except sqlite3.Error:
                allowed = True       # never lose a lookup to a bookkeeping error
            if not allowed:
                return self._quota_exhausted(source, limit)

        if not self._pace(source):
            key = source.quota_key or source.name
            return source.result(
                status="skipped",
                note=(f"held back to stay inside the {key} rate limit "
                      f"({pace_wait_hint(key):.0f}s), not asked"),
                detail={"paced": key})
        try:
            res = source.lookup(ind)
        except requests.RequestException as exc:
            return source.fail(exc)
        if (source.quota_key and self.store and res.status == "error"
                and quota_exhausted_note(res.note)):
            try:
                self.store.exhaust_quota(source.quota_key, limit)
            except sqlite3.Error:
                pass
        if self.store and res.status in ("found", "not_found", "matched",
                                         "no_match"):
            try:
                payload = dataclasses.asdict(res)
                payload["detail"] = {k: v for k, v in (payload["detail"] or {}).items()
                                     if not k.startswith("_")}
                self.store.put_cached(ind.kind, ind.value,
                                      SourceResult(**payload),
                                      logic_version=source.logic_version)
            except sqlite3.Error:
                pass
        return res

    def _quota_exhausted(self, source: Source, limit: Optional[int]) -> SourceResult:
        """The result for a source whose daily allowance is spent."""
        used, spent_by_provider = limit, False
        if self.store:
            try:
                state = self.store.quota_state(source.quota_key or "")
                used = state["used"] if limit is None else max(used or 0, state["used"])
                spent_by_provider = state["exhausted"]
            except sqlite3.Error:
                pass
        of = f"{used if used is not None else '?'}/" + (
            str(limit) if limit is not None else "unlimited")
        why = ("provider says the daily allowance is spent"
               if spent_by_provider else "daily budget spent")
        return source.result(
            status="skipped",
            note=f"{why} ({of} {source.quota_key} today), not asked",
            detail={"quota": source.quota_key, "used": used, "limit": limit,
                    "exhausted": spent_by_provider})

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
