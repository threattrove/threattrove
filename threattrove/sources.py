"""All data sources: file hashes, URLs, domains and infrastructure intel.

Each source declares:
  * ``kinds``   - which indicator types it can answer (hash/url/domain/ip)
  * ``category``- "reputation" (affects the verdict) or "intel" (context only)
  * ``env_key`` - API key env var; ``keyless=True`` means it works without one

Sources never fetch the submitted URL. They only query third-party APIs, so
the web front-end cannot be used as an SSRF proxy.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import os
import re
from typing import Any, Dict, List, Optional

import requests

from .core import (
    KIND_DOMAIN,
    KIND_HASH,
    KIND_IP,
    KIND_URL,
    VERDICT_CLEAN,
    VERDICT_KNOWN_GOOD,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    Indicator,
    Source,
    SourceResult,
    DEFAULT_TIMEOUT,
    registrable_domain,
)

ABUSECH = "https://mb-api.abuse.ch/api/v1/"


def _short(text: Any, limit: int = 120) -> str:
    s = str(text or "").strip().replace("\n", " ")
    return s[:limit]


def _otx_verdict(pulses: int, validation: List[str], kind: str) -> tuple:
    """Interpret OTX pulse counts, honouring its whitelist signals.

    A hash appearing in pulses is a strong signal. A *popular domain* also
    appears in many pulses simply because analysts reference it, so OTX marks
    such domains "Whitelisted" / "Known False Positive" -- that has to win.
    """
    names = [str(v).lower() for v in validation]
    whitelisted = any("whitelist" in n or "false positive" in n for n in names)

    if kind == KIND_HASH:
        if pulses >= 3:
            return VERDICT_MALICIOUS, f"{pulses} pulse(s)"
        if pulses >= 1:
            return VERDICT_SUSPICIOUS, f"{pulses} pulse(s)"
        return VERDICT_UNKNOWN, "no pulses"

    if whitelisted and pulses == 0:
        return VERDICT_KNOWN_GOOD, "whitelisted domain"
    if whitelisted:
        return VERDICT_UNKNOWN, f"whitelisted, but in {pulses} pulse(s)"
    if pulses >= 1:
        return VERDICT_SUSPICIOUS, f"appears in {pulses} pulse(s)"
    return VERDICT_UNKNOWN, "no pulses"


# ==========================================================================
# File hash sources
# ==========================================================================

class CIRCLHashlookup(Source):
    name = "circl"
    display = "CIRCL hashlookup"
    keyless = True
    homepage = "https://hashlookup.circl.lu/"
    kinds = (KIND_HASH,)

    def lookup(self, ind: Indicator) -> SourceResult:
        for algo in ("sha256", "sha1", "md5"):
            val = ind.hashes.get(algo)
            if not val:
                continue
            url = f"https://hashlookup.circl.lu/lookup/{algo}/{val}"
            r = self.session().get(url, timeout=DEFAULT_TIMEOUT)
            if r.status_code in (400, 404):
                continue
            if r.status_code != 200:
                return self.result(status="error", note=f"HTTP {r.status_code}")
            data = r.json()
            known_mal = str(data.get("KnownMalicious", "")).strip()
            link = url
            detail = {
                "FileName": data.get("FileName"),
                "FileSize": data.get("FileSize"),
                "KnownMalicious": data.get("KnownMalicious"),
                "ProductName": (data.get("ProductCode") or {}).get("ProductName"),
                "OpSystemName": (data.get("OpSystemCode") or {}).get("OpSystemName"),
            }
            if known_mal and known_mal.lower() not in ("none", "false", "0"):
                return self.result(status="found", verdict=VERDICT_MALICIOUS,
                                   note=f"listed by {known_mal}", link=link,
                                   detail=detail)
            return self.result(status="found", verdict=VERDICT_KNOWN_GOOD,
                               note=_short(data.get("FileName") or "NSRL known file", 60),
                               link=link, detail=detail)
        return self.result(status="not_found", note="not in NSRL / hashlookup")


class AlienVaultOTXFile(Source):
    name = "otx"
    display = "AlienVault OTX"
    env_key = "OTX_API_KEY"
    keyless = True
    homepage = "https://otx.alienvault.com/"
    kinds = (KIND_HASH,)

    def _headers(self) -> Dict[str, str]:
        key = self.key()
        return {"X-OTX-API-KEY": key} if key else {}

    def lookup(self, ind: Indicator) -> SourceResult:
        h = ind.preferred_hash()
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{h}/general"
        r = self.session().get(url, headers=self._headers(),
                               timeout=DEFAULT_TIMEOUT)
        if r.status_code == 404:
            return self.result(status="not_found")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        data = r.json()
        pulses = (data.get("pulse_info") or {}).get("count", 0) or 0
        analysis = data.get("analysis") or {}
        det = int(analysis.get("detection", 0) or 0)
        total = int(analysis.get("analysis", 0) or 0)
        validation = [v.get("name") for v in (data.get("validation") or [])
                      if v.get("name")]
        detail = {"pulses": pulses, "validation": validation[:4],
                  "engines": bool(total),
                  "names": _short(
                      (data.get("base_indicator") or {}).get("title", ""), 80)}
        link = f"https://otx.alienvault.com/indicator/file/{h}"
        verdict, note = _otx_verdict(pulses, validation, KIND_HASH)
        return self.result(status="found", verdict=verdict, detections=det,
                           total=total, note=note, link=link, detail=detail)


class MalwareBazaar(Source):
    name = "malwarebazaar"
    display = "MalwareBazaar (abuse.ch)"
    env_key = "ABUSECH_AUTH_KEY"
    homepage = "https://bazaar.abuse.ch/"
    kinds = (KIND_HASH,)

    def lookup(self, ind: Indicator) -> SourceResult:
        h = ind.preferred_hash()
        r = self.session().post(
            ABUSECH, data={"query": "get_info", "hash": h},
            headers={"Auth-Key": self.key() or ""}, timeout=DEFAULT_TIMEOUT)
        if r.status_code in (401, 403):
            return self.result(status="unauthorized", note="invalid Auth-Key")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        data = r.json()
        status = data.get("query_status")
        if status == "hash_not_found":
            return self.result(status="not_found")
        if status != "ok":
            return self.result(status="error", note=_short(status))
        entry = (data.get("data") or [{}])[0]
        sha = ind.hashes.get("sha256", h)
        return self.result(
            status="found", verdict=VERDICT_MALICIOUS,
            note=_short(entry.get("signature") or "known malware sample", 60),
            link=f"https://bazaar.abuse.ch/sample/{sha}/",
            detail={"signature": entry.get("signature"),
                    "file_type": entry.get("file_type"),
                    "first_seen": entry.get("first_seen"),
                    "tags": entry.get("tags"),
                    "reporter": entry.get("reporter")})


class ThreatFox(Source):
    name = "threatfox"
    display = "ThreatFox (abuse.ch)"
    env_key = "ABUSECH_AUTH_KEY"
    homepage = "https://threatfox.abuse.ch/"
    kinds = (KIND_HASH, KIND_URL, KIND_DOMAIN, KIND_IP)

    def lookup(self, ind: Indicator) -> SourceResult:
        term = ind.preferred_hash() if ind.kind == KIND_HASH else ind.value
        r = self.session().post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": term},
            headers={"Auth-Key": self.key() or "",
                     "Content-Type": "application/json"},
            timeout=DEFAULT_TIMEOUT)
        if r.status_code in (401, 403):
            return self.result(status="unauthorized", note="invalid Auth-Key")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        data = r.json()
        status = data.get("query_status")
        if status in ("no_result", "illegal_search_term"):
            return self.result(status="no_match")
        if status != "ok":
            return self.result(status="error", note=_short(status))
        entries = data.get("data") or []
        if not entries:
            return self.result(status="no_match")
        first = entries[0]
        return self.result(
            status="matched", verdict=VERDICT_MALICIOUS,
            note=_short(first.get("malware_printable") or "IOC match", 60),
            link=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{term}",
            detail={"malware": first.get("malware_printable"),
                    "threat_type": first.get("threat_type"),
                    "confidence": first.get("confidence_level"),
                    "first_seen": first.get("first_seen_utc")})


class URLhausPayload(Source):
    name = "urlhaus"
    display = "URLhaus payload (abuse.ch)"
    env_key = "ABUSECH_AUTH_KEY"
    homepage = "https://urlhaus.abuse.ch/"
    kinds = (KIND_HASH,)

    def lookup(self, ind: Indicator) -> SourceResult:
        # URLhaus accepts either digest. Prefer sha256 because a pasted hash is
        # almost always sha256 and no other digest can be derived from it.
        sha256 = ind.hashes.get("sha256")
        if sha256:
            field, value = "sha256_hash", sha256
        elif ind.hashes.get("md5"):
            field, value = "md5_hash", ind.hashes["md5"]
        else:
            return self.result(status="skipped", note="sha256 or md5 required")
        r = self.session().post(
            "https://urlhaus-api.abuse.ch/v1/payload/",
            data={field: value}, headers={"Auth-Key": self.key() or ""},
            timeout=DEFAULT_TIMEOUT)
        if r.status_code in (401, 403):
            return self.result(status="unauthorized", note="invalid Auth-Key")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        data = r.json()
        if data.get("query_status") != "ok":
            return self.result(status="not_found")
        return self.result(
            status="found", verdict=VERDICT_MALICIOUS,
            note=_short(data.get("signature") or "payload seen in URLhaus", 60),
            link=f"https://urlhaus.abuse.ch/browse.php?search={value}",
            detail={"file_type": data.get("file_type"),
                    "signature": data.get("signature"),
                    "url_count": data.get("url_count"),
                    "firstseen": data.get("firstseen")})


class VirusTotalFile(Source):
    name = "virustotal"
    display = "VirusTotal (files)"
    env_key = "VT_API_KEY"
    homepage = "https://www.virustotal.com/"
    kinds = (KIND_HASH,)

    def lookup(self, ind: Indicator) -> SourceResult:
        h = ind.preferred_hash()
        r = self.session().get(
            f"https://www.virustotal.com/api/v3/files/{h}",
            headers={"x-apikey": self.key() or ""}, timeout=DEFAULT_TIMEOUT)
        return _vt_parse(self, r, file_hash=h)


#: Hybrid Analysis scanner states that amount to a usable judgement. A
#: scanner in ``error`` did not analyse the file, so it must not pad the total.
HA_USABLE_STATES = {"malicious", "suspicious", "clean", "no specific threat",
                    "unknown", "whitelisted", "no threat"}
HA_FLAGGED_STATES = {"malicious", "suspicious"}

#: ``vx_family`` values that name a category rather than a family. Hybrid
#: Analysis fills this field with words like "Malware" on files it merely
#: disliked -- a popular 7-Zip build is tagged that way after a single engine
#: flagged it -- so these are not a determination and are not shown as a family
#: name.
HA_GENERIC_FAMILIES = frozenset({
    "malware", "malicious", "virus", "trojan", "worm", "backdoor",
    "dropper", "downloader", "ransomware", "stealer", "infostealer",
    "spyware", "adware", "pup", "pua", "riskware", "rootkit", "keylogger",
    "miner", "coinminer", "exploit", "phishing", "crimeware", "hacktool",
    "generic", "heuristic", "heur", "unknown", "unclassified", "other",
    "none", "n/a", "na", "bad",
})


def _meaningful_family(value: str) -> bool:
    """True when a family string names something more specific than a category."""
    name = (value or "").strip()
    if len(name) < 3 or not any(c.isalpha() for c in name):
        return False
    return name.lower().strip(".! ") not in HA_GENERIC_FAMILIES


class HybridAnalysis(Source):
    """Falcon Sandbox / Hybrid Analysis.

    Uses ``GET /api/v2/overview/{hash}``. The older ``POST /search/hash``
    was deprecated in API 2.35.0 and now answers 410 Gone, so it is only kept
    as a fallback for keys older than that cut-off.

    The response carries three things worth surfacing: the file's *name*
    (``last_file_name``), the sandbox verdict, and per-scanner results
    (``scanners_v2``). That is the only source in this list besides VirusTotal
    that says something about the file itself rather than about where a copy of
    it was seen.

    Verdict handling is deliberately split: a scanner hit or a named malware
    family is a determination and can convict; a high ``threat_score`` with no
    scanner agreement is not, because installers trip behavioural heuristics
    (an authentic 7-Zip installer scores 75 with every scanner clean).
    """

    name = "hybridanalysis"
    display = "Hybrid Analysis"
    env_key = "HA_API_KEY"
    homepage = "https://www.hybrid-analysis.com/"
    kinds = (KIND_HASH,)
    min_interval = 0.3      # free tier: 200 requests/minute

    API = "https://www.hybrid-analysis.com/api/v2"

    def _headers(self) -> Dict[str, str]:
        return {"api-key": self.key() or "", "User-Agent": "Falcon Sandbox",
                "Accept": "application/json"}

    def lookup(self, ind: Indicator) -> SourceResult:
        h = ind.hashes.get("sha256") or ind.preferred_hash()
        if not h:
            return self.result(status="skipped", note="no digest")

        r = self.session().get(f"{self.API}/overview/{h}",
                               headers=self._headers(), timeout=DEFAULT_TIMEOUT)
        entry = self._entry(r)
        if isinstance(entry, SourceResult):
            if entry.status == "not_found":
                entry.note = "no sandbox report"
            return entry
        if entry is None:            # deprecated endpoint fallback
            entry = self._via_search(h)
            if isinstance(entry, SourceResult):
                return entry
            if entry is None:
                return self.result(status="not_found", note="no sandbox report")

        return self._judge(entry, h)

    def _entry(self, r: requests.Response):
        """Normalise the transport-level outcomes into a SourceResult or dict."""
        if r.status_code in (401, 403):
            return self.result(status="unauthorized", note="invalid API key")
        if r.status_code == 404:
            return self.result(status="not_found")
        if r.status_code == 410:
            return None              # deprecated: caller retries the old way
        if r.status_code == 429:
            return self.result(status="error", note="rate limited (200/min)")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return self.result(status="error", note="bad JSON")
        if isinstance(data, list):
            data = data[0] if data else None
        if not isinstance(data, dict) or not data:
            return self.result(status="not_found")
        if not (data.get("sha256") or data.get("last_file_name") or
                data.get("scanners_v2") or data.get("verdict")):
            return self.result(status="not_found")
        return data

    def _via_search(self, h: str):
        """Fallback for keys issued before API 2.35.0 (pre-2026-08-21)."""
        r = self.session().get(f"{self.API}/search/hash", params={"hash": h},
                               headers=self._headers(), timeout=DEFAULT_TIMEOUT)
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return self.result(status="error", note="bad JSON")
        reports = (data or {}).get("reports") or []
        if not reports:
            return None
        best = max(reports, key=lambda x: bool(x.get("verdict")))
        return {"sha256": h, "verdict": best.get("verdict"),
                "last_file_name": best.get("filename"),
                "threat_score": None, "vx_family": None, "scanners_v2": {}}

    def _judge(self, entry: Dict[str, Any], h: str) -> SourceResult:
        scanners = entry.get("scanners_v2") or {}
        usable = {k: v for k, v in scanners.items()
                  if isinstance(v, dict)
                  and (v.get("status") or "").lower() in HA_USABLE_STATES}
        flagged = sorted(k for k, v in usable.items()
                         if (v.get("status") or "").lower() in HA_FLAGGED_STATES)
        total = len(usable)
        family_raw = (entry.get("vx_family") or "").strip()
        family = family_raw if _meaningful_family(family_raw) else ""
        verdict_raw = (entry.get("verdict") or "").strip().lower()
        score = entry.get("threat_score")
        whitelisted = bool(entry.get("whitelisted"))

        detail: Dict[str, Any] = {
            "engines": bool(total),
            "malicious": len(flagged),
            "suspicious": 0,
            "total_engines": total,
            "flagged_by": flagged,
            "verdict": entry.get("verdict"),
            "threat_score": score,
            "family": family or None,
            "family_raw": family_raw or None,
            "file_name": entry.get("last_file_name"),
            "type": entry.get("type"),
            "size": entry.get("size"),
            "first_seen": _short(entry.get("analysis_start_time"), 10),
            "tags": (entry.get("tags") or [])[:5],
        }
        link = f"https://www.hybrid-analysis.com/sample/{h}"

        # 1. A scanner hit is a direct determination about the file.
        if flagged:
            return self.result(status="found", verdict=VERDICT_MALICIOUS,
                               detections=len(flagged), total=total,
                               note=f"{len(flagged)}/{total} scanner(s) flagged"
                                    + (f" - {family}" if family else ""),
                               link=link, detail=detail)

        # 2. A named malware family is also a determination.
        if family and verdict_raw not in ("no specific threat", "no threat"):
            return self.result(status="found", verdict=VERDICT_MALICIOUS,
                               detections=0, total=total,
                               note=f"family: {family}", link=link, detail=detail)

        # 3. Verdict with no supporting scanner data: a lead, not a finding.
        if verdict_raw == "malicious" or (isinstance(score, int) and score >= 75):
            note = f"sandbox scored {score if score is not None else 'malicious'}"
            note += (f", 0/{total} scanners agree" if total else ", no scanner data")
            return self.result(status="found", verdict=VERDICT_SUSPICIOUS,
                               detections=0, total=total, note=note,
                               link=link, detail=detail)

        if verdict_raw == "suspicious":
            return self.result(status="found", verdict=VERDICT_SUSPICIOUS,
                               detections=0, total=total,
                               note="sandbox: suspicious" +
                                    (f", 0/{total} scanners agree" if total else ""),
                               link=link, detail=detail)

        # 4. The sandbox looked and found nothing.
        if whitelisted or verdict_raw in ("no specific threat", "no threat",
                                         "benign", "whitelisted"):
            name = entry.get("last_file_name") or "file"
            note = f"no threat found ({name})"
            if total:
                note = f"0/{total} scanner(s) flagged - {name}"
            return self.result(status="found", verdict=VERDICT_CLEAN,
                               detections=0, total=total, note=note,
                               link=link, detail=detail)

        return self.result(status="found", verdict=VERDICT_UNKNOWN,
                           detections=0, total=total,
                           note=_short(entry.get("verdict") or "no verdict", 40),
                           link=link, detail=detail)


class MalShare(Source):
    name = "malshare"
    display = "MalShare"
    env_key = "MALSHARE_API_KEY"
    homepage = "https://malshare.com/"
    kinds = (KIND_HASH,)

    def lookup(self, ind: Indicator) -> SourceResult:
        h = ind.preferred_hash()
        r = self.session().get(
            "https://malshare.com/api.php",
            params={"api_key": self.key(), "action": "getdetails", "hash": h},
            timeout=DEFAULT_TIMEOUT)
        if r.status_code == 403:
            return self.result(status="unauthorized", note="invalid API key")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return self.result(status="not_found")
        if not data or (isinstance(data, dict) and data.get("ERROR")):
            return self.result(status="not_found")
        entry = data[0] if isinstance(data, list) else data
        return self.result(
            status="found", verdict=VERDICT_MALICIOUS,
            note="sample in MalShare",
            link=f"https://malshare.com/sample.php?action=detail&hash={h}",
            detail={"type": entry.get("F_TYPE"), "sources": entry.get("SOURCES")})


class Triage(Source):
    name = "triage"
    display = "Hatching Triage"
    env_key = "TRIAGE_API_KEY"
    homepage = "https://tria.ge/"
    kinds = (KIND_HASH,)

    def lookup(self, ind: Indicator) -> SourceResult:
        h = ind.hashes.get("sha256") or ind.preferred_hash()
        r = self.session().get(
            f"https://tria.ge/api/v0/search?query=sha256:{h}",
            headers={"Authorization": f"Bearer {self.key()}"},
            timeout=DEFAULT_TIMEOUT)
        if r.status_code in (401, 403):
            return self.result(status="unauthorized", note="invalid API key")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        data = r.json()
        entries = data.get("data") or []
        if not entries:
            return self.result(status="not_found")
        entry = entries[0]
        analysis = entry.get("analysis") or {}
        score = analysis.get("score")
        detail = {"status": entry.get("status"), "score": score,
                  "tags": entry.get("tags")}
        link = f"https://tria.ge/{entry.get('id')}"
        verdict = str(analysis.get("verdict") or "").lower()
        if verdict and verdict != "benign":
            return self.result(status="found", verdict=VERDICT_MALICIOUS,
                               note=f"verdict: {verdict}", link=link, detail=detail)
        try:
            s = float(score) if score is not None else None
        except (TypeError, ValueError):
            s = None
        if s is not None:
            v = (VERDICT_MALICIOUS if s >= 7 else VERDICT_SUSPICIOUS if s >= 4
                 else VERDICT_CLEAN)
            return self.result(status="found", verdict=v,
                               note=f"score {s:g}/10", link=link, detail=detail)
        return self.result(status="found", verdict=VERDICT_UNKNOWN,
                           note="no verdict", link=link, detail=detail)


# ==========================================================================
# URL sources
# ==========================================================================

class AlienVaultOTXUrl(Source):
    name = "otx_url"
    display = "AlienVault OTX (URL)"
    env_key = "OTX_API_KEY"
    keyless = True
    homepage = "https://otx.alienvault.com/"
    kinds = (KIND_URL,)

    def lookup(self, ind: Indicator) -> SourceResult:
        from urllib.parse import quote
        q = quote(ind.value, safe="")
        url = f"https://otx.alienvault.com/api/v1/indicators/url/{q}/general"
        key = self.key()
        r = self.session().get(url, headers={"X-OTX-API-KEY": key} if key else {},
                               timeout=DEFAULT_TIMEOUT)
        if r.status_code == 404:
            return self.result(status="not_found")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        data = r.json()
        pulses = (data.get("pulse_info") or {}).get("count", 0) or 0
        validation = [v.get("name") for v in (data.get("validation") or [])
                      if v.get("name")]
        detail = {"pulses": pulses, "validation": validation[:5],
                  "url_list_count": len(data.get("url_list") or [])}
        link = f"https://otx.alienvault.com/indicator/url/{q}"
        verdict, note = _otx_verdict(pulses, validation, KIND_URL)
        return self.result(status="found", verdict=verdict, detections=pulses,
                           note=note, link=link, detail=detail)


class URLScanUrl(Source):
    name = "urlscan"
    display = "urlscan.io (URL)"
    env_key = "URLSCAN_API_KEY"
    keyless = True
    homepage = "https://urlscan.io/"
    kinds = (KIND_URL, KIND_DOMAIN, KIND_IP)
    min_interval = 1.0

    def lookup(self, ind: Indicator) -> SourceResult:
        if ind.kind == KIND_URL:
            query = f'page.url:"{ind.value}"'
        else:
            query = f"domain:{ind.value}" if ind.kind == KIND_DOMAIN else f"ip:{ind.value}"
        params = {"q": query, "size": 100}
        headers = {}
        key = self.key()
        if key:
            headers["API-Key"] = key
        r = self.session().get("https://urlscan.io/api/v1/search/",
                               params=params, headers=headers,
                               timeout=DEFAULT_TIMEOUT)
        if r.status_code == 429:
            return self.result(status="error", note="rate limited")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        data = r.json()
        results = data.get("results") or []
        total = int(data.get("total") or 0)
        if not results:
            return self.result(status="not_found", detail={"scans": 0})

        malicious = suspicious = 0
        domains, ips, newest = set(), set(), ""
        for item in results:
            task = item.get("task") or {}
            page = item.get("page") or {}
            verdicts = item.get("verdicts") or {}
            overall = (verdicts.get("overall") or {}) if isinstance(verdicts, dict) else {}
            try:
                score = float(overall.get("score") or 0)
            except (TypeError, ValueError):
                score = 0.0
            if overall.get("malicious") or score >= 50:
                malicious += 1
            elif score > 0:
                suspicious += 1
            if page.get("domain"):
                domains.add(page["domain"])
            if page.get("ip"):
                ips.add(page["ip"])
            newest = max(newest, task.get("time") or "")

        detail = {"scans": total, "malicious_scans": malicious,
                  "suspicious_scans": suspicious,
                  "domains": sorted(domains)[:6], "ips": sorted(ips)[:6],
                  "last_scan": newest}
        link = f"https://urlscan.io/search/#{query}"
        note = f"{total} scan(s), {malicious} flagged"
        if malicious:
            return self.result(status="found", verdict=VERDICT_MALICIOUS,
                               detections=malicious, total=total, note=note,
                               link=link, detail=detail)
        if suspicious:
            return self.result(status="found", verdict=VERDICT_SUSPICIOUS,
                               detections=suspicious, total=total, note=note,
                               link=link, detail=detail)
        return self.result(status="found", verdict=VERDICT_UNKNOWN,
                           detections=0, total=total, note=note,
                           link=link, detail=detail)


class URLhausUrl(Source):
    name = "urlhaus_url"
    display = "URLhaus (URL)"
    env_key = "ABUSECH_AUTH_KEY"
    homepage = "https://urlhaus.abuse.ch/"
    kinds = (KIND_URL,)

    def lookup(self, ind: Indicator) -> SourceResult:
        r = self.session().post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": ind.value}, headers={"Auth-Key": self.key() or ""},
            timeout=DEFAULT_TIMEOUT)
        if r.status_code in (401, 403):
            return self.result(status="unauthorized", note="invalid Auth-Key")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        data = r.json()
        if data.get("query_status") != "ok":
            return self.result(status="no_match")
        return self.result(
            status="matched", verdict=VERDICT_MALICIOUS,
            note=_short(data.get("threat") or "listed in URLhaus", 50),
            link=f"https://urlhaus.abuse.ch/browse.php?search={ind.value}",
            detail={"threat": data.get("threat"),
                    "tags": data.get("tags"),
                    "url_status": data.get("url_status"),
                    "date_added": data.get("date_added"),
                    "reporter": data.get("reporter")})


class VirusTotalUrl(Source):
    name = "virustotal_url"
    display = "VirusTotal (URL)"
    env_key = "VT_API_KEY"
    homepage = "https://www.virustotal.com/"
    kinds = (KIND_URL,)

    def lookup(self, ind: Indicator) -> SourceResult:
        url_id = base64.urlsafe_b64encode(
            ind.value.encode()).decode().strip("=")
        r = self.session().get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": self.key() or ""}, timeout=DEFAULT_TIMEOUT)
        return _vt_parse(self, r, url_value=ind.value)


class SafeBrowsing(Source):
    name = "gsb"
    display = "Google Safe Browsing"
    env_key = "GSB_API_KEY"
    homepage = "https://developers.google.com/safe-browsing"
    kinds = (KIND_URL, KIND_DOMAIN)

    THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
               "POTENTIALLY_HARMFUL_APPLICATION"]

    def lookup(self, ind: Indicator) -> SourceResult:
        target = ind.value if ind.kind == KIND_URL else f"http://{ind.value}/"
        body = {
            "client": {"clientId": "threattrove", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": self.THREATS,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target}],
            },
        }
        r = self.session().post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": self.key()}, json=body, timeout=DEFAULT_TIMEOUT)
        if r.status_code in (400, 403):
            return self.result(status="unauthorized", note="invalid API key")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        matches = (r.json() or {}).get("matches") or []
        if not matches:
            return self.result(status="no_match", verdict=VERDICT_CLEAN,
                               note="not listed")
        kinds = sorted({m.get("threatType", "?") for m in matches})
        return self.result(status="matched", verdict=VERDICT_MALICIOUS,
                           note=", ".join(kinds)[:60],
                           link="https://transparencyreport.google.com/safe-browsing/search",
                           detail={"threat_types": kinds})


class PhishTank(Source):
    name = "phishtank"
    display = "PhishTank"
    env_key = "PHISHTANK_APPKEY"
    homepage = "https://phishtank.org/"
    kinds = (KIND_URL,)

    def lookup(self, ind: Indicator) -> SourceResult:
        r = self.session().post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": ind.value, "format": "json",
                  "app_key": self.key()},
            timeout=DEFAULT_TIMEOUT)
        if r.status_code in (401, 403):
            return self.result(status="unauthorized", note="invalid app key")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json().get("results") or {}
        except ValueError:
            return self.result(status="error", note="non-JSON response")
        if not data.get("in_database"):
            return self.result(status="no_match")
        detail = {"verified": data.get("verified"),
                  "phish_id": data.get("phish_id"),
                  "submission_time": data.get("submission_time")}
        if data.get("valid") and data.get("verified"):
            return self.result(status="matched", verdict=VERDICT_MALICIOUS,
                               note="verified phishing URL",
                               link=f"https://phishtank.org/phish_detail.php?phish_id={data.get('phish_id')}",
                               detail=detail)
        return self.result(status="matched", verdict=VERDICT_SUSPICIOUS,
                           note="in database (unverified)",
                           link="https://phishtank.org/", detail=detail)


# ==========================================================================
# Domain sources
# ==========================================================================

class AlienVaultOTXDomain(Source):
    name = "otx_domain"
    display = "AlienVault OTX (domain)"
    env_key = "OTX_API_KEY"
    keyless = True
    homepage = "https://otx.alienvault.com/"
    kinds = (KIND_DOMAIN, KIND_IP)

    def lookup(self, ind: Indicator) -> SourceResult:
        section = "IPv4" if ind.kind == KIND_IP else "domain"
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{ind.value}/general"
        key = self.key()
        r = self.session().get(url, headers={"X-OTX-API-KEY": key} if key else {},
                               timeout=DEFAULT_TIMEOUT)
        if r.status_code == 404:
            return self.result(status="not_found")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        data = r.json()
        pulses = (data.get("pulse_info") or {}).get("count", 0) or 0
        mal = (data.get("malware") or {}).get("count", 0) or 0
        validation = [v.get("name") for v in (data.get("validation") or [])
                      if v.get("name")]
        detail = {"pulses": pulses, "malware_samples": mal,
                  "validation": validation[:4],
                  "asn": _short(data.get("asn"), 40),
                  "country": _short(data.get("country_name"), 40)}
        link = f"https://otx.alienvault.com/indicator/{section}/{ind.value}"
        verdict, note = _otx_verdict(pulses, validation, ind.kind)
        return self.result(status="found", verdict=verdict, detections=pulses,
                           note=note, link=link, detail=detail)


class VirusTotalDomain(Source):
    name = "virustotal_domain"
    display = "VirusTotal (domain/IP)"
    env_key = "VT_API_KEY"
    homepage = "https://www.virustotal.com/"
    kinds = (KIND_DOMAIN, KIND_IP)

    def lookup(self, ind: Indicator) -> SourceResult:
        path = "ip_addresses" if ind.kind == KIND_IP else "domains"
        r = self.session().get(
            f"https://www.virustotal.com/api/v3/{path}/{ind.value}",
            headers={"x-apikey": self.key() or ""}, timeout=DEFAULT_TIMEOUT)
        vt_kind = "ip-address" if ind.kind == KIND_IP else "domain"
        return _vt_parse(self, r, url_value=ind.value, vt_kind=vt_kind)


# ==========================================================================
# Infrastructure intel (context only, never changes the verdict)
# ==========================================================================

class DNSRecords(Source):
    name = "dns"
    display = "DNS records"
    keyless = True
    homepage = "https://developers.cloudflare.com/1.1.1.1/"
    kinds = (KIND_DOMAIN, KIND_IP)
    category = "intel"
    cache_ttl = 3600
    min_interval = 0.3

    TYPES = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CNAME": 5,
             "SOA": 6}

    def lookup(self, ind: Indicator) -> SourceResult:
        records: Dict[str, List[str]] = {}
        for label, rtype in self.TYPES.items():
            try:
                r = self.session().get(
                    "https://cloudflare-dns.com/dns-query",
                    params={"name": ind.value, "type": label},
                    headers={"accept": "application/dns-json"},
                    timeout=min(DEFAULT_TIMEOUT, 10))
            except requests.RequestException:
                continue
            if r.status_code != 200:
                continue
            try:
                answer = (r.json() or {}).get("Answer") or []
            except ValueError:
                continue
            vals = []
            for a in answer:
                data = str(a.get("data", "")).strip().strip('"')
                if label == "MX":
                    data = data.split(" ", 1)[-1]
                if data and data not in vals:
                    vals.append(data)
            if vals:
                records[label] = vals[:12]
        if not records:
            return self.result(status="not_found", note="no DNS records")
        note = ", ".join(sorted(records))
        return self.result(status="found", note=note,
                           detail={"records": records})


class RDAPWhois(Source):
    name = "rdap"
    display = "WHOIS / RDAP"
    keyless = True
    homepage = "https://rdap.org/"
    kinds = (KIND_DOMAIN, KIND_IP)
    category = "intel"
    cache_ttl = 7 * 24 * 3600
    min_interval = 1.0

    def lookup(self, ind: Indicator) -> SourceResult:
        kind = "ip" if ind.kind == KIND_IP else "domain"
        try:
            r = self.session().get(
                f"https://rdap.org/{kind}/{ind.value}",
                headers={"accept": "application/rdap+json"}, timeout=15)
        except requests.RequestException as exc:
            return self.fail(exc)
        if r.status_code == 404:
            return self.result(status="not_found", note="no RDAP record")
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return self.result(status="error", note="bad JSON")

        events = {}
        for ev in data.get("events") or []:
            action = ev.get("eventAction")
            if action:
                events[action] = str(ev.get("eventDate") or "")[:10]

        registrar = ""
        for ent in data.get("entities") or []:
            if "registrar" in (ent.get("roles") or []):
                registrar = _vcard_name(ent) or ""
                break
        if not registrar:
            for ent in data.get("entities") or []:
                if "registrant" in (ent.get("roles") or []):
                    registrar = _vcard_name(ent) or ""
                    break

        nameservers = []
        for ns in data.get("nameservers") or []:
            n = ns.get("ldhName") or ns.get("unicodeName")
            if n:
                nameservers.append(n.lower())

        detail = {
            "registrar": registrar,
            "created": events.get("registration", ""),
            "expires": events.get("expiration", ""),
            "updated": events.get("last changed", "") or events.get("last update of RDAP database", ""),
            "status": (data.get("status") or [])[:8],
            "nameservers": nameservers[:10],
            "handle": data.get("handle"),
        }
        if kind == "ip":
            detail["network"] = f"{data.get('startAddress','?')} - {data.get('endAddress','?')}"
            detail["country"] = data.get("country")
        bits = [b for b in (registrar, detail["created"]) if b]
        return self.result(status="found",
                           note=" / ".join(bits)[:80] or "record found",
                           link=f"https://{ind.value}" if kind == "domain" else "",
                           detail=detail)


class CertificateTransparency(Source):
    name = "crt"
    display = "Certificate Transparency"
    keyless = True
    homepage = "https://crt.sh/"
    kinds = (KIND_DOMAIN,)
    category = "intel"
    cache_ttl = 24 * 3600
    min_interval = 1.5

    def lookup(self, ind: Indicator) -> SourceResult:
        try:
            r = self.session().get(
                "https://crt.sh/", params={"q": ind.value, "output": "json"},
                timeout=25)
        except requests.RequestException as exc:
            return self.fail(exc)
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return self.result(status="error", note="bad JSON")
        if not data:
            return self.result(status="not_found", note="no certificates")
        names, issuers, earliest, latest = set(), set(), "", ""
        for entry in data:
            for n in str(entry.get("name_value") or "").split("\n"):
                n = n.strip().lower()
                if n and "*" not in n:
                    names.add(n)
            issuer = str(entry.get("issuer_name") or "")
            if issuer:
                m = re.search(r"CN=([^,]+)", issuer)
                issuers.add((m.group(1) if m else issuer)[:48])
            nb = str(entry.get("not_before") or "")[:10]
            if nb:
                earliest = nb if not earliest else min(earliest, nb)
                latest = nb if not latest else max(latest, nb)
        return self.result(
            status="found",
            note=f"{len(data)} cert(s), {len(names)} hostname(s)",
            link=f"https://crt.sh/?q={ind.value}",
            detail={"certificates": len(data), "hostnames": sorted(names)[:25],
                    "issuers": sorted(issuers)[:8], "first_seen": earliest,
                    "last_seen": latest})


class ReverseIP(Source):
    """Hosts co-located on the same IP. Opt-in (free tier is 50/day)."""

    name = "reverseip"
    display = "Reverse IP"
    keyless = True
    homepage = "https://hackertarget.com/reverse-ip-lookup/"
    kinds = (KIND_DOMAIN, KIND_IP)
    category = "intel"
    cache_ttl = 24 * 3600
    min_interval = 2.0

    def available(self) -> bool:
        return os.environ.get("TT_ENABLE_REVERSE_IP", "").lower() in (
            "1", "true", "yes", "on")

    def lookup(self, ind: Indicator) -> SourceResult:
        try:
            r = self.session().get(
                "https://api.hackertarget.com/reverseiplookup/",
                params={"q": ind.value}, timeout=15)
        except requests.RequestException as exc:
            return self.fail(exc)
        if r.status_code != 200:
            return self.result(status="error", note=f"HTTP {r.status_code}")
        text = r.text.strip()
        if not text or "error" in text.lower() or "no DNS" in text.lower():
            return self.result(status="not_found")
        hosts = [line.strip() for line in text.splitlines() if line.strip()]
        return self.result(status="found", note=f"{len(hosts)} co-hosted host(s)",
                           detail={"hosts": hosts[:25]})


def _vcard_name(entity: Dict[str, Any]) -> str:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return ""
    for item in vcard[1]:
        if isinstance(item, list) and item and item[0] == "fn" and len(item) > 3:
            return str(item[3])
    return ""


def _vt_parse(source: Source, r: requests.Response, file_hash: str = "",
               url_value: str = "", vt_kind: str = "url") -> SourceResult:
    """Shared parser for every VirusTotal object response."""
    if r.status_code == 401:
        return source.result(status="unauthorized", note="invalid API key")
    if r.status_code == 404:
        return source.result(status="not_found")
    if r.status_code == 429:
        return source.result(status="error", note="rate limited (free tier: 4/min)")
    if r.status_code != 200:
        return source.result(status="error", note=f"HTTP {r.status_code}")
    try:
        data = r.json()
    except ValueError:
        return source.result(status="error", note="bad JSON")

    attr = ((data.get("data") or {}).get("attributes") or {})
    stats = attr.get("last_analysis_stats") or {}
    mal = int(stats.get("malicious", 0) or 0)
    susp = int(stats.get("suspicious", 0) or 0)
    total = int(sum(int(v or 0) for v in stats.values()) or 0)
    threat = (attr.get("popular_threat_classification") or {})

    detail = {
        "engines": True,
        "malicious": mal,
        "suspicious": susp,
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "total_engines": total,
        "reputation": attr.get("reputation"),
        "threat_label": threat.get("suggested_threat_label"),
    }
    if file_hash:
        first_seen = attr.get("first_submission_date")
        if isinstance(first_seen, (int, float)):
            first_seen = _dt.datetime.utcfromtimestamp(first_seen).strftime("%Y-%m-%d")
        detail.update({"meaningful_name": attr.get("meaningful_name"),
                       "type_description": attr.get("type_description"),
                       "size": attr.get("size"),
                       "first_submission": first_seen})
        link = f"https://www.virustotal.com/gui/file/{file_hash}"
    else:
        detail.update({"categories": list((attr.get("categories") or {}).items())[:4],
                       "last_analysis_date": attr.get("last_analysis_date")})
        link = f"https://www.virustotal.com/gui/{vt_kind}/{url_value}"

    if mal > 0:
        verdict = VERDICT_MALICIOUS if mal >= 3 else VERDICT_SUSPICIOUS
        note = f"{mal}/{total} engines flagged"
    elif susp > 0:
        verdict, note = VERDICT_SUSPICIOUS, f"{susp}/{total} suspicious"
    else:
        verdict, note = VERDICT_CLEAN, f"0/{total} engines"
    return source.result(status="found", verdict=verdict, detections=mal,
                         total=total, note=note, link=link, detail=detail)


# ==========================================================================
# Registry
# ==========================================================================

ALL_SOURCES: List[Source] = [
    # hashes
    CIRCLHashlookup(),
    AlienVaultOTXFile(),
    MalwareBazaar(),
    ThreatFox(),
    URLhausPayload(),
    VirusTotalFile(),
    HybridAnalysis(),
    MalShare(),
    Triage(),
    # urls
    AlienVaultOTXUrl(),
    URLScanUrl(),
    URLhausUrl(),
    VirusTotalUrl(),
    SafeBrowsing(),
    PhishTank(),
    # domains / ip
    AlienVaultOTXDomain(),
    VirusTotalDomain(),
    # intel
    DNSRecords(),
    RDAPWhois(),
    CertificateTransparency(),
    ReverseIP(),
]

SOURCE_MAP = {s.name: s for s in ALL_SOURCES}
