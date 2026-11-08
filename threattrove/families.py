"""Normalise vendor family labels to canonical family names.

A chip on a result page and the /family browse pages are two views of this one
function: a chip is the canonical set ``normalize(raw).families``, and the
index behind a browse page is that same function run over cached rows.

Design rules implemented here
-----------------------------
1. Clean, then case-fold (never trust vendor capitalisation or separators).
2. Strip vendor noise *before* tokenising: build suffixes, "!AV" buckets,
   trailing confidence phrases.
3. Reject hedges and generic markers before family extraction, so "Generic",
   "possible", "malicious_confidence_100%" can never become a family.
4. Tokenise on separators plus CamelCase, then look every token up in a
   CLOSED alias table. Every table entry has a role: family / variant /
   taxonomy / hedge. A token absent from the table is *unmapped*: it is
   reported, never guessed at.
5. Canonical key = frozenset of canonical family ids. Order of tokens is
   therefore irrelevant: "trojan.draftor/salat" and "trojan.salat/draftor"
   collapse, "trojan.mirai/gafgyt" keeps both Mirai and Gafgyt.
6. No fuzzy matching, no Levenshtein, no substring merging. If the family
   set is empty the label is "generic" (only taxonomy/hedge tokens) or
   "noise" (CVE id, test file, tool artefact, confidence score).
7. The key is a set; a *primary* family exists only for display, chosen by
   the leftmost family token, with ties broken by the corpus.

From the package root::

    python3 -m threattrove.families selftest
    python3 -m threattrove.families report labels.jsonl
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, Tuple

FAMILY, VARIANT, TAXONOMY, HEDGE = "family", "variant", "taxonomy", "hedge"

# --------------------------------------------------------------------------
# Closed alias table. Keys are case-folded tokens as they appear after
# separator/CamelCase splitting. Values are (role, canonical id).
# Adding a family here is a reviewed one-line change; nothing else in the
# pipeline needs to know about it.
# --------------------------------------------------------------------------
ALIASES: dict[str, tuple[str, str]] = {
    # --- families (canonical ids are stable, human-readable handles) ------
    "mirai": (FAMILY, "Mirai"),
    "gafgyt": (FAMILY, "Gafgyt"),
    "tsunami": (FAMILY, "Tsunami"),
    "draftor": (FAMILY, "Draftor"),
    "salat": (FAMILY, "Salat"),
    "salatstealer": (FAMILY, "Salat"),
    "amos": (FAMILY, "Amos"),
    "lumma": (FAMILY, "Lumma"),
    "lummastealer": (FAMILY, "Lumma"),
    "cryxos": (FAMILY, "Cryxos"),
    "modiloader": (FAMILY, "ModiLoader"),
    "modildr": (FAMILY, "ModiLoader"),
    "guloader": (FAMILY, "GuLoader"),
    "dacic": (FAMILY, "Dacic"),
    "sliver": (FAMILY, "Sliver"),
    "chaos": (FAMILY, "Chaos"),
    "nanocore": (FAMILY, "NanoCore"),
    "rozena": (FAMILY, "Rozena"),
    "mikey": (FAMILY, "Mikey"),
    "fragtor": (FAMILY, "Fragtor"),
    "yogi": (FAMILY, "Yogi"),
    "valley": (FAMILY, "Valley"),
    "silverfox": (FAMILY, "SilverFox"),
    "wingo": (FAMILY, "Wingo"),
    "wanna": (FAMILY, "Wanna"),
    "medusa": (FAMILY, "Medusa"),
    "sload": (FAMILY, "Sload"),
    "autoinfector": (FAMILY, "AutoInfector"),
    "barys": (FAMILY, "Barys"),
    "bladabindi": (FAMILY, "Bladabindi"),
    "formbook": (FAMILY, "Formbook"),
    "agenttesla": (FAMILY, "AgentTesla"),
    "negasteal": (FAMILY, "Negasteal"),
    "prometei": (FAMILY, "Prometei"),
    "nemucod": (FAMILY, "Nemucod"),
    "connectwise": (FAMILY, "ConnectWise Control"),
    "connectwisecontrol": (FAMILY, "ConnectWise Control"),
    "malxmr": (FAMILY, "MalXMR"),
    "zbot": (FAMILY, "Zbot"),
    "mofksys": (FAMILY, "Mofksys"),
    "zeus": (FAMILY, "Zeus"),
    "flubot": (FAMILY, "FluBot"),
    # --- taxonomy: type / platform / format / behaviour words -------------
    "trojan": (TAXONOMY, "trojan"),
    "troj": (TAXONOMY, "trojan"),
    "backdoor": (TAXONOMY, "backdoor"),
    "downloader": (TAXONOMY, "downloader"),
    "dropper": (TAXONOMY, "dropper"),
    "droppers": (TAXONOMY, "dropper"),
    "loader": (TAXONOMY, "loader"),
    "hacktool": (TAXONOMY, "hacktool"),
    "miner": (TAXONOMY, "miner"),
    "ransom": (TAXONOMY, "ransomware"),
    "ransomware": (TAXONOMY, "ransomware"),
    "stealer": (TAXONOMY, "stealer"),
    "spy": (TAXONOMY, "spyware"),
    "spyware": (TAXONOMY, "spyware"),
    "trojanspy": (TAXONOMY, "spyware"),
    "trojanspyware": (TAXONOMY, "spyware"),
    "adware": (TAXONOMY, "adware"),
    "worm": (TAXONOMY, "worm"),
    "virus": (TAXONOMY, "virus"),
    "rootkit": (TAXONOMY, "rootkit"),
    "keylogger": (TAXONOMY, "keylogger"),
    "injector": (TAXONOMY, "injector"),
    "powershell": (TAXONOMY, "powershell"),
    "msil": (TAXONOMY, "msil"),
    "java": (TAXONOMY, "java"),
    "js": (TAXONOMY, "javascript"),
    "vbs": (TAXONOMY, "vbscript"),
    "macho": (TAXONOMY, "macho"),
    "ole2": (TAXONOMY, "ole2"),
    "dll": (TAXONOMY, "dll"),
    "dllhijack": (TAXONOMY, "dll-hijack"),
    "exe": (TAXONOMY, "pe"),
    "elf": (TAXONOMY, "elf"),
    "linux": (TAXONOMY, "linux"),
    "unix": (TAXONOMY, "unix"),
    "win": (TAXONOMY, "windows"),
    "win32": (TAXONOMY, "windows"),
    "win64": (TAXONOMY, "windows"),
    "windows": (TAXONOMY, "windows"),
    "mac": (TAXONOMY, "macos"),
    "osx": (TAXONOMY, "macos"),
    "android": (TAXONOMY, "android"),
    "script": (TAXONOMY, "script"),
    "html": (TAXONOMY, "html"),
    "doc": (TAXONOMY, "document"),
    "xls": (TAXONOMY, "document"),
    "pdf": (TAXONOMY, "document"),
    "archive": (TAXONOMY, "archive"),
    "application": (TAXONOMY, "application"),
    "app": (TAXONOMY, "application"),
    "installer": (TAXONOMY, "installer"),
    "bundle": (TAXONOMY, "bundle"),
    "nsis": (TAXONOMY, "nsis"),
    "falsesign": (TAXONOMY, "invalid-signature"),
    "shell": (TAXONOMY, "shell"),
    "ddos": (TAXONOMY, "ddos"),
    "botnet": (TAXONOMY, "botnet"),
    "exploit": (TAXONOMY, "exploit"),
    "expl": (TAXONOMY, "exploit"),
    "dump": (TAXONOMY, "memory-dump"),
    "svm": (TAXONOMY, "scan-engine"),
    "rat": (TAXONOMY, "rat"),
    "agent": (TAXONOMY, "agent"),
    # --- hedges: "we saw something, we don't know what" -------------------
    "generic": (HEDGE, "generic"),
    "genericfca": (HEDGE, "generic"),
    "malware": (HEDGE, "generic"),
    "filerepmalware": (HEDGE, "generic"),
    "infostl": (HEDGE, "infostealer"),
    "obfuse": (HEDGE, "obfuscated"),
    "obfuscated": (HEDGE, "obfuscated"),
    "shellcoderunner": (HEDGE, "shellcode-runner"),
    "suspicious": (HEDGE, "suspicious"),
    "suspic": (HEDGE, "suspicious"),
    "possible": (HEDGE, "possible"),
    "reputation": (HEDGE, "reputation"),
    "potentially": (HEDGE, "pua"),
    "unwanted": (HEDGE, "pua"),
    "pua": (HEDGE, "pua"),
    "pup": (HEDGE, "pua"),
    "riskware": (HEDGE, "riskware"),
    "malicious": (HEDGE, "score"),
    "confidence": (HEDGE, "score"),
    "dloadr": (HEDGE, "downloader"),
    # --- variants: recognised as a variant slot, deliberately not a family -
    "gameover": (VARIANT, "GameOver"),
    "marte": (VARIANT, "Marte"),
    "checksumcontroller": (VARIANT, "ChecksumController"),
}

# Labels that are not malware names at all.
NOISE: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^cve-\d{4}-\d{4,}$", re.I), "vulnerability-id"),
    (re.compile(r"^capa[_-]", re.I), "tool-artefact"),
    (re.compile(r"^(?:virus\.)?eicar(?:[./]test)?$", re.I), "test-file"),
]

SEP = re.compile(r"[.\/\[\]:,_;\s()%\-]+")
CAMEL = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+")
BUILD_SUFFIX = re.compile(r"-\d+(?:-\d+)*$")
BANG_SUFFIX = re.compile(r"![^!]*$")
TRAILING_PHRASE = re.compile(
    r"\s+(?:suspicious application|potentially unwanted application|"
    r"trojan|virus|malware)\s*$",
    re.I,
)


@dataclass
class Normalized:
    raw: str
    cleaned: str
    outcome: str                        # families | generic | noise
    families: tuple[str, ...] = ()      # sorted canonical ids
    primary: str | None = None
    variants: tuple[str, ...] = ()      # mapped variant-role tokens
    unmapped: tuple[str, ...] = ()      # tokens the table does not know
    reason: str | None = None           # noise reason

    @property
    def key(self) -> frozenset[str]:
        return frozenset(self.families)


def clean(label: str) -> str:
    s = label.strip()
    s = BANG_SUFFIX.sub("", s)
    s = BUILD_SUFFIX.sub("", s)
    s = TRAILING_PHRASE.sub("", s)
    return s.strip(" .-_/:")


def _tokens(cleaned: str) -> list[str]:
    out: list[str] = []
    # split on separators first, then handle CamelCase per token
    for chunk in SEP.split(cleaned):
        if not chunk:
            continue
        low = chunk.casefold()
        if low in ALIASES:
            out.append(low)
            continue
        parts = CAMEL.findall(chunk)
        if len(parts) > 1:
            out.extend(p.casefold() for p in parts if p)
        else:
            out.append(low)
    return out


def _meaningful(tok: str) -> bool:
    """Digits and single letters are separators in disguise, never families."""
    return not (tok.isdigit() or len(tok) < 2)


def normalize(label: str) -> Normalized:
    raw = label
    stripped = label.strip()
    # Noise patterns run on the raw label first: build-suffix stripping would
    # otherwise turn "CVE-2017-0147" into "CVE".
    for pat, reason in NOISE:
        if pat.match(stripped):
            return Normalized(raw, stripped, "noise", reason=reason)
    cleaned = clean(label)
    if not cleaned:
        return Normalized(raw, cleaned, "noise", reason="empty")
    for pat, reason in NOISE:
        if pat.match(cleaned):
            return Normalized(raw, cleaned, "noise", reason=reason)

    fam: list[str] = []
    var: list[str] = []
    unm: list[str] = []
    for tok in _tokens(cleaned):
        entry = ALIASES.get(tok)
        if entry is None:
            if _meaningful(tok):
                unm.append(tok)
        elif entry[0] == FAMILY:
            fam.append(entry[1])
        elif entry[0] == VARIANT:
            var.append(entry[1])
        # taxonomy/hedge contribute nothing to the key by design

    families = tuple(sorted(set(fam)))
    primary = fam[0] if fam else None
    outcome = "families" if families else "generic"
    return Normalized(
        raw, cleaned, outcome, families, primary,
        tuple(sorted(set(var))), tuple(sorted(set(unm))),
        None if families else "no family token",
    )


# --------------------------------------------------------------------------
# Self-tests: the behaviours the design promises, plus the traps found in
# production data.
# --------------------------------------------------------------------------
CASES: list[tuple[str, str, set[str]]] = [
    # same family, different vendor phrasing
    ("Trojan[Backdoor]/Linux.Mirai", "families", {"Mirai"}),
    ("Trojan/Linux.Mirai", "families", {"Mirai"}),
    ("Trojan.Linux.Mirai", "families", {"Mirai"}),
    ("Linux.Mirai.Generic", "families", {"Mirai"}),
    ("Linux/Mirai.BDB trojan", "families", {"Mirai"}),
    ("trojan.mirai", "families", {"Mirai"}),
    ("trojan.mirai/smlbo20", "families", {"Mirai"}),
    ("Unix.Trojan.Gafgyt-9939811-0", "families", {"Gafgyt"}),
    ("trojan.mirai/gafgyt", "families", {"Mirai", "Gafgyt"}),
    # order-independence
    ("trojan.draftor/salat", "families", {"Draftor", "Salat"}),
    ("trojan.salat/draftor", "families", {"Draftor", "Salat"}),
    ("trojan.amos/infostl", "families", {"Amos"}),
    ("trojan.infostl/amos", "families", {"Amos"}),
    ("trojan.salatstealer/lummastealer", "families", {"Salat", "Lumma"}),
    ("trojan.lummastealer/salat", "families", {"Salat", "Lumma"}),
    # distinct families stay distinct
    ("trojan.gafgyt", "families", {"Gafgyt"}),
    ("trojan.fragtor/mikey", "families", {"Fragtor", "Mikey"}),
    ("trojan.mikey/rozena", "families", {"Mikey", "Rozena"}),
    ("trojan.rozena/mikey", "families", {"Mikey", "Rozena"}),
    # hedges and junk
    ("trojan.", "generic", set()),
    ("Trojan.Generic", "generic", set()),
    ("Malware", "generic", set()),
    ("Linux/malicious_confidence_100%", "generic", set()),
    ("JS/Obfuscated.K suspicious application", "generic", set()),
    ("trojan.filerepmalware/abmrisk", "generic", set()),
    ("Win64/Injector.AOW trojan", "generic", set()),
    ("EICAR", "noise", set()),
    ("virus.eicar/test", "noise", set()),
    ("CVE-2017-0147", "noise", set()),
    ("Capa_reference_Google_Public_DNS_server", "noise", set()),
    # no guessing on unknown tokens
    ("WebMonitor/RevCode RAT", "generic", set()),
    ("trojan.acsogenixx/coruna", "generic", set()),
    # cross-source forms
    ("BScope.TrojanSpy.Zbot", "families", {"Zbot"}),
    ("Worm:Win32/Mofksys.RND!MTB AV", "families", {"Mofksys"}),
    ("Possible Zeus GameOver/FluBot", "families", {"Zeus", "FluBot"}),
    ("JS/TrojanDropper.ModiLoader", "families", {"ModiLoader"}),
    ("HackTool/ConnectWiseControl.i", "families", {"ConnectWise Control"}),
    ("SVM:TrojanDownloader/JS.Nemucod", "families", {"Nemucod"}),
    ("Adware.Win64.BundleInstaller.vl", "generic", set()),
]


#: Where each source keeps its malware label, and nothing else. VirusTotal
#: flattens the whole label into ``threat_label``; Hybrid Analysis exposes the
#: same string as ``family``; the feeds tag the family in ``signature`` or
#: ``malware``. A source that only carries a free-text ``note`` is left alone:
#: reading prose back as a label is how a lookup starts inventing names.
LABEL_FIELDS: tuple[tuple[str, str], ...] = (
    ("hybridanalysis", "family"),
    ("malwarebazaar", "signature"),
    ("threatfox", "malware"),
    ("urlhaus", "signature"),
    ("virustotal", "threat_label"),
)

#: MetaDefender's ``signature`` is deliberately absent above: it is a per-vendor
#: detection string ("Unknown/Eicar!428cbHx5"), not a family tag, and mapping it
#: would put engine noise in a chip.


def labels_of(row: dict) -> list[str]:
    """Every vendor label a single result row carries, in field order."""
    detail = row.get("detail") or {}
    if not isinstance(detail, dict):
        return []
    src = str(row.get("source") or "").split(".")[0]
    out: list[str] = []
    for prefix, field_name in LABEL_FIELDS:
        if src == prefix:
            value = detail.get(field_name)
            if isinstance(value, str) and value.strip():
                out.append(value.strip())
    return out


def chips_of(row: dict) -> list[dict]:
    """The family chips to draw for one reputation row.

    Primary family first, then the rest alphabetically, duplicates dropped: a
    row that says both ``Linux.Mirai.Generic`` and ``trojan.mirai/ddos`` is
    still one family on screen. An empty list is the normal, silent answer for
    generic, noise, and unmapped labels -- the template draws nothing.
    """
    chips: list[dict] = []
    seen: set[str] = set()
    for raw in labels_of(row):
        norm = normalize(raw)
        if norm.outcome != "families":
            continue
        ordered = ([norm.primary] if norm.primary else []) + [
            f for f in norm.families if f != norm.primary]
        for i, fam in enumerate(ordered):
            if not fam or fam in seen:
                continue
            seen.add(fam)
            chips.append({"name": fam, "primary": i == 0, "raw": raw})
    return chips


def build_index(rows: Iterable[tuple]) -> Dict[str, Dict[str, Dict[str, set]]]:
    """Fold cached rows into ``family -> sample value -> who named it``.

    ``rows`` yields ``(value, source, payload, ...)``, the shape
    ``Store.cache_rows`` returns (only the first three are read). Only the
    structured label fields are read
    (``LABEL_FIELDS``), so a provider's prose note can never invent a family
    here any more than it can in a chip.

    The result maps each family to the samples attributed to it, and each
    sample to the sources and the raw vendor spellings that got it there —
    which is what lets the browse page say *why* a sample belongs to a family
    instead of asking anyone to trust a bucket.
    """
    index: Dict[str, Dict[str, Dict[str, set]]] = {}
    for row in rows:
        value, source, payload = row[0], row[1], row[2]
        detail = (payload or {}).get("detail") or {}
        if not isinstance(detail, dict):
            continue
        for raw in labels_of({"source": source, "detail": detail}):
            norm = normalize(raw)
            if norm.outcome != "families":
                continue
            for fam in norm.families:
                entry = index.setdefault(fam, {}).setdefault(
                    value, {"sources": set(), "labels": set()})
                entry["sources"].add(source)
                entry["labels"].add(raw)
    return index


def label_sources(rows: Iterable[tuple]) -> Dict[str, Dict[str, set]]:
    """``family -> raw label -> the sources that actually sent that string``.

    ``build_index`` keeps one set of sources per sample, which answers "who
    named this sample" but not "who used this spelling". The browse page needs
    the second answer to tell a feed's own spelling apart from one engine's
    variant token, so this walks the same rows and keeps the pairing the fold
    throws away.
    """
    out: Dict[str, Dict[str, set]] = {}
    for row in rows:
        source, payload = row[1], row[2]
        detail = (payload or {}).get("detail") or {}
        if not isinstance(detail, dict):
            continue
        for raw in labels_of({"source": source, "detail": detail}):
            norm = normalize(raw)
            if norm.outcome != "families":
                continue
            for fam in set(norm.families):
                out.setdefault(fam, {}).setdefault(raw, set()).add(source)
    return out


def label_split(raws: Iterable[str]) -> Tuple[list, list]:
    """Split raw labels into plain names and labels carrying extra noise.

    "Clean" means the label resolves to this family and nothing else needs
    explaining: no token was left unrecognised, and no second family is named.
    Everything else goes to the second list, which is what the page folds away:
    a VirusTotal engine suffix (``trojan.mirai/smlbo20``), a variant token
    (``Linux/Mirai.FDF trojan``), or a co-attribution
    (``trojan.mirai/gafgyt``). The split is derived from the normaliser itself,
    never from a hand-kept allowlist of nice-looking strings.
    """
    plain: list = []
    variant: list = []
    for raw in raws:
        norm = normalize(raw)
        if norm.unmapped or len(set(norm.families)) > 1:
            variant.append(raw)
        else:
            plain.append(raw)
    return plain, variant


def selftest() -> int:
    bad = 0
    for label, want_outcome, want_fams in CASES:
        got = normalize(label)
        ok = got.outcome == want_outcome and set(got.families) == want_fams
        if not ok:
            bad += 1
            print(f"FAIL {label!r}: outcome={got.outcome} families={got.families} "
                  f"unmapped={got.unmapped} (wanted {want_outcome} {sorted(want_fams)})")
    print(f"{len(CASES) - bad}/{len(CASES)} cases pass")
    return 1 if bad else 0


def _collapse(rows: list[dict]) -> list[dict]:
    """HA exposes family and family_raw for the same rows: take max, not sum.

    Without this the HA half of the corpus is counted twice.
    """
    agg: dict[tuple[str, str], int] = {}
    for r in rows:
        root = r["source"].split(".")[0]
        key = (root, r["label"])
        agg[key] = max(agg.get(key, 0), r["n"])
    return [{"source": s, "label": lab, "n": c} for (s, lab), c in agg.items()]


def report(path: str) -> None:
    raw_rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    rows = _collapse(raw_rows)
    res = {i: normalize(r["label"]) for i, r in enumerate(rows)}
    n = {i: r["n"] for i, r in enumerate(rows)}
    total_n = sum(n.values())

    print(f"label rows: {len(raw_rows)} -> {len(rows)} after collapsing HA's "
          f"family/family_raw overlap")
    print(f"distinct label strings: {len({r['label'] for r in rows})}, "
          f"cached hash results: {total_n}")
    per_src = Counter()
    for i, r in enumerate(rows):
        per_src[r["source"]] += n[i]
    for src, c in sorted(per_src.items()):
        print(f"  {src:<28} {c:>5} results")

    w_out = Counter()
    c_out = Counter()
    for i, r in res.items():
        w_out[r.outcome] += n[i]
        c_out[r.outcome] += 1
    print("\noutcome        rows   %rows   results   %results")
    for oc in ("families", "generic", "noise"):
        print(f"{oc:<12} {c_out[oc]:>6}  {c_out[oc] / len(rows):>6.1%}"
              f"  {w_out[oc]:>8}  {w_out[oc] / total_n:>7.1%}")

    keys = {r.key for r in res.values() if r.outcome == "families"}
    print(f"\ndistinct family keys: {len(keys)}")

    groups: dict[frozenset[str], list[str]] = defaultdict(list)
    for i, r in res.items():
        if r.outcome == "families":
            groups[r.key].append(f"{rows[i]['source'][:2]}:{rows[i]['label']}")
    print("=== merge table (keys with >1 label) ===")
    for key in sorted(groups, key=lambda k: (-len(groups[k]), sorted(k))):
        labs = groups[key]
        if len(labs) < 2:
            continue
        print(f"{'+'.join(sorted(key)):<28} {len(labs):>2} labels  e.g. "
              f"{', '.join(sorted(labs)[:3])}")

    print("\n=== deliberate multi-family keys (never collapsed) ===")
    for key in sorted((k for k in keys if len(k) > 1), key=lambda k: sorted(k)):
        print(f"{'+'.join(sorted(key)):<28} {len(groups[key])} labels: "
              f"{', '.join(sorted(groups[key]))}")

    print("\n=== unmapped tokens (never become families) ===")
    unm = Counter()
    for r in res.values():
        for t in r.unmapped:
            unm[t] += 1
    for tok, c in unm.most_common(60):
        print(f"  {tok:<24} {c}")

    print("\n=== inverted family index (the view Phase B/ATT&CK consumes) ===")
    inv: dict[str, int] = Counter()
    inv_lab: dict[str, int] = Counter()
    for i, r in res.items():
        for fid in r.families:
            inv[fid] += n[i]
            inv_lab[fid] += 1
    for fid, c in inv.most_common():
        print(f"  {fid:<24} {c:>4} results  {inv_lab[fid]:>3} label rows")
    attributed = sum(n[i] for i, r in res.items() if r.families)
    print(f"  {'(totals)':<24} {sum(inv.values()):>4} attributions over "
          f"{attributed} attributed results ({attributed / total_n:.0%} of "
          f"{total_n}); multi-family rows counted once per family")

    print("\n=== rows with no family (generic/noise) ===")
    for i in sorted(res, key=lambda i: (res[i].outcome, rows[i]["label"])):
        r = res[i]
        if r.outcome == "families":
            continue
        print(f"  [{r.outcome[:4]}] {rows[i]['label']:<46} "
              f"n={n[i]:<3} unmapped={list(r.unmapped)}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "selftest"
    if cmd == "selftest":
        sys.exit(selftest())
    if cmd == "report":
        report(sys.argv[2] if len(sys.argv) > 2 else "tt_labels.jsonl")
        sys.exit(0)
    if cmd == "normalize":
        for lab in sys.argv[2:]:
            print(normalize(lab))
        sys.exit(0)
    print(__doc__)
    sys.exit(2)
