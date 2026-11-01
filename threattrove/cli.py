"""Command line interface for threattrove.

Examples
--------
    threattrove 44d88612fea8a8f36de82e1278abb02f
    threattrove https://example.com/login
    threattrove example.com --json
    threattrove --feed iocs.csv --out results.csv
    threattrove --feed suspicious.txt --fail-on-malicious
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .core import (
    VERSION,
    VERDICT_CLEAN,
    VERDICT_KNOWN_GOOD,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    Engine,
    Indicator,
    Report,
    Store,
    hash_type,
    hashes_for_file,
    parse_indicator,
)
from .sources import ALL_SOURCES, SOURCE_MAP

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_MALICIOUS = 3

# --------------------------------------------------------------------------
# Terminal styling
# --------------------------------------------------------------------------

_USE_COLOR = (
    sys.stdout.isatty()
    and not os.environ.get("NO_COLOR")
    and os.environ.get("TERM") != "dumb"
)

_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
}


def c(text: str, *styles: str) -> str:
    """Colourise *text* when stdout supports it."""
    if not _USE_COLOR or not styles:
        return text
    pre = "".join(_CODES[s] for s in styles if s in _CODES)
    return f"{pre}{text}{_CODES['reset']}"


VERDICT_STYLE = {
    VERDICT_MALICIOUS: ("red", "bold"),
    VERDICT_SUSPICIOUS: ("yellow", "bold"),
    VERDICT_CLEAN: ("green",),
    VERDICT_KNOWN_GOOD: ("cyan",),
    VERDICT_UNKNOWN: ("grey",),
}

VERDICT_BADGE = {
    VERDICT_MALICIOUS: "MALICIOUS",
    VERDICT_SUSPICIOUS: "SUSPICIOUS",
    VERDICT_CLEAN: "CLEAN",
    VERDICT_KNOWN_GOOD: "KNOWN GOOD",
    VERDICT_UNKNOWN: "UNKNOWN",
}

STATUS_MARK = {
    "found": "\u25cf",
    "not_found": "\u25cb",
    "error": "!",
    "unauthorized": "\u2717",
    "timeout": "\u23f1",
    "skipped": "-",
    "unknown": "\u25cb",
}


def colour_verdict(verdict: str, text: Optional[str] = None) -> str:
    return c(text or VERDICT_BADGE.get(verdict, verdict.upper()),
             *VERDICT_STYLE.get(verdict, ("grey",)))


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="threattrove",
        description=("Multi-source reputation lookup for file hashes, URLs, "
                     "domains and IP addresses. Aggregates free and keyed "
                     "threat-intelligence feeds into a single VirusTotal-style "
                     "verdict."),
        epilog=("Environment: ABUSECH_AUTH_KEY, VT_API_KEY, OTX_API_KEY, "
                "HA_API_KEY, MALSHARE_API_KEY, TRIAGE_API_KEY, "
                "URLSCAN_API_KEY, GSB_API_KEY, PHISHTANK_APPKEY, TT_ENABLE_REVERSE_IP, "
                "TT_DB, TT_CACHE_DB, TT_CACHE_TTL, TT_TIMEOUT, TT_DEADLINE."),
    )
    p.add_argument("indicators", nargs="*", metavar="INDICATOR",
                   help="hash, URL, domain or IP to look up")

    src = p.add_argument_group("input")
    src.add_argument("--file", "-f", action="append", default=[],
                     metavar="PATH",
                     help="file with one indicator per line (repeatable)")
    src.add_argument("--csv", action="append", default=[], metavar="PATH",
                     help="CSV file of indicators; header row auto-detected "
                          "(repeatable)")
    src.add_argument("--feed", action="append", default=[], metavar="PATH",
                     help="feed file, format auto-detected from extension and "
                          "content: .csv, .json/.jsonl or newline (repeatable)")

    out = p.add_argument_group("output")
    out.add_argument("--json", "-j", action="store_true",
                     help="emit JSON instead of a text report")
    out.add_argument("--out", "-o", metavar="PATH",
                     help="write results to PATH (format from extension: "
                          ".json, .csv, .jsonl)")
    out.add_argument("--quiet", "-q", action="store_true",
                     help="suppress progress output")
    out.add_argument("--fail-on-malicious", action="store_true",
                     help="exit 3 when any indicator is malicious "
                          "(handy in CI pipelines)")

    eng = p.add_argument_group("engine")
    eng.add_argument("--sources", metavar="LIST",
                     help="comma-separated source names, categories "
                          "(reputation,intel) or groups (keyless); default: all")
    eng.add_argument("--list-sources", action="store_true",
                     help="show available sources and exit")
    eng.add_argument("--no-cache", action="store_true",
                     help="ignore the SQLite result cache")
    eng.add_argument("--clear-cache", action="store_true",
                     help="delete cached results before running")
    eng.add_argument("--workers", type=int, default=6, metavar="N",
                     help="parallel lookups per indicator (default 6)")
    eng.add_argument("--timeout", type=float, default=None, metavar="SECS",
                     help="overall deadline per indicator (default 45)")

    loc = p.add_argument_group("local intel")
    loc.add_argument("--add-local", metavar="VALUE", action="append",
                     default=[],
                     help="store VALUE in the local database (repeatable)")
    loc.add_argument("--label", default="malware",
                     help="label for --add-local (default: malware)")
    loc.add_argument("--note", default="", help="note for --add-local")
    loc.add_argument("--import-local", metavar="FILE",
                     help="import every hash found in FILE (CSV/TSV/text) into "
                          "the local database")
    loc.add_argument("--import-limit", type=int, default=0, metavar="N",
                     help="import at most N hashes from --import-local")
    loc.add_argument("--dry-run", action="store_true",
                     help="with --import-local: report what would change, "
                          "write nothing")
    loc.add_argument("--list-local", action="store_true",
                     help="list local database entries and exit")
    loc.add_argument("--delete-local", metavar="VALUE",
                     help="remove VALUE from the local database")
    loc.add_argument("--stats", action="store_true",
                     help="show cache/local database statistics and exit")

    p.add_argument("--hash-file", action="append", default=[], metavar="PATH",
                   help="hash a local file (md5/sha1/sha256) and look it up")
    p.add_argument("--version", "-V", action="version",
                   version=f"threattrove {VERSION}")
    return p


# --------------------------------------------------------------------------
# Source selection
# --------------------------------------------------------------------------

def select_sources(spec: Optional[str]) -> List[Any]:
    if not spec:
        return list(ALL_SOURCES)
    wanted: List[str] = []
    groups: List[str] = []
    for token in (t.strip().lower() for t in spec.split(",")):
        if not token:
            continue
        if token in ("keyless", "reputation", "intel"):
            groups.append(token)
        else:
            wanted.append(token)

    chosen = []
    for s in ALL_SOURCES:
        if s.name in wanted:
            chosen.append(s)
            continue
        for g in groups:
            if g == "keyless" and s.keyless:
                chosen.append(s)
                break
            if g == s.category:
                chosen.append(s)
                break
    unknown = [w for w in wanted if w not in SOURCE_MAP]
    if unknown:
        print(f"unknown source(s): {', '.join(unknown)}", file=sys.stderr)
        print("use --list-sources to see the available names", file=sys.stderr)
    return chosen


def print_sources(store: Optional[Store] = None) -> None:
    rows: List[Tuple[str, ...]] = []
    for s in ALL_SOURCES:
        key = s.key()
        if s.keyless and not s.available():
            state = "opt-in"
        elif s.keyless:
            state = "open"
        elif key:
            state = "key ok"
        elif s.env_key:
            state = f"set {s.env_key}"
        else:
            state = "open"
        rows.append((s.name, ",".join(s.kinds), s.category, state,
                     (s.display or s.name)[:38]))

    w0 = max(len(r[0]) for r in rows)
    w1 = max(len(r[1]) for r in rows)
    w3 = max(len(r[3]) for r in rows)
    print(c(f"{'SOURCE'.ljust(w0)}  {'KINDS'.ljust(w1)}  {'CATEGORY':<10}  "
            f"{'AUTH'.ljust(w3)}  DESCRIPTION", "bold"))
    for name, kinds, cat, state, desc in rows:
        tint = "green" if state == "key ok" else (
            "grey" if state.startswith("set") else
            "yellow" if state == "opt-in" else "cyan")
        print(f"{name.ljust(w0)}  {kinds.ljust(w1)}  {cat:<10}  "
              f"{c(state.ljust(w3), tint)}  {c(desc, 'dim')}")
    active = sum(1 for s in ALL_SOURCES if s.available())
    print()
    print(f"{active}/{len(ALL_SOURCES)} sources active. "
          "Sources showing a variable name need that environment variable set.")
    if store is not None:
        st = store.stats()
        print(f"cache: {st.get('cached_entries', 0)} entries, "
              f"local db: {st.get('local_entries', 0)} entries")


# --------------------------------------------------------------------------
# Input collection
# --------------------------------------------------------------------------

HASH_HEADERS = {"hash", "hashes", "sha256", "sha256_hash", "sha1", "sha1_hash",
                "md5", "md5_hash", "file_hash", "sample_hash"}
URL_HEADERS = {"url", "urls", "uri", "link", "ioc_url"}
DOMAIN_HEADERS = {"domain", "host", "hostname", "fqdn", "domain_name"}
ANY_HEADERS = HASH_HEADERS | URL_HEADERS | DOMAIN_HEADERS | {
    "indicator", "value", "ioc", "indicator_value", "observable", "sha256sum"}


def _pick_column(header: Sequence[str]) -> Optional[int]:
    lowered = [h.strip().lower().replace("-", "_").replace(" ", "_")
               for h in header]
    for priority in (ANY_HEADERS,):
        for idx, name in enumerate(lowered):
            if name in priority:
                return idx
    return None


def read_plain(path: str) -> List[str]:
    out: List[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line)
    return out


def read_csv_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        sample = fh.read(8192)
        fh.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.reader(fh, dialect)
        rows = [r for r in reader if r and any(f.strip() for f in r)]
    if not rows:
        return []
    first = [f.strip() for f in rows[0]]
    col = _pick_column(first)
    if col is None:
        # no recognisable header: keep every cell that parses
        return [f.strip() for row in rows for f in row if f.strip()]
    if any(f.lower() in ANY_HEADERS for f in first):
        body = rows[1:]
    else:
        body = rows
    out = []
    for row in body:
        if col < len(row):
            val = row[col].strip()
            if val:
                out.append(val)
    return out


def read_json_file(path: str) -> List[str]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    items: List[Any] = []
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            items = json.loads(text)
        except json.JSONDecodeError:
            items = []
    else:
        # JSONL / ndjson
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    out: List[str] = []
    for it in items:
        if isinstance(it, str):
            out.append(it)
        elif isinstance(it, dict):
            for key in ("indicator", "value", "hash", "sha256", "md5", "sha1",
                        "url", "domain", "ioc"):
                if key in it and isinstance(it[key], str):
                    out.append(it[key])
                    break
    return out


def read_feed(path: str) -> List[str]:
    ext = Path(path).suffix.lower()
    if ext in (".csv", ".tsv"):
        return read_csv_file(path)
    if ext in (".json", ".jsonl", ".ndjson"):
        return read_json_file(path)
    head = ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096).lstrip()
    except OSError as exc:
        print(f"cannot read {path}: {exc}", file=sys.stderr)
        return []
    if head.startswith("[") or head.startswith("{"):
        return read_json_file(path)
    return read_plain(path)


def collect(args: argparse.Namespace) -> Tuple[List[Indicator], List[str]]:
    raw: List[str] = list(args.indicators)

    for path in args.file:
        raw.extend(read_plain(path))
    for path in args.csv:
        raw.extend(read_csv_file(path))
    for path in args.feed:
        raw.extend(read_feed(path))
    for path in args.hash_file:
        try:
            raw.append(hashes_for_file(path)["sha256"])
        except OSError as exc:
            print(f"cannot hash {path}: {exc}", file=sys.stderr)

    indicators: List[Indicator] = []
    rejected: List[str] = []
    seen = set()
    for item in raw:
        ind = parse_indicator(item)
        if ind is None:
            rejected.append(item)
            continue
        key = (ind.kind, ind.value)
        if key in seen:
            continue
        seen.add(key)
        indicators.append(ind)
    return indicators, rejected


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def _rule(width: int = 78, char: str = "\u2500") -> str:
    return c(char * width, "grey")


def _short(value: str, limit: int = 34) -> str:
    return value if len(value) <= limit else value[:limit - 1] + "\u2026"


def render_report(report: Report, verbose: bool = True) -> str:
    ind = report.indicator
    verdict = report.verdict()
    lines: List[str] = []
    lines.append("")
    lines.append(c(f"\u2501\u2501 {_short(ind.raw or ind.value, 66)} ", "bold"))
    lines.append("")
    lines.append(f"  {c(ind.label, 'dim')}"
                 + (f"  {c(_short(ind.value, 74), 'dim')}"
                    if ind.value != ind.raw else ""))
    badge = colour_verdict(verdict)
    lines.append(f"  {badge}    {report.confidence()}% confidence    "
                 f"{c(report.headline(), 'dim')}")
    if verbose:
        det, tot = report.engine_ratio()
        if tot:
            lines.append(f"  {c('detections', 'dim')}  {det}/{tot}")
        lines.append("")

    rep = report.reputation()
    if rep:
        lines.append("  " + c("SECURITY SOURCES", "bold"))
        lines.append("  " + _rule(74))
        for r in rep:
            lines.append(_fmt_result(r))
        lines.append("")

    intel = report.intel()
    if intel:
        lines.append("  " + c("CONTEXT / INTELLIGENCE", "bold"))
        lines.append("  " + _rule(74))
        for r in intel:
            lines.append(_fmt_result(r))
        lines.append("")

    if not rep and not intel:
        lines.append("  " + c("no sources were applicable to this indicator",
                              "yellow"))
        lines.append("")

    lines.append("  " + c(f"elapsed {report.elapsed:.2f}s  \u00b7  "
                          f"{len(rep)} security sources queried", "grey"))
    return "\n".join(lines)


def _fmt_result(r: Any) -> str:
    mark = STATUS_MARK.get(r.status, "?")
    tint = VERDICT_STYLE.get(r.verdict, ("grey",))
    if r.status in ("error", "unauthorized", "timeout"):
        tint = ("grey",)
    name = r.source.ljust(16)
    badge = VERDICT_BADGE.get(r.verdict, r.verdict.upper()).ljust(10)
    ratio = f"{r.detections}/{r.total}" if r.total else ""
    note = r.note or ""
    if len(note) > 44:
        note = note[:43] + "\u2026"
    return (f"  {c(mark, *tint)} {name} {c(badge, *tint)} "
            f"{c(ratio.ljust(7), 'dim')} {c(note, 'dim')}")


def render_text(reports: Sequence[Report], verbose: bool = True) -> str:
    if len(reports) == 1:
        return render_report(reports[0], verbose)
    chunks = [render_report(r, verbose=False) for r in reports]
    tally: Dict[str, int] = {}
    for r in reports:
        tally[r.verdict()] = tally.get(r.verdict(), 0) + 1
    summary = ["", c("\u2501\u2501 summary ", "bold"), ""]
    for verdict in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS, VERDICT_CLEAN,
                    VERDICT_KNOWN_GOOD, VERDICT_UNKNOWN):
        if tally.get(verdict):
            summary.append(f"  {colour_verdict(verdict).ljust(22)} "
                           f"{tally[verdict]}")
    summary.append("")
    summary.append(f"  {len(reports)} indicator(s) checked in "
                   f"{sum(r.elapsed for r in reports):.1f}s of query time")
    return "\n".join(chunks) + "\n" + "\n".join(summary)


def report_row(report: Report) -> Dict[str, Any]:
    ind = report.indicator
    rep = report.reputation()
    return {
        "indicator": ind.raw or ind.value,
        "kind": ind.kind,
        "verdict": report.verdict(),
        "score": report.score(),
        "confidence": report.confidence(),
        "headline": report.headline(),
        "flagged_by": ";".join(report.flagged_by()),
        "sources_ok": sum(1 for r in rep if r.status == "found"),
        "sources_failed": sum(1 for r in rep
                              if r.status in ("error", "unauthorized",
                                              "timeout")),
        "elapsed": round(report.elapsed, 2),
    }


CSV_FIELDS = ["indicator", "kind", "verdict", "score", "confidence",
              "headline", "flagged_by", "sources_ok", "sources_failed",
              "elapsed"]


def write_csv(path: str, reports: Sequence[Report]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for r in reports:
            writer.writerow(report_row(r))


def write_json(path: str, reports: Sequence[Report]) -> None:
    payload = [r.to_dict() for r in reports]
    Path(path).write_text(json.dumps(payload, indent=2, default=str),
                          encoding="utf-8")


def write_jsonl(path: str, reports: Sequence[Report]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for r in reports:
            fh.write(json.dumps(r.to_dict(), default=str) + "\n")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def _progress_printer(total: int, quiet: bool):
    if quiet or not total:
        return None
    state = {"n": 0, "t0": time.time()}

    def cb(report: Report) -> None:
        state["n"] += 1
        n = state["n"]
        if total == 1:
            return
        if not sys.stderr.isatty():
            return
        verdict = report.verdict()
        sys.stderr.write(
            f"\r  {n}/{total}  {colour_verdict(verdict, verdict.upper()):<18} "
            f"{_short(report.indicator.raw or report.indicator.value, 40)}"
            f"\033[K")
        sys.stderr.flush()
        if n == total:
            sys.stderr.write("\r" + " " * 78 + "\r")
            sys.stderr.flush()

    return cb


def cmd_list_local(store: Store) -> int:
    entries = store.list_local()
    if not entries:
        print("local database is empty")
        return EXIT_OK
    print(c(f"{'KIND':<8} {'VALUE':<66} {'LABEL':<12} NOTE", "bold"))
    for e in entries:
        print(f"{e.get('kind', ''):<8} {_short(str(e.get('value', '')), 66):<66}"
              f" {str(e.get('label', ''))[:12]:<12} {e.get('note', '')}")
    print(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}")
    return EXIT_OK


def cmd_import_local(store: Store, path: str, label: str, note: str,
                     limit: int = 0, dry_run: bool = False) -> int:
    """Load a hash dump into the local corpus, streaming and chunk-committed."""
    from .bulk import iter_hash_tokens

    src = Path(path)
    if not src.is_file():
        print(f"no such file: {path}", file=sys.stderr)
        return EXIT_USAGE

    counts: Dict[str, int] = {"md5": 0, "sha1": 0, "sha256": 0}
    total = 0
    t0 = time.time()

    if dry_run:
        # Membership check only: report the delta without writing anything.
        buf: List[str] = []
        already = 0
        for algo, value in iter_hash_tokens(src, limit=limit):
            counts[algo] = counts.get(algo, 0) + 1
            total += 1
            buf.append(value)
            if len(buf) >= 5000:
                already += store.count_local_in("hash", buf)
                buf = []
        if buf:
            already += store.count_local_in("hash", buf)
        print(c(f"dry run: {src.name}", "bold"))
        _print_import_counts(counts, total, time.time() - t0)
        print(f"  already stored     {already}")
        print(f"  would insert       {total - already}")
        print(c("  nothing written", "grey"))
        return EXIT_OK

    def pairs() -> Iterable[Tuple[str, str]]:
        nonlocal total
        for algo, value in iter_hash_tokens(src, limit=limit):
            counts[algo] = counts.get(algo, 0) + 1
            total += 1
            yield "hash", value

    inserted, updated = store.add_local_many(pairs(), label, note)
    elapsed = time.time() - t0
    print(c(f"imported {src.name}", "bold"))
    _print_import_counts(counts, total, elapsed)
    print(f"  inserted           {inserted}")
    print(f"  already present    {updated}")
    print(f"  label              {label}")
    if total:
        print(c(f"  {total / elapsed:,.0f} hashes/s", "grey"))
    if label.lower() in ("malware", "malicious", "bad", "block"):
        print(c("  note: local rows are direct file evidence, so each one "
                "convicts on its own", "grey"))
    return EXIT_OK


def _print_import_counts(counts: Dict[str, int], total: int,
                         elapsed: float) -> None:
    print(f"  hashes found       {total}")
    for algo in ("sha256", "sha1", "md5"):
        if counts.get(algo):
            print(f"    {algo:<16} {counts[algo]}")
    print(f"  parse time         {elapsed:.1f}s")


def cmd_stats(store: Store) -> int:
    st = store.stats()
    print(c("threattrove store", "bold"))
    for key in sorted(st):
        print(f"  {key:<18} {st[key]}")
    print(f"  {'db path':<18} {store.path}")
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    store = Store()

    try:
        if args.list_sources:
            print_sources(store)
            return EXIT_OK

        if args.clear_cache:
            n = store.clear_cache()
            print(f"cleared {n} cached result(s)", file=sys.stderr)

        if args.delete_local:
            parsed = parse_indicator(args.delete_local)
            n = store.delete_local(parsed.kind if parsed else "hash",
                                   parsed.value if parsed else args.delete_local)
            print(f"removed {n} local entr{'y' if n == 1 else 'ies'}",
                  file=sys.stderr)

        for value in args.add_local:
            ind = parse_indicator(value)
            if ind is None:
                print(f"cannot store {value!r}: not a valid indicator",
                      file=sys.stderr)
                continue
            store.add_local(ind.kind, ind.value, args.label, args.note)
            print(f"stored {ind.kind} {ind.value} as {args.label}",
                  file=sys.stderr)

        if args.list_local:
            return cmd_list_local(store)
        if args.stats:
            return cmd_stats(store)
        if args.import_local:
            note = args.note or f"imported from {Path(args.import_local).name}"
            return cmd_import_local(store, args.import_local, args.label, note,
                                    max(0, args.import_limit), args.dry_run)

        indicators, rejected = collect(args)
        for bad in rejected[:10]:
            print(f"skipping unrecognised input: {bad[:80]!r}", file=sys.stderr)
        if len(rejected) > 10:
            print(f"... and {len(rejected) - 10} more", file=sys.stderr)

        if not indicators:
            if args.add_local or args.delete_local:
                return EXIT_OK
            print("nothing to look up. Provide an indicator, --file, --csv or "
                  "--feed. See --help.", file=sys.stderr)
            return EXIT_USAGE

        if len(indicators) > int(os.environ.get("TT_BULK_MAX", "5000")):
            print("too many indicators; raise TT_BULK_MAX to process more",
                  file=sys.stderr)
            return EXIT_USAGE

        sources = select_sources(args.sources)
        engine = Engine(
            sources=sources,
            store=store,
            use_cache=not args.no_cache,
            max_workers=max(1, args.workers),
            deadline=args.timeout,
        )

        progress = _progress_printer(len(indicators), args.quiet)
        t0 = time.time()
        reports = engine.lookup_many(indicators, progress=progress)
        total = time.time() - t0

        # output -------------------------------------------------------
        ext = Path(args.out).suffix.lower() if args.out else ""
        if args.out:
            if ext == ".csv":
                write_csv(args.out, reports)
            elif ext in (".jsonl", ".ndjson"):
                write_jsonl(args.out, reports)
            else:
                write_json(args.out, reports)
            if not args.quiet:
                print(f"wrote {len(reports)} result(s) to {args.out}",
                      file=sys.stderr)

        if args.json:
            payload = [r.to_dict() for r in reports]
            print(json.dumps(payload[0] if len(payload) == 1 else payload,
                             indent=2, default=str))
        elif not args.out:
            print(render_text(reports, verbose=len(reports) == 1))
        elif not args.quiet and sys.stdout.isatty():
            print(render_text(reports, verbose=False))

        if len(indicators) > 1 and not args.quiet:
            print(c(f"  total wall time {total:.1f}s", "grey"),
                  file=sys.stderr)

        if args.fail_on_malicious and any(
                r.verdict() == VERDICT_MALICIOUS for r in reports):
            return EXIT_MALICIOUS
        return EXIT_OK
    finally:
        try:
            store.close()
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":  # pragma: no cover
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
