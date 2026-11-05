"""Flask web application: the public face of threattrove.

Run locally::

    threattrove-web            # or: python -m threattrove.web
    gunicorn -w 2 -b 0.0.0.0:8080 threattrove.web:app

The UI mirrors the parts of VirusTotal people use every day: paste a hash, URL
or domain, get a verdict, a per-source breakdown and a bulk queue.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import threading
import time
from typing import Any, Dict, List, Optional

from flask import (
    Flask,
    abort,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from . import cards
from .bulk import (
    MAX_ROWS,
    BulkJobs,
    BulkRunner,
    parse_any,
    parse_text,
    to_csv,
)
from .core import (
    VERDICT_LABEL,
    VERDICT_UNKNOWN,
    VERSION,
    Engine,
    Indicator,
    Store,
    defang,
    health_state,
    parse_indicator,
)
from .sources import ALL_SOURCES

MAX_UPLOAD_BYTES = int(os.environ.get("TT_MAX_UPLOAD", str(2 * 1024 * 1024)))
MAX_API_PER_MIN = int(os.environ.get("TT_RATE_LIMIT", "60"))
MAX_PAGE_PER_MIN = int(os.environ.get("TT_PAGE_RATE_LIMIT", "240"))
# A cache-bypassing lookup (`fresh=1`) is the only page view that spends a
# provider call, so it is rationed per client per UTC day. The provider
# allowance (TT_VT_DAILY_BUDGET) is the global backstop; this is the fair share
# that stops one crawler from being the only thing the allowance ever answers.
MAX_FRESH_PER_DAY = int(os.environ.get("TT_FRESH_PER_DAY", "40"))

# A client that declares itself a crawler gets the cached answer and nothing
# else. No page here is *fresher* for a crawler than for the last person who
# asked, and a link-follower walking thousands of indicators would spend the
# day's allowance before any real lookup happened.
BOT_UA = re.compile(
    r"(bot|spider|crawl|slurp|scrap|semrush|ahrefs|mj12|dotbot|petalbot"
    r"|bytespider|headless|phantomjs|facebookexternalhit|go-http-client"
    r"|python-urllib|libwww|okhttp)", re.I)
MAX_CONCURRENT_JOBS = int(os.environ.get("TT_MAX_JOBS", "2"))

KINDS = ("hash", "url", "domain", "ip")

#: Rows per page on /local. The unpaginated view rendered 500 rows into 174 KB
#: of HTML and sorted the whole table to do it; 50 rows is about 15 KB and the
#: page never scans the table.
LOCAL_PER_PAGE = 50

#: Rows per page on /recent. The feed used to render its whole history into one
#: 83 KB document that reads as a wall of rows and keeps growing; 50 rows is a
#: screenful, and the pager makes the rest reachable without a 1,000-row page.
RECENT_PER_PAGE = 50


def _int_arg(name: str, default: int) -> int:
    """A positive integer from the query string, or *default*."""
    try:
        value = int(request.args.get(name, ""))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


# --------------------------------------------------------------------------
# Runtime wiring
# --------------------------------------------------------------------------

class Runtime:
    """Holds the shared store, engine and bulk job machinery."""

    def __init__(self, store: Optional[Store] = None):
        self.store = store or Store()
        self.engine = Engine(store=self.store, max_workers=6)
        self.jobs = BulkJobs(self.store)
        self.runner = BulkRunner(self.engine, self.jobs, workers=3)
        self.job_slots = threading.Semaphore(MAX_CONCURRENT_JOBS)

    def start_job(self, job_id: str) -> None:
        def _worker() -> None:
            with self.job_slots:
                self.runner.run(job_id)

        threading.Thread(target=_worker, name=f"job-{job_id}",
                         daemon=True).start()


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------

class RateLimiter:
    """Tiny fixed-window limiter, good enough for a single-node deployment."""

    def __init__(self) -> None:
        self._hits: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def allow(self, bucket: str, limit: int, window: float = 60.0) -> bool:
        now = time.time()
        with self._lock:
            hits = [t for t in self._hits.get(bucket, []) if now - t < window]
            if len(hits) >= limit:
                self._hits[bucket] = hits
                return False
            hits.append(now)
            self._hits[bucket] = hits
            return True


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _fmt_ts(ts: Optional[float]) -> str:
    if not ts:
        return "\u2013"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def _rel_time(ts: Optional[float]) -> str:
    if not ts:
        return "\u2013"
    delta = max(0, time.time() - ts)
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta / 60)}m ago"
    if delta < 86400:
        return f"{int(delta / 3600)}h ago"
    return f"{int(delta / 86400)}d ago"


_QUERY_RE = re.compile(r"[?#].*$", re.S)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# A digest is compared against a report by its ends: the first characters say
# which sample, the last ones catch a mistyped tail. The middle is the part a
# reader can afford to lose on a phone. Seven and eight rather than eight and
# eight: a 390px phone leaves the indicator column about 70px, which is eight
# characters a line, so 17 characters spills an orphan character onto a third
# line while 16 fits two -- and the ellipsis lands at the end of the first,
# leaving the whole tail readable on the second.
SHORT_HEAD = 7
SHORT_TAIL = 8


def redact(value: str) -> str:
    """Drop the query string and fragment before an indicator is displayed.

    The recent feeds are public, and query strings routinely carry session
    tokens, e-mail addresses and order numbers that belong to whoever pasted
    the link. The scheme, host and path identify the sample; the rest is not
    ours to republish.
    """
    return _QUERY_RE.sub("", value or "")


def short_value(value: str) -> str:
    """Middle-truncate a hex digest for narrow screens; empty for anything else.

    A 64-character SHA-256 in a 390px table column wraps to eight lines and
    pushes every other lookup below the fold. The template renders both the
    full value and this shortened form and a media query picks one, so the
    desktop view keeps the whole digest and a phone shows
    ``first7\u2026last8`` -- short enough to need two lines in the column a
    390px screen leaves, long enough that both ends stay recognisable. Domains,
    IPs and URLs are left alone: truncating them would hide the part that
    identifies the indicator.

    Returns an empty string when the value is not a hash, which the templates
    use as "render the plain value, there is nothing to shorten".
    """
    text = (value or "").strip()
    if len(text) >= 32 and _HEX_RE.match(text):
        return f"{text[:SHORT_HEAD]}\u2026{text[-SHORT_TAIL:]}"
    return ""


def result_url(ind: Indicator) -> str:
    return url_for("result_page", kind=ind.kind, v=ind.value)


def public_base() -> str:
    """Absolute origin for share links, behind the reverse proxy.

    ``TT_PUBLIC_URL`` wins when it is set; otherwise the proxy's
    ``X-Forwarded-Proto`` is trusted so unfurlers get https, not http.
    """
    base = os.environ.get("TT_PUBLIC_URL", "").strip().rstrip("/")
    if base:
        return base
    proto = (request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip()
             or request.scheme or "https")
    return f"{proto}://{request.host}"


def canonical_base() -> str:
    """Absolute site root for ``/sitemap.xml`` and ``/robots.txt``.

    A crawler has to be given the name the site is published under, so the
    configured ``TT_SITE_URL`` wins over whatever Host header arrived. The
    request-derived origin is only the fallback for a bare install.
    """
    configured = os.environ.get("TT_SITE_URL", "").strip().rstrip("/")
    if configured.startswith(("http://", "https://")):
        return configured
    return public_base()


def _json_report(report: Any, include_results: bool = True) -> Dict[str, Any]:
    data = report.to_dict(include_results=include_results)
    data["verdict_label"] = VERDICT_LABEL.get(data["verdict"], data["verdict"])
    return data


def _quota_row(runtime: Runtime, source: Any) -> Optional[Dict[str, Any]]:
    """Today's usage of a shared provider allowance, for the sources page."""
    if not source.quota_key:
        return None
    limit = source.budget()
    used, exhausted = 0, False
    try:
        state = runtime.store.quota_state(source.quota_key)
        used, exhausted = state["used"], state["exhausted"]
    except Exception:      # a read-only or locked database must not break the page
        pass
    shared = sum(1 for o in ALL_SOURCES if o.quota_key == source.quota_key)
    return {"key": source.quota_key, "used": used, "limit": limit,
            "exhausted": exhausted, "shared": shared}


def _source_rows(runtime: Runtime) -> List[Dict[str, Any]]:
    rows = []
    for s in ALL_SOURCES:
        active = s.available()
        missing = s.opt_in_missing()
        if active:
            state, hint = "active", ""
        elif missing:
            # a source that is ready but switched off on purpose says how to
            # switch it on, so nobody goes looking for a missing key
            state, hint = "disabled", missing
        elif s.keyless:
            state, hint = "disabled", "opt-in flag"
        else:
            state, hint = "needs_key", s.env_key or ""
        rows.append({
            "name": s.name,
            "display": s.display or s.name,
            "kinds": list(s.kinds),
            "category": s.category,
            "homepage": s.homepage,
            "env_key": s.env_key,
            "keyless": s.keyless,
            "active": active,
            "state": state,
            "hint": hint,
            "opt_in": s.opt_in,
            "quota": _quota_row(runtime, s),
        })
    return rows


#: How long a canary result stays meaningful. The timer runs every four hours,
#: so a row older than a day means the canary itself stopped running.
HEALTH_STALE_SECONDS = 26 * 3600


def _status_payload(runtime: Runtime) -> Dict[str, Any]:
    """The source-health view: the last canary result for every source.

    Inactive sources are listed too, with the reason they are off, so the page
    answers "why is that feed not being asked?" without a trip to /sources.
    """
    rows = _source_rows(runtime)
    health = runtime.store.health_for()
    now = time.time()
    counts = {"ok": 0, "warn": 0, "bad": 0, "skip": 0, "unchecked": 0,
              "off": 0}
    newest = 0.0
    stale_count = 0
    out: List[Dict[str, Any]] = []
    for row in rows:
        h = health.get(row["name"]) or {}
        checked_at = float(h.get("checked_at") or 0)
        # A source with no recent canary answer is unproven, not healthy: the
        # timer that collects the answers may itself be dead. That is tracked
        # separately from ``state`` because it is the one condition a pager
        # must not miss, while a slow-but-answering source should not page.
        stale = False
        if not row["active"]:
            state, note = "off", row["hint"]
        elif not h:
            state, note = "unchecked", "no canary check yet"
            stale = True
        else:
            state = health_state(h.get("status", ""), h.get("drift"),
                                 h.get("expected", ""))
            note = h.get("note", "")
            newest = max(newest, checked_at)
            age = now - checked_at
            if age > HEALTH_STALE_SECONDS:
                state = "warn"
                note = f"last check {int(age // 3600)}h ago"
                stale = True
        if stale:
            stale_count += 1
        counts[state] = counts.get(state, 0) + 1
        out.append({
            "name": row["name"], "display": row["display"],
            "category": row["category"], "kinds": row["kinds"],
            "homepage": row["homepage"], "active": row["active"],
            "state": state, "note": note, "stale": stale,
            "status": h.get("status", ""), "verdict": h.get("verdict", ""),
            "indicator": h.get("indicator", ""),
            "latency_ms": h.get("latency_ms"),
            "baseline_ms": h.get("baseline_ms"), "drift": h.get("drift"),
            "checked_at": checked_at or None,
        })
    rank = {"bad": 0, "warn": 1, "skip": 2, "unchecked": 3, "ok": 4, "off": 5}
    out.sort(key=lambda r: (rank[r["state"]], str(r["display"]).lower()))
    checked = counts["ok"] + counts["warn"] + counts["bad"]
    if counts["bad"]:
        overall = "bad"
    elif counts["warn"]:
        overall = "warn"
    elif counts["ok"]:
        overall = "ok"
    else:
        # nothing was actually answered: an empty database and a run that only
        # ever got skips are both "no claim", not "healthy"
        overall = "unknown"
    return {
        "status": overall,
        "version": VERSION,
        "generated": now,
        "checked_at": newest or None,
        "interval_hours": 4,
        "stale_after_hours": HEALTH_STALE_SECONDS // 3600,
        "counts": counts,
        "stale_count": stale_count,
        "checked": checked,
        "sources": out,
    }


def create_app(store: Optional[Store] = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
        JSON_SORT_KEYS=False,
    )
    app.config.setdefault("SEND_FILE_MAX_AGE_DEFAULT", 3600)

    runtime = Runtime(store)
    app.extensions["threattrove"] = runtime
    limiter = RateLimiter()

    def client_ip() -> str:
        fwd = request.headers.get("X-Forwarded-For", "")
        return (fwd.split(",")[0].strip() if fwd else None) or \
            request.remote_addr or "unknown"

    def is_bot() -> bool:
        """True when the client declares itself a crawler in its User-Agent."""
        return bool(BOT_UA.search(request.headers.get("User-Agent", "")))

    def fresh_allowed() -> bool:
        """Reserve one cache-bypassing lookup for this client today.

        False means "answer from cache": the client is a crawler, or it has
        already spent its share of the day. It is never an error - the page and
        the JSON both still render, they just do not re-ask every provider.
        """
        if is_bot():
            return False
        if runtime.store is None:
            return True
        try:
            return runtime.store.take_quota("fresh:" + client_ip(),
                                            MAX_FRESH_PER_DAY)
        except Exception:      # never lose a lookup to a bookkeeping error
            return True

    def api_guard() -> Optional[Any]:
        if not limiter.allow(f"api:{client_ip()}", MAX_API_PER_MIN):
            resp = jsonify({
                "error": "rate_limited",
                "message": f"more than {MAX_API_PER_MIN} API requests per minute",
            })
            resp.status_code = 429
            resp.headers["Retry-After"] = "60"
            return resp
        return None

    def page_guard() -> Optional[Any]:
        if not limiter.allow(f"page:{client_ip()}", MAX_PAGE_PER_MIN):
            return render_template("error.html", code=429,
                                   message="Too many requests. Slow down."), 429
        return None

    @app.context_processor
    def inject_globals() -> Dict[str, Any]:
        return {
            "version": VERSION,
            "site_name": os.environ.get("TT_SITE_NAME", "ThreatTrove"),
            "verdict_label": VERDICT_LABEL,
            "fmt_ts": _fmt_ts,
            "rel_time": _rel_time,
            "max_rows": MAX_ROWS,
            "rate_limit": MAX_API_PER_MIN,
            "years": time.strftime("%Y"),
            "defang": defang,
            "redact": redact,
            "short_value": short_value,
            "public_base": public_base(),
            "site_base": canonical_base(),
        }

    # -- pages ------------------------------------------------------------
    @app.get("/")
    def index() -> Any:
        guard = page_guard()
        if guard:
            return guard
        rt: Runtime = app.extensions["threattrove"]
        stats = rt.store.stats()
        recent = rt.store.recent(8)
        return render_template("index.html", stats=stats, recent=recent,
                               sources=_source_rows(rt))

    @app.get("/search")
    def search() -> Any:
        q = (request.args.get("q") or "").strip()
        if not q:
            return redirect(url_for("index"))
        ind = parse_indicator(q)
        if ind is None:
            return render_template(
                "error.html", code=400,
                message=(f"{q[:120]!r} is not a hash, URL, domain or IP "
                         "address we recognise."),
            ), 400
        return redirect(result_url(ind))

    @app.get("/i/<kind>")
    def result_page(kind: str) -> Any:
        guard = page_guard()
        if guard:
            return guard
        if kind not in KINDS:
            abort(404)
        raw = request.args.get("v", "")
        ind = parse_indicator(raw)
        if ind is None or ind.kind != kind:
            return render_template(
                "error.html", code=400,
                message="That indicator could not be parsed.",
            ), 400

        rt: Runtime = app.extensions["threattrove"]
        wants_fresh = request.args.get("fresh") == "1"
        fresh = wants_fresh and fresh_allowed()
        report = rt.engine.lookup(ind, use_cache=not fresh)
        data = _json_report(report)

        resp = make_response(render_template(
            "result.html", report=data, indicator=ind,
            rep=[r for r in data["results"] if r["category"] == "reputation"],
            intel=[r for r in data["results"] if r["category"] == "intel"],
            raw_json=json.dumps(data, indent=2),
        ))
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Robots-Tag"] = "noindex"
        if wants_fresh:
            resp.headers["X-ThreatTrove-Fresh"] = "live" if fresh else "denied"
        return resp

    @app.get("/card/<kind>.png")
    def card_png(kind: str) -> Any:
        """The share image for one indicator: last recorded verdict only.

        Deliberately read-only. An unfurler hitting this route must never start
        a lookup, both because it would burn provider quota on a bot and
        because the image has to match what the site actually said.
        """
        if kind not in KINDS or not cards.available():
            abort(404)
        ind = parse_indicator(request.args.get("v", ""))
        if ind is None or ind.kind != kind:
            abort(404)

        rt: Runtime = app.extensions["threattrove"]
        last = rt.store.last_verdict(ind.kind, ind.value) or {}
        verdict = last.get("verdict") or VERDICT_UNKNOWN
        score = last.get("score")
        try:
            png = cards.render(ind.kind, ind.value, verdict, score)
        except Exception:            # noqa: BLE001 - a broken card is a 404, not a 500
            abort(404)

        resp = make_response(png)
        resp.headers["Content-Type"] = "image/png"
        resp.headers["Cache-Control"] = "public, max-age=300"
        resp.set_etag(f"{ind.kind}-{ind.value}-{verdict}-{score}")
        return resp.make_conditional(request)

    @app.get("/recent")
    def recent_page() -> Any:
        """The public lookup feed, one page at a time.

        It used to render every lookup it has ever recorded in a single
        document, which reads as a wall of rows and grows without bound. The
        newest page stays indexable; later pages are marked noindex so a crawler
        does not walk an ever-deepening history, and no response is cached
        because the next lookup changes it.
        """
        guard = page_guard()
        if guard:
            return guard
        rt: Runtime = app.extensions["threattrove"]
        total = rt.store.count_recent()
        pages = max(1, (total + RECENT_PER_PAGE - 1) // RECENT_PER_PAGE)
        page = min(max(1, _int_arg("page", 1)), pages)
        rows = rt.store.recent(RECENT_PER_PAGE, offset=(page - 1) * RECENT_PER_PAGE)
        shown = len(rows)
        resp = make_response(render_template(
            "recent.html", rows=rows, total=total, page=page, pages=pages,
            per_page=RECENT_PER_PAGE,
            first=(page - 1) * RECENT_PER_PAGE + 1 if shown else 0,
            last=(page - 1) * RECENT_PER_PAGE + shown,
        ))
        resp.headers["Cache-Control"] = "no-store"
        if page > 1:
            resp.headers["X-Robots-Tag"] = "noindex, follow"
        return resp

    @app.get("/sources")
    def sources_page() -> Any:
        guard = page_guard()
        if guard:
            return guard
        rt: Runtime = app.extensions["threattrove"]
        return render_template("sources.html", sources=_source_rows(rt))

    @app.get("/status")
    def status_page() -> Any:
        guard = page_guard()
        if guard:
            return guard
        rt: Runtime = app.extensions["threattrove"]
        return render_template("status.html", status=_status_payload(rt))

    @app.get("/about")
    def about_page() -> Any:
        guard = page_guard()
        if guard:
            return guard
        rt: Runtime = app.extensions["threattrove"]
        rows = _source_rows(rt)
        return render_template(
            "about.html", sources=rows, total=len(rows),
            active=sum(1 for r in rows if r["active"]),
            keyless=sum(1 for r in rows if r["keyless"]))

    @app.get("/privacy")
    def privacy_page() -> Any:
        guard = page_guard()
        if guard:
            return guard
        return render_template("privacy.html")

    @app.get("/robots.txt")
    def robots_txt() -> Any:
        """Crawler policy: the documented pages are public, results are not.

        The nine pages in the sitemap are what a crawler may index. A result
        page is computed per query string, is already `noindex`, and costs a
        provider call to build, so crawling it produces nothing for the crawler
        and spends the day's allowance for everyone else.
        """
        body = (
            "User-agent: *\n"
            "Allow: /\n"
            "Crawl-delay: 5\n"
            # Bulk upload needs a request body; a crawler has nothing to send.
            "Disallow: /api/v1/bulk\n"
            # Result pages: noindex, per-query, and each one is a live lookup.
            "Disallow: /i/\n"
            "Disallow: /*?fresh=1\n"
            "Disallow: /*?v=\n"
            "\n"
            "# Crawlers that re-ask every indicator they find are the reason the\n"
            "# daily allowance needs rationing; they get nothing here.\n"
            "User-agent: serpstatbot\n"
            "Disallow: /\n"
            "\n"
            "User-agent: SemrushBot\n"
            "Disallow: /\n"
            "\n"
            "User-agent: AhrefsBot\n"
            "Disallow: /\n"
            f"Sitemap: {canonical_base()}/sitemap.xml\n")
        resp = make_response(body, 200)
        resp.mimetype = "text/plain"
        resp.headers["Cache-Control"] = "public, max-age=3600"
        return resp

    @app.get("/sitemap.xml")
    def sitemap_xml() -> Any:
        """The publicly linkable pages, in the order people use them.

        Indicator result pages are left out on purpose: they are unbounded, and
        a crawler walking them would spend provider quota on every one.
        """
        base = canonical_base()
        pages = (
            ("/", "daily", "1.0"),
            ("/status", "hourly", "0.8"),
            ("/sources", "weekly", "0.7"),
            ("/about", "monthly", "0.6"),
            ("/recent", "hourly", "0.5"),
            ("/local", "weekly", "0.5"),
            ("/api", "monthly", "0.4"),
            ("/bulk", "monthly", "0.3"),
            ("/privacy", "yearly", "0.3"),
        )
        entries = "".join(
            f"  <url><loc>{base}{path}</loc><changefreq>{freq}</changefreq>"
            f"<priority>{prio}</priority></url>\n"
            for path, freq, prio in pages)
        xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
               '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
               f"{entries}</urlset>\n")
        resp = make_response(xml, 200)
        resp.mimetype = "application/xml"
        resp.headers["Cache-Control"] = "public, max-age=3600"
        return resp

    @app.route("/local", methods=["GET", "POST"])
    def local_page() -> Any:
        guard = page_guard()
        if guard:
            return guard
        rt: Runtime = app.extensions["threattrove"]
        message = ""
        if request.method == "POST":
            action = request.form.get("action", "add")
            value = (request.form.get("value") or "").strip()
            ind = parse_indicator(value)
            if action == "delete":
                if ind:
                    n = rt.store.delete_local(ind.kind, ind.value)
                    message = f"removed {n} entry"
                else:
                    message = "unknown indicator"
            else:
                if ind is None:
                    message = "that is not a valid indicator"
                else:
                    label = (request.form.get("label") or "malware").strip()
                    note = (request.form.get("note") or "").strip()[:200]
                    rt.store.add_local(ind.kind, ind.value, label, note)
                    message = f"stored {ind.value} as {label}"
            return redirect(url_for("local_page", msg=message))
        query = (request.args.get("q") or "").strip()[:120]
        kind = (request.args.get("kind") or "").strip().lower()
        if kind not in KINDS:
            kind = ""
        per_page = max(10, min(200, _int_arg("per_page", LOCAL_PER_PAGE)))
        total = rt.store.count_local(query, kind)
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(_int_arg("page", 1), pages)
        entries = rt.store.list_local(limit=per_page,
                                      offset=(page - 1) * per_page,
                                      query=query, kind=kind)
        shown = len(entries)
        return render_template(
            "local.html", entries=entries,
            message=request.args.get("msg", ""), total=total, page=page,
            pages=pages, per_page=per_page, query=query, kind=kind,
            first=(page - 1) * per_page + 1 if shown else 0,
            last=(page - 1) * per_page + shown,
        )

    # -- bulk -------------------------------------------------------------
    @app.route("/bulk", methods=["GET", "POST"])
    def bulk_page() -> Any:
        guard = page_guard()
        if guard:
            return guard
        rt: Runtime = app.extensions["threattrove"]
        error = ""
        if request.method == "POST":
            text = request.form.get("indicators", "")
            upload = request.files.get("file")
            label = (request.form.get("label") or "").strip()[:80]
            try:
                if upload and upload.filename:
                    data = upload.read(MAX_UPLOAD_BYTES + 1)
                    if len(data) > MAX_UPLOAD_BYTES:
                        error = "file is larger than the upload limit"
                    else:
                        items, skipped = parse_any(data, upload.filename,
                                                   MAX_ROWS)
                        label = label or upload.filename[:80]
                else:
                    items, skipped = parse_text(text, MAX_ROWS)
            except Exception as exc:  # noqa: BLE001
                items, skipped, error = [], 0, f"could not parse input: {exc}"

            if not error and not items:
                error = "no valid indicators found in that input"
            if not error:
                job_id = rt.jobs.create(items, label=label, skipped=skipped)
                rt.start_job(job_id)
                return redirect(url_for("bulk_result_page", job_id=job_id))
        return render_template("bulk.html", error=error,
                               recent=rt.jobs.recent(6))

    @app.get("/bulk/<job_id>")
    def bulk_result_page(job_id: str) -> Any:
        guard = page_guard()
        if guard:
            return guard
        rt: Runtime = app.extensions["threattrove"]
        job = rt.jobs.get(job_id)
        if not job:
            abort(404)
        items = rt.jobs.all_items(job_id)
        return render_template("bulk_result.html", job=job, items=items,
                               summary=rt.jobs.summary(job_id))

    @app.get("/bulk/<job_id>/export.csv")
    def bulk_export_csv(job_id: str) -> Any:
        rt: Runtime = app.extensions["threattrove"]
        if not rt.jobs.get(job_id):
            abort(404)
        payload = to_csv(rt.jobs.all_items(job_id)).encode("utf-8")
        return send_file(io.BytesIO(payload), mimetype="text/csv",
                         as_attachment=True,
                         download_name=f"threattrove-{job_id}.csv")

    @app.get("/bulk/<job_id>/export.json")
    def bulk_export_json(job_id: str) -> Any:
        rt: Runtime = app.extensions["threattrove"]
        if not rt.jobs.get(job_id):
            abort(404)
        payload = json.dumps(rt.jobs.all_items(job_id), indent=2).encode()
        return send_file(io.BytesIO(payload), mimetype="application/json",
                         as_attachment=True,
                         download_name=f"threattrove-{job_id}.json")

    # -- json api ---------------------------------------------------------
    def api_report(raw: str, expected: Optional[str] = None) -> Any:
        limited = api_guard()
        if limited:
            return limited
        ind = parse_indicator(raw or "")
        if ind is None:
            return jsonify({"error": "bad_request",
                            "message": "could not parse that indicator"}), 400
        if expected and ind.kind != expected:
            return jsonify({
                "error": "bad_request",
                "message": f"expected a {expected}, got a {ind.kind}",
            }), 400
        rt: Runtime = app.extensions["threattrove"]
        wants_fresh = request.args.get("fresh") == "1"
        fresh = wants_fresh and fresh_allowed()
        report = rt.engine.lookup(ind, use_cache=not fresh)
        resp = jsonify(_json_report(report))
        resp.headers["X-ThreatTrove-Version"] = VERSION
        resp.headers["Cache-Control"] = "public, max-age=60"
        # `fresh` is a courtesy for a scripted analyst, not a licence to re-ask
        # every provider; say which way the request actually went.
        resp.headers["X-ThreatTrove-Fresh"] = (
            "denied" if wants_fresh and not fresh
            else "live" if fresh else "cached")
        return resp

    @app.get("/api/v1/hash/<value>")
    def api_hash(value: str) -> Any:
        return api_report(value, "hash")

    @app.get("/api/v1/url")
    def api_url() -> Any:
        return api_report(request.args.get("url", ""), "url")

    @app.get("/api/v1/domain")
    def api_domain() -> Any:
        return api_report(request.args.get("domain", ""), "domain")

    @app.get("/api/v1/ip")
    def api_ip() -> Any:
        return api_report(request.args.get("ip", ""), "ip")

    @app.get("/api/v1/lookup")
    def api_lookup() -> Any:
        return api_report(request.args.get("q", ""))

    @app.post("/api/v1/bulk")
    def api_bulk() -> Any:
        limited = api_guard()
        if limited:
            return limited
        rt: Runtime = app.extensions["threattrove"]
        upload = request.files.get("file")
        label = (request.form.get("label") or "").strip()[:80]
        if upload and upload.filename:
            data = upload.read(MAX_UPLOAD_BYTES + 1)
            if len(data) > MAX_UPLOAD_BYTES:
                return jsonify({"error": "too_large",
                                "message": "file exceeds upload limit"}), 413
            items, skipped = parse_any(data, upload.filename, MAX_ROWS)
        else:
            body = request.get_data(as_text=True) or ""
            if "indicators" in request.form:
                body = request.form["indicators"]
            if not body.strip():
                return jsonify({"error": "bad_request",
                                "message": "no indicators supplied"}), 400
            items, skipped = parse_text(body, MAX_ROWS)
        if not items:
            return jsonify({"error": "bad_request",
                            "message": "no valid indicators found"}), 400
        job_id = rt.jobs.create(items, label=label, skipped=skipped)
        rt.start_job(job_id)
        resp = jsonify({"job_id": job_id, "total": len(items),
                        "skipped": skipped,
                        "status_url": url_for("api_bulk_status",
                                              job_id=job_id, _external=True)})
        resp.status_code = 202
        return resp

    @app.get("/api/v1/bulk/<job_id>")
    def api_bulk_status(job_id: str) -> Any:
        limited = api_guard()
        if limited:
            return limited
        rt: Runtime = app.extensions["threattrove"]
        job = rt.jobs.get(job_id)
        if not job:
            return jsonify({"error": "not_found"}), 404
        job = dict(job)
        job["summary"] = rt.jobs.summary(job_id)
        job["created_iso"] = _fmt_ts(job["created"])
        return jsonify(job)

    @app.get("/api/v1/bulk/<job_id>/items")
    def api_bulk_items(job_id: str) -> Any:
        limited = api_guard()
        if limited:
            return limited
        rt: Runtime = app.extensions["threattrove"]
        if not rt.jobs.get(job_id):
            return jsonify({"error": "not_found"}), 404
        return jsonify({"job_id": job_id, "items": rt.jobs.all_items(job_id)})

    @app.get("/api/v1/sources")
    def api_sources() -> Any:
        limited = api_guard()
        if limited:
            return limited
        rt: Runtime = app.extensions["threattrove"]
        return jsonify({"version": VERSION, "sources": _source_rows(rt)})

    @app.get("/api/v1/stats")
    def api_stats() -> Any:
        limited = api_guard()
        if limited:
            return limited
        rt: Runtime = app.extensions["threattrove"]
        stats = dict(rt.store.stats())
        stats["sources_active"] = sum(1 for s in ALL_SOURCES if s.available())
        stats["sources_total"] = len(ALL_SOURCES)
        stats["version"] = VERSION
        return jsonify(stats)

    @app.get("/api/v1/status")
    def api_status() -> Any:
        """Source health as JSON, optionally as an HTTP check for a pager.

        ``?strict=1`` (also ``true``/``yes``) answers 503 only when a source is
        broken (``bad``) or its canary data has gone stale -- the two states
        that mean lookups are wrong or unproven. ``?strict=warn`` (also
        ``all``) is the loud setting: it also fails on latency drift and on a
        source that answers differently than it used to. With no ``strict``
        argument the payload is informational and never fails.
        """
        api_limited = api_guard()
        if api_limited:
            return api_limited
        rt: Runtime = app.extensions["threattrove"]
        data = _status_payload(rt)
        resp = jsonify(data)
        mode = (request.args.get("strict") or "").strip().lower()
        failing = bool(data["counts"].get("bad")) or data["stale_count"] > 0
        if mode in ("warn", "all"):
            failing = failing or bool(data["counts"].get("warn"))
        elif mode not in ("1", "true", "yes"):
            failing = False
        if failing:
            resp.status_code = 503
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/api")
    def api_docs() -> Any:
        return render_template("api.html", sources=_source_rows(
            app.extensions["threattrove"]))

    @app.get("/healthz")
    @app.get("/health")
    def healthz() -> Any:
        return jsonify({"status": "ok", "version": VERSION})

    # -- errors -----------------------------------------------------------
    @app.errorhandler(404)
    def not_found(_exc: Any) -> Any:
        return render_template("error.html", code=404,
                               message="Nothing lives at that address."), 404

    @app.errorhandler(413)
    def too_large(_exc: Any) -> Any:
        return jsonify({"error": "too_large",
                        "message": "upload exceeds the size limit"}), 413

    @app.errorhandler(500)
    def server_error(_exc: Any) -> Any:
        return render_template("error.html", code=500,
                               message="Internal error. The server log has "
                                       "the details."), 500

    @app.after_request
    def security_headers(resp: Any) -> Any:
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

    return app


#: WSGI entry point for gunicorn/uwsgi: ``threattrove.web:app``
app = create_app()


def main() -> None:  # pragma: no cover
    parser = argparse.ArgumentParser(
        prog="threattrove-web",
        description="Run the threattrove web UI and JSON API (development server).",
        epilog="For production use gunicorn: "
        "gunicorn -c deploy/gunicorn.conf.py threattrove.web:app",
    )
    parser.add_argument(
        "--host", default=os.environ.get("TT_HOST", "127.0.0.1"), help="bind address"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("TT_PORT", "8080")),
        help="bind port",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=os.environ.get("TT_DEBUG") == "1",
        help="enable the Flask reloader and debugger",
    )
    parser.add_argument("--version", action="version", version=f"threattrove {VERSION}")
    args = parser.parse_args()

    print(f"threattrove {VERSION} serving on http://{args.host}:{args.port}")
    print(f"database: {app.extensions['threattrove'].store.path}")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":  # pragma: no cover
    main()
