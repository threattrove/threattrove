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
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

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

from .bulk import (
    MAX_ROWS,
    BulkJobs,
    BulkRunner,
    parse_any,
    parse_text,
    to_csv,
)
from .core import (
    VERSION,
    VERDICT_LABEL,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    Engine,
    Indicator,
    Store,
    parse_indicator,
)
from .sources import ALL_SOURCES

MAX_UPLOAD_BYTES = int(os.environ.get("TT_MAX_UPLOAD", str(2 * 1024 * 1024)))
MAX_API_PER_MIN = int(os.environ.get("TT_RATE_LIMIT", "60"))
MAX_PAGE_PER_MIN = int(os.environ.get("TT_PAGE_RATE_LIMIT", "240"))
MAX_CONCURRENT_JOBS = int(os.environ.get("TT_MAX_JOBS", "2"))

KINDS = ("hash", "url", "domain", "ip")


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


def result_url(ind: Indicator) -> str:
    return url_for("result_page", kind=ind.kind, v=ind.value)


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
        use_cache = request.args.get("fresh") != "1"
        report = rt.engine.lookup(ind, use_cache=use_cache)
        data = _json_report(report)

        resp = make_response(render_template(
            "result.html", report=data, indicator=ind,
            rep=[r for r in data["results"] if r["category"] == "reputation"],
            intel=[r for r in data["results"] if r["category"] == "intel"],
            raw_json=json.dumps(data, indent=2),
        ))
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Robots-Tag"] = "noindex"
        return resp

    @app.get("/recent")
    def recent_page() -> Any:
        guard = page_guard()
        if guard:
            return guard
        rt: Runtime = app.extensions["threattrove"]
        return render_template("recent.html", rows=rt.store.recent(200))

    @app.get("/sources")
    def sources_page() -> Any:
        guard = page_guard()
        if guard:
            return guard
        rt: Runtime = app.extensions["threattrove"]
        return render_template("sources.html", sources=_source_rows(rt))

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
        entries = rt.store.list_local()
        return render_template("local.html", entries=entries,
                               message=request.args.get("msg", ""))

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
        fresh = request.args.get("fresh") == "1"
        report = rt.engine.lookup(ind, use_cache=not fresh)
        resp = jsonify(_json_report(report))
        resp.headers["X-ThreatTrove-Version"] = VERSION
        resp.headers["Cache-Control"] = "public, max-age=60"
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
