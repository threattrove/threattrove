"""Gunicorn configuration for threattrove.

    gunicorn -c deploy/gunicorn.conf.py threattrove.web:app

Each worker keeps its own SQLite connection, so the worker count stays small on
purpose: lookups are network-bound, and every worker also runs bulk jobs.
"""

import multiprocessing
import os

bind = os.environ.get("TT_BIND", "127.0.0.1:8080")
workers = int(os.environ.get("TT_WORKERS", "2"))
worker_class = "gthread"
threads = int(os.environ.get("TT_THREADS", "8"))

timeout = int(os.environ.get("TT_GUNICORN_TIMEOUT", "120"))
graceful_timeout = 30
keepalive = 5

max_requests = 2000
max_requests_jitter = 200

accesslog = os.environ.get("TT_ACCESS_LOG", "-")
errorlog = os.environ.get("TT_ERROR_LOG", "-")
loglevel = os.environ.get("TT_LOG_LEVEL", "info")
access_log_format = '%({x-forwarded-for}i)s %(h)s "%(r)s" %(s)s %(b)s %(D)sus'

# Trust the reverse proxy for scheme/host so url_for() builds https:// links.
forwarded_allow_ips = os.environ.get("TT_FORWARDED_ALLOW_IPS", "127.0.0.1")
proxy_allow_ips = forwarded_allow_ips

if os.environ.get("TT_PRELOAD", "0") == "1":
    preload_app = True

# gthread workers already parallelise; this only caps the process count.
def worker_exit(server, worker):  # noqa: ARG001
    pass


_cpu = multiprocessing.cpu_count()
if workers > _cpu:
    workers = _cpu
