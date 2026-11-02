#!/usr/bin/env python3
"""Offline checks for the cache-bypass ration and the crawler policy.

A `fresh=1` request is the only page view that spends a provider call, so it is
rationed per client per UTC day and not honoured at all for a client that
declares itself a crawler. A refused `fresh=1` must still answer - from cache -
because an error page for a bot is a worse outcome than a cached page.

Nothing here touches the network: the engine is stubbed.
"""
from __future__ import annotations

import os
import pathlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove import web as webmod  # noqa: E402
from threattrove.core import Report, SourceResult, Store  # noqa: E402
from threattrove.web import create_app  # noqa: E402

FAILED = []
HASH = "44d88612fea8a8f36de82e1278abb02f"
CRAWLER = ("serpstatbot/2.1 (advanced backlink tracking bot; "
           "https://serpstatbot.com/; abuse@serpstatbot.com)")
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def check(label, ok, detail=""):
    if ok:
        print("  ok   " + label)
    else:
        print("  FAIL " + label + ((" - " + detail) if detail else ""))
        FAILED.append(label)


class Engine:
    """Records the cache decision the app made; never calls a source."""

    def __init__(self):
        self.seen = []

    def lookup(self, indicator, use_cache=True):
        self.seen.append(bool(use_cache))
        return Report(indicator=indicator, results=[
            SourceResult(source="alpha", status="found", verdict="unknown"),
        ])

    def last(self):
        return self.seen[-1]


def main():
    store = Store(Path(tempfile.mkdtemp()) / "fresh.db")
    app = create_app(store)
    app.config.update(TESTING=True)
    rt = app.extensions["threattrove"]
    engine = Engine()
    rt.engine.lookup = engine.lookup
    client = app.test_client()
    limit = webmod.MAX_FRESH_PER_DAY

    def reset():
        store.conn.execute("DELETE FROM quota WHERE quota LIKE 'fresh:%'")
        store.conn.commit()

    def page(fresh=False, ua=BROWSER, ip=None):
        q = {"v": HASH}
        if fresh:
            q["fresh"] = "1"
        h = {"User-Agent": ua}
        if ip:
            h["X-Forwarded-For"] = ip
        return client.get("/i/hash", query_string=q, headers=h)

    def api(fresh=False, ua=BROWSER, ip=None):
        q = {}
        if fresh:
            q["fresh"] = "1"
        h = {"User-Agent": ua}
        if ip:
            h["X-Forwarded-For"] = ip
        return client.get("/api/v1/hash/" + HASH, query_string=q, headers=h)

    print("-- a plain page view never spends a call")
    reset()
    r = page(ip="10.1.0.1")
    check("page answers 200", r.status_code == 200, str(r.status_code))
    check("plain page reads the cache", engine.last() is True)
    check("no fresh header when none was asked",
          "X-ThreatTrove-Fresh" not in r.headers)

    print("\n-- fresh=1 from a person")
    reset()
    r = page(fresh=True, ip="10.1.0.2")
    check("page answers 200", r.status_code == 200, str(r.status_code))
    check("fresh page bypasses the cache", engine.last() is False)
    check("page reports the live answer",
          r.headers.get("X-ThreatTrove-Fresh") == "live",
          str(r.headers.get("X-ThreatTrove-Fresh")))
    check("it is charged against that client",
          store.quota_state("fresh:10.1.0.2")["used"] == 1)

    print("\n-- fresh=1 from a crawler")
    reset()
    r = page(fresh=True, ua=CRAWLER, ip="10.1.0.3")
    check("crawler page still answers 200", r.status_code == 200, str(r.status_code))
    check("crawler gets the cached answer, not a live one", engine.last() is True)
    check("crawler is told the bypass was denied",
          r.headers.get("X-ThreatTrove-Fresh") == "denied",
          str(r.headers.get("X-ThreatTrove-Fresh")))
    check("crawler spends none of the budget",
          store.quota_state("fresh:10.1.0.3")["used"] == 0)

    print("\n-- the same rule on /api/v1")
    reset()
    ok = api(fresh=True, ip="10.1.0.4")
    check("api fresh=1 is honoured for a person",
          engine.last() is False and ok.headers.get("X-ThreatTrove-Fresh") == "live")
    bad = api(fresh=True, ua=CRAWLER, ip="10.1.0.5")
    check("api fresh=1 is denied for a crawler",
          engine.last() is True and bad.headers.get("X-ThreatTrove-Fresh") == "denied")
    check("a denied api call is not an error", bad.status_code == 200,
          str(bad.status_code))
    plain = api(ip="10.1.0.4")
    check("an api call without fresh says cached",
          plain.headers.get("X-ThreatTrove-Fresh") == "cached",
          str(plain.headers.get("X-ThreatTrove-Fresh")))

    print("\n-- one client cannot spend the day")
    reset()
    client_ip = "10.1.0.6"
    seen = [api(fresh=True, ip=client_ip).headers.get("X-ThreatTrove-Fresh")
            for _ in range(limit)]
    check("the first %d are live" % limit, seen == ["live"] * limit,
          str(sorted(set(seen))))
    spent = api(fresh=True, ip=client_ip)
    check("the next one is denied",
          spent.headers.get("X-ThreatTrove-Fresh") == "denied",
          str(spent.headers.get("X-ThreatTrove-Fresh")))
    check("a spent budget still answers", spent.status_code == 200,
          str(spent.status_code))
    check("the spent client reads the cache", engine.last() is True)
    check("the ledger stops at the limit",
          store.quota_state("fresh:" + client_ip)["used"] == limit,
          str(store.quota_state("fresh:" + client_ip)["used"]))
    shared = page(fresh=True, ip=client_ip)
    check("the page route shares the same budget",
          shared.headers.get("X-ThreatTrove-Fresh") == "denied",
          str(shared.headers.get("X-ThreatTrove-Fresh")))

    print("\n-- other clients are unaffected")
    other = api(fresh=True, ip="10.1.0.7")
    check("a different client is still live",
          other.headers.get("X-ThreatTrove-Fresh") == "live",
          str(other.headers.get("X-ThreatTrove-Fresh")))

    print("\n-- the ledger stays out of the provider view")
    reset()
    api(fresh=True, ip="10.1.0.8")
    html = client.get("/sources").get_data(as_text=True)
    check("/sources does not list per-client rows", "fresh:" not in html)
    rows = [r[0] for r in store.conn.execute(
        "SELECT quota FROM quota WHERE quota LIKE 'fresh:%'")]
    check("per-client rows are namespaced", rows == ["fresh:10.1.0.8"], str(rows))

    print("\n-- robots.txt keeps crawlers off result pages")
    robots = client.get("/robots.txt").get_data(as_text=True)
    for needle in ("Disallow: /i/", "Disallow: /*?fresh=1", "Disallow: /*?v=",
                   "User-agent: serpstatbot", "Disallow: /api/v1/bulk",
                   "Allow: /", "Sitemap:"):
        check("robots has %r" % needle, needle in robots)
    check("serpstatbot is named before the sitemap line",
          robots.index("User-agent: serpstatbot") < robots.index("Sitemap:"))

    static = pathlib.Path(__file__).resolve().parent.parent / "deploy" / "robots.txt"
    served = [line.strip() for line in static.read_text(encoding="utf-8").splitlines()
              if line.strip() and not line.strip().startswith("#")]
    generated = [line.strip() for line in robots.splitlines()
                 if line.strip() and not line.strip().startswith("#")]
    check("deploy/robots.txt exists and is served", static.exists(), str(static))
    check("the served robots.txt matches the app policy",
          [l for l in served if not l.startswith("Sitemap:")] ==
          [l for l in generated if not l.startswith("Sitemap:")],
          "static=%r app=%r" % (served, generated))
    check("the served robots.txt names the canonical sitemap",
          any(l.startswith("Sitemap: https://") for l in served))

    store.close()
    print()
    if FAILED:
        print("%d failed" % len(FAILED))
        return 1
    print("all fresh/crawler checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
