#!/usr/bin/env python3
"""Offline checks for the public documentation pages.

The three pages that used to 404 (/about, /privacy, /sitemap.xml) are the point:
a crawler or a reader landing on any of them must get a real page, the sitemap
must be well-formed XML, and every URL it advertises must answer 200.
"""
from __future__ import annotations

import os
import sys
import tempfile
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove.core import VERSION, Store  # noqa: E402
from threattrove.web import create_app  # noqa: E402

SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"

failures = []


def check(name, ok, detail=""):
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{(' - ' + detail) if detail and not ok else ''}")
    if not ok:
        failures.append(name)


def main() -> int:
    os.environ["TT_SITE_URL"] = "https://threattrove.example"
    tmp = tempfile.mkdtemp(prefix="tt-docs-")
    store = Store(os.path.join(tmp, "docs.db"))
    app = create_app(store)
    app.config.update(TESTING=True)
    client = app.test_client()
    try:
        print("pages")
        for path, needle in (("/about", b"How a verdict is reached"),
                             ("/privacy", b"What is stored"),
                             ("/robots.txt", b"Sitemap:"),
                             ("/sitemap.xml", b"<urlset")):
            r = client.get(path)
            check(f"GET {path} is 200", r.status_code == 200, str(r.status_code))
            check(f"GET {path} has a body", needle in r.data,
                  r.data[:120].decode("utf-8", "replace"))

        print("crawler files")
        robots = client.get("/robots.txt").data.decode()
        check("robots points at the canonical sitemap",
              "https://threattrove.example/sitemap.xml" in robots, robots)
        check("robots allows the public pages", "Allow: /" in robots)
        check("robots keeps bulk uploads out", "Disallow: /api/v1/bulk" in robots)

        raw = client.get("/sitemap.xml").data
        check("sitemap uses the configured origin, not the Host header",
              b"https://threattrove.example/" in raw)
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            check("sitemap is well-formed XML", False, str(exc))
            root = None
        if root is not None:
            check("sitemap root is urlset", root.tag == SITEMAP_NS + "urlset", root.tag)
            locs = [e.text for e in root.iter(SITEMAP_NS + "loc")]
            check("sitemap lists nine pages", len(locs) == 9, str(len(locs)))
            check("sitemap has the new pages",
                  any(u.endswith("/about") for u in locs)
                  and any(u.endswith("/privacy") for u in locs), str(locs))
            for url in locs:
                path = url[len("https://threattrove.example"):] or "/"
                r = client.get(path)
                check(f"advertised URL {path} answers 200", r.status_code == 200,
                      str(r.status_code))

        print("navigation")
        home = client.get("/").data.decode()
        check("nav links to About", 'href="/about"' in home)
        check("footer links to Privacy", 'href="/privacy"' in home)
        about = client.get("/about").data.decode()
        check("every page loads its stylesheet from this host",
              'href="/static/style.css' in about)
        # static files are served with a one-hour browser cache, so the URL has
        # to carry the version or a stylesheet fix stays invisible for an hour.
        check("the stylesheet URL is busted by the app version",
              f'href="/static/style.css?v={VERSION}"' in about,
              "missing ?v=" + VERSION)
        check("og:url uses the configured origin, not the Host header",
              'content="https://threattrove.example/about"' in about)

        print("a page never echoes a query unescaped")
        r = client.get("/about?q=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        body = r.data.decode("utf-8", "replace")
        check("about still answers 200 to a hostile query", r.status_code == 200)
        check("about escapes the echoed query", "<script>alert(1)" not in body)
    finally:
        store.close()

    print()
    if failures:
        print(f"FAILED {len(failures)}: {', '.join(failures)}")
        return 1
    print("all docs checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
