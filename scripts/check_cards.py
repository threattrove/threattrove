#!/usr/bin/env python3
"""Check the Open Graph share cards end to end, without touching the network.

Run from the repository root::

    python3 scripts/check_cards.py [outdir]

Renders one card per verdict, asserts the card route serves a decodable
1200x630 PNG, and asserts the result page advertises it. The engine is stubbed,
so no provider is contacted.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove import cards  # noqa: E402
from threattrove.core import (  # noqa: E402
    Report,
    SourceResult,
    Store,
    defang,
    parse_indicator,
)
from threattrove.web import create_app  # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    if ok:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}{(' — ' + detail) if detail else ''}")
        FAILED.append(label)


def png_size(data: bytes):
    """(width, height) from the PNG IHDR chunk, or None if it is not a PNG."""
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


def main() -> int:
    outdir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp())
    outdir.mkdir(parents=True, exist_ok=True)
    print(f"output: {outdir}")

    defang_cases = [
        ("http://evil.example/login.php", "hxxp://evil[.]example/login[.]php"),
        ("evil.example", "evil[.]example"),
        ("1.2.3.4", "1[.]2[.]3[.]4"),
    ]
    for raw, want in defang_cases:
        check(f"defang {raw!r}", defang(raw) == want, defang(raw))

    if not cards.available():
        print("  FAIL Pillow is not installed — cards would 404")
        return 1
    check("Pillow importable", True)

    print("\n-- rendering")
    samples = [
        ("url", "http://malware-delivery.example/payload.exe", "malicious", 100),
        ("domain", "example.com", "clean", -20),
        ("hash", "44d88612fea8a8f36de82e1278abb02f", "known_good", -100),
        ("ip", "203.0.113.9", "unknown", 0),
    ]
    for kind, value, verdict, score in samples:
        data = cards.render(kind, value, verdict, score)
        size = png_size(data)
        path = outdir / f"card-{kind}-{verdict}.png"
        path.write_bytes(data)
        check(f"render {verdict} card", size == (1200, 630), str(size))

    # long URL: exercises the two-line truncation path
    long_val = "https://cdn.badfiles.example/a/very/long/path/" + "x" * 220 + "/setup.exe"
    check("render long URL card",
          png_size(cards.render("url", long_val, "suspicious", 60)) == (1200, 630))
    (outdir / "card-long-url.png").write_bytes(
        cards.render("url", long_val, "suspicious", 60))

    # caching must return the same bytes, not re-render
    a = cards.render("domain", "example.com", "clean", -20)
    check("cache hit is stable", a == cards.render("domain", "example.com", "clean", -20))

    print("\n-- routes (engine stubbed)")
    store = Store(Path(tempfile.mkdtemp()) / "cards.db")
    app = create_app(store)
    rt = app.extensions["threattrove"]
    ind = parse_indicator("example.com")
    report = Report(indicator=ind, results=[
        SourceResult(source="alpha", status="found", verdict="clean"),
        SourceResult(source="beta", status="not_found", verdict="clean"),
    ])
    rt.engine.lookup = lambda indicator, use_cache=True: report
    store.record_lookup(report)

    client = app.test_client()

    page = client.get("/i/domain?v=example.com")
    html = page.get_data(as_text=True)
    check("result page 200", page.status_code == 200, str(page.status_code))
    check("result page keeps noindex",
          page.headers.get("X-Robots-Tag") == "noindex")
    check("twitter card is large", "summary_large_image" in html)

    m = re.search(r'<meta property="og:image" content="([^"]+)"', html)
    check("og:image present", bool(m))
    if m:
        img_url = m.group(1)
        check("og:image points at card", "/card/domain.png" in img_url, img_url)
        check("og:image is absolute", img_url.startswith("http"), img_url)
        path_q = img_url[img_url.index("/card/"):]
        card = client.get(path_q)
        check("card route 200", card.status_code == 200, str(card.status_code))
        check("card is a PNG", png_size(card.get_data()) == (1200, 630))
        check("card content-type",
              card.headers.get("Content-Type") == "image/png",
              card.headers.get("Content-Type", ""))
        check("card is cacheable",
              "public" in card.headers.get("Cache-Control", ""),
              card.headers.get("Cache-Control", ""))
        etag = card.headers.get("ETag", "")
        again = client.get(path_q, headers={"If-None-Match": etag})
        check("card honours ETag", again.status_code == 304, str(again.status_code))
        (outdir / "card-route.png").write_bytes(card.get_data())

    check("indicator is defanged in og:title",
          'content="example[.]com' in html)

    url_m = re.search(r'<meta property="og:url" content="([^"]+)"', html)
    check("og:url keeps the indicator",
          bool(url_m) and "v=example.com" in url_m.group(1),
          url_m.group(1) if url_m else "missing")

    desc_m = re.search(r'<meta property="og:description" content="([^"]*)"', html)
    desc = desc_m.group(1) if desc_m else ""
    check("description has no negative score", "score -" not in desc, desc)
    check("description names the verdict", desc.startswith("Clean"), desc)

    # cards are read-only: an indicator never looked up still renders, as unknown
    cold = client.get("/card/domain.png?v=never-looked-up.example")
    check("cold indicator still renders", cold.status_code == 200,
          str(cold.status_code))

    check("wrong kind is 404", client.get("/card/hash.png?v=example.com").status_code == 404)
    check("bad kind is 404", client.get("/card/bogus.png?v=example.com").status_code == 404)
    check("junk value is 404", client.get("/card/domain.png?v=%00%20").status_code == 404)

    store.close()
    print()
    if FAILED:
        print(f"{len(FAILED)} check(s) failed")
        return 1
    print("all card checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
