#!/usr/bin/env python3
"""Check that public feeds do not republish query strings and fragments.

Run from the repository root::

    python3 scripts/check_privacy.py

The recent feeds are public on this instance, and a pasted URL often carries a
token, an e-mail address or an order number. Those stay in the lookup that was
asked for; they must not show up on the front page or /recent. Nothing here
touches the network: the engine is stubbed.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove.core import (  # noqa: E402
    Report,
    SourceResult,
    Store,
    parse_indicator,
)
from threattrove.web import create_app, redact  # noqa: E402

FAILED = []

SECRET = "sess-9f3c2a7b41d0"          # stands in for a real token
TOKENISED = f"https://portal.example/reset?token={SECRET}&user=a@b.example#top"
FRAGMENTED = "https://portal.example/doc#section-2"
PLAIN = "https://portal.example/login"


def check(label, ok, detail=""):
    if ok:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}{(' — ' + detail) if detail else ''}")
        FAILED.append(label)


def main() -> int:
    print("-- redact()")
    check("strips query string", redact(TOKENISED) == "https://portal.example/reset")
    check("strips fragment", redact(FRAGMENTED) == "https://portal.example/doc")
    check("leaves a plain URL alone", redact(PLAIN) == PLAIN)
    check("leaves a hash alone", redact("44d88612fea8a8f36de82e1278abb02f")
          == "44d88612fea8a8f36de82e1278abb02f")
    check("handles empty input", redact("") == "")

    print("\n-- public feeds")
    store = Store(Path(tempfile.mkdtemp()) / "privacy.db")
    app = create_app(store)
    rt = app.extensions["threattrove"]

    def fake_lookup(indicator, use_cache=True):
        return Report(indicator=indicator, results=[
            SourceResult(source="alpha", status="found", verdict="unknown"),
        ])

    rt.engine.lookup = fake_lookup
    for value in (PLAIN, TOKENISED, FRAGMENTED):
        store.record_lookup(fake_lookup(parse_indicator(value)))

    client = app.test_client()
    for path in ("/", "/recent"):
        page = client.get(path)
        html = page.get_data(as_text=True)
        check(f"{path} 200", page.status_code == 200, str(page.status_code))
        check(f"{path} hides the token", SECRET not in html)
        check(f"{path} hides the query parameter name", "token=" not in html)
        check(f"{path} hides the fragment", "section-2" not in html)
        check(f"{path} keeps the path", "portal.example/reset" in html)
        linked = re.search(r'href="/i/url\?v=[^"]+"[^>]*>' + re.escape(PLAIN),
                           html)
        check(f"{path} keeps a link for clean URLs", bool(linked),
              PLAIN)
        check(f"{path} marks the redaction", "?…" in html)

    # the lookup the user asked for still shows the full value to them
    own = client.get("/i/url", query_string={"v": TOKENISED}).get_data(as_text=True)
    check("the report itself keeps the exact value", "portal.example/reset?token=" in own)

    stats = client.get("/api/v1/stats").get_json() or {}
    check("stats endpoint has no indicator values",
          SECRET not in str(stats) and "lookups_total" in stats)

    store.close()
    print()
    if FAILED:
        print(f"{len(FAILED)} check(s) failed")
        return 1
    print("all privacy checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
