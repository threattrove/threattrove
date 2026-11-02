#!/usr/bin/env python3
"""Check defanged indicator handling: paste what you actually have.

Run from the repository root::

    python3 scripts/check_refang.py

Exits non-zero on the first failed expectation. Nothing here touches the
network: parsing only.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove import bulk  # noqa: E402
from threattrove.core import (  # noqa: E402
    KIND_DOMAIN,
    KIND_HASH,
    KIND_IP,
    KIND_URL,
    extract_indicators,
    parse_indicator,
    refang,
)

FAILED = []


def check(cond: bool, msg: str) -> None:
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        FAILED.append(msg)


def one(text: str):
    ind = parse_indicator(text)
    return (ind.kind, ind.value) if ind else (None, None)


def main() -> int:
    print("refang: single indicators")
    cases = [
        ("hxxp://evil[.]com/x", KIND_URL, "http://evil.com/x"),
        ("hxxps://evil[.]com/a?b=1", KIND_URL, "https://evil.com/a?b=1"),
        ("hxxp[:]//evil[.]com/x", KIND_URL, "http://evil.com/x"),
        ("HXXPS://EVIL[.]COM/Path", KIND_URL, "https://evil.com/Path"),
        ("hxxp://evil(.)com/x", KIND_URL, "http://evil.com/x"),
        ("evil[dot]com", KIND_DOMAIN, "evil.com"),
        ("evil dot com", KIND_DOMAIN, "evil.com"),
        ("evil[.]co[.]uk", KIND_DOMAIN, "evil.co.uk"),
        ("evil[.]com/path", KIND_URL, "http://evil.com/path"),
        ("1[.]2[.]3[.]4", KIND_IP, "1.2.3.4"),
        ("44d88612fea8a8f36de82e1278abb02f", KIND_HASH,
         "44d88612fea8a8f36de82e1278abb02f"),
    ]
    for text, kind, value in cases:
        got_kind, got_value = one(text)
        check(got_kind == kind and got_value == value,
              f"{text!r} -> {kind} {value} (got {got_kind} {got_value})")

    print("refang: paste junk")
    zw = "evil\u200b[.]\u200bcom"
    check(one(zw) == (KIND_DOMAIN, "evil.com"), "zero-width characters stripped")
    zhash = "44d88612fea8a8f3\u200b6de82e1278abb02f"
    check(one(zhash)[0] == KIND_HASH, "zero-width inside a hash still parses")
    ind = parse_indicator("hxxp://evil[.]com/x")
    check(ind is not None and ind.raw == "hxxp://evil[.]com/x",
          "original paste is preserved in .raw")
    ind = parse_indicator("hxxp://user[:]pw[at]evil[.]com/")
    check(ind is not None and ind.host == "evil.com",
          "userinfo with [at] still resolves the host")

    print("refang: plain text is left alone")
    for text in ("hello (world).", "Version 2.3.0 was released.",
                 "the quick brown fox", "http://example.com/a?b=c"):
        check(refang(text) == text, f"{text!r} unchanged")
    for text in [c[0] for c in cases] + [zw, zhash]:
        check(refang(refang(text)) == refang(text), f"idempotent: {text!r}")

    print("refang: no false positives")
    for text in ("hello", "report", "site", "", "nothing to see here"):
        check(parse_indicator(text) is None,
              f"{text!r} is not turned into an indicator")

    print("extract: report bodies")
    report = """\
Subject: possible dropper, please check

We saw traffic to hxxp://evil[.]example[.]com/payload[.]exe from the host
10[.]20[.]30[.]40. The sample is
44d88612fea8a8f36de82e1278abb02f (md5) and the C2 domain looks like
bad-c2 dot net. Do not open invoice.pdf.
"""
    found = extract_indicators(report)
    got = {(i.kind, i.value) for i in found}
    check((KIND_URL, "http://evil.example.com/payload.exe") in got,
          "URL pulled out of prose")
    check((KIND_IP, "10.20.30.40") in got, "defanged IP pulled out of prose")
    check((KIND_HASH, "44d88612fea8a8f36de82e1278abb02f") in got,
          "hash pulled out of prose")
    check((KIND_DOMAIN, "bad-c2.net") in got, "'bad-c2 dot net' refanged")
    check(not any(v.endswith(".pdf") for _, v in got),
          "file name 'invoice.pdf' is not treated as a domain")
    check(len(found) == len({(i.kind, i.value) for i in found}),
          "no duplicates in extraction")
    check(all(i.kind != KIND_DOMAIN or i.value != "evil.example.com" for i in found),
          "host of an extracted URL is not looked up twice")

    check(extract_indicators("Nothing to see here, just a sentence.") == [],
          "plain prose yields no indicators")

    print("bulk: pasted lists")
    text = "\n".join([
        "# comment",
        "",
        "hxxp://evil[.]com/a",
        "evil[.]com",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "example.com,seen in ticket 4711",
        "Contact hxxp://bad[.]test/x then 192[.]168[.]1[.]9",
    ])
    items, skipped = bulk.parse_text(text)
    values = {(i.kind, i.value) for i in items}
    check((KIND_URL, "http://evil.com/a") in values, "bulk keeps a defanged URL")
    check((KIND_DOMAIN, "evil.com") in values, "bulk keeps a defanged domain")
    check((KIND_DOMAIN, "example.com") in values, "'value,note' row still works")
    check((KIND_URL, "http://bad.test/x") in values
          and (KIND_IP, "192.168.1.9") in values,
          "prose line yields both indicators")
    check(skipped == 0, f"nothing silently dropped (skipped={skipped})")
    check(len(items) == len({(i.kind, i.value) for i in items}),
          "bulk output is deduplicated")

    print()
    if FAILED:
        print(f"{len(FAILED)} check(s) failed")
        return 1
    print("all refang checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
