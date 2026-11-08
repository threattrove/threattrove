#!/usr/bin/env python3
"""Check vendor-label normalisation and the family pages, without the network.

Run from the repository root::

    python3 scripts/check_families.py

Two halves. The first exercises ``threattrove.families`` directly: the closed
alias table must collapse vendor spellings, keep a two-family label as two
families whatever the order, and report an unknown token instead of inventing a
family. The second seeds a temporary ``Store`` with six cached hash rows and
drives the real app through Flask's test client, so the index, one family page,
paging, the 404s and the result-page chips are checked against rendered HTML.
No provider is contacted.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threattrove import families  # noqa: E402
from threattrove.core import Report, SourceResult, Store  # noqa: E402
from threattrove.web import create_app  # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    if ok:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}{(' — ' + str(detail)) if detail else ''}")
        FAILED.append(label)


def seed(store: Store, value: str, source: str, field: str, raw: str) -> None:
    """Cache one hash answer carrying a single vendor label field."""
    store.put_cached(
        "hash", value,
        SourceResult(source=source, status="found", verdict="malicious",
                     detail={field: raw}),
    )


def main() -> int:
    print("-- normaliser")
    n = families.normalize("Trojan.Linux.Mirai")
    check("vendor prefix and platform collapse",
          (n.outcome, n.families) == ("families", ("Mirai",)),
          f"{n.outcome} {n.families}")
    check("same key for every spelling of Mirai",
          len({families.normalize(s).key for s in (
              "Trojan.Linux.Mirai", "Trojan.Mirai", "Mirai", "TROJAN.MIRAI",
              "Linux/Mirai.FDF trojan")}) == 1)

    n = families.normalize("trojan.mirai/smlbo20")
    check("engine suffix keeps the family",
          n.families == ("Mirai",), n.families)
    check("engine suffix is reported, not guessed",
          "smlbo20" in n.unmapped, n.unmapped)

    n = families.normalize("trojan.mirai/gafgyt")
    check("two families in one label",
          n.key == frozenset({"Mirai", "Gafgyt"}), n.families)
    check("the first family named is the primary",
          n.primary == "Mirai", n.primary)
    check("two-family labels are order independent",
          families.normalize("trojan.draftor/salat").key
          == families.normalize("trojan.salat/draftor").key
          == frozenset({"Draftor", "Salat"}))

    for raw in ("Trojan.Generic", "Generic", "malicious_confidence_100%"):
        n = families.normalize(raw)
        check(f"{raw!r} is not a family",
              n.outcome != "families" and not n.families,
              f"{n.outcome} {n.families}")

    n = families.normalize("trojan.zzzznotafamily")
    check("unknown token never becomes a family",
          n.families == () and "zzzznotafamily" in n.unmapped,
          f"{n.families} {n.unmapped}")

    chips = families.chips_of({"source": "virustotal",
                               "detail": {"threat_label": "trojan.mirai/gafgyt"}})
    check("one chip per family, primary first",
          [c["name"] for c in chips] == ["Mirai", "Gafgyt"], chips)
    check("chip keeps the raw label it came from",
          all(c["raw"] == "trojan.mirai/gafgyt" for c in chips))
    check("generic label draws no chip",
          families.chips_of({"source": "virustotal",
                             "detail": {"threat_label": "Trojan.Generic"}}) == [])
    check("engine signature draws no chip",
          families.chips_of({"source": "metadefender",
                             "detail": {"signature": "Unknown/Eicar!428cbHx5"}}) == [])

    plain, variants = families.label_split(
        ["Mirai", "Trojan.Mirai", "trojan.mirai/gafgyt", "trojan.mirai/smlbo20"])
    check("plain labels stay plain",
          sorted(plain) == ["Mirai", "Trojan.Mirai"], plain)
    check("noisy labels fold away",
          sorted(variants) == ["trojan.mirai/gafgyt", "trojan.mirai/smlbo20"],
          variants)

    print("\n-- pages")
    store = Store(Path(tempfile.mkdtemp()) / "families.db")
    vt_two = "a" * 32       # Mirai + Gafgyt in one VirusTotal label
    ha_one = "b" * 32       # Hybrid Analysis
    mb_one = "c" * 32       # MalwareBazaar
    vt_suffix = "d" * 32    # Mirai plus an unmapped engine token
    vt_generic = "e" * 32   # a generic label: no family, no page
    tf_one = "f" * 32       # a second family, alone
    seed(store, vt_two, "virustotal", "threat_label", "trojan.mirai/gafgyt")
    seed(store, ha_one, "hybridanalysis", "family", "Trojan.Mirai")
    seed(store, mb_one, "malwarebazaar", "signature", "Mirai")
    seed(store, vt_suffix, "virustotal", "threat_label", "trojan.mirai/smlbo20")
    seed(store, vt_generic, "virustotal", "threat_label", "Trojan.Generic")
    seed(store, tf_one, "threatfox", "malware", "Draftor")

    app = create_app(store)
    rt = app.extensions["threattrove"]
    labels = {"threat_label": {vt_two: "trojan.mirai/gafgyt",
                               vt_suffix: "trojan.mirai/smlbo20",
                               vt_generic: "Trojan.Generic"}}
    rt.engine.lookup = lambda ind, use_cache=True: Report(
        indicator=ind,
        results=[SourceResult(source="virustotal", status="found",
                              verdict="malicious",
                              detail={"threat_label": labels["threat_label"].get(
                                  ind.value, "Trojan.Mirai")})],
    )
    client = app.test_client()

    index = client.get("/family")
    html = index.get_data(as_text=True)
    check("index 200", index.status_code == 200, index.status_code)
    check("index is cacheable",
          "public" in index.headers.get("Cache-Control", ""),
          index.headers.get("Cache-Control", ""))
    check("index counts only attributed samples", " 5 of 6 cached" in html,
          "expected 5 of 6")
    check("index lists Mirai", 'fam-card-name">Mirai' in html)
    check("index counts Mirai's four samples",
          'fam-card-n">4 samples' in html)
    check("index lists the single-sample families",
          'fam-card-name">Draftor' in html and 'fam-card-name">Gafgyt' in html)
    check("index never lists a generic label",
          'fam-card-name">Generic' not in html)
    check("index sorts by sample count",
          html.index('fam-card-name">Mirai') < html.index('fam-card-name">Draftor'))
    check("index names the sources that contributed",
          "hybridanalysis" in html and "malwarebazaar" in html)

    page = client.get("/family/Mirai")
    html = page.get_data(as_text=True)
    check("family page 200", page.status_code == 200, page.status_code)
    check("family page sample total", "4 cached samples" in html,
          "expected 4")
    check("family page distinct labels", "4 distinct vendor labels" in html,
          "expected 4")
    # Only the Gafgyt label names a second family; the engine-suffix sample is
    # still Mirai alone, so that count must stay at one.
    check("family page counts the co-tagged sample",
          "<b>1</b><span>also in another family</span>" in html)
    check("family page lists every contributing source",
          ">virustotal<" in html and ">malwarebazaar<" in html
          and ">hybridanalysis<" in html)
    for value in (vt_two, ha_one, mb_one, vt_suffix):
        check(f"family page lists {value[:8]}…", f'title="{value}"' in html)

    head, _, tail = html.partition("<details")
    check("plain labels are shown up front",
          "Trojan.Mirai" in head and ">Mirai<" in head)
    check("noisy labels start folded away",
          "trojan.mirai/gafgyt" not in head and "trojan.mirai/gafgyt" in tail,
          "combined label leaked out of <details>")
    check("engine-suffix label is folded away",
          "trojan.mirai/smlbo20" in tail)
    check("folded block says why", "second family name" in tail)

    check("co-occurrence is counted per sample",
          "Named alongside" in html
          and 'Gafgyt<span class="fam-chip-n">1</span>' in html)

    lower = client.get("/family/mirai")
    check("family lookup is case insensitive", lower.status_code == 200,
          lower.status_code)
    check("lower-case lookup is the same page",
          "4 cached samples" in lower.get_data(as_text=True))

    missing = client.get("/family/NoSuchFamily")
    check("unknown family is 404", missing.status_code == 404,
          missing.status_code)
    check("unknown family says why",
          "No cached sample is attributed to that family."
          in missing.get_data(as_text=True))
    check("a generic label is not a family page",
          client.get("/family/Trojan.Generic").status_code == 404)
    check("the generic token alone is not a family page",
          client.get("/family/Generic").status_code == 404)

    clamped = client.get("/family/Mirai?page=99")
    check("out-of-range page clamps", clamped.status_code == 200,
          clamped.status_code)
    check("clamped page is the last page",
          "page 1 / 1" in clamped.get_data(as_text=True))
    check("junk page argument is tolerated",
          client.get("/family/Mirai?page=abc").status_code == 200)

    draftor = client.get("/family/Draftor").get_data(as_text=True)
    check("a one-sample family reads as one sample",
          "1 cached sample attributed" in draftor, "expected singular")
    check("a clean family has nothing to fold away", "<details" not in draftor)
    check("one-sample family names its source", ">threatfox<" in draftor)

    gafgyt = client.get("/family/Gafgyt").get_data(as_text=True)
    check("the other family links back",
          'class="fam-chip alt" href="/family/Mirai"' in gafgyt)
    check("co-tagged sample is counted once per family",
          "<b>1</b><span>also in another family</span>" in gafgyt)

    print("\n-- result page chips")
    result = client.get(f"/i/hash?v={vt_two}")
    html = result.get_data(as_text=True)
    check("result page 200", result.status_code == 200, result.status_code)
    check("primary chip links to the family",
          'class="fam-chip" href="/family/Mirai"' in html)
    check("primary chip carries the raw label",
          'title="Mirai — named by this source as trojan.mirai/gafgyt"' in html)
    check("second family gets the alt chip",
          'class="fam-chip alt" href="/family/Gafgyt"' in html)

    generic = client.get(f"/i/hash?v={vt_generic}").get_data(as_text=True)
    check("generic label renders no chip", "fam-chip" not in generic)

    print("\n-- memoisation")
    seed(store, "1" * 32, "virustotal", "threat_label", "Linux/Mirai.FDF trojan")
    again = client.get("/family/Mirai").get_data(as_text=True)
    check("a new cache row reaches the page", "5 cached samples" in again,
          "memo did not notice the new row")

    print("\n-- empty cache")
    empty = Store(Path(tempfile.mkdtemp()) / "empty.db")
    empty_client = create_app(empty).test_client()
    empty_page = empty_client.get("/family")
    check("empty index 200", empty_page.status_code == 200,
          empty_page.status_code)
    check("empty index says so",
          "No cached answer carries a family label yet."
          in empty_page.get_data(as_text=True))
    check("empty index has no cards",
          'class="fam-card"' not in empty_page.get_data(as_text=True))

    empty.close()
    store.close()
    print()
    if FAILED:
        print(f"{len(FAILED)} check(s) failed")
        return 1
    print("all family checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
