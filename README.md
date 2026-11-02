# ThreatTrove

**Self-hosted reputation lookup for file hashes, URLs, domains and IPs — built to run on [threattrove.com](https://threattrove.com) or on your own box.**

ThreatTrove does the three things most people open VirusTotal for: paste an
indicator, get a verdict, and see *which* sources said what. It runs keyless out
of the box (9 sources, no account anywhere) and gets sharper as you add API keys.

```
$ threattrove 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

━━ 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

  File hash
  MALICIOUS    93% confidence    Listed as malicious by 4 independent sources, and 67/76 engines agree (virus.eicar/test)
  detections  67/76

  SECURITY SOURCES
  ──────────────────────────────────────────────────────────────────────────
  ● circl            MALICIOUS          listed by malshare.com
  ● otx              MALICIOUS          49 pulse(s), 1 no-threat pulse(s) ignored
  ○ malwarebazaar    UNKNOWN
  ? threatfox        UNKNOWN
  ○ urlhaus          UNKNOWN
  ● virustotal       MALICIOUS  66/75   66/75 engines flagged
  ● hybridanalysis   MALICIOUS  1/1     1/1 scanner(s) flagged - EICAR
  ○ malshare         UNKNOWN

  elapsed 0.48s  ·  8 security sources queried
```

That is the EICAR test file on an install with every key set. Take the keys away
and the same hash reads `SUSPICIOUS 45%`: CIRCL and OTX both call it malicious,
but neither examined the file, so corroboration on its own is a lead rather than
a conviction. That distinction is the whole point — see
[How a verdict is produced](#how-a-verdict-is-produced).

---

## Why another one

* **Keyless by default.** CIRCL hashlookup, AlienVault OTX, urlscan.io, crt.sh,
  DNS and RDAP answer without registration, so a fresh clone is useful in ~30s.
* **One verdict, many voices.** Each source gets its own row with status, note
  and (where it exists) an engine ratio; the verdict needs corroboration from two
  independent sources before it says "malicious", and shows an evidence
  breakdown rather than a single unexplained number.
* **Built for bulk.** CSV/feed ingestion in the CLI and in the web UI, with
  SQLite-backed jobs you can poll and export.
* **Own your data.** Everything — cache, bulk jobs, your own labels — lives in a
  single SQLite file you control. Nothing phones home.
* **Small.** Flask + requests + gunicorn. No queue, no Redis, no JS build step.

---

## Quickstart

```bash
pip install threattrove

threattrove 44d88612fea8a8f36de82e1278abb02f      # CLI
threattrove-web --port 8080                       # UI + API on http://127.0.0.1:8080
```

Or from source:

```bash
git clone https://github.com/threattrove/threattrove && cd threattrove
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

Python 3.9+. Runtime dependencies: `requests`, `flask`, `gunicorn`.

---

## CLI

```bash
# one indicator, text report
threattrove 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
threattrove https://example.com/login
threattrove example.com --json

# hash a local file and look it up
threattrove --hash-file ./suspicious.exe

# bulk: CSV, newline list or JSON/JSONL feed (format auto-detected)
threattrove --csv iocs.csv --out results.csv
threattrove --feed hashes.txt --out results.jsonl
threattrove --feed feed.json --fail-on-malicious      # exit 3 if anything is bad

# sources and engine tuning
threattrove --list-sources
threattrove ioc.example --sources keyless              # only keyless sources
threattrove ioc.example --sources reputation,intel     # by category
threattrove ioc.example --no-cache --timeout 60 --workers 8

# local corpus: your own known-bad / known-good labels
threattrove --add-local 275a021b... --label malware --note "EICAR test file"
threattrove --list-local
threattrove --stats

# bulk local corpus: import a whole blocklist into the same table
threattrove --import-local full.csv --dry-run     # count and sample, write nothing
threattrove --import-local full.csv --label malware --note "MalwareBazaar"
```

Exit codes: `0` success, `1` usage error, `3` `--fail-on-malicious` tripped.

### Importing a blocklist

`--import-local FILE` streams a dump of any shape into the `local` table: a
MalwareBazaar export with ten columns, a quoted CSV, a newline list of MD5s, or
a mixed feed. Every field of every line is scanned and any md5/sha1/sha256-shaped
token is taken, so no column map is needed and a header row is skipped on its own.
Duplicates collapse by primary key, so re-importing the same file is safe — an
existing row is replaced (relabelled), not doubled. Writes commit in chunks of
20,000 rows, which keeps a running web instance responsive and lands around
15,000 hashes/second.

`--dry-run` is the safe first pass: it reports how many hashes the file contains,
how many are already stored, how many are new, and prints a sample, without
touching the database. `--import-limit N` caps a run at the first N hashes when
you want to spot-check a very large file first. Importing 1.16M SHA256 values
lands around 140 MB of SQLite — plan disk accordingly.

---

## Web UI

| Page | What it does |
| --- | --- |
| `/` | Paste a hash, URL, domain or IP; recent lookups |
| `/search?q=…` | Resolve any indicator and redirect to its result page |
| `/i/<kind>?q=…` | Result page: verdict, score, per-source table, what decided it |
| `/bulk` | Upload a CSV/feed or paste a list; runs as a background job |
| `/bulk/<job_id>` | Job progress, per-row verdicts, CSV/JSON export |
| `/recent` | The lookup feed, newest first, 50 rows a page |
| `/sources` | Source catalogue with live state (`active` / `needs key` / `opt-in`) |
| `/local` | The local corpus: 50 rows a page, filter by kind, search a value, add or delete |
| `/status` | Per-source health: last canary answer, latency, drift, and what is not answering |
| `/about` | What the verdict rules are, what the tool does not claim, and who it is for |
| `/privacy` | What is stored, what is sent upstream, what is never collected |
| `/api` | JSON API documentation |
| `/sitemap.xml`, `/robots.txt` | Crawler index and policy, absolute URLs from `TT_SITE_URL` |
| `/health`, `/healthz` | Liveness JSON: `{"status":"ok","version":"…"}` |

---

## JSON API

All lookups accept `?fresh=1` to bypass the cache. Responses are
VirusTotal-shaped (`data.attributes`-ish flat object with `verdict`, `score`,
`confidence`, `results[]`).

```bash
curl -s http://127.0.0.1:8080/api/v1/hash/44d88612fea8a8f36de82e1278abb02f
curl -s "http://127.0.0.1:8080/api/v1/url?url=https://example.com/login"
curl -s "http://127.0.0.1:8080/api/v1/domain?domain=example.com"
curl -s "http://127.0.0.1:8080/api/v1/lookup?q=$(echo -n evil | sha256sum | cut -d' ' -f1)"
curl -s http://127.0.0.1:8080/api/v1/sources
curl -s http://127.0.0.1:8080/api/v1/stats
```

Bulk over the API — submit, then poll:

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/bulk \
     -F file=@iocs.csv -F label=incident-42
# {"job_id":"j_ab12…","total":120,"skipped":0,"status_url":"…/api/v1/bulk/j_ab12…"}

curl -s http://127.0.0.1:8080/api/v1/bulk/j_ab12…
curl -s http://127.0.0.1:8080/api/v1/bulk/j_ab12…/items
```

Raw bodies work too (`text/plain`, one indicator per line). Limits come from
`TT_RATE_LIMIT` (default 60/min per IP) and `TT_MAX_UPLOAD` (2 MiB).

---

## How a verdict is produced

Each source returns `verdict`, `detections`/`total` (engines), `note` and a raw
`detail`. Weights are only used for bookkeeping; the verdict itself is driven by
**corroboration** — how many independent sources actually say malicious.

| Condition | Verdict |
| --- | --- |
| The hash is in your imported local corpus, no allowlist conflict | MALICIOUS, confidence 70+ |
| 2 or more sources say malicious, at least one examined the file | MALICIOUS |
| 2 or more sources say malicious, none examined the file | SUSPICIOUS, confidence capped at 45 |
| 1 source says malicious (no allowlist conflict) | SUSPICIOUS |
| Sources say suspicious, none say malicious, and the engines cleared the file | CLEAN, with the weak flags named |
| Sources say suspicious, none say malicious | SUSPICIOUS |
| A malware feed and a curated allowlist both match | UNKNOWN (refuse to guess) |
| Source says known-good (NSRL, whitelist) | KNOWN GOOD |
| Sources say clean | CLEAN |
| Nothing answered | UNKNOWN |

Confidence is a grade of agreement, not a sum of points:

| Corroborating sources | Confidence |
| --- | --- |
| 1 | 45 |
| 2 | 75 |
| 3 | 88 |
| 4 | 93 |
| 5+ | 96 |

A source that also reports engines adds a small bonus, capped at 98. Why the
floor exists: a lone feed hit is frequently a stale entry, an over-broad
signature, or a shared-hosting address, and calling that "malicious" is how a
lookup tool loses its users' trust. One hit is reported as a lead, with the
name of the source that produced it.

Two rules keep genuine vendor software out of the alarm path. **Direct
evidence**: only sources that examined the file itself (sample repositories,
engine scans, sandboxes, a local analyst) can convict, because feeds record
where a copy was *served from* and routinely accuse software that attackers
re-hosted — the classic case is an authentic installer listed as a URLhaus
payload. **Engine clearance**: when every antivirus engine that scanned the file
reports zero detections over at least two engine slots, heuristic-only
suspicion (a sandbox behavioural score, an OTX pulse) is demoted to CLEAN with a
confidence of 35, and the headline names the sources that still flag it. A
conviction is never erased by a clean sweep, and a single scanner is not enough
to call a sweep. **Operator corpus**: a local row you imported or added yourself
is a decision about that exact file made by the instance's owner, not a
third-party feed's guess, so it convicts without waiting for a second source and
reads `Listed in your local blocklist`. An allowlist row still outranks a feed
hit, and a local row never overrides a conflicting allowlist into MALICIOUS.

Every report also carries an **evidence breakdown** (`evidence` in the JSON)
that groups the sources that answered into four classes — blocklists, sandbox
engines, community intel, reputation — and shows how many sources inside each
class agree. That is the honest alternative to a vendor count: instead of "73
engines", you see "2/3 blocklists, 0/1 sandbox". The result page draws it as
the **What decided this** panel described below.

Sources in the `intel` category (DNS, RDAP, crt.sh, reverse IP) enrich the
report but never change the verdict. Engine ratios are only computed from
sources that actually report engines — a urlscan "6987 scans" is a scan count,
not a detection count, and is shown as `–`.

**Engine floor**: a VirusTotal-style sweep only makes a call when at least three
engines agree *and* at least 3% of the engines that ran, because one vendor out
of ninety is noise rather than a determination. `8.8.8.8` carries a single flag
out of 92 engines, so it reads `1/92 engines flagged, below the 3 needed to call
it` and contributes no verdict instead of arriving as SUSPICIOUS — the raw ratio
is still shown, the sweep simply does not speak for it. A sub-floor flag also no
longer blocks engine clearance, so one noisy vendor cannot keep a heuristic
alarm alive.

Deliberate anti-noise choices: OTX pulses that carry `Whitelisted domain` or
`Known False Positive` validation are downgraded to UNKNOWN, and a pulse whose
tags say it is not a threat (`no problems`, `false positive`, `benign`, …) is
not counted at all — otherwise a lab-coverage pulse titled "UAlberta Computer
Lab Issues" makes every invented hash read suspicious; two "suspicious"
sources never add up to "malicious"; and a family label that names a category
rather than a family (`malware`, `trojan`, `generic`, `heur`, …) is neither used
to convict a file nor shown in the headline. Hybrid Analysis fills `vx_family`
with words like `Malware` on files it merely disliked — a popular 7-Zip binary
carries that tag — so a category word is not a determination.

### What decided this

A vendor count tells you how many engines disliked a file. It does not tell you
why this instance reached the verdict it did, or what would have changed it. So
every result page carries a **What decided this** panel (`decision` in the JSON)
with three parts.

*Weights per evidence class.* Each class that answered gets a bar showing the
net weight it contributed (blocklists, sandbox engines, community intel,
reputation), the sources inside it, and how many of them flagged the indicator.
The class that carried the verdict sits at the top; a class that answered and
abstained still appears, drawn short and grey, because "this feed looked and
found nothing" is part of the argument.

*Counterfactuals.* Each line re-runs the real verdict rules over a hypothetical
result set and prints what the answer would have been:

```
If MalwareBazaar or URLhaus payload had missed it   ->  SUSPICIOUS  45%
If MalShare flagged it too                          ->  MALICIOUS   88%
If you allowlist it                                 ->  KNOWN GOOD  100%
```

None of that is templated prose. `Report.decision()` calls `verdict()` and
`confidence()` on a copy of the report with a source removed or added
(`dataclasses.replace`), so if the conviction rules change, the promises in this
panel change with them — including the case where the answer is "nothing would
change it", in which case no line is printed. Sources that could raise the
verdict are taken from the live registry, filtered to the indicator type and to
the ones this deployment can actually query, so a domain is never told to
consult a hash-only sample repository and a self-hosted install without a
VirusTotal key is never given advice it cannot follow.

*Caveats.* Up to two structural notes: nobody examined the file itself, the
engines cleared it while a heuristic kept flagging it, your own corpus is what
made it malicious, or a feed and an allowlist both match and the tool refuses to
average them.

### What file is this hash?

When a source names the file — NSRL/CIRCL `FileName`/`ProductName`/
`OpSystemName`, VirusTotal `meaningful_name`/`type_description`, MalwareBazaar
`file_type` — the name is lifted out of the raw detail blob and shown under the
verdict (`file_identity` in the JSON). A known Windows binary therefore renders
as `Known good: cmd.exe (Microsoft Windows Operating System)` rather than as an
anonymous hash.

---

## Sources

24 sources are compiled in; 9 work with no key. `httpx`-free HTTP via `requests`.
Feodo Tracker's C2 list is not an HTTP source at all: it is imported into the
local corpus instead (see [Keeping the local blocklist current](#keeping-the-local-blocklist-current)).

| Source | Kind | Category | Key | Env var |
| --- | --- | --- | --- | --- |
| CIRCL hashlookup | hash | reputation | keyless | — |
| AlienVault OTX (file) | hash | reputation | keyless | — |
| AlienVault OTX (URL) | url | reputation | keyless | — |
| AlienVault OTX (domain/IP) | domain/ip | reputation | keyless | — |
| urlscan.io | url/domain/ip | reputation | keyless | — |
| DNS (Cloudflare DoH) | domain/ip | intel | keyless | — |
| RDAP | domain/ip | intel | keyless | — |
| crt.sh | domain | intel | keyless | — |
| reverse IP (HackerTarget) | domain/ip | intel | keyless, **opt-in** | `TT_ENABLE_REVERSE_IP=1` |
| VirusTotal (file/url) | hash/url | reputation | keyed | `VT_API_KEY` |
| VirusTotal (domain/IP) | domain/ip | reputation | keyed, **opt-in** | `VT_API_KEY` + `TT_VT_DOMAINS=1` |
| MetaDefender (file) | hash | reputation | keyed | `MD_API_KEY` |
| MetaDefender (URL) | url | reputation | keyed | `MD_API_KEY` |
| MetaDefender (domain/IP) | domain/ip | reputation | keyed | `MD_API_KEY` |
| MalwareBazaar | hash | reputation | keyed | `ABUSECH_AUTH_KEY` |
| ThreatFox | hash/url/domain/ip | reputation | keyed | `ABUSECH_AUTH_KEY` |
| URLhaus (hash + URL) | hash/url | reputation | keyed | `ABUSECH_AUTH_KEY` |
| Hybrid Analysis | hash | reputation | keyed | `HA_API_KEY` |
| MalShare | hash | reputation | keyed | `MALSHARE_API_KEY` |
| Triage | hash | reputation | keyed | `TRIAGE_API_KEY` |
| Google Safe Browsing | url/domain | reputation | keyed | `GSB_API_KEY` |
| PhishTank | url | reputation | keyed | `PHISHTANK_APPKEY` |
| urlscan (keyed) | url/domain/ip | reputation | keyed | `URLSCAN_API_KEY` |

Notes:

* abuse.ch (MalwareBazaar, ThreatFox, URLhaus) requires a free Auth-Key from
  <https://auth.abuse.ch/> since API 3.0.0. A bad key answers **403**, which
  ThreatTrove reports as `unauthorized` — the run continues.
* Feodo Tracker needs no key and is never queried live: `scripts/import_feodo.py`
  folds abuse.ch's C2 IP list — address, port, malware family, last online — into
  the `local` table as `kind=ip`, where the corpus is consulted before any
  upstream source. A hit therefore survives an upstream outage, and a C2 that
  drops off the feed keeps its last label instead of vanishing.
  abuse.ch's larger `ipblocklist_aggressive.csv` (~8,000 addresses,
  almost all offline since 2022) is deliberately not imported: those
  addresses have mostly been reassigned to someone else by now.
* `TT_ENABLE_REVERSE_IP` is off by default because that lookup sends the queried
  IP/hostname to a third-party service. That's the one source gated on consent.
* `TT_VT_DOMAINS` is off by default for a different reason. VirusTotal's
  domain/IP endpoint mostly reports a stray engine or two out of ninety, which
  the engine floor already reduces to "no verdict", so it spends the key's
  allowance to say very little. Set `TT_VT_DOMAINS=1` to turn it back on.
* The three VirusTotal sources share one daily allowance, because they spend one
  key. The cap is `TT_VT_DAILY_BUDGET` (default 400 of the 500 a free key
  allows), counted per UTC day in the SQLite database. When it is reached — or
  VirusTotal itself answers `quota exceeded` — those sources report `skipped`
  with the counter in the note and make no further requests until the day rolls
  over. Cached answers are still served, so a repeated lookup costs nothing,
  and the skipped answer is not cached, so a lookup gets a real answer again
  tomorrow. `/sources` and `/api/v1/sources` show `used/limit today` for each
  shared allowance.
* `fresh=1` is the one page view that spends a provider call: it skips the
  cache and asks every source again. It is rationed per client and per UTC day
  by `TT_FRESH_PER_DAY` (default 40), counted in the same `quota` table, and it
  is not honoured at all for a client whose User-Agent declares itself a
  crawler. A refused `fresh=1` is not an error: the page or the JSON still
  renders, from cache, and the API says which way it went
  (`X-ThreatTrove-Fresh: live|denied|cached`). `/robots.txt` keeps crawlers out
  of `/i/` result pages entirely, because those pages are per-query, already
  `noindex`, and each one is a live lookup. The provider allowance above is the
  backstop behind the per-client share.
* MetaDefender Cloud is the second engine panel. VirusTotal and MetaDefender
  report on different vendor sensors, so their agreement is worth more than one
  panel answering twice — but neither panel can convict alone: both collapse
  onto the same `engine-panel` authority, and a file still needs a second,
  independent authority (a sample feed, a sandbox, a local analyst) before it
  is called malicious. Its community key allows 1000 reputation lookups a day
  and 500 an hour; `TT_MD_DAILY_BUDGET` (default 800) and
  `TT_MD_MIN_INTERVAL` (default 7.2s) keep a burst from spending either.
* Sources without a key are simply skipped and listed as `needs key` in
  `/sources`; they never fail a lookup.
* Google Safe Browsing is a blocklist, not a clearance. A URL that is not on
  Google's lists is reported as `no_match` with **no verdict** — the same
  answer a keyless source gives — because Safe Browsing only knows what it has
  crawled and blocked. (Until 2.6.0 that answer was `clean`, which let a list
  with no opinion drag a verdict towards benign.) If the key is valid but the
  API is not enabled for its project, the `403` is reported as *API not enabled
  for this key's project* instead of being mistaken for a bad key.
* Safe Browsing's API is licensed for **non-commercial use only**. An install
  that sells lookups or carries advertising must move to the Web Risk API.
* PhishTank's verdict flags are the strings `"y"`/`"n"`, not booleans. Only a
  record that is both `valid` **and** `verified` is called phishing; a listed
  record marked invalid or unverified carries no verdict. (Until 2.6.0 `"n"`
  was truthy, so withdrawn records were reported as verified phishing.)
  PhishTank also sits behind a Cloudflare challenge that refuses non-browser
  API clients, so in practice the source answers `error` with *upstream blocks
  API clients (Cloudflare)* and makes no claim either way.
* Hybrid Analysis is read through `GET /api/v2/overview/{sha256}`; the older
  `POST /search/hash` was withdrawn in API 2.35.0 and now answers `410 Gone`.
  Its `scanners_v2` results feed the `x/y engines` figure on the result page,
  and only scanners that actually returned a judgement are counted (a scanner
  in `error` is not a clean engine). A high sandbox `threat_score` with no
  scanner agreement and no named family is reported as `suspicious`, not
  `malicious`, because installers trip behavioural heuristics — an official
  7-Zip installer scores 75 with every engine clean.
* MalShare is read through `GET /api.php?action=details&hash=…&api_key=…`, and
  a found sample counts as a direct authority (it has the file). Until 2.7.0
  the source asked for `action=getdetails`, which MalShare answers with **200
  and a zero-length body** — indistinguishable from a miss — so every lookup
  was cached as `not_found` and the source never contributed a verdict. An
  empty or non-JSON body is now `error`, never a miss. A stored sample is
  `malicious` weight; like any lone authority it reports `suspicious` on its
  own and convicts beside an engine panel or the local corpus. The free tier
  allows 2000 calls a day, so a `429` is reported as `error` naming that
  allowance rather than as a miss.

---

## Configuration

Copy `deploy/threattrove.env.example` and edit. The important ones:

| Variable | Default | Meaning |
| --- | --- | --- |
| `TT_DB` | `~/.threattrove/threattrove.db` | cache + jobs + local corpus |
| `TT_CACHE_TTL` | `604800` | cache lifetime, seconds |
| `TT_TIMEOUT` | `20` | per-source HTTP timeout |
| `TT_DEADLINE` | `45` | whole-lookup budget, seconds |
| `TT_BULK_MAX` | `5000` | indicators per bulk job / CLI run |
| `TT_MAX_JOBS` | `2` | concurrent bulk jobs per worker |
| `TT_MAX_UPLOAD` | `2097152` | upload cap, bytes |
| `TT_RATE_LIMIT` | `60` | API requests/min per IP |
| `TT_PAGE_RATE_LIMIT` | `240` | page requests/min per IP |
| `TT_FRESH_PER_DAY` | `40` | cache-bypassing lookups per IP per day |
| `TT_SITE_URL` | `https://threattrove.com` | canonical base URL |
| `TT_SITE_NAME` | `ThreatTrove` | brand shown in nav, titles, OG tags |
| `TT_ENABLE_REVERSE_IP` | *(empty)* | `1` enables reverse-IP |
| `TT_VT_DOMAINS` | *(empty)* | `1` enables VirusTotal domain/IP lookups |
| `TT_VT_DAILY_BUDGET` | `400` | VirusTotal requests/day, shared by its three sources |
| `TT_MD_DAILY_BUDGET` | `800` | MetaDefender requests/day, shared by its three sources |
| `TT_MD_MIN_INTERVAL` | `7.2` | seconds between MetaDefender calls (500/hour ceiling) |

Both URL-side blocklists (Google Safe Browsing, PhishTank) are keyed and
optional; without a key they are skipped like any other source.

### Cache invalidation

A cache entry is only reused by the code that wrote it. Every source declares a
`logic_version` integer; the version is stored alongside the payload, and a
lookup ignores any entry whose version does not match the source's current one.

That matters because a parser fix and a stale cache can otherwise fight: if a
source's verdict rules change while entries they produced are still inside
`TT_CACHE_TTL` (a week by default), the corrected verdict would not be visible
until each of those entries expired.

* **Upgrading invalidates the cache once.** Databases written before 2.1.7 gain
the column with the default `0`, which no source declares, so every pre-existing
entry is ignored and re-fetched on its next lookup. Nothing is deleted: the rows
are overwritten as they are refreshed, so the cost is one extra upstream request
per indicator, not a cold cache.
* **Bumping is a code change, not a config knob.** When you change how a source
parses a response or decides a verdict, raise its `logic_version` by one in
`threattrove/sources.py`. Sources that share response-shaping helpers must be
bumped together. Leaving it alone is the right choice for refactors that cannot
change an output.
* **`?fresh=1` and `--no-cache` still work**; they bypass the cache entirely and
rewrite the entry at the current version.

---

## Deployment

> The deploy files (deploy/, Dockerfile, docker-compose.yml) are not part of the PyPI package -- the wheel and sdist ship only the installation. Clone the repository to deploy.

### Docker

```bash
cp deploy/threattrove.env.example .env     # add keys if you have them
docker compose up -d --build
curl -s http://127.0.0.1:8080/health
```

Data persists in the `threattrove-data` volume (`/data/threattrove.db`). The image
runs as an unprivileged user with a read-only root filesystem.

### systemd + nginx on threattrove.com

```bash
useradd --system --home /opt/threattrove --shell /usr/sbin/nologin threattrove
git clone <repo> /opt/threattrove && cd /opt/threattrove
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/pip install --no-deps .
install -d -o threattrove -g threattrove /var/lib/threattrove
install -Dm640 deploy/threattrove.env.example /etc/threattrove/threattrove.env
install -Dm644 deploy/threattrove.service /etc/systemd/system/threattrove.service
systemctl daemon-reload && systemctl enable --now threattrove

# TLS + reverse proxy
apt install nginx certbot python3-certbot-nginx
install -Dm644 deploy/nginx-threattrove.conf /etc/nginx/sites-available/threattrove.com
ln -s /etc/nginx/sites-available/threattrove.com /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
certbot --nginx -d threattrove.com -d www.threattrove.com
```

### Keeping the local blocklist current

The site is far more useful with a real corpus behind it, and `--import-local`
is how one is loaded. A full MalwareBazaar dump is a one-off (~510 MB of CSV,
3.5 M hashes); the timer below keeps it moving afterwards.

```bash
# one-off: full dump, fetched once and folded in (about 6 minutes for 3.5M rows)
curl -o full.csv.zip "https://mb-api.abuse.ch/v2/files/exports/$ABUSECH_AUTH_KEY/full.csv.zip"
unzip -o full.csv.zip
threattrove --import-local full.csv --dry-run     # count first, write nothing
threattrove --import-local full.csv --label malware --note "malwarebazaar full dump"

# recurring: hourly refresh from recent.csv (last 48 hours, ~430 KB)
install -Dm755 deploy/threattrove-refresh /usr/local/sbin/threattrove-refresh
install -Dm644 deploy/threattrove-refresh.service /etc/systemd/system/
install -Dm644 deploy/threattrove-refresh.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now threattrove-refresh.timer
systemctl start threattrove-refresh.service      # run once now
```

Feodo Tracker's C2 list rides along in the same hourly job, and needs no key:

```bash
# one-off, or leave it to threattrove-refresh.timer
sudo -u threattrove env TT_DB=/var/lib/threattrove/threattrove.db \
  /opt/threattrove/.venv/bin/python scripts/import_feodo.py --dry-run
```

`threattrove-refresh` runs the import first, before it checks for the abuse.ch
key: a failure prints a warning and the MalwareBazaar refresh still happens. Rows
are updated in place (`ON CONFLICT DO UPDATE`), so re-importing the same IPs each
hour does not churn `added_at` or reshuffle `/local`.

### Checking that the sources still answer

A source can break without failing: it answers HTTP 200 with a document that
parses to "not found". That is how Safe Browsing's unlisted answer and
MalShare's empty detail page both read as misses until 2.6.0 and 2.7.0.

The canary asks every active source about an indicator whose answer should not
change, and records what came back:

```bash
.venv/bin/python scripts/source_canary.py --dry-run   # show answers, write nothing
.venv/bin/python scripts/source_canary.py             # record them
install -Dm644 deploy/threattrove-canary.service /etc/systemd/system/
install -Dm644 deploy/threattrove-canary.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now threattrove-canary.timer
```

The first healthy answer becomes the expected one, and its latency becomes a
baseline; a source that later answers differently, or four times slower, is a
warning. A run costs one request per active source and bypasses the cache, so
a cached answer cannot hide the breakage it is looking for.

Results are on `/status` and in `/api/v1/status`. The JSON is meant to be
polled, and `?strict=1` turns it into an HTTP check: it answers 503 only when a
source is `bad` — it errored, timed out, or answered something nobody can
classify — or when its canary data is **stale**, meaning no check in the last 26
hours. Staleness is tracked separately from the per-source state because a dead
timer is the one failure that would otherwise look tidy: the last stored rows
keep saying `ok` forever.

`?strict=warn` (alias `all`) is the loud setting: it also fails on latency
drift and on a source that answers differently than it used to. That is a good
alarm for a human reading `/status` and a poor one for a pager, because a feed
that is merely slow would wake you at 3 a.m. With no `strict` argument the
payload is informational and always 200.

A source that was not asked — its allowance is spent, or a sibling endpoint of
the same provider was just called — is reported as `skip` and never decides the
verdict. A source with no canary row at all counts as stale: unproven is not
healthy.

Two monitors cover the site, and both fit on a free plan:

| monitor | URL | rule |
| --- | --- | --- |
| liveness | `https://threattrove.com/health` | HTTP 200, keyword `"status":"ok"` |
| source health | `https://threattrove.com/api/v1/status?strict=1` | HTTP 200 |

The second is the one that catches "the site is up but every lookup is wrong",
and it stays green through a slow provider. Pause both around a deploy: the
restart is brief, but a release that enables a source the canary has not seen
yet would be stale for up to four hours and page you for it. Both endpoints are
`no-store` (or, for `/health`, uncached JSON), so a monitor sees the live answer
rather than a CDN copy.

The old documented export URLs (`/export/csv/full/`, `/export/txt/sha256/full/`)
now answer **410 Gone**; the live endpoint takes the Auth-Key in the path, as
above. `recent.csv` is regenerated every five minutes and full dumps hourly, so
fetching recent.csv hourly is well inside abuse.ch's guidance. The import is
idempotent, so the 48-hour overlap between runs relabels rows instead of
doubling them — a second run in a row reports `inserted 0`.

Check that the timer is armed and that the last run succeeded:

```bash
systemctl list-timers threattrove-refresh.timer
systemctl show threattrove-refresh.service -p Result -p ExecMainStatus
journalctl -u threattrove-refresh.service -n 20 --no-pager
```

`deploy/gunicorn.conf.py` binds `127.0.0.1:8080`, 2 gthread workers × 8 threads,
120s timeout (bulk lookups are slow by nature). Nginx adds TLS/HSTS, gzip,
static caching and per-zone rate limits.

**Public-instance checklist**

1. Set `TT_RATE_LIMIT` low (30–60) — every lookup fans out to 8+ upstreams, and
   they rate-limit *you* first.
2. Keep `TT_ENABLE_REVERSE_IP` off unless your privacy notice says otherwise.
3. Add `X-Forwarded-For` handling (already configured) so the limiter sees real
   clients.
4. Cache is shared, so identical indicators are only queried upstream once per
   `TT_CACHE_TTL`.
5. `/health` is the liveness endpoint used by the Docker healthcheck.

---

### Nightly database backup

The cache, the bulk job records and the 3.5M-row local corpus all live in one
SQLite file, and nothing else in this deployment is that file. Copying it with
`cp` can catch it mid-checkpoint; `scripts/backup_db.py` uses SQLite's backup
API instead, so the snapshot is consistent while the web workers keep reading
and writing. Each snapshot is checked and gzipped before it is kept.

```bash
sudo install -D -o threattrove -g threattrove -m 0644 \
    deploy/threattrove-backup.service /etc/systemd/system/
sudo install -D -o threattrove -g threattrove -m 0644 \
    deploy/threattrove-backup.timer /etc/systemd/system/
sudo mkdir -p /var/backups/threattrove
sudo chown threattrove:threattrove /var/backups/threattrove
sudo systemctl daemon-reload
sudo systemctl enable --now threattrove-backup.timer

sudo systemctl start threattrove-backup.service     # one run now
journalctl -u threattrove-backup -n 5 --no-pager
ls -lh /var/backups/threattrove
```

Every run writes `/var/backups/threattrove/threattrove-<UTCstamp>.db.gz` and
keeps the last `TT_BACKUP_KEEP` (default 7). A snapshot that fails its check is
left behind as `.part` and the run exits non-zero, so a broken backup shows up
in `systemctl --failed` instead of going missing quietly.

## Project layout

```
threattrove/
  core.py       parse indicators, Engine (threaded, paced, deadline), Store, Report
  sources.py    24 source implementations + verdict helpers
  bulk.py       CSV/JSON/newline parsing, job runner, CSV export
  cli.py        `threattrove` entry point
  web.py        Flask app factory + `threattrove-web`
  feeds.py      blocklist parsing (Feodo Tracker C2 CSV → local rows)
  templates/    Jinja2 views
  static/       app.js, style.css, favicon.svg
scripts/smoke.py        offline parser/verdict checks + live lookups
scripts/import_feodo.py Feodo C2 import into the local corpus
deploy/                 gunicorn, systemd, nginx, env example, blocklist refresh
legacy/threattrove-v1-cli.py   original single-file CLI (superseded, kept for reference)
Dockerfile, docker-compose.yml
```

## Testing

```bash
.venv/bin/python scripts/smoke.py --offline   # parsing, verdicts, evidence, clearance, blocklist import, cache versions
.venv/bin/python scripts/smoke.py             # + live hash/URL/domain lookups
.venv/bin/python scripts/check_vt_floor.py    # engine-ratio floor (offline)
.venv/bin/python scripts/check_quota.py       # shared allowance, skipped answers, sources page (offline)
.venv/bin/python scripts/check_metadefender.py # second engine panel: parsing, floor, quota share (offline; --live adds real calls)
.venv/bin/python scripts/check_gsb.py         # Safe Browsing and PhishTank: flags, refusals, "no data" (offline; --live adds real calls)
.venv/bin/python scripts/check_malshare.py    # MalShare action/status contract, silence is not a miss (offline; --live adds real calls)
.venv/bin/python scripts/check_corroboration.py  # authority collapsing and corroboration (offline)
.venv/bin/python scripts/check_refang.py      # defanged indicators (offline)
.venv/bin/python scripts/check_cards.py       # evidence cards and page rendering (offline)
.venv/bin/python scripts/check_privacy.py     # no queried value leaks to the page or logs (offline)
.venv/bin/python scripts/check_status.py      # /local and /recent paging, source-health states, /status and /api/v1/status (offline)
.venv/bin/python scripts/check_feodo.py       # Feodo parsing, in-place re-import, local-corpus verdict (offline)
.venv/bin/python scripts/check_docs.py        # /about, /privacy, /sitemap.xml, /robots.txt (offline)
.venv/bin/python scripts/check_fresh.py       # fresh=1 rationing, crawler policy, robots (offline)
.venv/bin/python scripts/check_monitor.py     # strict=1 pager contract: bad and stale fail, drift alone does not (offline)
```

## Limitations

* ThreatTrove never uploads files — it hashes locally and only sends hashes.
* Keyless sources are free, so they are shallow: absence of a hit means "no data",
  never "safe". Treat `UNKNOWN` as unknown.
* No user accounts, no per-user quota: the rate limiter is per IP, meant for a
  single node behind a proxy.
* Nothing is authenticated, including `/local` and `/api/v1/bulk`. Anyone who can
  reach the port can read the corpus and add or delete rows. Put it behind your
  proxy's auth, or keep it on a private network.
* Bulk jobs run inside the web worker process. Two workers means two independent
  job pools (fine for this scale; swap in a real queue if you outgrow it).
* Cached verdicts are not re-derived until an entry expires or its source's
  `logic_version` changes, so an upstream provider revising its data is picked up
  on the next `TT_CACHE_TTL` window, not immediately.

## License

MIT.
