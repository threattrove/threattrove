# ThreatTrove

**Self-hosted reputation lookup for file hashes, URLs, domains and IPs — built to run on [threattrove.com](https://threattrove.com) or on your own box.**

ThreatTrove does the three things most people open VirusTotal for: paste an
indicator, get a verdict, and see *which* sources said what. It runs keyless out
of the box (8 sources, no account anywhere) and gets sharper as you add API keys.

```
$ threattrove 44d88612fea8a8f36de82e1278abb02f

━━ 44d88612fea8a8f36de82e1278abb02f

  File hash
  MALICIOUS    75% confidence    Listed as malicious by 2 independent sources

  SECURITY SOURCES
  ──────────────────────────────────────────────────────────────────────────
  ● circl            MALICIOUS          listed by malshare.com
  ● otx              MALICIOUS          50 pulse(s)

  elapsed 1.14s  ·  2 security sources queried
```

That's the EICAR test file, found by two keyless sources with no API key set.

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
| `/` | Paste a hash, URL or domain; recent lookups |
| `/i/hash?q=…`, `/i/url?q=…`, `/i/domain?q=…` | Result page: verdict, score, per-source table |
| `/bulk` | Upload a CSV/feed or paste a list; runs as a background job |
| `/bulk/<job_id>` | Job progress, per-row verdicts, CSV/JSON export |
| `/recent` | Recent lookups on this instance |
| `/sources` | Source catalogue with live state (`active` / `needs key` / `opt-in`) |
| `/local` | Manage the local corpus |
| `/api` | JSON API documentation |

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

Every report also carries an **evidence breakdown** (`evidence` in the JSON,
an evidence strip on the result page) that groups the sources that answered into
four classes — blocklists, sandbox engines, community intel, reputation — and
shows how many sources inside each class agree. That is the honest alternative
to a vendor count: instead of "73 engines", you see "2/3 blocklists, 0/1 sandbox".

Sources in the `intel` category (DNS, RDAP, crt.sh, reverse IP) enrich the
report but never change the verdict. Engine ratios are only computed from
sources that actually report engines — a urlscan "6987 scans" is a scan count,
not a detection count, and is shown as `–`.

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

### What file is this hash?

When a source names the file — NSRL/CIRCL `FileName`/`ProductName`/
`OpSystemName`, VirusTotal `meaningful_name`/`type_description`, MalwareBazaar
`file_type` — the name is lifted out of the raw detail blob and shown under the
verdict (`file_identity` in the JSON). A known Windows binary therefore renders
as `Known good: cmd.exe (Microsoft Windows Operating System)` rather than as an
anonymous hash.

---

## Sources

21 sources are compiled in; 8 work with no key. `httpx`-free HTTP via `requests`.

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
| VirusTotal (file/url/domain) | hash/url/domain/ip | reputation | keyed | `VT_API_KEY` |
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
* `TT_ENABLE_REVERSE_IP` is off by default because that lookup sends the queried
  IP/hostname to a third-party service. That's the one source gated on consent.
* Sources without a key are simply skipped and listed as `needs key` in
  `/sources`; they never fail a lookup.
* Hybrid Analysis is read through `GET /api/v2/overview/{sha256}`; the older
  `POST /search/hash` was withdrawn in API 2.35.0 and now answers `410 Gone`.
  Its `scanners_v2` results feed the `x/y engines` figure on the result page,
  and only scanners that actually returned a judgement are counted (a scanner
  in `error` is not a clean engine). A high sandbox `threat_score` with no
  scanner agreement and no named family is reported as `suspicious`, not
  `malicious`, because installers trip behavioural heuristics — an official
  7-Zip installer scores 75 with every engine clean.

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
| `TT_SITE_URL` | `https://threattrove.com` | canonical base URL |
| `TT_SITE_NAME` | `ThreatTrove` | brand shown in nav, titles, OG tags |
| `TT_ENABLE_REVERSE_IP` | *(empty)* | `1` enables reverse-IP |

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
journalctl -u threattrove-refresh.service -n 20 --no-pager
```

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

## Project layout

```
threattrove/
  core.py       parse indicators, Engine (threaded, paced, deadline), Store, Report
  sources.py    21 source implementations + verdict helpers
  bulk.py       CSV/JSON/newline parsing, job runner, CSV export
  cli.py        `threattrove` entry point
  web.py        Flask app factory + `threattrove-web`
  templates/    Jinja2 views
  static/       app.js, style.css, favicon.svg
scripts/smoke.py        offline parser/verdict checks + live lookups
deploy/                 gunicorn, systemd, nginx, env example, blocklist refresh
legacy/threattrove-v1-cli.py   original single-file CLI (superseded, kept for reference)
Dockerfile, docker-compose.yml
```

## Testing

```bash
.venv/bin/python scripts/smoke.py --offline   # parsing, verdicts, evidence, clearance, blocklist import, cache versions
.venv/bin/python scripts/smoke.py             # + live hash/URL/domain lookups
```

## Limitations

* ThreatTrove never uploads files — it hashes locally and only sends hashes.
* Keyless sources are free, so they are shallow: absence of a hit means "no data",
  never "safe". Treat `UNKNOWN` as unknown.
* No user accounts, no per-user quota: the rate limiter is per IP, meant for a
  single node behind a proxy.
* Bulk jobs run inside the web worker process. Two workers means two independent
  job pools (fine for this scale; swap in a real queue if you outgrow it).
* Cached verdicts are not re-derived until an entry expires or its source's
  `logic_version` changes, so an upstream provider revising its data is picked up
  on the next `TT_CACHE_TTL` window, not immediately.

## License

MIT.
