# NewASM — Staged Attack Surface Management Pipeline

A single-command recon orchestrator for **authorized** external attack-surface
mapping. Runs on Kali, chains best-in-class recon tools, and stores every stage
in a portable SQLite database + JSON so you can query and diff the surface over
time.

> ⚠️ **Authorized use only.** Run this exclusively against assets you have
> written permission to test. Port and aggressive scans are intrusive.

## Pipeline

```
1. findomain + subdominator → subdomain enumeration (merged, deduped to unique)
2. dnsx                → ACTIVENESS: resolve (A/CNAME), drop NXDOMAIN
3. httpx-toolkit       → HTTP status/title/tech  (enrichment — 404s are KEPT)
4. cdncheck            → skip CDN/WAF edges, dedupe to unique scannable IPs
                         (skipped edges + provider → stages/04_cdn_skipped.json)
5. rustscan            → open-port discovery on each UNIQUE IP
                         (naabu deprecated; opt back in via --port-scanners)
6. nmap -Pn --min-rate 10000 -p- → fast full-port sweep on ALL scannable IPs
                         (add -sV/-A for version+NSE; --nmap-ports "" = hit IPs only)
```

### Design decisions (why it's built this way)

- **404s are never dropped.** A 404 is a live web server — dropping it deletes
  real attack surface. Only *unresolvable* (NXDOMAIN) and *dead* hosts are cut.
- **Scan unique IPs, not subdomains.** Hundreds of subdomains often share a few
  IPs; we collapse to unique IPs so each host is scanned once, then map results
  back. Big speed win.
- **CDN/WAF IPs are skipped** before scanning (pointless + ban risk). Cloud
  (AWS/GCP) origins are kept — they're real surface.
- **SQLite is the pipe.** Raw tool output → `raw/`, parsed rows → `asm.db`,
  per-stage snapshots → `stages/`. One portable, queryable artifact.

## Install

**Ubuntu — one shot:** `bash setup.sh` (full walkthrough in [`SETUP.md`](SETUP.md)).
Installs findomain, subdominator, dnsx, httpx, cdncheck, naabu, rustscan, nmap and
persists PATH. On **Kali**, most tools ship in apt (`httpx` is `httpx-toolkit` there —
NewASM auto-detects both).

The orchestrator itself needs **no `pip install`** — pure standard library. The only
Python dependency is `subdominator` (see [`requirements.txt`](requirements.txt)),
installed into `~/Tools/Subdominator/sub` by `setup.sh`.

Quick check that everything is on PATH:

```bash
for t in findomain subdominator dnsx httpx cdncheck naabu rustscan masscan nmap; do
  command -v $t >/dev/null && echo "OK  $t" || echo "MISSING $t"
done
```

## Usage

```bash
python3 asm.py -d example.com                     # full pipeline (nmap on found ports)
python3 asm.py -d example.com --no-subdominator    # findomain only (faster)
python3 asm.py -d example.com --no-nmap           # stop after rustscan
python3 asm.py -d example.com --nmap-full          # zero-FN: nmap -p- on every IP (slow)
sudo python3 asm.py -d example.com --masscan-only  # fast: masscan discovers ports, nmap scans only those
sudo python3 asm.py -d example.com --masscan       # union masscan + rustscan for max discovery
python3 asm.py -d example.com --threads-portscan 12 -v
python3 asm.py -d example.com --nmap-flags "-sS -A"   # SYN scan (needs sudo)
sudo python3 asm.py -d internal.lan --allow-private-ips   # internal engagement
```

## Output layout

```
output/example.com_20260721_101500/
├── asm.db                 # SQLite — the queryable surface inventory
├── report.md              # human-readable summary
├── report.json            # machine-readable summary
├── asm.log                # full run log
├── stages/                # per-stage JSON snapshots (01..06)
└── raw/                   # raw tool output (findomain, dnsx, httpx, nmap XML…)
```

## Querying results

```bash
sqlite3 output/example.com_*/asm.db

sqlite> SELECT ip, port, service, product FROM ports ORDER BY ip, port;
sqlite> SELECT subdomain, status_code, tech FROM http_probes WHERE status_code!=404;
sqlite> SELECT subdomain, value FROM dns_records WHERE record_type='CNAME';  -- takeover hunting
sqlite> SELECT ip, script_id, output FROM nmap_findings;
```

## Roadmap (next stages)

- Subdomain-takeover check on dangling CNAMEs
- `tlsx` for cert SAN harvesting (finds subdomains DNS missed)
- Diff engine across runs ("what's new since last week")
- Wrap stages as Celery tasks for distributed, rate-limited scaling
- `notify` integration for Slack/Telegram alerts on new findings
```
