# NewASM — Architecture

**NewASM** is a staged external **Attack Surface Management (ASM)** recon pipeline.
Given one authorized root domain it enumerates subdomains, resolves them, probes
HTTP, filters CDN/WAF edges, port-scans the real origins, and deep-scans the open
ports — persisting every stage to SQLite + JSON for querying, diffing, and reporting.

- **Version:** 0.1.0
- **Runtime:** Python 3 (developed cross-platform via `pathlib`; runs on Kali Linux where the external tools live)
- **Entrypoint:** `python3 asm.py -d <domain> [options]`
- **Standard invocation:** `sudo python3 asm.py -d <domain> --nmap-only -v`
- **Scope:** authorized VAPT / red-team recon on in-scope assets only

> **Design mandate:** this tool is deployed at organization level, so **scan
> correctness (zero false-negatives / false-positives) outranks performance** in
> every design decision. Defaults favor completeness; speed is opt-in. The
> correctness safeguards this drove are called out throughout and summarized in
> [§9](#9-correctness-safeguards).

---

## 1. Module layout

```
asm.py ..................... CLI entrypoint: argparse -> config.Settings -> Pipeline.run()
architecture.md ............ this document (system as-built)
archi_update.md ............ working notes: optimization roadmap + tracked defects/fixes
asmtool/
├─ __init__.py ............. package metadata (__version__)
├─ pipeline.py ............. orchestrator: run dir, run lifecycle, stage wiring, reporting
├─ stages.py .............. the 6 recon stages + tarpit precheck + Context + inter-stage input logging
├─ runner.py .............. CommandRunner: subprocess exec, tool discovery, timeouts
├─ storage.py ............. SQLite persistence (asm.db) + report readback + tarpit port mgmt
├─ config.py .............. Settings dataclass, tool binary names, timeouts, CDN/WAF/cloud
│                           provider sets, tarpit probe ports, httpx flags
└─ utils.py ............... pure helpers: scope, IP validation, JSONL, static CDN net
```

**Layering (dependency direction):**

```
asm.py
  └─> pipeline.py ──> stages.py ──> runner.py   (external tools)
                          │     └──> storage.py  (SQLite)
                          └────────> utils.py    (pure functions)
                          └────────> config.py   (Settings / constants)
```

`stages.py` is the only place that knows *what* each recon step does; `runner.py`
and `storage.py` are side-effect adapters; `utils.py` is pure and independently
testable. The `Context` dataclass is the dependency-injection seam handing every
stage its `runner`, `storage`, `settings`, `domain`, `run_id`, and `workdir`.

---

## 2. End-to-end data flow

```mermaid
flowchart TD
    CLI([cli: root domain]) --> S1

    subgraph P[Pipeline.run - single process, sequential]
        S1[Stage 1 · subdomains\nfindomain + subdominator] -->|List str| S2[Stage 2 · resolve = ACTIVENESS\ndnsx · active iff resolves to IP]
        S2 -->|resolved hosts| S3[Stage 3 · http_probe\nhttpx · enrich only, never gates scan\n→ 03_alive_urls.txt, 03_fuzz_targets.txt, 03_tech.json]
        S2 -->|Dict host to ips| S4[Stage 4 · cdn_filter\ncdncheck + static net\n→ 04_scannable_domains.txt]
        S3 -->|reached hosts cross-check| S4
        S4 -->|List scannable ip| S5[Stage 5 · port_scan\nrustscan / masscan · naabu deprecated]
        S4 -->|List scannable ip| TP{Tarpit\nprecheck}
        TP -->|tarpit IPs| S6
        S5 -->|Dict ip to ports| S6[Stage 6 · nmap -Pn --min-rate 10000\n+ post-scan tarpit safety net]
    end

    S1 & S2 & S3 & S4 & S5 & S6 -.->|parsed rows| DB[(asm.db · SQLite)]
    S1 & S2 & S3 & S4 & S5 & S6 -.->|raw output| RAW[raw/*]
    S1 & S2 & S3 & S4 & S5 & S6 -.->|snapshot| ST[stages/NN_*.json + .txt]
    DB --> R[report.md + report.json]
```

**Key properties**

- **Sequential, single process, in-memory hand-off.** Each stage returns a plain
  Python object consumed by the next. There is no message broker or async runtime
  (see [archi_update.md](archi_update.md) §2 for the planned asyncio model).
- **Triple persistence per stage:** verbatim tool output to `raw/`, a parsed
  snapshot to `stages/NN_*.json`, and normalized rows to `asm.db`. A crashed run
  therefore still leaves a queryable partial result.
- **Resilience:** `Pipeline.run()` wraps the whole chain in try/except so a
  `KeyboardInterrupt` (`status=interrupted`) or unexpected error (`status=error`)
  still finalizes the run row and writes a report.

---

## 3. The six stages (detailed flow)

Each stage: reads its input, runs an external tool via `CommandRunner`, writes raw
output, persists parsed rows, and returns data for the next stage. All stages log
their received input via `_log_input()` (see [§10](#10-observability)).

### Stage 1 — Subdomain enumeration  `stage_subdomains`
- **Tools:** `findomain -t <domain> -q`; optionally `subdominator -d <domain> -o <file>`
  (RevoltSecurities; binary resolved from `--subdominator-bin`, PATH, or the known
  `~/Tools/Subdominator/sub/bin` location).
- **Input:** the seed root domain.
- **Logic:** collects names from findomain + subdominator + the seed, normalizes each
  (`utils.clean_host`), keeps only in-scope names (`utils.in_scope`), tracks
  provenance per name (which tool found it). subdominator writes one subdomain per
  line to `-o`; `in_scope` filtering drops any banner/log lines automatically.
  Both tools run non-interactively (empty stdin) and their failures are non-fatal.
- **Consolidation:** findomain ∪ subdominator (+ seed) are merged into one hostname-
  keyed dict, so overlaps collapse and only the **UNIQUE** in-scope set advances. The
  completion log reports the split (`findomain=X, subdominator=Y, overlap=Z`) and
  `01_subdomains.json` records per-source counts + a `by_source` map — the merge
  is auditable, not implicit.
- **Output:** `List[str]` of unique in-scope subdomains → `subdomains` table.
- **Artifacts:** `stages/01_subdomains.json`, `raw/findomain.txt`,
  `raw/subdominator.txt`, `raw/all_subdomains.txt`.
- **Toggle:** `--no-subdominator` (findomain only); `--subdominator-bin <path>`.

### Stage 2 — DNS resolution = ACTIVENESS  `stage_resolve`
- **Tool:** `dnsx -l <input> -a -aaaa -cname -resp -j -silent -o <out>` (+ `-wd <domain>` only if `--wildcard-filter`)
- **Input:** subdomains from Stage 1.
- **This is the activeness gate.** A subdomain is **active** iff dnsx returns at
  least one **A record**. Discovery (Stage 1, passive sources) does NOT imply a
  live IP — a discovered name can be NXDOMAIN, CNAME-to-dead-target, IPv6-only, or
  stale. Only active (resolving) names advance to CDN-filter / scanning.
- **Logic:** parses dnsx JSONL; stores `A` and `CNAME` records; maps subdomain→IP;
  marks a subdomain `resolves=1` when it has A records. **Drops only NXDOMAIN.**
  Logs the inactive names explicitly (discovered but unresolved → possible dangling
  DNS / subdomain-takeover candidates) so they're visible, not silently gone.
- **Output:** `Dict[host -> [ips]]` → `dns_records`, `subdomain_hosts` tables; the
  active/inactive split is surfaced in the report (see §8).
- **Artifacts:** `stages/02_resolved.json`, `raw/dnsx.jsonl`, `raw/dnsx_input.txt`.
- **Correctness note:** `--wildcard-filter` (dnsx `-wd`) is **OFF by default** — on a
  CDN/wildcard-DNS domain it filters out every real subdomain. See
  [archi_update.md](archi_update.md) §3.
- **Known gap:** `-aaaa` is requested but only `a`/`cname` are parsed → IPv6 records
  are currently discarded (tracked, [archi_update.md](archi_update.md) §3.4).

### Stage 3 — HTTP probe  `stage_http_probe`  *(enrichment only)*
- **Tool:** `httpx-toolkit` (ProjectDiscovery httpx; binary `httpx-toolkit` preferred,
  else `httpx`), run with the flag set in `config.HTTPX_FLAGS`.
- **Input:** the active (resolving) hostnames — keys of Stage 2's map.
- **Logic:** enrichment only — records URL, status, title, webserver, **tech-detect**,
  plus the connected **IP**, **CNAME**, httpx's own **CDN** verdict, content
  type/length, redirect **location**, **favicon** mmh3 hash, **JARM** TLS
  fingerprint, **ASN**, and response time. **404s are stored, never dropped.**
  Never removes anything from the surface. Trim `config.HTTPX_FLAGS` if an older
  httpx build rejects a newer flag (favicon/jarm/asn).
- **Alive URLs collection:** as each httpx record is parsed, the URL is collected
  into an alive-URLs list. URLs whose status code is 200, 401, or 403 are
  additionally collected as fuzz targets — these are the status codes worth
  directory-fuzzing (serving content or blocking access behind auth).
- **Tech-detect artifact:** httpx already runs with `-tech-detect`, so the
  fingerprints (technologies + web server) are captured as their own stage output:
  a per-host view (`by_host`) plus a technology→hosts inventory (`technologies`).
  No extra tool run needed.
- **Output:** `http_probes` table, **and returns the set of hosts httpx REACHED**
  (httpx emits a record only for hosts that answered = proof of a completed HTTP(S)
  handshake). This set feeds Stage 4's reachability cross-check.
- **Artifacts:**
  - `stages/03_http.json` — probed count + reached host count.
  - `stages/03_alive_urls.txt` — every URL httpx got a response from, deduplicated,
    sorted, one per line. Suitable as input to any HTTP tool (wafw00f, nuclei, etc.).
  - `stages/03_fuzz_targets.txt` — only URLs that returned **200, 401, or 403**.
    Filtered subset of alive_urls, ready for directory fuzzing (ffuf, feroxbuster).
  - `stages/03_tech.json` — per-host tech fingerprints + technology→hosts index.
  - `raw/httpx.jsonl`, `raw/httpx_input.txt`.
- **Role:** httpx is **NOT** the activeness test — DNS resolution (Stage 2) is.
  A subdomain with no web server can still have open SSH/RDP/DB ports, so httpx
  must never *remove* a host from scanning; it only annotates and, via the
  cross-check, can force-KEEP a reachable host. It runs right after resolution
  (conventional recon order); the scan path does not otherwise depend on it.
- **Blank-page hosts:** hosts returning a blank HTTP response (no content) are
  **KEPT**, not filtered. A blank web page does not mean no attack surface — the
  host may have SSH, RDP, databases, or other services on non-HTTP ports.
- **Toggle:** `--no-httpx` (also disables the cross-check, since there's no data).

### Stage 4 — CDN / WAF filter  `stage_cdn_filter`
- **Tools:** `cdncheck -update` (refresh ranges), then `cdncheck -j -resp -silent`
  with the IP list piped on **STDIN** (JSON read from stdout). cdncheck's input flag
  is `-i`/stdin — **not** `-l`; passing `-l` made it exit rc=2 and classify nothing.
- **Input:** Stage 2's host→IP map (flattened + de-duplicated to unique public IPs).
- **Logic:** classifies each IP and decides what is *scannable* **by PROVIDER, not
  by cdncheck's category** — because cdncheck tags cloud load-balancer ranges
  (notably Google Cloud HTTPS LB) as category `cdn`/`waf` even though the IP is the
  org's own edge serving their apps. Skipping those is a false negative, so:
  - **`CDN_EDGE_PROVIDERS`** (Cloudflare, CloudFront, Fastly, Akamai, Imperva…) →
    genuine shared edges → **skipped** (scanning them yields the CDN's ports, not
    the client's, plus ban risk).
  - **`CLOUD_ORIGIN_PROVIDERS`** (Google, AWS, Azure, Oracle, DigitalOcean…) → the
    customer's own load balancer / instance → **kept scannable** unless `--no-cloud`.
    This is what fixes Google-LB-hosted services (grafana/jenkins) being wrongly
    dropped.
  - **`WAF_EDGE_PROVIDERS`** (Imperva/Incapsula, Sucuri, Barracuda, Radware…) →
    genuine shared WAF edges → **skipped**. On-prem WAFs (F5 BIG-IP on the org's
    own IP) are invisible to cdncheck and remain scannable (fingerprint with wafw00f).
  - **Anything else cdncheck flags → fail OPEN and scan it** (never drop a possibly
    live origin), logging a warning so provider sets can be tuned.
  - **httpx-reachability cross-check:** any IP that Stage 3 proved reachable is
    force-kept scannable, overriding a cdncheck skip (empirical proof beats
    classification). Only ever *adds* hosts, so it can't cause a false negative.
    Genuine CDN edges stay skipped unless `--scan-reachable-cdn` (scanning an edge
    returns the edge's ports, not the origin's = false positive). Disable with
    `--no-httpx-rescue`.
  - Parsing is **schema-drift tolerant** (`_classify_cdncheck`): handles boolean
    flags, string values, nested objects, and name-only fields.
  - A **deterministic static safety net** (`utils.static_cdn_name`, Cloudflare +
    Fastly + Akamai published ranges) catches edges cdncheck missed (stale data /
    schema drift / tool absent) and **only ever adds** detections. Google/AWS are
    deliberately excluded from the static net because those ranges overlap real
    origins and blanket-flagging would drop live assets.
- **Output:** `List[str]` of scannable IPs → `hosts` table (`is_cdn`, `cdn_name`, `is_scannable`).
- **Artifacts:**
  - `stages/04_hosts.json` — the **full host inventory**: every unique IP as
    `{ip, scannable, provider, category, source, subdomains}` — scannable AND
    CDN/WAF-skipped, so the whole surface is in one file.
  - `stages/04_all_domains.txt` — every resolved subdomain in the IP set, one per line.
  - `stages/04_scannable_domains.txt` — just the subdomains behind scannable (non-CDN)
    IPs, one per line (ready-to-use target list).
  - `stages/04_cdn_skipped.json` — the filtered-out CDN/WAF/cloud edges, each tagged
    with provider, category, which classifier caught it (`cdncheck` vs `static-net`),
    and its resolving subdomains — so the exclusion set is auditable.
  - `stages/04_waf_cdn.json` — the skipped edges split into WAF vs CDN vs cloud
    buckets, with per-IP provider and source labelling.
- **Toggles:** `--no-cdncheck` (static net becomes sole classifier — weaker, test
  use), `--no-cdncheck-update`, `--no-cloud`, `--allow-private-ips`.

### Stage 5 — Port scan  `stage_port_scan`
- **Tool (default):** `rustscan -a <ip> --ulimit <n> -b <batch> -t <ms> --tries <n> -g --scan-order random`
  (per IP, threaded). `-b`/`-t`/`--tries` are **reliability tuning** (default batch
  1000, timeout 2500 ms, tries 2): on filtered / high-latency hosts an aggressive
  single-try burst loses open-port SYN-ACKs, so retransmits + a wider timeout +
  smaller batches materially cut false negatives.
- **masscan (opt-in):** `masscan -iL <input> -p 1-65535 --rate <n> --retries <n> -oL <out>`.
  Stateless, async full-port scan of the **WHOLE** IP list in one process —
  dramatically faster than per-IP rustscan on large sets. Needs root (raw sockets).
  Added via `--masscan` (UNIONed with rustscan) or `--masscan-only` (sole discovery
  scanner; nmap then scans only discovered ports instead of `-p-`, cutting scan time
  sharply). Completeness rests on `--retries` + masscan's 10s `--wait` window for
  late SYN-ACKs.
- **Deprecated (opt-in):** `naabu -l <input> -s c -Pn -p - -rate <n> -c <n> -json -silent -o <out>`.
  naabu gave unreliable results in the field and was dropped from the default; the
  code path is retained (`--port-scanners "rustscan,naabu"`) until a replacement is chosen.
- **Input:** scannable IPs from Stage 4.
- **Logic:** runs **every scanner in `port_scanners`** and **UNIONs** the open ports.
  With the default single scanner there is no union; add a second scanner to restore
  the cross-check. **Skipped entirely under `--nmap-only`** (empty scanner list) — nmap
  then does its own full discovery. Persistence is single-threaded after the union.
- **Output:** `Dict[ip -> [ports]]` → `ports` table. **These ports are what Stage 6
  deep-scans in discovered-ports mode.**
- **Artifacts:** `stages/05_ports.json`, `raw/rustscan/<ip>.txt`, `raw/masscan.txt`,
  `raw/naabu.jsonl` (if opted in).
- **Config:** `--port-scanners rustscan`, `--threads-portscan`, `--rustscan-ulimit`,
  `--rustscan-tries`, `--rustscan-timeout`, `--rustscan-batch`, `--masscan`,
  `--masscan-only`, `--masscan-rate`, `--masscan-retries` (`--naabu-rate` only
  if naabu is opted back in).
- **Caveat:** rustscan is unprivileged (connect-based) and stays a *fast signal*, not
  the authority — even tuned it can miss on aggressively-filtered hosts, which is why
  the default nmap still `-p-`s every scannable IP and `--nmap-only` exists.

### Stage 6 — nmap scan  `stage_nmap`

Stage 6 is the most complex stage. It includes tarpit detection (two layers),
the nmap deep scan itself, and post-scan validation. The complete flow:

#### 6a. Tarpit precheck  `_tarpit_precheck`

Before any full port scan, nmap probes 20 unlikely ports (e.g. 7, 79, 12345,
63210 — ports no legitimate server would have open) across **ALL** scannable IPs
in **ONE** nmap invocation. Any IP where >= 15 of these 20 ports respond open is
flagged as a **tarpit** — a load balancer or WAF that SYN-ACKs on every port.

- **Detection is behaviour-based, NOT provider-based.** It works on any vendor's
  infrastructure (Google Cloud HTTPS LB, Incapsula, unknown WAFs) without
  maintaining provider lists. No legitimate host has 15+ of these random ports open.
- **Timing:** the precheck runs with `--max-rtt-timeout 3000ms --max-retries 2`
  and deliberately does **NOT** use `--min-rate`. Using `--min-rate 10000` caused
  nmap to blast all probes in <0.1s and close the receive window before high-latency
  hosts responded, letting tarpits slip through with 0 detected probe ports.
- **Result:** tarpit IPs are scanned on a curated web-port set only
  (`80,443,8080,8443,8000,8888`), not the full 65535. This saves hours of nmap
  time and eliminates tens of thousands of fake open-port entries.
- **Artifacts:** `stages/06_tarpit_precheck.json` (probe ports used, threshold,
  flagged IPs, curated ports); `raw/tarpit_precheck.xml` (nmap XML output).

#### 6b. nmap deep scan

- **Tool:** `nmap -Pn --min-rate 10000 [port scope] -oX <xml> <ip>` (per IP, threaded).
- **Input:** the scannable IP list **and** Stage 5's port map **and** tarpit IPs
  from the precheck.
- **Two scoping modes:**
  - **EXPLICIT (default, `nmap_ports=["-p-"]`)** — nmap scans **every scannable
    IP** over the full port range, independent of the port scanner, so a lossy
    rustscan can't gate it (zero-FN at the port level). `--min-rate 10000` keeps the
    full sweep fast; the default flags do **not** run version/NSE (add `-sV`/`-A`).
    **Tarpit IPs** within this mode get the curated port set instead of `-p-`.
  - **DISCOVERED (`--nmap-ports ""`)** — nmap scans only the ports Stage 5 found, on
    the hit IPs only (the fast, rustscan-dependent mode; skips portless IPs).
    **Tarpit IPs** still get scanned on curated ports even if Stage 5 found nothing.
- **`--nmap-only` mode:** Stage 5 is skipped entirely (empty scanner list). nmap does
  its own full `-p-` discovery across every scannable IP. Most reliable, slowest.
  This is the standard scan mode.
- **`--nmap-host-timeout`:** caps a single stuck/tarpitting host so the batch keeps
  moving (e.g. `20m`).
- `-Pn` avoids the "host down → skip" false negative on ICMP-silent hosts.
- Parses nmap XML for open ports (+ service/version and NSE findings **if**
  `-sV`/`-A`/`-sC` added via `--nmap-flags`).
- **Privilege check:** without root, nmap downgrades to TCP connect scan (`-sT`),
  which is less reliable on filtered hosts. A warning is logged if not running as
  root and `-sT` is not explicitly set.

#### 6c. Post-scan tarpit safety net

After **each IP's** nmap scan completes, the pipeline checks the total number of
open ports recorded for that IP. If `port_count > 500` and the IP was **not**
already flagged by the precheck, it is a **post-scan tarpit** — a tarpit the
precheck missed.

- **Why this exists:** some tarpits are selective — they filter the 20 probe ports
  specifically (scoring 0/20 on the precheck) but SYN-ACK on the full port range.
  Example: `92.204.80.20` (European host, not Google) scored 0/20 on probe ports but
  had 63,553 fake open ports on a full `-p-` scan.
- **Action:** the fake ports are **purged** from the database (`storage.purge_ports`)
  and replaced with the curated web-port set (`80,443,8080,8443,8000,8888`).
- **Result:** the report stays clean; the IP is flagged with detection method
  `"post-scan (fake ports purged)"` instead of the precheck method.

#### 6d. Outputs

- **Database:** enriches `ports` table; populates `nmap_findings` (only when NSE is enabled).
- **Artifacts:**
  - `stages/06_tarpit_precheck.json` — precheck results (see 6a).
  - `stages/06_nmap.json` — scanned host count, port scope, **all tarpit IPs**
    (merged precheck + post-scan), separated into `tarpit_precheck` and
    `tarpit_postscan` lists with curated ports used.
  - `raw/nmap/<ip>.xml` — per-IP nmap XML output.
- **Toggles:** `--no-nmap`, `--nmap-flags`, `--nmap-ports` (`""` = discovered mode),
  `--nmap-full` (force `-p-` on all), `--nmap-host-timeout`, `--nmap-only`,
  `--nmap-only-rustscan-hits`, `--no-tarpit-detection`, `--tarpit-threshold`.

---

## 4. Tarpit detection — design rationale

Tarpits are load balancers or WAFs that SYN-ACK on every port. Without detection,
a single tarpit IP produces 30,000–65,000 fake "open" ports, drowning the real
surface in noise and wasting hours of nmap time. Real-world examples:

| Domain | Tarpit IP | Fake ports | Vendor |
|---|---|---|---|
| netmeds.com | 7 Google GCLB IPs | ~413,370 total | Google Cloud HTTPS LB |
| indiansuperleague.com | 92.204.80.20 | 63,553 | European host (non-Google) |

**Two-layer detection:**

```
Layer 1: PRECHECK (before full scan)
  └─ Probe 20 unlikely ports on ALL IPs
  └─ Score: open_count >= 15/20 → tarpit
  └─ Catches: tarpits that SYN-ACK everything uniformly (Google GCLB)

Layer 2: POST-SCAN SAFETY NET (after each IP's nmap finishes)
  └─ Check: port_count > 500 and IP not already flagged
  └─ Catches: selective tarpits that filter probe ports but tarpit on full range
  └─ Action: purge fake ports, replace with curated set

Result for detected tarpits:
  └─ Scanned on curated ports only: 80, 443, 8080, 8443, 8000, 8888
  └─ Report shows detection method (precheck vs post-scan)
```

**Critical design decisions:**
- **Behaviour-based, NOT provider-based.** The same provider (e.g. Google) can serve
  both tarpits (GCLB shared edges) and legitimate origins (customer VMs). A
  behaviour test works universally across all vendors and domains.
- **Threshold (15/20) is generous.** Even if 6–7 probe ports happen to be open on a
  legitimate multi-service host (unlikely), it won't reach 15. False-positive risk
  is effectively zero.
- **Curated ports, not silence.** Tarpit IPs are still scanned — on web ports that
  might have real services. The pipeline never drops a host entirely.
- **Fail open.** If tarpit detection is uncertain, the IP is scanned normally (zero-FN
  mandate). The post-scan safety net catches anything the precheck missed.

---

## 5. Persistence (`asm.db`, SQLite)

One portable single-file DB is the queryable "pipe" between stages. Raw tool output
stays on disk under `raw/`; only *parsed* rows go to SQLite. `UNIQUE` constraints
make re-runs idempotent. `run_id` scopes every row so multiple runs coexist.

| Table             | Written by                | Purpose |
|-------------------|---------------------------|---------|
| `runs`            | pipeline lifecycle        | one row per invocation: domain, started/finished, status |
| `subdomains`      | Stage 1 (Stage 2 flips `resolves`) | name, source (provenance), resolves 0/1 · `UNIQUE(run_id,name)` |
| `dns_records`     | Stage 2                   | A + CNAME rows · `UNIQUE(run_id,subdomain,type,value)` |
| `subdomain_hosts` | Stage 2                   | subdomain ↔ IP map · `UNIQUE(run_id,subdomain,ip)` |
| `hosts`           | Stage 4                   | unique IP, is_cdn, cdn_name, is_scannable · `UNIQUE(run_id,ip)` |
| `http_probes`     | Stage 3                   | url, status_code, title, webserver, tech, ip, cname, cdn_name, content_type/length, location, favicon, jarm, asn, response_time |
| `ports`           | Stage 5 (Stage 6 enriches)| ip, port, protocol, state, service, product, version · `UNIQUE(run_id,ip,port,protocol)` |
| `nmap_findings`   | Stage 6                   | ip, port, script_id, output, raw_ref |

**Tarpit-specific operations:**
- `Storage.port_count(run_id, ip)` — returns the number of open ports for an IP
  (used by the post-scan safety net to detect tarpits after scanning).
- `Storage.purge_ports(run_id, ip)` — deletes all port rows for an IP (used when
  a post-scan tarpit is detected; the fake ports are replaced with the curated set).

**Concurrency safety:** the single SQLite connection is written **only from the main
thread**. Threaded stages (rustscan in Stage 5, nmap in Stage 6) return data via
`as_completed`, and the main thread performs the inserts — no cross-thread DB access.

---

## 6. Subprocess runner (`runner.py`)

Every external command goes through `CommandRunner` for uniform behavior:

- **Tool discovery:** `resolve_binary()` tries each candidate name (`shutil.which`,
  cached) — e.g. `httpx-toolkit` then `httpx`. `available()` gates each stage so a
  missing tool degrades gracefully instead of crashing mid-pipeline. **Sudo-aware:**
  candidate lists also probe `~/go/bin` (for both `$HOME` and `$SUDO_USER`'s home)
  and `/usr/local/bin`, because `sudo` strips PATH of user-installed Go tools.
- **Execution:** `subprocess.run(capture_output=True, text=True, timeout=…)`.
  Returns `(returncode, stdout, stderr)`.
- **Conventions:** rc `127` = tool not found (never raises), rc `124` = timeout
  (like GNU `timeout`). The caller decides how to degrade.
- **Dry-run:** `--dry-run` logs the command and returns success without executing.

---

## 7. Configuration & CLI

All tunables live in `config.Settings`; CLI flags in `asm.py` override them per run.
Tool names/timeouts are module constants (`TOOL_BINARIES`, `TIMEOUTS`).

| Flag | Setting | Default | Effect |
|------|---------|---------|--------|
| `-d, --domain` | — | (required) | root domain to enumerate |
| `-o, --output` | — | `output` | output root directory |
| `--no-subdominator` | `use_subdominator` | on | Stage 1: findomain only |
| `--subdominator-bin` | `subdominator_bin` | PATH/known loc | path to subdominator binary |
| `--no-httpx` | `run_httpx` | on | skip Stage 3 |
| `--no-nmap` | `run_nmap` | on | skip Stage 6 |
| `--threads` | both scan threads | (per-tool defaults) | global concurrency — sets both portscan and nmap threads |
| `--threads-portscan` | `threads_portscan` | 8 | rustscan worker fan-out |
| `--threads-nmap` | `threads_nmap` | 3 | nmap worker fan-out (>10 → bandwidth warning) |
| `--port-scanners` | `port_scanners` | `rustscan` | scanners to run + UNION (naabu deprecated) |
| `--no-naabu` | (drops naabu) | off | **deprecated** — naabu no longer run by default |
| `--no-rustscan` | (drops rustscan) | off | skip the rustscan port scan |
| `--masscan` | (adds masscan) | off | add masscan to Stage 5 (UNIONed with rustscan) |
| `--masscan-only` | (masscan sole scanner) | off | fast two-phase: masscan discovers, nmap scans only those ports |
| `--masscan-rate` | `masscan_rate` | 10000 | masscan packets/sec (global budget) |
| `--masscan-retries` | `masscan_retries` | 3 | masscan retransmits (zero-FN lever) |
| `--rustscan-ulimit` | `rustscan_ulimit` | 5000 | rustscan `--ulimit` |
| `--rustscan-tries` | `rustscan_tries` | 2 | rustscan `--tries` (retransmits — cuts FNs on lossy hosts) |
| `--rustscan-timeout` | `rustscan_timeout` | 2500 | rustscan `-t` ms (raise for high-latency hosts) |
| `--rustscan-batch` | `rustscan_batch` | 1000 | rustscan `-b` batch (lower = less bursty = fewer drops) |
| `--naabu-rate` | `naabu_rate` | 1000 | naabu packets/sec (only if naabu opted in) |
| `--nmap-flags` | `nmap_flags` | `-Pn --min-rate 10000` | nmap scan flags (add `-sV`/`-A` for version/NSE) |
| `--nmap-ports` | `nmap_ports` | `-p-` | scope for every scannable IP; `""` = discovered-ports mode |
| `--nmap-full` | `nmap_full` | off | zero-FN: nmap `-p-` on every scannable IP (slow) |
| `--nmap-only` | (skips Stage 5 + forces `-p-`) | off | nmap does ALL discovery; rustscan skipped (most reliable) |
| `--nmap-host-timeout` | `nmap_host_timeout` | (none) | nmap `--host-timeout` per IP (e.g. `20m`) — caps a stuck host |
| `--nmap-only-rustscan-hits` | `nmap_scan_all_scannable` | off (scan all) | with explicit scope, gate nmap on Stage-5 hits |
| `--no-cdncheck` | `use_cdncheck` | on | skip cdncheck; static net only |
| `--no-cdncheck-update` | `cdncheck_update` | on (update) | skip `cdncheck -update` |
| `--no-httpx-rescue` | `httpx_rescue` | on | disable the httpx-reachability cross-check |
| `--scan-reachable-cdn` | `scan_reachable_cdn` | off | rescue also force-scans reachable CDN edges |
| `--no-tarpit-detection` | `tarpit_detection` | on | disable pre-scan tarpit detection |
| `--tarpit-threshold` | `tarpit_threshold` | 15 | min probe ports (out of 20) to flag a tarpit |
| `--wildcard-filter` | `wildcard_filter` | off | dnsx `-wd` (brute-force only) |
| `--allow-private-ips` | `allow_private_ips` | off | also scan RFC1918/loopback |
| `--no-cloud` | `scan_cloud_ips` | on (keep cloud) | also skip cloud IPs |
| `--dry-run` | `dry_run` | off | log commands, don't execute |
| `-v, --verbose` | — | off | DEBUG logging (full stage payloads) |
| `--version` | — | — | print version and exit |

**39 CLI flags** total (including `-d`, `-o`, `-v`, `--version`).

---

## 8. Output artifacts

Each run creates `output/<domain>_<YYYYmmdd_HHMMSS>/`:

```
<domain>_<stamp>/
├─ asm.db ................. SQLite DB (all parsed rows, queryable)
├─ asm.log ............... full run log (INFO + DEBUG if -v)
├─ report.md ............. human-readable surface summary + open ports + tarpits
├─ report.json ........... machine-readable counts + open ports + tarpit IPs
├─ raw/ .................. verbatim tool output (audit trail)
│   ├─ findomain.txt, subdominator.txt, all_subdomains.txt
│   ├─ dnsx_input.txt, dnsx.jsonl
│   ├─ httpx_input.txt, httpx.jsonl
│   ├─ cdncheck_input.txt, cdncheck.jsonl
│   ├─ rustscan/<ip>.txt       (per-IP rustscan output)
│   ├─ masscan_input.txt, masscan.txt  (if masscan used)
│   ├─ naabu_input.txt, naabu.jsonl    (if naabu opted in)
│   ├─ nmap/<ip>.xml           (per-IP nmap XML output)
│   └─ tarpit_precheck.xml     (tarpit probe nmap output)
└─ stages/ ............... per-stage snapshots
    ├─ 01_subdomains.json ...... subdomain list + source provenance
    ├─ 02_resolved.json ........ host→IP resolution map
    ├─ 03_http.json ............ httpx probe summary
    ├─ 03_alive_urls.txt ....... all URLs that responded (deduplicated)
    ├─ 03_fuzz_targets.txt ..... URLs with status 200/401/403 (fuzzing input)
    ├─ 03_tech.json ............ technology fingerprints + inventory
    ├─ 04_hosts.json ........... full host inventory (scannable + skipped)
    ├─ 04_all_domains.txt ...... every resolved subdomain
    ├─ 04_scannable_domains.txt  subdomains behind non-CDN IPs
    ├─ 04_cdn_skipped.json ..... filtered CDN/WAF edges + provider + source
    ├─ 04_waf_cdn.json ......... WAF vs CDN vs cloud split of skipped edges
    ├─ 05_ports.json ........... Stage 5 port map (ip→ports)
    ├─ 06_tarpit_precheck.json . tarpit detection results (probe ports, threshold)
    └─ 06_nmap.json ............ nmap scan summary + all tarpits (precheck + post-scan)
```

The report tables are built by re-reading `asm.db` (`Storage.counts()`,
`open_ports_summary()`, `active_subdomains()`, `inactive_subdomains()`), and
tarpit data from `06_tarpit_precheck.json` + `06_nmap.json`, so the report always
reflects persisted truth. Both `report.md` and `report.json` include:

- **Surface summary table** — subdomains, resolvable, unique IPs, scannable IPs,
  CDN/WAF skipped, tarpit IPs, HTTP services, open ports, nmap findings.
- **Tarpit anomalies section** — each tarpit IP with its detection method (precheck
  vs post-scan) and the curated port set applied.
- **Subdomains section** — **active** (resolved → scanned, with their IPs) and
  **inactive** (discovered but unresolved → flagged for dangling-DNS review).
- **Open ports table** — every open port with IP, service, product, version.

---

## 9. Correctness safeguards

The zero-FN / zero-FP mandate is enforced by these concrete measures:

| Risk | Safeguard |
|------|-----------|
| Wildcard filter nuking real subdomains | dnsx `-wd` **off by default** |
| CDN edges scanned as origins (FP) | cdncheck `-update` + schema-tolerant parser + static safety net |
| Real origins dropped as "CDN" (FN) | Provider-based classification (not category-based); static net excludes Google/AWS; cloud kept by default |
| Unknown provider flagged (FN) | **Fail open** — scan and warn, never silently drop |
| cdncheck missed by sudo PATH (FN) | Sudo-aware binary resolution probes `~/go/bin` + `$SUDO_USER`'s home |
| httpx-proved host dropped (FN) | Reachability cross-check force-keeps proved IPs |
| Tarpit IPs producing 65K fake ports (FP) | **Two-layer tarpit detection**: precheck (20 probe ports, threshold 15/20) + post-scan safety net (port_count > 500 → purge) |
| Selective tarpits evading precheck (FP) | Post-scan safety net catches tarpits that filter probe ports but tarpit on full range |
| Precheck too fast for slow hosts | No `--min-rate` on precheck; uses `--max-rtt-timeout 3000ms --max-retries 2` |
| Lossy fast scanner hiding open ports (FN) | `--nmap-full` / `--nmap-only` runs nmap `-p-` on all scannable IPs, ungated |
| Single scanner missing ports (FN) | Stage 5 UNIONs all configured scanners; masscan available as a second scanner |
| ICMP-silent hosts skipped (FN) | `-Pn` on nmap (and on naabu if opted in) |
| HTTP 404s dropped from surface | Stage 3 stores 404s, never drops |
| Blank-page hosts dropped | Stage 3 keeps them — no web ≠ no attack surface (SSH/RDP/DB on other ports) |
| Unprivileged nmap missing ports | Warning logged when not root (SYN scan needs root) |
| Silent tool failure | `CommandRunner` degrades gracefully; inter-stage logging shows empty hand-offs |
| Tarpit IPs fully silenced | Curated ports still scanned — pipeline never drops a host entirely |

---

## 10. Observability

`stages._log_input()` logs every inter-stage hand-off so the data flow is visible:

- **INFO** (always): count + short sample —
  `→ stage5/port_scan input: 3 scannable IPs  (from stage4/cdn_filter)  [1.2.3.4, …]`
- **DEBUG** (`-v`): the full payload —
  `→ stage2/resolve input (full payload from stage1/subdomains): ['a.x.com', …]`

Hand-off chain: `cli → stage1/subdomains → stage2/resolve → {stage3/http_probe,
stage4/cdn_filter} → stage5/port_scan → tarpit_precheck → stage6/nmap`. Each stage
also emits a `Stage N complete: …` summary. Logs go to stdout and `asm.log`.

**Tarpit-specific logging:**
- Precheck: logs each flagged IP with its open-probe-port score.
- Post-scan: `"Post-scan tarpit caught: <ip> — <N> open ports (precheck missed it)"`
  when the safety net triggers.
- Stage 6 completion: total tarpit count split by detection method.

---

## 11. External dependencies

Must be on `PATH` (Kali package names): `findomain`, `subdominator`, `dnsx`,
`httpx-toolkit`/`httpx`, `cdncheck`, `rustscan`, `nmap`. Optional: `masscan`
(only if `--masscan` or `--masscan-only`). `naabu` is optional (deprecated —
only needed if opted back in via `--port-scanners`). Any missing tool is skipped
with a warning rather than aborting the run. Python stdlib only (no third-party
Python packages).

---

## 12. Known limitations & roadmap

Tracked in detail in [archi_update.md](archi_update.md):

- **IPv6 dropped** — Stage 2 ignores AAAA records (§3.4).
- **CDN-fronted origin discovery** — scanning edges alone under-reports the true
  surface; needs cert-transparency / historical-DNS / SPF-MX pivots (§3.3).
- **cdncheck data health** — observed emitting 0 records on obvious CDN IPs on some
  hosts; the static net backstops it, but verify with `cdncheck -i <ip> -json`.
- **Performance model** — current thread-per-subprocess fan-out has no global
  concurrency budget; planned move to asyncio + one semaphore + OS niceness/cgroups
  (§2, Tiers 1–3).
- **Discovery scanner** — naabu deprecated; single-scanner discovery (rustscan) now
  feeds DISCOVERED-mode nmap, so a scanner miss is only recoverable via `--nmap-full`.
  masscan is now opt-in as a second scanner; a stateless sweep (masscan/zmap) to keep
  discovery both fast and complete, restoring the union cross-check (§3.1, §3.5).
- **`subdomains.source` accumulation** — provenance string appends on every touch
  (cosmetic) (§3.4).

### Planned enhancements (not yet implemented)

| Enhancement | Description | Integration point |
|---|---|---|
| wafw00f | WAF fingerprinting (F5, ModSecurity, etc.) | Parallel process after Stage 4, on alive URLs behind non-CDN IPs |
| Directory fuzzing (ffuf) | Directory/path discovery on live web targets | Post-pipeline, using `03_fuzz_targets.txt` as input |
| Nuclei | Template-based vulnerability scanning | After port scan, on alive URLs |
| Exposed panel detection | Fingerprint admin panels (Jenkins, Grafana, phpMyAdmin) from httpx tech-detect + title | Regex matching in Stage 3 data |
| Subdomain takeover detection | Check inactive subdomains for dangling DNS | Post Stage 2, on inactive subdomain list |
| Run-to-run diffing | Compare surfaces between scans | Database queries across `run_id`s |
| Screenshot capture | Visual recon of web targets | After Stage 3, on alive URLs |
| Risk scoring | Prioritize findings by severity | Post-pipeline analysis |
| HTML report | Rich interactive report | Replaces/supplements report.md |
