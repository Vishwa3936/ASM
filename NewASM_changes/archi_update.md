# NewASM — Architecture & Optimization Reference

> Working notes for the NewASM recon pipeline. Two concerns are tracked here:
> **(A)** performance / CPU-resource optimization, and **(B)** scan *correctness*
> (false-negative / false-positive elimination) for org-level deployment.
> This file is a design reference, not runtime config.

---

## 1. Current architecture

### 1.1 Layering

```
asm.py ................ CLI entrypoint: argparse -> config.Settings -> Pipeline.run()
└─ asmtool/
   ├─ pipeline.py ..... Orchestrator: run dir, run lifecycle, report writer
   ├─ stages.py ....... The 6 recon stages + shared Context dataclass
   ├─ runner.py ....... CommandRunner: subprocess exec, tool discovery, timeouts
   ├─ storage.py ...... SQLite persistence (asm.db) + readback for reports
   ├─ config.py ....... Settings dataclass, tool binaries, timeouts
   └─ utils.py ........ Pure helpers: scope, IP validation, JSONL, file I/O
```

Clean layered pipeline: orchestration -> stage logic -> side-effect adapters
(runner/storage) -> pure functions (utils). The `Context` dataclass is the
dependency-injection seam handing each stage its runner, storage, settings, workdir.

### 1.2 Stage data flow

```mermaid
flowchart TD
    S1[Stage 1: subdomains\nfindomain + bbot] -->|List[str]| S2[Stage 2: resolve\ndnsx  drops NXDOMAIN]
    S2 -->|Dict sub->ips| S3[Stage 3: http_probe\nhttpx enrich, 404s kept]
    S2 -->|Dict sub->ips| S4[Stage 4: cdn_filter\ncdncheck -> scannable IPs]
    S4 -->|List[ip]| S5[Stage 5: port_scan\nrustscan]
    S5 -->|Dict ip->ports| S6[Stage 6: nmap -sT -A\ndeep scan]
```

Flow between stages is **in-memory, single process, strictly sequential**
(`pipeline.py`). Each stage also triple-writes:

- `raw/`         — verbatim tool output (audit trail)
- `stages/NN_*.json` — parsed per-stage snapshot
- `asm.db`       — parsed rows keyed by `run_id` (the queryable "pipe")

### 1.3 SQLite schema (asm.db)

| Table             | Written by            | Holds |
|-------------------|-----------------------|-------|
| `runs`            | pipeline lifecycle    | one row per invocation (domain, timestamps, status) |
| `subdomains`      | Stage 1 (+2 flips `resolves`) | name, source (provenance), resolves 0/1 |
| `dns_records`     | Stage 2               | A + CNAME rows (NOTE: AAAA requested but not stored) |
| `subdomain_hosts` | Stage 2               | subdomain -> ip many-to-many |
| `hosts`           | Stage 4               | unique IP, is_cdn, cdn_name, is_scannable |
| `http_probes`     | Stage 3               | url, status, title, webserver, tech |
| `ports`           | Stage 5 (+6 enrich)   | ip, port, proto, service/product/version |
| `nmap_findings`   | Stage 6               | ip, port, script_id, output, raw_ref |

Raw tool output stays on disk under `raw/`; only *parsed* rows go to SQLite.

### 1.4 Concurrency model

Two levels of parallelism, **neither is Python-CPU-bound**:

1. **Intra-tool** — findomain / dnsx / httpx / cdncheck each run as ONE subprocess
   doing heavy internal concurrency.
2. **Inter-target fan-out** — only the two per-IP stages use Python threads:
   - `stage_port_scan`: `ThreadPoolExecutor(max_workers=8)`
   - `stage_nmap`:      `ThreadPoolExecutor(max_workers=3)`

Worker threads block in `subprocess.run`. SQLite is single-connection and written
only from the main thread (workers return data via `as_completed`) — no cross-thread
DB hazard. This is correct and safe.

---

## 2. Concern A — CPU / resource optimization

### 2.1 Where the burden actually comes from

The Python process is nearly idle; load comes from external scanners and fan-out:

| Source | Why it burns the box |
|---|---|
| `rustscan --ulimit 5000` x 8 concurrent | up to ~40k open sockets -> kernel softirq / network-stack CPU, FD exhaustion, NIC saturation. #1 spike. |
| `nmap -sT -A` x 3 | `-A` = version detect + default NSE scripts + OS detect + traceroute (NSE is CPU-heavy) |
| Fixed `max_workers` (8/3) | blind to core count / system load |
| No global budget | port-scan's 8 and nmap's 3 are independent; nothing caps *total* concurrent scanners |

Key point: this is ~90% an **OS-scheduling + rate-limiting** problem, ~10% an
orchestration-model problem. `multiprocessing` is the WRONG tool (work is
I/O/subprocess-bound, not Python-CPU-bound). `asyncio` alone won't lower CPU — it
buys *control* (unified budget + backpressure).

### 2.2 Tier 1 — quick wins (biggest relief, minimal code)

- **Lower OS priority of every scanner** — prefix commands in the runner:
  `nice -n 19 ionice -c 3 <cmd>`. Most direct lever for "don't burden the CPU".
- **Hard-cap via cgroups v2**:
  `systemd-run --user --scope -p CPUQuota=200% -p CPUWeight=20 python3 asm.py ...`
- **Rate-limit tools at the source**: rustscan `-b/--batch-size` + `-t` timeout;
  nmap `--max-rate`; dnsx `-rl` + `-t`.
- **Size concurrency to the machine**: `min(8, os.cpu_count())`, nmap `cpu//4`.

### 2.3 Tier 2 — structural (asyncio + one global budget)

Replace thread-per-subprocess / per-stage pools with a single event loop + ONE
shared `asyncio.Semaphore` budget across all stages. Use `asyncio.create_subprocess_exec`
+ `asyncio.TaskGroup` (3.11+). Add an AIMD / load-average governor that pauses new
launches while `getloadavg()` is hot. Stream (producer/consumer `asyncio.Queue`) so
DNS->HTTP->scan overlap instead of batching at stage boundaries — flattens the CPU curve.

Caveat: keep SQLite writes on a single owner (main coroutine or one queue consumer).

### 2.4 Tier 3 — only if it outgrows one box

Arq / Dramatiq (lightweight queues), Prefect / Temporal (durable resumable
workflows — stages already persist, so they map cleanly), Dask (data-parallel over
huge target lists). Do NOT adopt now; operational overhead not yet justified.

**Recommendation:** Tier 1 now (solves the stated CPU problem, ~20 lines, zero risk),
Tier 2 later for a single tunable concurrency ceiling.

---

## 3. Concern B — scan correctness (org-level: zero FN / FP tolerance)

Observed run (hamleys.com): 15/21 resolve -> 20 scannable IPs -> **0 CDN/WAF
skipped** -> rustscan found ports on only **2/20** IPs -> nmap deep-scanned **2** hosts.
Three distinct correctness defects surface here.

### 3.1 DEFECT: nmap is gated behind rustscan (false-negative amplifier)  [FIXED]

> **Status: fixed, then re-tuned for efficiency (2026-07).** `stage_nmap` takes
> `scannable_ips` + the Stage-5 `port_map`. It now runs in one of two modes:
> * **DISCOVERED (default, `Settings.nmap_ports=[]`)** — nmap version/script-scans
>   ONLY the ports Stage 5 (rustscan) found on each IP, so it no longer re-scans
>   all 65535 ports to re-discover them. This was the dominant runtime cost
>   (nmap = ~97% of a ~1.5 h run; full `-p-` re-scan on multi-port hosts ≈ 9
>   min/host). IPs with no Stage-5 ports are logged and skipped.
> * **FULL (`--nmap-full`, or explicit `--nmap-ports "-p-"`)** — the original
>   zero-FN behaviour: nmap `-p-` on EVERY scannable IP, independent of rustscan.
>   Retained as the escape hatch for max-paranoia runs.
>
> TRADE-OFF (zero-FN mandate): in DISCOVERED mode, a port the discovery scanner
> misses is not seen by nmap either — the fast scanner is once again a gate. This
> was a deliberate, user-approved efficiency choice; `--nmap-full` restores the
> non-lossy path. Longer term, a stateless discovery sweep (masscan/zmap, see the
> "modern architecture options" notes) would let DISCOVERED mode stay both fast
> AND complete. Original analysis kept below for context.
>
> **Default changed again (2026-07):** the default is now **ALL-SCANNABLE** —
> `nmap -Pn --min-rate 10000 -p-` on every scannable IP (`nmap_flags` +
> `nmap_ports=["-p-"]`). This restores zero-FN at the port level (nmap covers every
> IP, not just rustscan's hits) while `--min-rate 10000` keeps the full sweep fast.
> Trade-off: the default flags drop `-A`/`-sV`, so there is **no version/NSE
> detection** unless the operator adds `-sV`/`-A` to `--nmap-flags`; and a high
> `--min-rate` can miss ports on lossy links (rustscan's Stage-5 union mitigates).
> DISCOVERED mode is still available via `--nmap-ports ""`.


`stage_nmap` iterates `port_map.items()` — only IPs where rustscan already reported
open ports. So a lossy fast-scanner (rustscan) is the sole gate to the authoritative
scanner (nmap). **Any rustscan miss = permanent, invisible false negative.**

- rustscan is invoked with **no `-t` (timeout), no `--tries` (default 1), no `-p`
  range** -> default all-65535 with a single aggressive try. On lossy / rate-limited
  / distant paths, a dropped or late SYN-ACK is reported as closed.
- The code treats "rustscan returned nothing" as "host has no open ports" — it CANNOT
  distinguish **closed** from **filtered/timed-out**. That ambiguity is the core FN risk.

**Fix direction for zero-tolerance:**
- Do not let rustscan gate nmap. Either (a) run nmap directly on all resolved IPs
  (`-p-` or a vetted top-N), or (b) run nmap as an independent confirmation pass on
  every IP rustscan reported as empty.
- Add retries/timeout to rustscan (`--tries 2+`, higher `-t`).
- Record a per-IP scan *status* (scanned-clean vs filtered vs error), never collapse
  "no result" into "no ports".

### 3.2 DEFECT: cdncheck reported 0 CDN on an obviously CDN-fronted domain  [FIXED]

> **Status: fixed.** Three-part fix in `stage_cdn_filter`:
> 1. `cdncheck -update` runs first (toggle `Settings.cdncheck_update`, `--no-cdncheck-update`)
>    to refresh stale provider ranges.
> 2. `_classify_cdncheck()` parses CDN/WAF/cloud detections tolerant to schema
>    drift (bool+name, string, nested object, or name-only shapes).
> 3. A deterministic static safety net (`utils.static_cdn_name`, Cloudflare +
>    Fastly published ranges) catches anything cdncheck misses and logs a warning.
>    Validated: the 6 Cloudflare/Fastly IPs from the hamleys.com run are now flagged;
>    the 9 real-origin IPs pass through. Original analysis kept below for context.


hamleys.com resolved to `104.20.25.86`, `172.66.155.112` (**Cloudflare**) and
`151.101.x.x` (**Fastly**), yet Stage 4 logged "0 CDN/WAF skipped, 20 scannable".
Confirmation: the only ports found were `2083, 2086, 2095, 8880` — these are
**Cloudflare's alternate HTTP/HTTPS ports**, proving those IPs are Cloudflare edges.

Consequences (both FP and FN):
- **False positives**: reported "open ports" belong to the CDN, not the client's asset.
- **False negatives**: the real origin behind the CDN is never discovered/scanned.
- Wasted time + ban risk hammering CDN edges (also explains the multi-minute rustscan stalls).

**CONFIRMED root cause (was NOT stale data):** the invocation used `cdncheck -l <file>`,
but cdncheck's input flag is `-i`/STDIN — `-l` is unknown to it, so it exited **rc=2**
and emitted nothing → 0 records → nothing filtered on every run. **Fix:** feed IPs on
stdin, parse stdout (`cdncheck -j -resp -silent`). Verified live — cdncheck returns
`{"input":"13.225.5.19","cdn":true,"cdn_name":"cloudfront"}`, which `_classify_cdncheck`
reads as `("cdn","cloudfront")` → skipped. CloudFront is categorized `cdn` (not `cloud`),
so it filters correctly with no AWS service-tag classifier needed. The earlier
"stale ranges / schema mismatch" theories were wrong; the parser tolerance and static
net still stand as defense-in-depth.

### 3.7 DEFECT: Google Cloud LB origins skipped as "google cdn" (FN)  [FIXED]

> **Status: fixed (2026-07).** Observed (milkbasket.com): `grafana.milkbasket.com`
> (34.149.112.99) and `jenkins.milkbasket.com` (34.49.202.236) are **live, exposed
> login pages**, yet `04_cdn_skipped.json` flagged them `provider=google,
> category=cdn` and excluded them from scanning — along with ~10 Google IPs incl.
> `34.120.38.33` (37 hostnames: the whole app platform). Root cause: cdncheck tags
> **Google Cloud HTTPS Load Balancer** ranges as category `cdn`, and Stage 4 skipped
> everything categorised `cdn`/`waf`. But a Google LB IP is the org's OWN edge (it
> doesn't hide an origin the way Cloudflare does) → skipping it is a false negative.
>
> **Fix:** Stage 4 now decides keep-vs-skip by **provider name**, not cdncheck's
> category (`config.CDN_EDGE_PROVIDERS` vs `config.CLOUD_ORIGIN_PROVIDERS`), and
> **fails open** — any flagged provider that isn't a recognised shared-CDN edge is
> scanned as a possible origin (and logged). Genuine CDNs (Cloudflare, CloudFront,
> Fastly, Akamai) still skip; Google/AWS/Azure LB + instance IPs are kept. CloudFront
> stays skipped correctly: it genuinely hides the origin (S3/ALB elsewhere), so it is
> not a dropped-scannable-asset. Distinct from §3.3 (finding the origin *behind* a
> real CDN) — this was wrongly classifying an origin AS a CDN.
>
> **Belt-and-suspenders (implemented 2026-07):** an **httpx-reachability
> cross-check** now backs up the provider list. Stage 3 returns the set of hosts
> httpx actually reached (a completed HTTP(S) handshake = empirical proof the IP is
> reachable/open); Stage 4 force-keeps any such IP that a classifier tried to skip
> (`Settings.httpx_rescue`, `--no-httpx-rescue`). It only ever ADDS hosts, so it
> can't cause an FN, and it catches misclassification *dynamically* rather than
> relying on the static provider list staying correct. Genuine CDN edges stay
> skipped by default (httpx reached the edge, not the hidden origin → scanning it is
> a false positive); `--scan-reachable-cdn` overrides for a maximal run.

### 3.8 rustscan under-reporting on filtered hosts (FN)  [MITIGATED 2026-07]

Observed (milkbasket.com): rustscan found ports on **2/11** scannable IPs; a manual
`sudo nmap -p- -Pn --min-rate 10000` found 80/443 on **10/11**. rustscan misses
because the Google-LB hosts drop closed ports (65533 filtered) and rate-limit, so its
aggressive single-try SYN burst loses the open-port SYN-ACKs. Three-part response:

1. **Refined rustscan** (`Settings.rustscan_tries=2`, `rustscan_timeout=2500ms`,
   `rustscan_batch=1000`; `--rustscan-tries/-timeout/-batch`): retransmit dropped
   SYN-ACKs, tolerate 0.5s latency, and reduce burstiness — a more complete fast
   signal for the default discovered-ports feed to nmap.
2. **`--nmap-only`** mode: skips rustscan entirely and lets nmap do full `-p-`
   discovery on every scannable IP (`port_scanners=[]` + `nmap_full`). Removes the
   rustscan dependency for zero-FN sign-off runs (slowest, most reliable).
3. **Root warning:** without root, nmap silently downgrades to a connect scan (`-sT`)
   which itself missed ~3 open ports vs SYN in testing. `stage_nmap` now warns unless
   run as root, so `sudo` (→ SYN scan) is the obvious accuracy fix.

Note the Stage-6 "scan all scannable `-p-`" default already *recovered* rustscan's
misses here (3 → 17 open ports), validating that decision — nmap, not rustscan, is
the port authority. Longer term, a stateless sweep (masscan) replaces rustscan for
fast + complete discovery (§3.1).

### 3.5 DEFECT: port scan finds 0 ports even on hosts httpx reached  [FIXED]

Observed (indiansuperleague.com): Stage 3 httpx recorded **5 live HTTP services**,
yet Stage 5 (rustscan) and Stage 6 (nmap) reported **0 open ports** on all 7 IPs.
If httpx completed HTTP(S) handshakes, 80/443 are provably open + reachable — so
the ports exist and the *scanners* weren't seeing them (a probing-layer defect).

Root causes fixed:
1. **nmap had no `-Pn`.** The 7 IPs are CDN/cloud (Akamai `23.206/23.212.x`,
   Google `35.186.x`) that ignore ICMP. Without `-Pn`, nmap marks them "down" and
   scans nothing -> silent false negative. `Settings.nmap_flags` now defaults to
   `["-sT","-A","-Pn"]`.
2. **Single lossy scanner.** rustscan alone was the port-discovery source and it
   returned nothing (likely SYN-burst rate-limiting / ulimit vs system cap). naabu
   was added as a second (UNIONed) scanner, but **naabu is now DEPRECATED** (2026-07):
   it produced unreliable/unexpected results in the field, so `Settings.port_scanners`
   defaults to `["rustscan"]` only. The naabu code path (`_scan_naabu`, `-s c -Pn -p -`)
   is retained for opt-in (`--port-scanners "rustscan,naabu"`) until a replacement
   scanner (candidate: masscan for a stateless discovery sweep) is chosen. NOTE: with
   a single discovery scanner feeding DISCOVERED-mode nmap (§3.1), the union's
   cross-check is gone — revisit when the replacement lands.
3. **Akamai added to the static CDN safety net** (`utils._STATIC_CDN_RANGES`) so the
   `23.x` edges are excluded from scanning. Google/AWS deliberately NOT added —
   those ranges overlap real GCP/EC2 origins; blanket-flagging them would drop live
   assets. Cloud edge-vs-origin stays cdncheck's job.

Still to verify on the box: cdncheck logged "0 records parsed" on obvious Akamai
IPs -> its range data looks broken even after `-update`. Confirm with
`cdncheck -i 23.206.173.42 -json`; the static net covers Akamai meanwhile.

### 3.3 DEFECT: scanning CDN edges instead of origins

Even with cdncheck fixed, a CDN-fronted org surface needs **origin discovery**
(e.g. historical DNS, SPF/MX, cert transparency pivots, Shodan/Censys, direct-IP
takeover checks) — otherwise the "attack surface" is Cloudflare's, not the client's.
Track as a roadmap item; scanning edge IPs alone is a systemic false-surface problem.

### 3.4 Other correctness notes

- **AAAA dropped**: dnsx runs `-aaaa` but `stage_resolve` only reads `rec.get("a")`
  and `cname`. IPv6 surface is silently discarded -> IPv6-only hosts = false negatives.
- **subdomains.source accumulation**: `ON CONFLICT ... source=source||','||excluded.source`
  appends every touch -> duplicated provenance strings across re-runs (cosmetic, but
  pollutes reporting).
- **"NXDOMAIN dropped" label** is hardcoded in Stage 2 log text even when dnsx returned
  empty for other reasons (e.g. the earlier `-wd` wildcard-filter collapse) — misleading
  during triage.

---

## 3.6 Observability: inter-stage input logging

`stages._log_input()` logs every hand-off between stages so you can see exactly
what each stage received from the previous one:
- **INFO**  : count + short sample, e.g.
  `→ stage5/port_scan input: 3 scannable IPs (from stage4/cdn_filter) [1.2.3.4, …]`
- **DEBUG** (`-v`): the full payload (`... input (full payload from ...): [...]`).

Chain of hand-offs: cli → stage1/subdomains → stage2/resolve → {stage3/http_probe,
stage4/cdn_filter} → stage5/port_scan → stage6/nmap. `--no-cdncheck` skips cdncheck
and makes the static safety net the sole classifier (weaker; test use).

## 4. Priority for org deployment

1. **Fix cdncheck detection** (3.2) — currently mislabels the entire surface. Highest impact.
2. **Decouple nmap from rustscan** (3.1) — remove the single lossy gate; add filtered-vs-closed status.
3. **Add rustscan retries/timeouts** (3.1) — reduce transport-level false negatives.
4. **Origin discovery** (3.3) — for CDN-fronted targets.
5. **IPv6 + provenance cleanups** (3.4).
6. CPU optimization (Section 2) — Tier 1 first.

_Correctness (Section 3) outranks performance (Section 2) for a zero-FN/FP mandate._
