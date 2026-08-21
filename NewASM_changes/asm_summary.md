# NewASM — Capability Summary

*A plain-language overview of what NewASM does, how it works, and the value it
delivers. Written for management and stakeholders — no technical background needed.
For engineering detail see [`architecture.md`](architecture.md).*

---

## What it is

NewASM is an automated **Attack Surface Management (ASM)** tool. In a single command
it maps everything an organization exposes to the internet — every website,
application, server, and service reachable from the outside — and produces a clear,
queryable inventory of that exposure.

It examines the organization **the way an external attacker would**: from the outside,
with no inside knowledge, surfacing assets the organization may have forgotten it even
had.

---

## Why it matters

You can't defend what you don't know is exposed. Teams constantly spin up new
services, development and staging environments, and third-party integrations — and
many end up internet-facing without anyone tracking them. NewASM continuously answers
three business-critical questions:

- **What of ours is exposed to the internet?**
- **What is running on it?**
- **Which of those are risky and worth attention?**

On a recent assessment, for example, it surfaced internet-exposed **Jenkins**
(build/deployment automation) and **Grafana** (monitoring) login consoles — high-value
targets that are easy to overlook and dangerous if left open.

---

## How it works — the flow

NewASM runs as a **six-stage pipeline in a single process**. Each stage runs a
best-in-class open-source recon tool, hands its parsed output to the next stage in
memory, and simultaneously persists everything to a **SQLite database**, per-stage
**JSON snapshots**, and **raw tool output** — so every result is queryable and
auditable, and a crashed run still leaves partial results on disk.

| Stage | Tool(s) | What it does | Hands to the next stage |
|-------|---------|--------------|--------------------------|
| **1. Discover** | `findomain` + `subdominator` | Passive subdomain enumeration from many public sources (certificate-transparency logs, DNS aggregators, etc.); results are merged and de-duplicated to unique in-scope names | List of candidate subdomains |
| **2. Validate** | `dnsx` | Resolves each name (A / AAAA / CNAME). "Active" means it resolves to a real IP; dead / non-existent names (NXDOMAIN) are dropped | Live host → IP-address map |
| **3. Profile** | `httpx-toolkit` | Probes each live host over HTTP/HTTPS — status code, page title, technology stack, web server, plus the connected IP, CDN verdict, favicon hash, TLS (JARM) fingerprint and ASN. *Enrichment only — it never decides what gets scanned* | HTTP intelligence **+ a "reached" list** (which hosts actually answered) |
| **4. Filter** | `cdncheck` (+ built-in IP ranges) | Classifies each unique IP by provider. Shared third-party edges (Cloudflare, CloudFront, Fastly…) are skipped; the organization's own cloud/origin servers are kept. Stage 3's "reached" list force-keeps anything proven reachable | List of scannable IPs (the org's own assets) |
| **5. Scan** | `rustscan` | Fast open-port discovery on each scannable IP, tuned for reliability (retries, wider timeout, smaller batches) on filtered / rate-limiting hosts | IP → open-ports map |
| **6. Deep scan** | `nmap` | Service and version identification on the discovered ports — or a full all-ports sweep in the authoritative mode — producing the definitive service inventory | Services / versions → report |

*(An older scanner, `naabu`, is retained but deprecated; `rustscan` is the default.)*

### How the stages connect

```
seed domain
   │
   ▼
[1] Discover   findomain + subdominator   ─►  unique subdomains
   │
   ▼
[2] Validate   dnsx (DNS resolution)      ─►  live host → IP map
   │
   ├───────────────►  [3] Profile   httpx-toolkit   (enrichment; returns "reached" hosts)
   │                         │
   ▼                         ▼  reachability cross-check
[4] Filter     cdncheck  ◄───┘            ─►  scannable IPs (org's own assets)
   │
   ▼
[5] Scan       rustscan                   ─►  IP → open ports
   │
   ▼
[6] Deep scan  nmap                       ─►  services / versions
   │
   ▼
Reports  +  SQLite database
```

Two details worth calling out:

- **Two branches after Validate.** Stages 3 (Profile) and 4 (Filter) both consume
  Stage 2's live-host map, but they operate on different things: Profile works on
  *hostnames* (what's running), Filter works on *IP addresses* (what to scan). Profile
  never removes a host from the scan — it can only *confirm* reachability.
- **The reachability cross-check.** If Stage 3 proves a host is live but Stage 4's
  classification would have skipped its IP, the reachability evidence wins and the IP
  is kept — a safeguard against wrongly discarding a real, exposed asset.

---

## What you get

Every run produces a self-contained set of deliverables:

- A **queryable database** of the complete attack surface — assets, addresses,
  services, and open ports in one portable file.
- **Human-readable and machine-readable reports** summarizing the exposure.
- **Target lists and raw evidence** ready to feed reporting, ticketing, or
  detection-engineering pipelines.
- A **point-in-time snapshot** that can be compared across runs to see what is new or
  has changed since last time.

---

## What makes it trustworthy

NewASM is built for **organization-wide deployment where accuracy is non-negotiable.**
It is deliberately designed to avoid two failure modes:

- **Missing a real exposure** (a *false negative*) — the more dangerous error.
- **Flagging something that isn't real** (a *false positive*) — wasted effort and noise.

Correctness is prioritized over raw speed. The key safeguards, in plain terms:

- **Multiple discovery sources** are merged so assets aren't missed.
- **Shared addresses are de-duplicated**, so each server is examined once — efficient
  *and* complete.
- **Infrastructure-aware:** it recognizes shared third-party platforms and focuses
  effort on the organization's *own* assets, not someone else's network.
- **Reachability cross-check:** anything proven reachable is never silently dropped
  from scanning.
- **Reliability tuning plus a "gold-standard" mode** for assessments where zero missed
  ports is essential.

---

## Operating principles

- **Authorized use only.** NewASM is run exclusively against assets the organization
  owns or has explicit written permission to test.
- **Single command, repeatable.** One invocation runs the full pipeline end to end;
  results are portable and easy to share.
- **Isolated and auditable.** Every step retains raw evidence, so any finding can be
  independently verified for reporting.

---

## In short

NewASM gives an organization **continuous, accurate visibility into its internet-facing
exposure** — the same view an attacker has — packaged as clear, queryable reports that
plug directly into security operations, risk reporting, and defensive engineering.
