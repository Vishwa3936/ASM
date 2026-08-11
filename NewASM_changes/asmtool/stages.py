"""The six recon stages. Each stage reads its input, runs a tool, writes raw
output to disk, persists parsed rows to SQLite, and returns data for the next
stage. Stages are deliberately independent so they are easy to test/swap.

Pipeline order (corrected for ASM correctness):
  1. subdomains  findomain + subdominator (passive candidates — not yet proven live)
  2. resolve     dnsx  = ACTIVENESS: active iff it resolves to an IP (drop NXDOMAIN)
  3. http_probe  httpx (enrich only: status/title/tech — 404s KEPT; never gates scan)
  4. cdn_filter  cdncheck + static net (skip CDN/WAF edges; keep cloud origins;
                 skipped edges written to stages/04_cdn_skipped.json with provider)
  5. port_scan   rustscan on UNIQUE non-CDN IPs (naabu deprecated; scanners UNIONed
                 if more than one is configured)
  6. nmap_scan   nmap -Pn --min-rate 10000 -p- on ALL scannable IPs (default);
                 --nmap-ports "" switches to discovered-ports mode (hit IPs only)
"""

from __future__ import annotations

import logging
import os
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from . import config, utils
from .runner import CommandRunner
from .storage import Storage

log = logging.getLogger("asm.stages")


@dataclass
class Context:
    domain: str
    run_id: int
    workdir: Path
    runner: CommandRunner
    storage: Storage
    settings: config.Settings

    def raw(self, *parts: str) -> Path:
        p = self.workdir.joinpath("raw", *parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def stage_file(self, name: str) -> Path:
        p = self.workdir / "stages" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


def _log_input(stage: str, kind: str, items, source: str) -> None:
    """Log what a stage received from the previous stage.

    INFO shows the count + a short sample (the inter-stage hand-off at a glance);
    DEBUG (-v) dumps the full payload so you can see every item fed in.
    """
    if isinstance(items, dict):
        n = len(items)
        head = list(items.items())[:6]
        sample = ", ".join(f"{k}->{v}" for k, v in head)
    else:
        seq = list(items)
        n = len(seq)
        head = seq[:8]
        sample = ", ".join(str(s) for s in head)
    more = ", …" if n > len(head) else ""
    log.info("→ %s input: %d %s  (from %s)  [%s%s]",
             stage, n, kind, source, sample, more)
    log.debug("→ %s input (full payload from %s): %r", stage, source, items)


# ---------------------------------------------------------------------------
# Stage 1 — Subdomain enumeration (findomain + subdominator)
# ---------------------------------------------------------------------------
def stage_subdomains(ctx: Context) -> List[str]:
    _log_input("stage1/subdomains", "seed domain", [ctx.domain], "cli")
    found: Dict[str, Set[str]] = {}

    def add(name: str, source: str) -> None:
        name = utils.clean_host(name)
        if name and utils.in_scope(name, ctx.domain):
            found.setdefault(name, set()).add(source)

    add(ctx.domain, "seed")

    # findomain: -q prints one subdomain per line, nothing else. Resolve to the
    # full path (not the bare name) so it runs even when the install dir is off
    # root's PATH under sudo (e.g. ~/go/bin) — same reason cdncheck needs it.
    findomain_bin = ctx.runner.resolve_binary(config.TOOL_BINARIES["findomain"])
    if findomain_bin:
        rc, out, _ = ctx.runner.run(
            [findomain_bin, "-t", ctx.domain, "-q"], timeout=config.TIMEOUTS["findomain"]
        )
        ctx.raw("findomain.txt").write_text(out, encoding="utf-8")
        for line in out.splitlines():
            add(line, "findomain")
        log.info("findomain: %d names", sum(1 for s in found.values() if "findomain" in s))
    else:
        log.warning("findomain not found — skipping")

    # subdominator (RevoltSecurities): passive enumeration. Writes one subdomain
    # per line to -o; add() keeps only in-scope names, so any banner/log lines are
    # filtered out. Binary may be outside PATH — resolve override / known location.
    if ctx.settings.use_subdominator:
        candidates = ([ctx.settings.subdominator_bin] if ctx.settings.subdominator_bin
                      else config.TOOL_BINARIES["subdominator"])
        sub_bin = ctx.runner.resolve_binary(candidates)
        if sub_bin:
            outfile = ctx.raw("subdominator.txt")
            rc, out, err = ctx.runner.run(
                [sub_bin, "-d", ctx.domain, "-o", str(outfile)],
                timeout=config.TIMEOUTS["subdominator"],
                stdin_input="",  # non-interactive, so it can never block on a prompt
            )
            text = outfile.read_text(errors="ignore") if outfile.exists() else (out or "")
            for line in text.splitlines():
                add(line, "subdominator")
            n_sub = sum(1 for s in found.values() if "subdominator" in s)
            if rc == 0:
                log.info("subdominator: %d names", n_sub)
            else:
                # Never fatal — findomain results stand and the pipeline continues.
                reason = "timed out" if rc == 124 else f"exited rc={rc}"
                log.warning("subdominator %s and contributed %d names — continuing "
                            "with findomain only. stderr tail: %s", reason, n_sub,
                            (err or "").strip()[-300:] or "(none)")
        else:
            log.warning("subdominator not found — set --subdominator-bin <path> or add "
                        "it to PATH; skipping")

    # Consolidate findomain + subdominator (+ seed): `found` is keyed by cleaned
    # hostname, so both tools' outputs are merged and de-duplicated here — only the
    # UNIQUE in-scope set advances to the pipeline. `source` records which tool(s)
    # found each name (a name seen by both collapses to one row).
    subdomains = sorted(found)
    for name in subdomains:
        ctx.storage.add_subdomain(ctx.run_id, name, ",".join(sorted(found[name])), False)
    ctx.storage.commit()

    n_findomain = sum(1 for s in found.values() if "findomain" in s)
    n_sub = sum(1 for s in found.values() if "subdominator" in s)
    n_both = sum(1 for s in found.values() if {"findomain", "subdominator"} <= s)
    utils.dump_json(ctx.stage_file("01_subdomains.json"), {
        "count": len(subdomains),
        "sources": {"findomain": n_findomain, "subdominator": n_sub, "overlap": n_both},
        "by_source": {name: sorted(found[name]) for name in subdomains},
        "subdomains": subdomains,
    })
    utils.write_lines(ctx.raw("all_subdomains.txt"), subdomains)
    log.info("Stage 1 complete: %d UNIQUE in-scope subdomains "
             "(findomain=%d, subdominator=%d, overlap=%d) — merged & deduped",
             len(subdomains), n_findomain, n_sub, n_both)
    return subdomains


# ---------------------------------------------------------------------------
# Stage 2 — DNS resolution (dnsx). Drops only NXDOMAIN; filters wildcards.
# ---------------------------------------------------------------------------
def stage_resolve(ctx: Context, subdomains: List[str]) -> Dict[str, List[str]]:
    _log_input("stage2/resolve", "subdomains", subdomains, "stage1/subdomains")
    if not subdomains:
        return {}
    # Resolve to the full path so dnsx runs even when installed only in ~/go/bin
    # and PATH is stripped under sudo — a bare-name failure here aborts the WHOLE
    # pipeline (total false negative), so this is the most important site to fix.
    dnsx_bin = ctx.runner.resolve_binary(config.TOOL_BINARIES["dnsx"])
    if not dnsx_bin:
        log.error("dnsx not found — cannot resolve; aborting downstream scans")
        return {}

    infile = utils.write_lines(ctx.raw("dnsx_input.txt"), subdomains)
    outfile = ctx.raw("dnsx.jsonl")
    cmd = [dnsx_bin, "-l", str(infile), "-a", "-aaaa", "-cname", "-resp",
           "-j", "-silent", "-o", str(outfile)]
    # Wildcard filtering is opt-in — on a CDN-fronted domain it would drop
    # every real subdomain (see config.Settings.wildcard_filter).
    if ctx.settings.wildcard_filter:
        cmd += ["-wd", ctx.domain]
    ctx.runner.run(cmd, timeout=config.TIMEOUTS["dnsx"])

    sub_to_ips: Dict[str, List[str]] = {}
    text = outfile.read_text(errors="ignore") if outfile.exists() else ""
    for rec in utils.read_jsonl(text):
        host = utils.clean_host(utils.first(rec, "host", "input", default=""))
        if not host:
            continue
        a_records = rec.get("a") or []
        for ip in a_records:
            ctx.storage.add_dns_record(ctx.run_id, host, "A", ip)
            ctx.storage.map_subdomain_host(ctx.run_id, host, ip)
        for cname in (rec.get("cname") or []):
            ctx.storage.add_dns_record(ctx.run_id, host, "CNAME", cname)
        if a_records:
            sub_to_ips[host] = list(a_records)
            ctx.storage.add_subdomain(ctx.run_id, host, "dnsx", True)
    ctx.storage.commit()

    utils.dump_json(ctx.stage_file("02_resolved.json"), sub_to_ips)
    log.info("Stage 2 complete: %d/%d subdomains are ACTIVE (resolve to an IP)",
             len(sub_to_ips), len(subdomains))

    # Surface the inactive names: discovered (passive sources) but no A record.
    # These are NOT scanned; an empty/dead record here can indicate dangling DNS
    # (subdomain-takeover candidate) and is worth an analyst's eyes.
    unresolved = [s for s in subdomains if s not in sub_to_ips]
    if unresolved:
        log.info("Stage 2: %d subdomain(s) did NOT resolve (inactive — review for "
                 "dangling DNS / takeover): %s", len(unresolved), ", ".join(unresolved))
    return sub_to_ips


# ---------------------------------------------------------------------------
# Stage 3 — HTTP probe (httpx). Enrichment only. 404s are stored, never dropped.
# ---------------------------------------------------------------------------
def stage_http_probe(ctx: Context, hosts: List[str]) -> Set[str]:
    """Probe resolved hosts over HTTP(S). Enrichment only (404s kept, never gates
    the scan). Returns the set of hostnames httpx actually REACHED — httpx emits a
    record only for hosts that answered, so each record is proof of a completed
    HTTP(S) handshake. Stage 4 uses this set as a zero-FN reachability cross-check.
    """
    _log_input("stage3/http_probe", "resolved hosts", hosts, "stage2/resolve")
    if not ctx.settings.run_httpx or not hosts:
        return set()
    binary = ctx.runner.resolve_binary(config.TOOL_BINARIES["httpx"])
    if not binary:
        log.warning("httpx/httpx-toolkit not found — skipping HTTP enrichment")
        return set()

    infile = utils.write_lines(ctx.raw("httpx_input.txt"), hosts)
    outfile = ctx.raw("httpx.jsonl")
    ctx.runner.run(
        [binary, "-l", str(infile), *config.HTTPX_FLAGS, "-o", str(outfile)],
        timeout=config.TIMEOUTS["httpx"],
    )

    stored = 0
    reached: Set[str] = set()
    tech_rows: List[Dict[str, Any]] = []   # per-host tech-detect rows (03_tech.json)
    tech_index: Dict[str, List[str]] = {}  # technology -> [hosts] inventory
    text = outfile.read_text(errors="ignore") if outfile.exists() else ""
    for rec in utils.read_jsonl(text):
        # httpx puts the input hostname in "input" and the CONNECTED IP in "host".
        host = utils.clean_host(rec.get("input") or "")
        ip = rec.get("host") or ""
        if not ip and isinstance(rec.get("a"), list) and rec.get("a"):
            ip = rec["a"][0]

        tech = rec.get("tech") or rec.get("technologies") or []
        if isinstance(tech, str):  # some builds emit a comma string, not a list
            tech = [t.strip() for t in tech.split(",") if t.strip()]
        webserver = utils.first(rec, "webserver", "web_server")
        cname = rec.get("cname") or []
        # httpx's own CDN verdict (-cdn): a second signal alongside cdncheck.
        cdn_name = rec.get("cdn_name") or (rec.get("cdn") if isinstance(rec.get("cdn"), str) else None)
        if cdn_name and rec.get("cdn_type"):
            cdn_name = f"{cdn_name} ({rec.get('cdn_type')})"
        asn = rec.get("asn")
        if isinstance(asn, dict):  # {as_number, as_name, as_country, ...} → flat string
            asn = " ".join(str(v) for v in (asn.get("as_number"), asn.get("as_name"),
                                            asn.get("as_country")) if v) or None
        fav = rec.get("favicon")

        ctx.storage.add_http_probe(ctx.run_id, {
            "subdomain": host,
            "url": rec.get("url"),
            "status_code": utils.first(rec, "status_code", "status-code"),
            "title": rec.get("title"),
            "webserver": webserver,
            "tech": ", ".join(tech) if isinstance(tech, list) else tech,
            "ip": ip or None,
            "cname": ", ".join(cname) if isinstance(cname, list) else cname,
            "cdn_name": cdn_name,
            "content_type": rec.get("content_type"),
            "content_length": rec.get("content_length"),
            "location": rec.get("location"),
            "favicon": str(fav) if fav not in (None, "") else None,
            "jarm": rec.get("jarm"),
            "asn": asn,
            "response_time": rec.get("time") or rec.get("response_time"),
        })
        stored += 1
        if host:
            reached.add(host)   # httpx answered → provably reachable
        # Tech-detect artifact: httpx already runs with -tech-detect, so capture the
        # fingerprints (technologies + web server) as their own stage output.
        if tech or webserver:
            tech_list = tech if isinstance(tech, list) else []
            tech_rows.append({"subdomain": host or None, "url": rec.get("url"),
                              "ip": ip or None, "webserver": webserver,
                              "tech": tech_list})
            for t in tech_list:
                hosts = tech_index.setdefault(t, [])
                if host and host not in hosts:
                    hosts.append(host)
    ctx.storage.commit()
    utils.dump_json(ctx.stage_file("03_http.json"),
                    {"probed": stored, "reached_hosts": len(reached)})
    # Separate tech-detect artifact: a per-host view + a technology->hosts inventory,
    # both derived from httpx's -tech-detect output (no extra tool run).
    utils.dump_json(ctx.stage_file("03_tech.json"), {
        "hosts_with_tech": len(tech_rows),
        "total_probed": stored,
        "technologies": {t: sorted(h) for t, h in sorted(tech_index.items())},
        "by_host": tech_rows,
    })
    log.info("Stage 3 complete: %d HTTP services recorded (incl. 404s); "
             "%d host(s) reachable (fed to Stage-4 cross-check)", stored, len(reached))
    log.info("Stage 3: tech-detect artifact written — %d host(s) fingerprinted, "
             "%d distinct technologies (stages/03_tech.json)",
             len(tech_rows), len(tech_index))
    return reached


# ---------------------------------------------------------------------------
# Stage 4 — CDN/WAF filter (cdncheck). Dedupe to unique scannable IPs.
# ---------------------------------------------------------------------------
def _classify_cdncheck(rec: Dict) -> Optional[Tuple[str, str]]:
    """Extract (category, provider_name) from a cdncheck JSON record, or None.

    Tolerant to cdncheck schema drift across versions — the classifier keys on
    whatever shape is present, so a real detection is never silently dropped:
      * boolean flag + sibling name : {"cdn": true, "cdn_name": "cloudflare"}
      * string value               : {"cdn": "cloudflare"}
      * nested object              : {"cdn": {"name": "cloudflare"}}
      * name-only (no bool)        : {"cdn_name": "cloudflare"}
    Categories are checked cdn -> waf -> cloud (first match wins).
    """
    for category in ("cdn", "waf", "cloud"):
        val = rec.get(category)
        name: Optional[str] = None
        if isinstance(val, dict):
            name = val.get("name") or val.get("value")
        elif isinstance(val, str) and val:
            name = val
        # explicit sibling name field (covers the boolean-flag shape)
        name = name or rec.get(f"{category}_name")
        # a truthy flag with no resolvable name still means "detected"
        if not name and (val is True or (isinstance(val, str) and val)):
            name = category
        if name:
            return category, str(name)
    return None


def _cdncheck_flagged(rec: Dict, category: str) -> bool:
    """True if a cdncheck record flags this specific category (cdn/waf/cloud).

    Independent of _classify_cdncheck's cdn->waf->cloud precedence, so an IP that
    is BOTH a CDN and a WAF (e.g. Cloudflare) is still recognised as a WAF for the
    04_waf_cdn.json labelling. Tolerant to the same schema shapes, PLUS a type field
    like {"cdn_type": "waf"} or {"type": "waf"} that some cdncheck builds emit.
    """
    val = rec.get(category)
    if isinstance(val, dict) and (val.get("name") or val.get("value")):
        return True
    if isinstance(val, str) and val:
        return True
    if val is True:
        return True
    if rec.get(f"{category}_name"):
        return True
    for k in ("type", "cdn_type", "category"):
        if str(rec.get(k, "")).strip().lower() == category:
            return True
    return False


def stage_cdn_filter(ctx: Context, sub_to_ips: Dict[str, List[str]],
                     reached_hosts: Optional[Set[str]] = None) -> List[str]:
    _log_input("stage4/cdn_filter", "host→IP maps", sub_to_ips, "stage2/resolve")
    all_ips = {ip for ips in sub_to_ips.values() for ip in ips}
    all_ips = {ip for ip in all_ips
               if utils.is_public_ip(ip) or ctx.settings.allow_private_ips}
    if not all_ips:
        return []

    cdn_map: Dict[str, str] = {}   # ip -> cdn/waf/cloud name (means: do NOT scan)
    cdn_detail: Dict[str, Dict[str, str]] = {}  # ip -> {provider, category, source}
    records = 0
    if not ctx.settings.use_cdncheck:
        log.warning("cdncheck disabled (--no-cdncheck) — static CDN safety net "
                    "(Cloudflare/Fastly/Akamai) is the ONLY classifier; other "
                    "CDNs/WAFs will be scanned as origins")
    elif ctx.runner.available(config.TOOL_BINARIES["cdncheck"]):
        # Resolve to the FULL path. available() above matches an absolute candidate
        # (e.g. ~/go/bin/cdncheck) via shutil.which regardless of PATH, but a bare
        # `cdncheck` in run() hits subprocess's own PATH lookup, which under sudo
        # omits ~/go/bin → FileNotFoundError (rc=127) → the tool silently no-ops and
        # every CDN/WAF edge gets scanned as an origin. Invoking the resolved path
        # closes that gap (this exact bug scanned Incapsula tarpits as origins).
        cdncheck_bin = ctx.runner.resolve_binary(config.TOOL_BINARIES["cdncheck"])
        # Refresh provider ranges first — stale data silently misclassifies real
        # CDN edges as scannable origins (the #1 false-positive source).
        if ctx.settings.cdncheck_update:
            ctx.runner.run([cdncheck_bin, "-update"], timeout=config.TIMEOUTS["cdncheck"])

        # cdncheck's input flag is -i (NOT -l), and with no flag it reads targets
        # from STDIN. Feed on stdin + parse STDOUT — the most version-robust
        # interface. Passing `-l` made cdncheck reject an unknown flag (exit rc=2)
        # and emit nothing, which is why every prior run logged "0 records parsed".
        utils.write_lines(ctx.raw("cdncheck_input.txt"), sorted(all_ips))  # audit trail
        rc, out, err = ctx.runner.run(
            [cdncheck_bin, "-j", "-resp", "-silent"],
            timeout=config.TIMEOUTS["cdncheck"],
            stdin_input="\n".join(sorted(all_ips)) + "\n",
        )
        ctx.raw("cdncheck.jsonl").write_text(out or "", encoding="utf-8")  # audit trail
        if rc != 0 and not (out or "").strip():
            log.warning("cdncheck exited rc=%s with no output (%s) — falling back to "
                        "the static CDN net", rc, (err or "").strip()[:200])
        for rec in utils.read_jsonl(out or ""):
            records += 1
            ip = utils.first(rec, "ip", "input", "host", default="")
            hit = _classify_cdncheck(rec)
            if not hit:
                continue
            category, name = hit
            provider = name.strip().lower()
            waf_flag = _cdncheck_flagged(rec, "waf")
            # Decide keep-vs-skip by PROVIDER, not just cdncheck's category —
            # cdncheck mislabels cloud load-balancer ranges (e.g. Google Cloud
            # HTTPS LB serving grafana/jenkins) as category "cdn"/"waf", and
            # skipping those live origins is a false negative. Under the zero-FN
            # mandate we fail OPEN toward scanning.
            if provider in config.CDN_EDGE_PROVIDERS or provider in config.WAF_EDGE_PROVIDERS:
                pass  # genuine shared CDN/WAF edge → fall through to skip
            elif provider in config.CLOUD_ORIGIN_PROVIDERS or category == "cloud":
                # org's own cloud origin (incl. LB ranges cdncheck tags cdn/waf).
                # NOTE: this KEEPS a cloud IP even when cdncheck tags it "waf" — an
                # origin behind a WAF is real surface; skipping it is a false negative.
                if ctx.settings.scan_cloud_ips:
                    continue          # keep it scannable
                category = "cloud"    # --no-cloud: record as a skipped cloud IP
            else:
                # flagged cdn/waf but the provider is unknown to us — never drop a
                # possibly-live origin; scan it and warn so the set can be tuned.
                log.warning("cdncheck flagged %s as %s (provider '%s') which is not a "
                            "known CDN/WAF edge — scanning it as a possible origin "
                            "(zero-FN). Add to CDN_EDGE_PROVIDERS/WAF_EDGE_PROVIDERS "
                            "to exclude.", ip, category, name)
                continue
            # Label WAF vs CDN vs cloud for the 04_waf_cdn.json artifact. cloud wins
            # (a --no-cloud skip), then a genuine WAF edge (provider or cdncheck's own
            # waf flag), else CDN.
            edge_type = ("cloud" if category == "cloud"
                         else "waf" if (waf_flag or provider in config.WAF_EDGE_PROVIDERS)
                         else "cdn")
            cdn_map[ip] = name
            cdn_detail[ip] = {"provider": name, "category": category,
                              "source": "cdncheck", "type": edge_type}
        log.info("cdncheck: %d records parsed, %d flagged as CDN/WAF/cloud",
                 records, len(cdn_map))
    else:
        log.warning("cdncheck NOT FOUND on PATH — falling back to the static CDN/WAF "
                    "net (Cloudflare/Fastly/Akamai/Incapsula only). Any OTHER CDN/WAF "
                    "edge will be SCANNED as an origin: false positives + noise (e.g. "
                    "WAF tarpits that report thousands of open ports). Common cause: "
                    "running under `sudo`, whose PATH omits ~/go/bin. Fix: install "
                    "cdncheck to /usr/local/bin, or run "
                    "`sudo env \"PATH=$PATH\" python3 asm.py ...`")

    # Deterministic backstop: catch well-known CDN ranges cdncheck missed
    # (stale data, schema drift, or tool absent). Only ADDS detections.
    static_added = 0
    for ip in all_ips:
        if ip in cdn_map:
            continue
        provider = utils.static_cdn_name(ip)
        if provider:
            # Label WAF vs CDN from the provider so a static-net Incapsula hit lands
            # in the WAF bucket of 04_waf_cdn.json (not the CDN one).
            edge_type = "waf" if provider in config.WAF_EDGE_PROVIDERS else "cdn"
            cdn_map[ip] = provider
            cdn_detail[ip] = {"provider": provider, "category": edge_type,
                              "source": "static-net", "type": edge_type}
            static_added += 1
            log.warning("static range flags %s as %s (%s) — cdncheck missed it "
                        "(not found, or run `cdncheck -update`?)", ip, provider, edge_type)
    if static_added:
        log.warning("static CDN safety net caught %d IP(s) cdncheck did not", static_added)

    # Reverse the Stage-2 host→IP map into IP→subdomains, so every IP artifact can
    # carry the subdomain(s) that resolved to it (many subdomains often share one
    # IP). Restricted to the public/in-scope IP set this stage considered.
    ip_to_subs: Dict[str, Set[str]] = {}
    for sub, ips in sub_to_ips.items():
        for ip in ips:
            if ip in all_ips:
                ip_to_subs.setdefault(ip, set()).add(sub)

    def subs_of(ip: str) -> List[str]:
        return sorted(ip_to_subs.get(ip, set()))

    # httpx-reachability cross-check (zero-FN backstop): if httpx completed an
    # HTTP(S) handshake to a host, that host's IP is PROVABLY reachable with an open
    # web port — it must not be dropped by a cdncheck misclassification. Force such
    # IPs back to scannable. This can only ADD hosts (never remove), so it cannot
    # introduce a false negative. Genuine CDN edges are LEFT skipped by default:
    # httpx reached the edge, not the hidden origin, so scanning it yields the
    # edge's ports (a false positive) + ban risk — override with --scan-reachable-cdn.
    if ctx.settings.httpx_rescue and reached_hosts:
        reached_ips = {ip for host in reached_hosts
                       for ip in sub_to_ips.get(host, []) if ip in all_ips}
        for ip in sorted(reached_ips & set(cdn_map)):
            detail = cdn_detail.get(ip, {})
            provider = str(detail.get("provider", "")).strip().lower()
            is_edge = (detail.get("source") == "static-net"
                       or provider in config.CDN_EDGE_PROVIDERS
                       or provider in config.WAF_EDGE_PROVIDERS)
            names = ",".join(subs_of(ip)) or "?"
            if is_edge and not ctx.settings.scan_reachable_cdn:
                log.info("httpx reached %s via CDN edge %s (%s) — origin hidden behind "
                         "the CDN; leaving it skipped (use --scan-reachable-cdn to scan "
                         "the edge)", names, ip, detail.get("provider", "cdn"))
                continue
            cdn_map.pop(ip, None)
            cdn_detail.pop(ip, None)
            log.warning("httpx-rescue: %s (%s) was skipped as %s/%s but httpx reached "
                        "it → forcing SCANNABLE (reachability overrides cdncheck)",
                        ip, names, detail.get("category", "?"), detail.get("provider", "?"))

    scannable: List[str] = []
    for ip in sorted(all_ips):
        is_cdn = ip in cdn_map
        ctx.storage.add_host(ctx.run_id, ip, is_cdn, cdn_map.get(ip), not is_cdn)
        if not is_cdn:
            scannable.append(ip)
    ctx.storage.commit()

    # 04_hosts.json — EVERY unique IP (scannable AND CDN/WAF-skipped), each tagged
    # with the subdomain(s) that resolved to it and its classification. This is the
    # full host inventory, not just the scannable subset: `scannable` flags whether
    # the IP advances to the port scan, and provider/category/source are set for the
    # skipped CDN/WAF/cloud edges.
    all_hosts = []
    for ip in sorted(all_ips):
        detail = cdn_detail.get(ip, {})
        is_cdn = ip in cdn_map
        all_hosts.append({
            "ip": ip,
            "scannable": not is_cdn,
            "provider": detail.get("provider") if is_cdn else None,
            "category": detail.get("category") if is_cdn else None,
            "source": detail.get("source") if is_cdn else None,
            "subdomains": subs_of(ip),
        })
    utils.dump_json(ctx.stage_file("04_hosts.json"),
                    {"unique_ips": len(all_ips), "cdn_or_waf": len(cdn_map),
                     "scannable_count": len(scannable), "static_net_added": static_added,
                     "hosts": all_hosts})

    # Companion .txt files (one host per line):
    #  * 04_scannable_domains.txt — subdomains behind scannable (non-CDN) IPs.
    #  * 04_all_domains.txt        — every resolved subdomain in this stage's IP set.
    scannable_domains = sorted({sub for ip in scannable for sub in subs_of(ip)})
    all_domains = sorted({sub for subs in ip_to_subs.values() for sub in subs})
    utils.write_lines(ctx.stage_file("04_scannable_domains.txt"), scannable_domains)
    utils.write_lines(ctx.stage_file("04_all_domains.txt"), all_domains)

    # Dedicated artifact: the IPs that were FILTERED OUT (not scanned) as CDN/WAF/
    # cloud edges, each tagged with the provider, the category, which classifier
    # caught it (cdncheck vs the static safety net), and the resolving subdomains.
    # Always written (even if empty) so the exclusion set is auditable per run.
    skipped_rows = [
        {"ip": ip,
         "provider": cdn_detail.get(ip, {}).get("provider", cdn_map[ip]),
         "category": cdn_detail.get(ip, {}).get("category", "unknown"),
         "type": cdn_detail.get(ip, {}).get("type", "cdn"),
         "source": cdn_detail.get(ip, {}).get("source", "unknown"),
         "subdomains": subs_of(ip)}
        for ip in sorted(cdn_map)
    ]
    utils.dump_json(ctx.stage_file("04_cdn_skipped.json"),
                    {"count": len(skipped_rows), "skipped": skipped_rows})

    # Dedicated categorisation of the SKIPPED edges into WAF vs CDN (vs cloud, when
    # --no-cloud drops cloud origins). Pure LABELLING of IPs already excluded above —
    # it does NOT change what gets scanned. "waf" = a genuine shared WAF-edge provider
    # or an IP cdncheck flagged waf; on-prem WAFs (F5 BIG-IP on the org's own IP) are
    # invisible to cdncheck and remain scannable (fingerprint them with wafw00f).
    waf_rows, cdn_rows, cloud_rows = [], [], []
    for row in skipped_rows:
        bucket = {"waf": waf_rows, "cloud": cloud_rows}.get(row["type"], cdn_rows)
        bucket.append(row)
    utils.dump_json(ctx.stage_file("04_waf_cdn.json"),
                    {"waf_count": len(waf_rows), "cdn_count": len(cdn_rows),
                     "cloud_skipped_count": len(cloud_rows),
                     "waf": waf_rows, "cdn": cdn_rows, "cloud_skipped": cloud_rows})
    if waf_rows:
        log.info("Stage 4: %d IP(s) categorised as WAF edges and skipped from port "
                 "scanning (see stages/04_waf_cdn.json)", len(waf_rows))

    log.info("Stage 4 complete: %d unique IPs (%d scannable, %d CDN/WAF/cloud skipped); "
             "%d subdomains total, %d behind scannable IPs",
             len(all_ips), len(scannable), len(cdn_map),
             len(all_domains), len(scannable_domains))
    return scannable


# ---------------------------------------------------------------------------
# Stage 5 — Port scan over UNIQUE IPs. Runs every configured scanner and UNIONs
# the results (a port open per ANY scanner counts), to minimise false negatives.
# Default scanner is rustscan; naabu is deprecated (unreliable in the field) but
# the code path is retained for opt-in via --port-scanners "rustscan,naabu".
# These ports are what Stage 6 (nmap) deep-scans, so a Stage-5 miss here is only
# recoverable via --nmap-full (full -p- re-scan).
# ---------------------------------------------------------------------------
def stage_port_scan(ctx: Context, ips: List[str]) -> Dict[str, List[int]]:
    _log_input("stage5/port_scan", "scannable IPs", ips, "stage4/cdn_filter")
    if not ips:
        return {}
    if not ctx.settings.port_scanners:
        # Intentional (e.g. --nmap-only): no fast scanner runs; nmap does its own
        # full -p- discovery in Stage 6. Not an error — just skip cleanly.
        log.info("Stage 5 skipped: no port scanners configured — nmap will do full "
                 "port discovery in Stage 6 (--nmap-only)")
        return {}

    port_map: Dict[str, Set[int]] = {}
    ran: List[str] = []
    for scanner in ctx.settings.port_scanners:
        if scanner == "naabu" and ctx.runner.available(config.TOOL_BINARIES["naabu"]):
            _scan_naabu(ctx, ips, port_map)
            ran.append("naabu")
        elif scanner == "rustscan" and ctx.runner.available(config.TOOL_BINARIES["rustscan"]):
            _scan_rustscan(ctx, ips, port_map)
            ran.append("rustscan")
        elif scanner == "masscan" and ctx.runner.available(config.TOOL_BINARIES["masscan"]):
            _scan_masscan(ctx, ips, port_map)
            ran.append("masscan")
        else:
            log.warning("port scanner '%s' not found on PATH — skipping it", scanner)

    if not ran:
        log.error("no port scanner available (%s) — skipping port scan",
                  ", ".join(ctx.settings.port_scanners))
        return {}

    # Single-threaded persist after the union (keeps SQLite off worker threads).
    result: Dict[str, List[int]] = {}
    for ip in sorted(port_map):
        ordered = sorted(port_map[ip])
        result[ip] = ordered
        for p in ordered:
            ctx.storage.add_port(ctx.run_id, ip, p)
    ctx.storage.commit()

    utils.dump_json(ctx.stage_file("05_ports.json"), result)
    log.info("Stage 5 complete: %d/%d IPs have open ports (%d total) via %s",
             len(result), len(ips), sum(len(v) for v in result.values()),
             "+".join(ran))
    return result


def _scan_naabu(ctx: Context, ips: List[str], port_map: Dict[str, Set[int]]) -> None:
    """naabu connect scan over the whole IP list in one invocation.

    -s c   : TCP connect scan (no root; same reachability httpx has)
    -Pn    : skip host discovery (CDN/cloud hosts ignore ICMP; without this
             naabu declares them down and scans nothing)
    -p -   : all 65535 ports (zero-false-negative default)
    """
    naabu_bin = ctx.runner.resolve_binary(config.TOOL_BINARIES["naabu"])
    infile = utils.write_lines(ctx.raw("naabu_input.txt"), sorted(ips))
    outfile = ctx.raw("naabu.jsonl")
    ctx.runner.run(
        [naabu_bin, "-l", str(infile), "-s", "c", "-Pn", "-p", "-",
         "-rate", str(ctx.settings.naabu_rate), "-c", str(ctx.settings.naabu_concurrency),
         "-json", "-silent", "-o", str(outfile)],
        timeout=config.TIMEOUTS["naabu"],
    )
    text = outfile.read_text(errors="ignore") if outfile.exists() else ""
    for rec in utils.read_jsonl(text):
        ip = utils.clean_host(utils.first(rec, "ip", "host", default=""))
        port = rec.get("port")
        if isinstance(port, dict):          # tolerate nested {"Port": 443} schema
            port = port.get("Port") or port.get("port")
        if ip and isinstance(port, int):
            port_map.setdefault(ip, set()).add(port)


def _scan_masscan(ctx: Context, ips: List[str], port_map: Dict[str, Set[int]]) -> None:
    """masscan stateless full-port scan over the WHOLE IP list in one invocation.

    masscan is async/stateless, so it scans every IP concurrently inside a single
    process — dramatically faster than nmap -p- (or per-IP rustscan) on a large set.
    It is the discovery half of the fast two-phase scan (--masscan-only): masscan
    finds the open ports, nmap then scans ONLY those ports (discovered mode).

    -iL       : read targets from a file (the whole scannable set)
    -p        : port range (default full 1-65535, mirroring nmap -p-)
    --rate    : packets/sec, a global budget (keep it under the link's capacity so
                probes are not dropped — dropped SYNs = missed ports = false negatives)
    --retries : retransmit each probe, so one dropped SYN-ACK is not a permanent miss
                (zero-FN lever; masscan's default 10s --wait also collects late replies)
    -oL       : grepable list output — robust to parse (masscan's -oJ can emit
                slightly malformed JSON, e.g. a trailing comma)

    Needs root for raw sockets. Warns and no-ops cleanly if run unprivileged, so an
    accidental non-sudo run does not silently report zero ports as if it scanned.
    """
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        log.warning("masscan needs root for raw sockets — without sudo it finds "
                    "nothing. Skipping masscan (run with sudo, or use rustscan).")
        return

    masscan_bin = ctx.runner.resolve_binary(config.TOOL_BINARIES["masscan"])
    infile = utils.write_lines(ctx.raw("masscan_input.txt"), sorted(ips))
    outfile = ctx.raw("masscan.txt")
    ctx.runner.run(
        [masscan_bin, "-iL", str(infile), "-p", ctx.settings.masscan_ports,
         "--rate", str(ctx.settings.masscan_rate),
         "--retries", str(ctx.settings.masscan_retries),
         "-oL", str(outfile)],
        timeout=config.TIMEOUTS["masscan"],
    )

    text = outfile.read_text(errors="ignore") if outfile.exists() else ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # -oL line format: "open tcp <port> <ip> <timestamp>"
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open" and parts[1] == "tcp":
            try:
                port = int(parts[2])
            except ValueError:
                continue
            ip = utils.clean_host(parts[3])
            if ip:
                port_map.setdefault(ip, set()).add(port)


def _scan_rustscan(ctx: Context, ips: List[str], port_map: Dict[str, Set[int]]) -> None:
    """rustscan (its own async scan) per IP, concurrently.

    Tuned for reliability on filtered / rate-limiting hosts (see config.Settings):
    --tries retransmits so a dropped SYN-ACK isn't a permanent miss, -t widens the
    timeout for high-latency hosts, and -b caps batch size so bursts don't trip
    the host's rate-limiter. rustscan is only the fast SIGNAL — nmap remains the
    authority — but a more complete signal means a more complete default scan.
    """
    rustscan_bin = ctx.runner.resolve_binary(config.TOOL_BINARIES["rustscan"])

    def scan_one(ip: str):
        rc, out, _ = ctx.runner.run(
            [rustscan_bin, "-a", ip,
             "--ulimit", str(ctx.settings.rustscan_ulimit),
             "-b", str(ctx.settings.rustscan_batch),
             "-t", str(ctx.settings.rustscan_timeout),
             "--tries", str(ctx.settings.rustscan_tries),
             "-g", "--scan-order", "random"],
            timeout=config.TIMEOUTS["rustscan"],
        )
        ctx.raw("rustscan", f"{ip}.txt").write_text(out, encoding="utf-8")
        return ip, _parse_rustscan(out)

    total = len(ips)
    with ThreadPoolExecutor(max_workers=ctx.settings.threads_portscan) as pool:
        futures = {pool.submit(scan_one, ip): ip for ip in ips}
        for done, fut in enumerate(as_completed(futures), 1):
            ip, ports = fut.result()
            for p in ports:
                port_map.setdefault(ip, set()).add(p)
            # -v progress: increments as each host finishes (verbose/DEBUG only).
            log.debug("Stage 5 progress: %d/%d scanned (%d left) — done: %s",
                      done, total, total - done, ip)


def _parse_rustscan(out: str) -> List[int]:
    """Parse rustscan greppable line: '1.2.3.4 -> [22,80,443]'."""
    ports: List[int] = []
    m = re.search(r"->\s*\[([0-9,\s]+)\]", out)
    if m:
        for tok in m.group(1).split(","):
            tok = tok.strip()
            if tok.isdigit():
                ports.append(int(tok))
    return sorted(set(ports))


# ---------------------------------------------------------------------------
# Pre-scan tarpit detection.
#
# Some LBs/WAFs (Google Cloud HTTPS LB, Incapsula) SYN-ACK on EVERY port.
# A full -p- scan on these reports 65K fake open ports and wastes hours.
# This precheck probes a small set of unlikely ports in ONE nmap invocation
# across ALL scannable IPs. Any IP with >= threshold probe ports open is a
# tarpit and gets scanned on a curated web-port set only.
# ---------------------------------------------------------------------------
def _tarpit_precheck(ctx: Context, ips: List[str],
                     nmap_bin: str) -> Set[str]:
    """Probe unlikely ports to detect tarpit IPs (LBs/WAFs that SYN-ACK every
    port). Returns the set of IPs confirmed as tarpits."""
    if not ctx.settings.tarpit_detection or not ips:
        return set()

    probe_ports = ",".join(str(p) for p in config.TARPIT_PROBE_PORTS)
    total_probes = len(config.TARPIT_PROBE_PORTS)
    threshold = ctx.settings.tarpit_threshold

    log.info("Tarpit precheck: probing %d ports on %d IPs (threshold: %d/%d)",
             total_probes, len(ips), threshold, total_probes)

    xml_path = ctx.raw("tarpit_precheck.xml")
    ctx.runner.run(
        [nmap_bin, "-Pn", "--min-rate", "10000", "-p", probe_ports,
         "-oX", str(xml_path), *sorted(ips)],
        timeout=config.TIMEOUTS["nmap"],
    )

    tarpit_ips: Set[str] = set()
    if not xml_path.exists():
        log.warning("Tarpit precheck: no XML output — skipping detection")
        return tarpit_ips

    try:
        root = ET.parse(str(xml_path)).getroot()
    except ET.ParseError:
        log.warning("Tarpit precheck: could not parse XML — skipping detection")
        return tarpit_ips

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        open_count = sum(
            1 for port in host.findall("./ports/port")
            if port.find("state") is not None
            and port.find("state").get("state") == "open"
        )
        if open_count >= threshold:
            tarpit_ips.add(ip)
            log.warning("Tarpit detected: %s — %d/%d probe ports open "
                        "(threshold %d). Will scan curated ports only.",
                        ip, open_count, total_probes, threshold)

    if tarpit_ips:
        log.info("Tarpit precheck: %d/%d IPs flagged as tarpits — these will "
                 "be scanned on ports [%s] instead of -p-",
                 len(tarpit_ips), len(ips), config.TARPIT_CURATED_PORTS)
    else:
        log.info("Tarpit precheck: no tarpits detected — all %d IPs get a "
                 "full scan", len(ips))

    utils.dump_json(ctx.stage_file("06_tarpit_precheck.json"), {
        "probe_ports": config.TARPIT_PROBE_PORTS,
        "threshold": threshold,
        "total_ips_checked": len(ips),
        "tarpit_ips": sorted(tarpit_ips),
        "curated_ports": config.TARPIT_CURATED_PORTS,
    })
    return tarpit_ips


# ---------------------------------------------------------------------------
# Stage 6 — nmap scan. Default: -Pn --min-rate 10000 -p- on ALL scannable IPs
# (fast full-port sweep, no rustscan dependency). Concurrent across IPs.
# ---------------------------------------------------------------------------
def stage_nmap(ctx: Context, scannable_ips: List[str],
               port_map: Dict[str, List[int]]) -> None:
    _log_input("stage6/nmap", "scannable IPs", scannable_ips, "stage4/cdn_filter")
    _log_input("stage6/nmap", "stage-5 port hits", port_map, "stage5/port_scan")
    if not ctx.settings.run_nmap:
        return
    nmap_bin = ctx.runner.resolve_binary(config.TOOL_BINARIES["nmap"])
    if not nmap_bin:
        log.error("nmap not found — skipping deep scan")
        return

    # Privilege check: without root, nmap can't open raw sockets, so it silently
    # downgrades to a TCP connect scan (-sT) which is markedly less reliable on
    # filtered / rate-limiting hosts (it dropped ~3 open ports vs a SYN scan in
    # testing). A SYN scan needs root. Warn once so the downgrade is never silent.
    if hasattr(os, "geteuid") and os.geteuid() != 0 \
            and "-sT" not in ctx.settings.nmap_flags:
        log.warning("not running as root — nmap will use a TCP connect scan (no raw "
                    "sockets), which misses ports on filtered hosts. Run with `sudo` "
                    "for a SYN scan (the reliable, zero-FN choice).")

    # Tarpit detection: probe unlikely ports to find LBs/WAFs that SYN-ACK
    # everything. Runs ONE nmap invocation across all IPs — finishes in seconds.
    tarpit_ips = _tarpit_precheck(ctx, scannable_ips, nmap_bin)
    curated_scope = ["-p", config.TARPIT_CURATED_PORTS]

    # Two scoping modes:
    #  * EXPLICIT  — --nmap-full (= -p-) or --nmap-ports "<scope>": that scope is
    #    applied to EVERY scannable IP (zero-false-negative when -p-, but slow —
    #    nmap re-scans the full range itself).
    #  * DISCOVERED (default, empty nmap_ports) — nmap version/script-scans ONLY
    #    the ports Stage 5 (rustscan) found on each IP, so it never re-scans all
    #    65535. IPs with no Stage-5 ports have nothing to enrich and are skipped.
    explicit_scope: List[str] = ["-p-"] if ctx.settings.nmap_full \
        else list(ctx.settings.nmap_ports)

    if explicit_scope:
        targets = sorted(scannable_ips) if ctx.settings.nmap_scan_all_scannable \
            else sorted(ip for ip in scannable_ips if port_map.get(ip))
        scope_desc = " ".join(explicit_scope)

        def ports_for(ip: str) -> List[str]:
            if ip in tarpit_ips:
                return curated_scope
            return explicit_scope
    else:
        # In discovered-ports mode, tarpit IPs still need to be scanned (on
        # curated ports) even if Stage 5 found nothing for them.
        discovered_targets = set(ip for ip in scannable_ips if port_map.get(ip))
        targets = sorted(discovered_targets | (tarpit_ips & set(scannable_ips)))
        scope_desc = "stage-5 discovered ports"

        def ports_for(ip: str) -> List[str]:
            if ip in tarpit_ips:
                return curated_scope
            return ["-p", ",".join(str(p) for p in sorted(port_map[ip]))]

        # Surface IPs we are NOT deep-scanning because Stage 5 found no ports —
        # so the skip is auditable and the analyst can force --nmap-full if wanted.
        no_ports = [ip for ip in scannable_ips
                    if not port_map.get(ip) and ip not in tarpit_ips]
        if no_ports:
            log.info("Stage 6: %d scannable IP(s) had no Stage-5 ports — nothing to "
                     "deep-scan (pass --nmap-full to force a full -p- scan): %s",
                     len(no_ports), ", ".join(sorted(no_ports)))

    if not targets:
        log.info("Stage 6: no nmap targets (port scope: %s)", scope_desc)
        return

    host_timeout = (["--host-timeout", ctx.settings.nmap_host_timeout]
                    if ctx.settings.nmap_host_timeout else [])

    def scan_one(ip: str):
        xml_path = ctx.raw("nmap", f"{ip}.xml")
        ctx.runner.run(
            [nmap_bin, *ctx.settings.nmap_flags, *ports_for(ip), *host_timeout,
             "-oX", str(xml_path), ip],
            timeout=config.TIMEOUTS["nmap"],
        )
        return ip, xml_path

    total = len(targets)
    with ThreadPoolExecutor(max_workers=ctx.settings.threads_nmap) as pool:
        futures = [pool.submit(scan_one, ip) for ip in targets]
        for done, fut in enumerate(as_completed(futures), 1):
            ip, xml_path = fut.result()
            _ingest_nmap_xml(ctx, ip, xml_path)
            # -v progress: increments as each host finishes (verbose/DEBUG only).
            log.debug("Stage 6 progress: %d/%d scanned (%d left) — done: %s",
                      done, total, total - done, ip)
    ctx.storage.commit()

    utils.dump_json(ctx.stage_file("06_nmap.json"),
                    {"scanned_hosts": len(targets),
                     "ips_with_ports": len(port_map),
                     "scannable_ips": len(scannable_ips),
                     "port_scope": scope_desc,
                     "tarpit_ips": sorted(tarpit_ips),
                     "tarpit_curated_ports": config.TARPIT_CURATED_PORTS
                     if tarpit_ips else None})
    log.info("Stage 6 complete: deep-scanned %d host(s) (port scope: %s)%s",
             len(targets), scope_desc,
             f" — {len(tarpit_ips)} tarpit(s) scanned on curated ports only"
             if tarpit_ips else "")


def _ingest_nmap_xml(ctx: Context, ip: str, xml_path: Path) -> None:
    if not xml_path.exists():
        return
    try:
        root = ET.parse(str(xml_path)).getroot()
    except ET.ParseError:
        log.warning("Could not parse nmap XML for %s", ip)
        return
    raw_ref = str(xml_path.relative_to(ctx.workdir))
    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            portid = int(port.get("portid", 0))
            proto = port.get("protocol", "tcp")
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc = port.find("service")
            service = svc.get("name") if svc is not None else None
            product = svc.get("product") if svc is not None else None
            version = svc.get("version") if svc is not None else None
            ctx.storage.add_port(ctx.run_id, ip, portid, service, product, version)
            for script in port.findall("script"):
                ctx.storage.add_nmap_finding(
                    ctx.run_id, ip, portid,
                    script.get("id", ""), (script.get("output") or "").strip(), raw_ref,
                )
        # host-level scripts (e.g. smb-os-discovery)
        for script in host.findall("./hostscript/script"):
            ctx.storage.add_nmap_finding(
                ctx.run_id, ip, None,
                script.get("id", ""), (script.get("output") or "").strip(), raw_ref,
            )
