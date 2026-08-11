#!/usr/bin/env python3
"""
NewASM — staged external Attack Surface Management recon pipeline.

Purpose       : Automate subdomain -> DNS -> HTTP -> CDN-filter -> port ->
                deep-scan recon against an authorized target, storing every
                stage to SQLite + JSON for querying and diffing.
Usage context : Authorized VAPT / red-team recon on in-scope assets only.
Run on        : Kali Linux (findomain, subdominator, dnsx, httpx-toolkit, cdncheck,
                rustscan, nmap must be on PATH).

Examples:
    python3 asm.py -d example.com
    python3 asm.py -d example.com --no-subdominator --threads-portscan 12
    python3 asm.py -d example.com --no-nmap -o /home/kali/asm-runs
    python3 asm.py -d example.com --nmap-flags "-sS -A"   # -sS needs root
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Ensure the package is importable when run as `python3 asm.py` from this dir.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from asmtool import __version__, config  # noqa: E402
from asmtool.pipeline import Pipeline  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="asm.py",
        description="Staged Attack Surface Management recon pipeline.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--domain", required=True, help="Root domain (in-scope) to enumerate")
    p.add_argument("-o", "--output", default="output", help="Output root directory")

    p.add_argument("--no-subdominator", action="store_true",
                   help="Skip subdominator (findomain only)")
    p.add_argument("--subdominator-bin", default=None,
                   help="Path to the subdominator binary (if not on PATH)")
    p.add_argument("--no-httpx", action="store_true", help="Skip HTTP probing stage")
    p.add_argument("--no-nmap", action="store_true", help="Skip nmap deep scan (rustscan only)")

    p.add_argument("--threads", type=int, default=None,
                   help="Global scan concurrency — sets BOTH --threads-portscan and "
                        "--threads-nmap at once (the per-tool flags below override it). "
                        "NOTE: masscan is a single async process tuned by --masscan-rate, "
                        "not threads. Raising nmap concurrency too high multiplies the "
                        "aggregate packet rate → dropped probes → missed ports, so match "
                        "it to your LINK, not your CPU")
    p.add_argument("--threads-portscan", type=int, default=None,
                   help=f"Concurrent rustscan workers (default: {config.Settings.threads_portscan})")
    p.add_argument("--threads-nmap", type=int, default=None,
                   help=f"Concurrent nmap workers — keep low, -p-/-A is heavy "
                        f"(default: {config.Settings.threads_nmap})")
    p.add_argument("--rustscan-ulimit", type=int, default=config.Settings.rustscan_ulimit,
                   help="rustscan --ulimit (raise for faster scans)")
    p.add_argument("--rustscan-tries", type=int, default=config.Settings.rustscan_tries,
                   help="rustscan --tries (retransmits; higher = fewer missed ports on "
                        "lossy / filtered / high-latency hosts)")
    p.add_argument("--rustscan-timeout", type=int, default=config.Settings.rustscan_timeout,
                   help="rustscan -t timeout in ms (raise for slow / high-latency hosts)")
    p.add_argument("--rustscan-batch", type=int, default=config.Settings.rustscan_batch,
                   help="rustscan -b batch size (lower = less bursty = fewer dropped SYN-ACKs)")
    p.add_argument("--port-scanners", default="rustscan",
                   help="Comma list of port scanners to run and UNION (e.g. 'rustscan' "
                        "or 'rustscan,naabu'). Missing tools are skipped. naabu is "
                        "DEPRECATED and no longer in the default set")
    p.add_argument("--no-naabu", action="store_true",
                   help="[DEPRECATED — naabu is no longer run by default] drop naabu "
                        "from --port-scanners if it was added back")
    p.add_argument("--no-rustscan", action="store_true",
                   help="Skip the rustscan port scan (drop it from --port-scanners)")
    p.add_argument("--masscan", action="store_true",
                   help="Add masscan to the Stage-5 port scanners (UNIONed with "
                        "rustscan). Stateless full-port scan of the whole IP set in one "
                        "process — fast on large sets. Needs sudo (raw sockets)")
    p.add_argument("--masscan-only", action="store_true",
                   help="Fast two-phase scan for large IP sets: masscan is the SOLE "
                        "discovery scanner (rustscan skipped) and nmap scans ONLY the "
                        "ports masscan found (not -p-), cutting nmap time sharply. Needs "
                        "sudo. Trusts masscan's port set (its --retries/--wait mitigate "
                        "misses); add -sV via --nmap-flags for version detection, or "
                        "--nmap-full to force a zero-FN -p- sweep instead")
    p.add_argument("--masscan-rate", type=int, default=config.Settings.masscan_rate,
                   help="masscan --rate packets/sec (raise on fast, low-loss links; too "
                        "high drops probes = missed ports)")
    p.add_argument("--masscan-retries", type=int, default=config.Settings.masscan_retries,
                   help="masscan --retries (retransmits; higher = fewer missed ports on "
                        "lossy / filtered hosts)")
    p.add_argument("--naabu-rate", type=int, default=config.Settings.naabu_rate,
                   help="naabu packets/sec")
    p.add_argument("--nmap-flags", default="-Pn --min-rate 10000",
                   help="nmap flags (quoted). Default '-Pn --min-rate 10000': -Pn keeps "
                        "ICMP-silent hosts in scope, --min-rate paces a fast sweep. Add "
                        "-sV or -A for service/version + NSE detection (slower)")
    p.add_argument("--nmap-ports", default="-p-",
                   help="nmap port scope applied to EVERY scannable IP (default '-p-' = "
                        "all 65535; '--top-ports 1000' for speed). Pass '' (empty) for "
                        "discovered-ports mode: only the ports Stage 5 found, hit IPs only")
    p.add_argument("--nmap-full", action="store_true",
                   help="Zero-false-negative mode: nmap scans ALL 65535 ports (-p-) on "
                        "every scannable IP, ignoring Stage 5 (slow). Overrides --nmap-ports")
    p.add_argument("--nmap-only", action="store_true",
                   help="Skip rustscan (Stage 5) entirely and let nmap do all port "
                        "discovery itself: -p- on every scannable IP. Most reliable, "
                        "slowest; uses the default '-Pn --min-rate 10000' — run with sudo "
                        "for a SYN scan. Overrides --port-scanners and forces -p-")
    p.add_argument("--nmap-host-timeout", default="",
                   help="nmap --host-timeout per IP (e.g. '20m'): caps a single stuck/"
                        "tarpitting host so the batch keeps moving. Empty = no cap")
    p.add_argument("--nmap-only-rustscan-hits", action="store_true",
                   help="With an explicit --nmap-ports/--nmap-full, restrict nmap to IPs "
                        "where Stage 5 found ports (the default discovered mode already does this)")
    p.add_argument("--no-httpx-rescue", action="store_true",
                   help="Disable the httpx-reachability cross-check (by default, any IP "
                        "httpx proved reachable is force-kept scannable even if cdncheck "
                        "flagged it — a zero-FN backstop that only ever adds hosts)")
    p.add_argument("--scan-reachable-cdn", action="store_true",
                   help="Extend httpx-rescue to genuine CDN edges too: scan any reachable "
                        "IP even if it's Cloudflare/CloudFront/etc. (max zero-FN; note this "
                        "scans the edge, not the hidden origin — noisy + ban risk)")
    p.add_argument("--no-cdncheck", action="store_true",
                   help="Skip cdncheck entirely; use only the built-in static CDN "
                        "safety net (Cloudflare/Fastly/Akamai) to filter edges")
    p.add_argument("--no-cdncheck-update", action="store_true",
                   help="Skip 'cdncheck -update' (reuse existing provider range data)")

    p.add_argument("--no-tarpit-detection", action="store_true",
                   help="Disable pre-scan tarpit detection (by default, IPs that "
                        "SYN-ACK on nearly every probe port are flagged as tarpits "
                        "and scanned on curated web ports only, saving hours of "
                        "nmap time and eliminating tens of thousands of fake ports)")
    p.add_argument("--tarpit-threshold", type=int,
                   default=config.Settings.tarpit_threshold,
                   help="Tarpit detection: minimum probe ports (out of "
                        f"{len(config.TARPIT_PROBE_PORTS)}) that must be open to "
                        "flag an IP as a tarpit")

    p.add_argument("--wildcard-filter", action="store_true",
                   help="Enable dnsx wildcard filtering (-wd). Only for brute-force "
                        "enum; drops real subdomains on CDN/wildcard domains")
    p.add_argument("--allow-private-ips", action="store_true",
                   help="Also scan RFC1918/loopback targets (internal engagements)")
    p.add_argument("--no-cloud", action="store_true",
                   help="Also skip cloud (AWS/GCP) IPs, not just CDN/WAF edges")

    p.add_argument("--dry-run", action="store_true", help="Log commands without executing")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    p.add_argument("--version", action="version", version=f"NewASM {__version__}")
    return p


def _resolve_port_scanners(args: argparse.Namespace) -> list:
    """Build the port-scanner list from --port-scanners, minus any --no-<scanner>."""
    # --masscan-only: masscan is the SOLE Stage-5 scanner (rustscan/naabu dropped).
    if args.masscan_only:
        return ["masscan"]
    scanners = [s.strip() for s in args.port_scanners.split(",") if s.strip()]
    if args.no_naabu:
        scanners = [s for s in scanners if s != "naabu"]
    if args.no_rustscan:
        scanners = [s for s in scanners if s != "rustscan"]
    # --masscan: add masscan alongside the others (results are UNIONed downstream).
    if args.masscan and "masscan" not in scanners:
        scanners.append("masscan")
    return scanners


def configure_logging(workdir: Path, verbose: bool) -> None:
    workdir.mkdir(parents=True, exist_ok=True)
    handlers = [logging.StreamHandler(sys.stdout),
                logging.FileHandler(workdir / "asm.log", encoding="utf-8")]
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )


def main() -> int:
    args = build_parser().parse_args()

    # --masscan-only is the fast two-phase scan: nmap scans ONLY the ports masscan
    # discovered (discovered mode = empty nmap_ports) instead of re-running -p-
    # itself. Honour an explicit --nmap-full (zero-FN -p-) as an override, and don't
    # touch a caller-supplied --nmap-ports value.
    nmap_ports_arg = args.nmap_ports
    if args.masscan_only and not args.nmap_full and args.nmap_ports == "-p-":
        nmap_ports_arg = ""

    # --threads is a convenience that sets both scan-concurrency knobs at once; an
    # explicit per-tool --threads-portscan / --threads-nmap still overrides it.
    threads_portscan = (args.threads_portscan if args.threads_portscan is not None
                        else args.threads if args.threads is not None
                        else config.Settings.threads_portscan)
    threads_nmap = (args.threads_nmap if args.threads_nmap is not None
                    else args.threads if args.threads is not None
                    else config.Settings.threads_nmap)

    settings = config.Settings(
        threads_portscan=threads_portscan,
        threads_nmap=threads_nmap,
        rustscan_ulimit=args.rustscan_ulimit,
        rustscan_tries=args.rustscan_tries,
        rustscan_timeout=args.rustscan_timeout,
        rustscan_batch=args.rustscan_batch,
        masscan_rate=args.masscan_rate,
        masscan_retries=args.masscan_retries,
        # --nmap-only skips rustscan (empty scanner list) and forces nmap's own
        # full -p- discovery across every scannable IP.
        port_scanners=([] if args.nmap_only else _resolve_port_scanners(args)),
        naabu_rate=args.naabu_rate,
        nmap_flags=args.nmap_flags.split(),
        nmap_ports=nmap_ports_arg.split(),
        nmap_full=(args.nmap_full or args.nmap_only),
        nmap_host_timeout=(args.nmap_host_timeout or None),
        nmap_scan_all_scannable=not args.nmap_only_rustscan_hits,
        use_subdominator=not args.no_subdominator,
        subdominator_bin=(str(Path(args.subdominator_bin).expanduser())
                          if args.subdominator_bin else None),
        run_nmap=not args.no_nmap,
        run_httpx=not args.no_httpx,
        wildcard_filter=args.wildcard_filter,
        allow_private_ips=args.allow_private_ips,
        scan_cloud_ips=not args.no_cloud,
        use_cdncheck=not args.no_cdncheck,
        cdncheck_update=not args.no_cdncheck_update,
        httpx_rescue=not args.no_httpx_rescue,
        scan_reachable_cdn=args.scan_reachable_cdn,
        tarpit_detection=not args.no_tarpit_detection,
        tarpit_threshold=args.tarpit_threshold,
        dry_run=args.dry_run,
    )

    pipeline = Pipeline(args.domain.strip().lower(), Path(args.output), settings)
    configure_logging(pipeline.workdir, args.verbose)

    log = logging.getLogger("asm")
    log.info("NewASM %s starting for '%s'", __version__, args.domain)
    log.info("Output: %s", pipeline.workdir)
    if settings.threads_nmap > 10:
        log.warning("threads-nmap=%d is high — that many concurrent nmap scans, each at "
                    "--min-rate, can saturate the link and drop probes (missed ports = "
                    "false negatives). Match scan concurrency to bandwidth, not CPU.",
                    settings.threads_nmap)

    report = pipeline.run()

    print("\n" + "=" * 60)
    print(f"  Done. Markdown: {report}")
    print(f"  JSON report:    {report.with_name('report.json')}")
    print(f"  Database:       {pipeline.workdir / 'asm.db'}")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
