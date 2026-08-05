"""Central configuration for the NewASM pipeline.

Everything tunable lives here so you can adjust behaviour without touching the
stage logic. CLI flags in asm.py override the relevant values at runtime.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# External tool binary names.
# For httpx we prefer Kali's `httpx-toolkit` (ProjectDiscovery httpx) so we do
# NOT collide with the Python `httpx` HTTP client that ships under the same
# name in many distros. The runner tries each candidate in order.
# ---------------------------------------------------------------------------
TOOL_BINARIES = {
    "findomain": ["findomain"],
    # subdominator (RevoltSecurities) usually lives in a venv bin outside PATH —
    # try PATH first, then the common install location. Override per-run with
    # --subdominator-bin <path>.
    "subdominator": ["subdominator",
                     os.path.expanduser("~/Tools/Subdominator/sub/bin/subdominator")],
    "dnsx": ["dnsx"],
    "httpx": ["httpx-toolkit", "httpx"],
    "cdncheck": ["cdncheck"],
    "naabu": ["naabu"],
    "rustscan": ["rustscan"],
    "nmap": ["nmap"],
}

# Per-invocation subprocess timeouts (seconds). Port/host tools are per-target,
# except naabu which scans the whole IP list in one invocation.
TIMEOUTS = {
    "findomain": 600,
    "subdominator": 600,
    "dnsx": 900,
    "httpx": 900,
    "cdncheck": 300,
    "naabu": 1800,     # whole list
    "rustscan": 900,   # per IP
    "nmap": 1800,      # per IP
}

# ---------------------------------------------------------------------------
# CDN/cloud classification allow/deny sets (Stage 4).
#
# cdncheck returns a (category, provider) for each flagged IP, but its category
# is unreliable for cloud load balancers: Google Cloud HTTPS LB, some AWS ALB and
# Azure ranges are tagged category "cdn"/"waf" even though the IP is the ORG'S OWN
# edge serving their apps (e.g. grafana/jenkins on a Google LB IP). Skipping those
# is a false negative. So Stage 4 decides keep-vs-skip by PROVIDER NAME:
#
#   * CDN_EDGE_PROVIDERS  -> genuine shared third-party CDN/WAF edges. The origin
#     is hidden behind them and scanning the edge is pointless + ban-risky. SKIP.
#   * CLOUD_ORIGIN_PROVIDERS -> cloud/hosting providers. The flagged IP is the
#     customer's own load balancer / instance = real surface. KEEP (scannable),
#     unless --no-cloud.
#   * anything else cdncheck flags -> unrecognised: FAIL OPEN and scan it, so a
#     mislabelled origin is never silently dropped (zero-false-negative mandate).
#
# Names are compared lower-cased. Add to CDN_EDGE_PROVIDERS (not the other set) if
# a new provider should be excluded — that keeps the default biased toward scanning.
CDN_EDGE_PROVIDERS = frozenset({
    "cloudflare", "cloudfront", "fastly", "akamai", "akamaitechnologies",
    "incapsula", "imperva", "sucuri", "stackpath", "cachefly", "keycdn",
    "maxcdn", "edgecast", "verizon", "verizondigitalmedia", "limelight",
    "cdn77", "bunny", "bunnycdn", "gcore", "g-core", "azion", "medianova",
    "quantil", "cdnetworks", "section", "cloudflarewarp", "cloudflarespectrum",
})
CLOUD_ORIGIN_PROVIDERS = frozenset({
    "google", "googlecloud", "gcp", "google cloud", "googleusercontent",
    "amazon", "aws", "ec2", "amazonaws", "amazon web services",
    "azure", "microsoft", "microsoftazure", "windowsazure",
    "oracle", "oraclecloud", "ibm", "ibmcloud",
    "digitalocean", "linode", "vultr", "hetzner", "ovh", "scaleway",
    "alibaba", "alicloud", "aliyun", "tencent", "tencentcloud",
})

# httpx-toolkit (ProjectDiscovery httpx) flags for Stage 3. Beyond the core
# status/title/tech-detect, we harvest the connected IP, CNAME, httpx's OWN CDN
# detection (a second signal alongside cdncheck), content type/length, redirect
# location, favicon mmh3 hash (asset fingerprint / Shodan pivot), JARM TLS
# fingerprint (server/WAF/LB identity), ASN (ownership), and response time.
# NOTE: an unknown flag makes httpx abort the whole run — trim here if an older
# httpx build rejects one (favicon/jarm/asn are the newest).
HTTPX_FLAGS = [
    "-json", "-status-code", "-title", "-tech-detect", "-web-server",
    "-ip", "-cname", "-cdn", "-content-type", "-content-length",
    "-location", "-favicon", "-jarm", "-asn", "-response-time",
    "-follow-redirects", "-silent",
]


@dataclass
class Settings:
    """Runtime knobs (populated from CLI defaults, overridable per run)."""

    # Concurrency
    threads_portscan: int = 8      # rustscan is fast → higher fan-out
    threads_nmap: int = 3          # nmap -A is slow/loud → keep low

    # Port scanners to run, in order. If more than one is listed, results are
    # UNIONed (a port found by ANY scanner counts) to minimise false negatives.
    # Each is skipped if not on PATH.
    # NOTE: naabu is DEPRECATED — it produced unreliable results in the field, so
    # it is no longer in the default set. The code path is kept (opt back in with
    # --port-scanners "rustscan,naabu") until a replacement scanner is chosen.
    port_scanners: List[str] = field(default_factory=lambda: ["rustscan"])

    # naabu (deprecated, not run by default): connect scan (-s c, no root),
    # host-discovery skipped (-Pn). Knobs retained for the opt-in path.
    naabu_rate: int = 1000          # packets/sec
    naabu_concurrency: int = 25     # naabu -c workers

    # rustscan tuning. Defaults are hardened for reliability on filtered / high-
    # latency hosts (Google LB & co. drop closed ports and rate-limit, so an
    # aggressive single-try burst loses the open-port SYN-ACKs → false negatives):
    #   tries   : retransmit, so one dropped SYN-ACK is not a permanent miss
    #   timeout : wait long enough for slow (0.5s+) hosts to answer (milliseconds)
    #   batch   : smaller, less-bursty batches trip host rate-limiting less often
    # These trade speed for completeness. In the default mode rustscan is the FAST
    # signal feeding nmap, so accuracy here directly shrinks nmap's blind spots.
    rustscan_ulimit: int = 5000
    rustscan_tries: int = 2
    rustscan_timeout: int = 2500   # ms
    rustscan_batch: int = 1000

    # nmap default flags. -Pn skips host discovery (CDN/cloud hosts drop ICMP;
    # without -Pn nmap marks them "down" and scans NOTHING — a silent false
    # negative). --min-rate 10000 paces the scan fast enough that a full-port sweep
    # across EVERY scannable IP finishes quickly. No -sT: nmap auto-selects SYN
    # (as root — faster) or connect (unprivileged).
    # NOTE: these flags do NOT do version/service detection or run NSE scripts —
    # add -sV (or -A) to get service/product/version + script findings (slower).
    # A high --min-rate trades some accuracy for speed on lossy links; rustscan
    # (Stage 5) is unioned in as a cross-check.
    nmap_flags: List[str] = field(default_factory=lambda: ["-Pn", "--min-rate", "10000"])

    # Behaviour toggles
    use_subdominator: bool = True
    subdominator_bin: Optional[str] = None   # explicit binary path (else PATH/known loc)
    run_nmap: bool = True
    run_httpx: bool = True
    # dnsx wildcard filtering (-wd). OFF by default: it nukes every subdomain of
    # a wildcard-DNS / CDN-fronted domain (e.g. Cloudflare), dropping real assets.
    # Turn ON only when brute-forcing, to strip wildcard false-positives.
    wildcard_filter: bool = False
    allow_private_ips: bool = False   # skip RFC1918/loopback targets by default
    scan_cloud_ips: bool = True       # AWS/GCP origins are real surface; keep them
    dry_run: bool = False

    # cdncheck: primary CDN/WAF/cloud classifier. When False, the static safety
    # net (utils._STATIC_CDN_RANGES: Cloudflare/Fastly/Akamai) is the SOLE
    # classifier — fine for testing, but weaker: CDNs outside that list get
    # scanned as origins (false positives). Keep True for org runs.
    use_cdncheck: bool = True
    # cdncheck: refresh provider IP ranges before classifying. Stale data is a
    # major false-positive source (real CDN edges scanned as if they were origins).
    cdncheck_update: bool = True

    # httpx-reachability cross-check (Stage 4). If httpx completed an HTTP(S)
    # handshake to a host, its IP is provably reachable/open — force it back to
    # scannable even if cdncheck classified it as something to skip. Only ever ADDS
    # hosts (never removes), so it cannot cause a false negative. Genuine CDN edges
    # stay skipped unless scan_reachable_cdn is set (scanning an edge returns the
    # edge's ports, not the hidden origin's = a false positive + ban risk).
    httpx_rescue: bool = True
    scan_reachable_cdn: bool = False

    # nmap authority (zero-false-negative). rustscan is a lossy fast scanner; if
    # it gates nmap, every rustscan miss becomes a permanent, invisible false
    # negative. With this True, nmap runs on EVERY non-CDN IP, using rustscan only
    # as an early signal — not as the set of hosts worth deep-scanning.
    nmap_scan_all_scannable: bool = True
    # Port scope for the nmap scan, applied to EVERY scannable IP.
    # DEFAULT ["-p-"] = all 65535 ports on ALL scannable IPs (zero-false-negative,
    # kept fast by --min-rate in nmap_flags). Use ["--top-ports","1000"] to trade
    # completeness for speed, or set to [] (via --nmap-ports "") for "discovered-
    # ports mode" — nmap then scans ONLY the ports Stage 5 found, on the hit IPs.
    nmap_ports: List[str] = field(default_factory=lambda: ["-p-"])
    # Zero-false-negative escape hatch: scan ALL 65535 ports (-p-) on every
    # scannable IP, independent of what Stage 5 found (slow). Set via --nmap-full;
    # overrides nmap_ports.
    nmap_full: bool = False
    # Per-host wall-clock cap passed to nmap as --host-timeout (e.g. "20m").
    # Empty/None = no cap. A single filtered or tarpitting host scanning a wide
    # port range can otherwise hold a worker slot until the whole-run subprocess
    # timeout; this bounds it so the batch keeps moving (the IP is logged partial).
    nmap_host_timeout: Optional[str] = None
