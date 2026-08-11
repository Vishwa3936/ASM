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
#
# SUDO GOTCHA (this bit us in the field): the pipeline is usually run with
# `sudo` (for a SYN scan), but `sudo` resets PATH/HOME to root's. Go tools
# (cdncheck, dnsx, httpx, naabu) install to the invoking user's ~/go/bin, which
# is NOT on root's PATH — so `cdncheck` silently becomes "not found" and Stage 4
# degrades to the static net, letting WAF/CDN edges (e.g. Incapsula tarpits) get
# scanned. To prevent that, every tool's candidate list also probes ~/go/bin
# (for both the current HOME and $SUDO_USER's home) and /usr/local/bin.
# ---------------------------------------------------------------------------
def _sudo_aware_homes() -> List[str]:
    """Home dirs to probe for user-installed tools. Under `sudo`, HOME is /root
    but the tools were installed as the invoking user, so also probe $SUDO_USER's
    home. Order: current HOME first, then the sudo-invoking user."""
    homes: List[str] = []
    home = os.environ.get("HOME")
    if home:
        homes.append(home)
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            homes.append(os.path.expanduser("~" + sudo_user))
        except Exception:
            pass
    seen: set = set()
    return [h for h in homes if not (h in seen or seen.add(h))]


def _tool_paths(path_names: List[str], binname: Optional[str] = None) -> List[str]:
    """Candidate list for a tool: PATH names first, then common install locations
    (~/go/bin — including the sudo user's — and /usr/local/bin). Absolute
    candidates that do not exist are simply skipped by the runner's resolver."""
    binname = binname or path_names[0]
    cands = list(path_names)
    for h in _sudo_aware_homes():
        cands.append(os.path.join(h, "go", "bin", binname))
    cands.append(os.path.join("/usr/local/bin", binname))
    seen: set = set()
    return [c for c in cands if not (c in seen or seen.add(c))]


def _subdominator_paths() -> List[str]:
    """subdominator (RevoltSecurities) lives in a venv bin outside PATH; probe the
    known install path under the current HOME and the sudo user's home. Override
    per-run with --subdominator-bin <path>."""
    cands = ["subdominator"]
    for h in _sudo_aware_homes():
        cands.append(os.path.join(h, "Tools", "Subdominator", "sub", "bin", "subdominator"))
    seen: set = set()
    return [c for c in cands if not (c in seen or seen.add(c))]


TOOL_BINARIES = {
    "findomain": _tool_paths(["findomain"]),
    "subdominator": _subdominator_paths(),
    "dnsx": _tool_paths(["dnsx"]),
    "httpx": _tool_paths(["httpx-toolkit", "httpx"], binname="httpx"),
    "cdncheck": _tool_paths(["cdncheck"]),
    "naabu": _tool_paths(["naabu"]),
    "rustscan": _tool_paths(["rustscan"]),
    "masscan": _tool_paths(["masscan"]),
    "nmap": _tool_paths(["nmap"]),
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
    "masscan": 1800,   # whole list (stateless, one invocation)
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

# Genuine shared WAF-EDGE providers. Used to (a) SKIP their IPs like any other
# shared edge (the origin is hidden behind them) and (b) LABEL skipped edges as
# WAF vs CDN in stages/04_waf_cdn.json. Membership here does NOT change the zero-FN
# rule: a cloud-origin / unknown-provider IP that cdncheck merely TAGS as "waf" is
# still SCANNED, because an on-prem origin sitting behind a WAF is real surface
# (this is the grafana/jenkins-on-Google-LB false negative we must not reintroduce).
# NOTE: cdncheck is range-based, so it only catches CLOUD/SHARED WAF edges — an
# on-prem F5 BIG-IP ASM on the org's own IP is invisible to it (use wafw00f).
WAF_EDGE_PROVIDERS = frozenset({
    "imperva", "incapsula", "imperva incapsula", "sucuri", "barracuda",
    "radware", "fortiweb", "fortinet", "f5", "f5 silverline", "silverline",
    "citrix", "netscaler", "wallarm", "reblaze", "signal sciences", "sqreen",
})
# NOTE: dual providers that are BOTH a CDN and a WAF (Cloudflare, Akamai) are NOT
# listed here — they live in CDN_EDGE_PROVIDERS and are labelled WAF only when
# cdncheck actually flags that specific IP as waf, so pure-CDN Cloudflare IPs are
# not all mislabelled as WAF.

# ---------------------------------------------------------------------------
# Tarpit detection (pre-scan, Stage 6).
#
# Some load balancers / WAF edges (Google Cloud HTTPS LB, Incapsula) SYN-ACK on
# EVERY port — a tarpit. A naive -p- scan reports 65K "open" ports per IP,
# drowning the real surface in noise and wasting hours of nmap time. The tarpit
# precheck probes a small set of unlikely ports BEFORE the full scan; if nearly
# all respond open, the IP is flagged and scanned on a curated web-port set only.
#
# This is behaviour-based (port-count anomaly), NOT provider-based, so it catches
# any tarpit regardless of vendor — future-proof and zero false-negative risk
# (no legitimate server has 15+ of these random ports open).
# ---------------------------------------------------------------------------
TARPIT_PROBE_PORTS: List[int] = [
    7, 19, 79, 311, 1137, 2345, 3827, 5555, 7291, 9999,
    12345, 17834, 23456, 29173, 34567, 39821, 44444, 49999, 54321, 63210,
]
TARPIT_CURATED_PORTS: str = "80,443,8080,8443,8000,8888"

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

    # masscan: stateless full-port discovery for LARGE IP sets. Unlike rustscan
    # (per-IP) and nmap -p- (slow, per-IP), masscan async-scans the WHOLE list in a
    # single process, so 100+ IPs finish in minutes. Needs root (raw sockets). It is
    # the discovery half of the fast two-phase scan (--masscan-only): masscan finds
    # the open ports, nmap then scans ONLY those ports (discovered mode) instead of
    # re-running -p- itself — the big time saver. Completeness (zero-FN) rests on
    # retries + masscan's default 10s --wait: a dropped SYN-ACK is retransmitted and
    # late responses are still collected, so the trusted port set stays complete.
    masscan_rate: int = 10000        # packets/sec (global). Raise on fast, low-loss links
    masscan_retries: int = 3         # retransmits per port — completeness vs speed (zero-FN)
    masscan_ports: str = "1-65535"   # full range by default (mirrors nmap -p-)

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

    # Tarpit detection. A pre-scan probe on TARPIT_PROBE_PORTS (20 unlikely
    # ports); if >= tarpit_threshold respond open, the IP is a tarpit (LB/WAF
    # that SYN-ACKs every port). Tarpits are scanned on TARPIT_CURATED_PORTS
    # only, saving hours of nmap time and eliminating tens of thousands of fake
    # open-port entries. Behaviour-based — works regardless of provider.
    tarpit_detection: bool = True
    tarpit_threshold: int = 15           # out of 20 probe ports
