"""Small pure helpers: scope checks, IP validation, file I/O, JSONL parsing."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List


def in_scope(name: str, root_domain: str) -> bool:
    """True if `name` is the root domain or a subdomain of it."""
    name = name.strip().lower().rstrip(".")
    root = root_domain.strip().lower().rstrip(".")
    return name == root or name.endswith("." + root)


def is_public_ip(ip: str) -> bool:
    """True for globally-routable addresses (excludes RFC1918/loopback/etc.)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def clean_host(value: str) -> str:
    """Normalise a hostname: strip scheme, port, path, whitespace, trailing dot."""
    value = value.strip().lower()
    value = re.sub(r"^[a-z]+://", "", value)
    value = value.split("/")[0].split(":")[0]
    return value.rstrip(".")


def write_lines(path: Path, lines: Iterable[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return path


def read_jsonl(text: str) -> Iterator[Dict[str, Any]]:
    """Yield parsed objects from JSON-lines text, skipping malformed lines."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def dump_json(path: Path, obj: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    return path


def first(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Return the first present, truthy key from a dict (tolerates tool schema drift)."""
    for k in keys:
        if k in d and d[k]:
            return d[k]
    return default


# ---------------------------------------------------------------------------
# Deterministic CDN safety net.
#
# cdncheck is the primary CDN/WAF/cloud classifier, but its provider ranges can
# be stale or its JSON schema can drift between versions — either failure marks
# a real CDN edge as a scannable "origin" (false positive) and hides the true
# origin behind it (false negative). These published, stable anycast ranges are
# a backstop: they only ADD detections cdncheck missed, never remove any. Kept
# intentionally small (the big always-CDN providers). Source of truth remains
# cdncheck; run `cdncheck -update` to refresh its data.
# ---------------------------------------------------------------------------
_STATIC_CDN_RANGES: Dict[str, List[str]] = {
    "cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
    "fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
        "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
        "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18",
        "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
    ],
    # Akamai is pure CDN (never a customer origin) so blanket-flagging is safe.
    # NOTE: deliberately NO Google/AWS blocks here — those ranges overlap real
    # GCP/EC2 origins, and flagging them would DROP live assets (false negative).
    # Cloud classification is left to cdncheck, which distinguishes edge vs origin.
    "akamai": [
        "23.32.0.0/11", "23.192.0.0/11", "2.16.0.0/13", "104.64.0.0/10",
        "184.24.0.0/13", "184.50.0.0/15", "88.221.0.0/16", "96.16.0.0/15",
        "96.6.0.0/15", "95.100.0.0/15", "92.122.0.0/15", "72.246.0.0/15",
        "173.222.0.0/15", "118.214.0.0/16", "69.192.0.0/16",
    ],
    # Imperva Incapsula — a shared WAF edge (a reverse proxy; customers point DNS
    # at it and never host origins on its IPs), so blanket-flagging is safe like
    # Akamai. These published, stable ranges are the backstop that catches
    # Incapsula's port-spoofing tarpits (it SYN-ACKs EVERY port → thousands of
    # fake "open" ports) when cdncheck is unavailable. Labelled WAF in Stage 4.
    "incapsula": [
        "45.60.0.0/16", "45.223.0.0/16", "45.64.64.0/22", "107.154.0.0/16",
        "149.126.72.0/21", "185.11.124.0/22", "192.230.64.0/18",
        "198.143.32.0/19", "199.83.128.0/21", "203.28.246.0/24",
    ],
}

_STATIC_CDN_NETS: List[Any] = []  # lazily compiled [(name, ip_network), ...]


def static_cdn_name(ip: str) -> Any:
    """Return the provider name if `ip` falls in a known static CDN range, else None."""
    global _STATIC_CDN_NETS
    if not _STATIC_CDN_NETS:
        _STATIC_CDN_NETS = [
            (name, ipaddress.ip_network(cidr))
            for name, cidrs in _STATIC_CDN_RANGES.items()
            for cidr in cidrs
        ]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, net in _STATIC_CDN_NETS:
        if addr in net:
            return name
    return None
