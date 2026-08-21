#!/usr/bin/env python3
"""
Filter alive URLs down to those with NO known WAF — the minimal set
worth passing to wafw00f.

Logic:
  alive URLs (Stage 3)
    minus URLs behind CDN/WAF edges (Stage 4 skipped IPs)
    minus URLs where httpx already identified a WAF/CDN (cdn_name set)
    = URLs on scannable IPs with no known WAF
    → stages/04_waf_unknown_urls.txt

Usage:
  python3 waf_filter.py -r output/domain_20260816_120000
  wafw00f -i output/domain_20260816_120000/stages/04_waf_unknown_urls.txt -o waf.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Optional, Set


def read_alive_urls(run_dir: Path) -> list[str]:
    path = run_dir / "stages" / "03_alive_urls.txt"
    if not path.exists():
        raise FileNotFoundError(f"Missing {path} — run the ASM pipeline first")
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_skipped_ips(run_dir: Path) -> Set[str]:
    path = run_dir / "stages" / "04_cdn_skipped.json"
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    return {entry["ip"] for entry in data.get("skipped", []) if entry.get("ip")}


def read_httpx_records(run_dir: Path) -> Dict[str, dict]:
    """Parse httpx JSONL → {url: {ip, cdn_name}} for every probed URL."""
    path = run_dir / "raw" / "httpx.jsonl"
    if not path.exists():
        return {}
    url_map: Dict[str, dict] = {}
    for line in path.read_text(errors="ignore", encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = rec.get("url")
        if not url:
            continue
        ip = rec.get("host") or ""
        if not ip and isinstance(rec.get("a"), list) and rec["a"]:
            ip = rec["a"][0]
        cdn_name = rec.get("cdn_name") or (rec.get("cdn") if isinstance(rec.get("cdn"), str) else None)
        url_map[url] = {"ip": ip, "cdn_name": cdn_name}
    return url_map


def main() -> int:
    p = argparse.ArgumentParser(description="Filter alive URLs to WAF-unknown subset for wafw00f")
    p.add_argument("-r", "--run-dir", required=True, help="ASM run output directory")
    args = p.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"Error: {run_dir} does not exist")
        return 1

    alive_urls = read_alive_urls(run_dir)
    skipped_ips = read_skipped_ips(run_dir)
    httpx_map = read_httpx_records(run_dir)

    kept: list[str] = []
    dropped_cdn_edge = 0
    dropped_waf_known = 0
    dropped_no_ip = 0

    for url in alive_urls:
        rec = httpx_map.get(url)
        if not rec:
            dropped_no_ip += 1
            continue
        ip = rec["ip"]
        if ip in skipped_ips:
            dropped_cdn_edge += 1
            continue
        if rec["cdn_name"]:
            dropped_waf_known += 1
            continue
        kept.append(url)

    out_path = run_dir / "stages" / "04_waf_unknown_urls.txt"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(kept) + "\n" if kept else "", encoding="utf-8")

    print(f"Alive URLs (Stage 3):       {len(alive_urls)}")
    print(f"  - CDN/WAF edge (Stage 4): {dropped_cdn_edge}")
    print(f"  - WAF already known:      {dropped_waf_known}")
    print(f"  - No IP mapped:           {dropped_no_ip}")
    print(f"  = WAF-unknown (kept):     {len(kept)}")
    print(f"\nWritten: {out_path}")
    if kept:
        print(f"\nRun wafw00f:")
        print(f"  wafw00f -i {out_path} -o waf_results.json")
    else:
        print("\nNo URLs need WAF fingerprinting — all have known WAF/CDN.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
