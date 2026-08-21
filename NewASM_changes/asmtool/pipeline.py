"""Pipeline orchestrator: wires the eight stages together, manages the run
directory, and writes the final report (JSON + Markdown).

Data flow between stages is in-memory (single process), but every stage also
persists to SQLite + stage JSON, so a crashed run leaves a queryable partial
result and raw tool output on disk.

Stages 7 (feroxbuster) and 8 (nuclei) run in background threads parallel to
Stages 4-6: they only need Stage 3 output, not port scan or nmap results.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from . import config, stages, utils
from .runner import CommandRunner
from .storage import Storage

log = logging.getLogger("asm.pipeline")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Pipeline:
    def __init__(self, domain: str, output_root: Path, settings: config.Settings) -> None:
        self.domain = domain
        self.settings = settings
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.workdir = output_root / f"{domain}_{stamp}"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.runner = CommandRunner(dry_run=settings.dry_run)
        self.storage = Storage(self.workdir / "asm.db")

    def run(self) -> Path:
        run_id = self.storage.start_run(self.domain, _now())
        ctx = stages.Context(
            domain=self.domain, run_id=run_id, workdir=self.workdir,
            runner=self.runner, storage=self.storage, settings=self.settings,
        )
        status = "completed"
        ferox_thread: Optional[threading.Thread] = None
        nuclei_thread: Optional[threading.Thread] = None
        try:
            # 1. Enumerate candidate subdomains (passive sources — not yet proven live).
            subs = stages.stage_subdomains(ctx)

            # 2. ACTIVENESS = DNS resolution. dnsx is the authority: a subdomain is
            #    "active" iff it resolves to an IP. Only resolving names advance;
            #    discovered-but-unresolved names are recorded as inactive.
            resolved = stages.stage_resolve(ctx, subs)

            # 3. HTTP enrichment on the active (resolved) subdomains. Enrichment
            #    ONLY — it never gates or REMOVES a host from the scan (a host with
            #    no web server can still have open SSH/RDP/DB ports). It DOES return
            #    the set of hosts it proved reachable, used in Stage 4 as an additive
            #    zero-FN cross-check (reachable hosts can only be force-KEPT).
            reached_hosts = stages.stage_http_probe(ctx, sorted(resolved.keys()))

            # 7. Directory fuzzing (optional, --fuzz). Starts HERE — right after
            #    Stage 3 writes 03_fuzz_targets.txt. No dependency on Stages 4-6:
            #    directory fuzzing is HTTP-level (goes through CDNs to the real app),
            #    so CDN filtering only matters for port scanning, not fuzzing. Runs
            #    in a background thread parallel to Stages 4-6.
            if self.settings.run_feroxbuster:
                ferox_thread = threading.Thread(
                    target=self._run_feroxbuster, args=(ctx,),
                    name="feroxbuster", daemon=True,
                )
                ferox_thread.start()
                log.info("Stage 7 (feroxbuster) launched in background — "
                         "running parallel to Stages 4-6")

            # 8. Nuclei CVE + misconfiguration scanning (optional, --nuclei).
            #    Like feroxbuster, starts right after Stage 3 — only needs
            #    03_tech.json + 03_alive_urls.txt. Parallel to Stages 4-6.
            if self.settings.run_nuclei:
                nuclei_thread = threading.Thread(
                    target=self._run_nuclei, args=(ctx,),
                    name="nuclei", daemon=True,
                )
                nuclei_thread.start()
                log.info("Stage 8 (nuclei) launched in background — "
                         "running parallel to Stages 4-6")

            # 4. Drop CDN/WAF edges so we scan real origins, not shared CDN infra.
            #    Any IP httpx proved reachable is force-kept scannable (overrides a
            #    cdncheck misclassification; never removes a host).
            scannable_ips = stages.stage_cdn_filter(ctx, resolved, reached_hosts)

            # 5. Port-scan the active origins → open ports.
            port_map = stages.stage_port_scan(ctx, scannable_ips)

            # 6. nmap aggressive deep scan (authoritative) over the scannable IPs.
            stages.stage_nmap(ctx, scannable_ips, port_map)
        except KeyboardInterrupt:
            status = "interrupted"
            log.warning("Interrupted by user — partial results preserved")
        except Exception as exc:  # noqa: BLE001 — keep the run resilient
            status = "error"
            log.exception("Pipeline error: %s", exc)
        finally:
            if ferox_thread and ferox_thread.is_alive():
                log.info("Waiting for feroxbuster background thread to finish…")
                ferox_thread.join()
            if nuclei_thread and nuclei_thread.is_alive():
                log.info("Waiting for nuclei background thread to finish…")
                nuclei_thread.join()
            self.storage.finish_run(run_id, _now(), status)

        report_path = self._write_report(run_id, status)
        self.storage.close()
        return report_path

    @staticmethod
    def _run_feroxbuster(ctx: stages.Context) -> None:
        try:
            stages.stage_feroxbuster(ctx)
        except Exception as exc:  # noqa: BLE001
            log.warning("Feroxbuster background thread failed: %s", exc)

    @staticmethod
    def _run_nuclei(ctx: stages.Context) -> None:
        try:
            stages.stage_nuclei(ctx)
        except Exception as exc:  # noqa: BLE001
            log.warning("Nuclei background thread failed: %s", exc)

    # -- reporting --------------------------------------------------------
    def _read_tarpit_data(self) -> Dict[str, Any]:
        """Read tarpit results from both precheck and post-scan stage files."""
        data: Dict[str, Any] = {}
        precheck = self.workdir / "stages" / "06_tarpit_precheck.json"
        if precheck.exists():
            try:
                data = json.loads(precheck.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        # Merge post-scan tarpits from 06_nmap.json (IPs the precheck missed).
        nmap_file = self.workdir / "stages" / "06_nmap.json"
        if nmap_file.exists():
            try:
                nmap_data = json.loads(nmap_file.read_text(encoding="utf-8"))
                postscan = nmap_data.get("tarpit_postscan", [])
                if postscan:
                    all_tarpits = sorted(set(data.get("tarpit_ips", []) + postscan))
                    data["tarpit_ips"] = all_tarpits
                    data["tarpit_postscan"] = postscan
            except (json.JSONDecodeError, OSError):
                pass
        return data

    def _write_report(self, run_id: int, status: str) -> Path:
        counts = self.storage.counts(run_id)
        ports = self.storage.open_ports_summary(run_id)
        active = self.storage.active_subdomains(run_id)      # {sub: [ips]}
        inactive = self.storage.inactive_subdomains(run_id)  # [names]
        fuzz_rows = self.storage.fuzz_results_summary(run_id)
        nuclei_rows = self.storage.nuclei_findings_summary(run_id)
        tarpit_data = self._read_tarpit_data()
        tarpit_ips = tarpit_data.get("tarpit_ips", [])

        utils.dump_json(self.workdir / "report.json", {
            "domain": self.domain,
            "status": status,
            "generated_at": _now(),
            "counts": counts,
            "subdomains": {"active": active, "inactive": inactive},
            "open_ports": [dict(r) for r in ports],
            "tarpit_ips": tarpit_ips,
            "fuzz_results": [dict(r) for r in fuzz_rows],
            "nuclei_findings": [dict(r) for r in nuclei_rows],
        })

        lines = [
            f"# ASM Report — {self.domain}",
            "",
            f"- Status: **{status}**",
            f"- Generated: {_now()}",
            f"- Database: `asm.db`  |  Raw output: `raw/`  |  Stages: `stages/`",
            "",
            "## Surface summary",
            "",
            "| Metric | Count |",
            "|---|---|",
            f"| Subdomains discovered | {counts['subdomains']} |",
            f"| Resolvable (live DNS) | {counts['resolvable']} |",
            f"| Unique IPs | {counts['hosts']} |",
            f"| Scannable IPs (non-CDN) | {counts['scannable_hosts']} |",
            f"| CDN/WAF IPs (skipped) | {counts['cdn_hosts']} |",
            f"| Tarpit IPs (curated scan) | {len(tarpit_ips)} |",
            f"| HTTP services probed | {counts['http_services']} |",
            f"| Open ports | {counts['open_ports']} |",
            f"| nmap script findings | {counts['nmap_findings']} |",
            f"| Directory fuzz paths | {counts['fuzz_results']} |",
            f"| Nuclei CVE findings | {counts['nuclei_findings']} |",
            "",
        ]
        if tarpit_ips:
            curated = tarpit_data.get("curated_ports", config.TARPIT_CURATED_PORTS)
            threshold = tarpit_data.get("threshold", "N/A")
            probe_count = len(tarpit_data.get("probe_ports", []))
            postscan = set(tarpit_data.get("tarpit_postscan", []))
            lines += [
                "## Tarpit anomalies",
                "",
                f"IPs that SYN-ACK on nearly every port. These are load balancers "
                f"or WAF edges that fake-open all ports. Scanned on curated ports "
                f"`[{curated}]` only.",
                "",
                "| Tarpit IP | Detection | Action |",
                "|---|---|---|",
            ]
            for ip in tarpit_ips:
                method = "post-scan (fake ports purged)" if ip in postscan \
                    else f"precheck ({threshold}/{probe_count} probe ports open)"
                lines.append(f"| {ip} | {method} | Scanned ports {curated} only |")
            lines.append("")

        lines += [
            "## Subdomains",
            "",
            f"Activeness is decided by DNS resolution (dnsx): a subdomain is "
            f"**active** only if it resolves to an IP. "
            f"**{len(active)} active**, **{len(inactive)} inactive**.",
            "",
            "### Active (resolved → scanned)",
            "",
            "| Subdomain | Resolved IP(s) |",
            "|---|---|",
        ]
        for sub in sorted(active):
            lines.append(f"| {sub} | {', '.join(active[sub])} |")
        lines += [
            "",
            "### Inactive (discovered but did NOT resolve — review for dangling DNS / takeover)",
            "",
        ]
        if inactive:
            lines += [f"- {name}" for name in inactive]
        else:
            lines.append("_None — every discovered subdomain resolved._")
        lines += [
            "",
            "## Open ports",
            "",
            "| IP | Port | Service | Product | Version |",
            "|---|---|---|---|---|",
        ]
        for r in ports:
            lines.append(
                f"| {r['ip']} | {r['port']} | {r['service'] or ''} | "
                f"{r['product'] or ''} | {r['version'] or ''} |"
            )
        if fuzz_rows:
            lines += [
                "",
                "## Directory fuzzing (feroxbuster)",
                "",
                f"**{len(fuzz_rows)} path(s)** discovered across fuzzed targets.",
                "",
                "| Target URL | Discovered Path | Status | Length |",
                "|---|---|---|---|",
            ]
            for r in fuzz_rows:
                lines.append(
                    f"| {r['target_url']} | {r['found_url']} | "
                    f"{r['status'] or ''} | {r['content_length'] or ''} |"
                )
        if nuclei_rows:
            lines += [
                "",
                "## Nuclei CVE findings",
                "",
                f"**{len(nuclei_rows)} finding(s)** from tech-targeted CVE + "
                f"misconfiguration scanning.",
                "",
                "| Severity | Template | Host | Matched At | Description |",
                "|---|---|---|---|---|",
            ]
            for r in nuclei_rows:
                desc = (r["description"] or "")[:80]
                lines.append(
                    f"| {r['severity'] or ''} | {r['template_id']} | "
                    f"{r['host']} | {r['matched_at'] or ''} | {desc} |"
                )
        report_md = self.workdir / "report.md"
        report_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

        log.info("Report written: %s", report_md)
        log.info("Summary: %s", counts)
        return report_md
