"""Pipeline orchestrator: wires the six stages together, manages the run
directory, and writes the final report (JSON + Markdown).

Data flow between stages is in-memory (single process), but every stage also
persists to SQLite + stage JSON, so a crashed run leaves a queryable partial
result and raw tool output on disk.
"""

from __future__ import annotations

import json
import logging
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
            self.storage.finish_run(run_id, _now(), status)

        report_path = self._write_report(run_id, status)
        self.storage.close()
        return report_path

    # -- reporting --------------------------------------------------------
    def _read_tarpit_data(self) -> Dict[str, Any]:
        """Read tarpit precheck results from the stage file, if it exists."""
        tarpit_file = self.workdir / "stages" / "06_tarpit_precheck.json"
        if tarpit_file.exists():
            try:
                return json.loads(tarpit_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _write_report(self, run_id: int, status: str) -> Path:
        counts = self.storage.counts(run_id)
        ports = self.storage.open_ports_summary(run_id)
        active = self.storage.active_subdomains(run_id)      # {sub: [ips]}
        inactive = self.storage.inactive_subdomains(run_id)  # [names]
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
            "",
        ]
        if tarpit_ips:
            curated = tarpit_data.get("curated_ports", config.TARPIT_CURATED_PORTS)
            threshold = tarpit_data.get("threshold", "N/A")
            probe_count = len(tarpit_data.get("probe_ports", []))
            lines += [
                "## Tarpit anomalies",
                "",
                f"IPs that SYN-ACK on nearly every port (≥{threshold}/{probe_count} "
                f"probe ports open). These are load balancers or WAF edges that "
                f"fake-open all ports. Scanned on curated ports `[{curated}]` only.",
                "",
                "| Tarpit IP | Action |",
                "|---|---|",
            ]
            for ip in tarpit_ips:
                lines.append(f"| {ip} | Scanned ports {curated} only |")
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
        report_md = self.workdir / "report.md"
        report_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

        log.info("Report written: %s", report_md)
        log.info("Summary: %s", counts)
        return report_md
