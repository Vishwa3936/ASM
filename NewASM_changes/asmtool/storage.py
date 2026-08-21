"""Persistence layer: a single-file SQLite DB plus raw/stage artifacts on disk.

Why SQLite over flat files as the "pipe" between stages:
  * one portable file (asm.db) you can scp to Kali and query with `sqlite3`
  * dedup via UNIQUE constraints (idempotent re-runs)
  * real queries across the surface ("all hosts with port 3389", "new since...")
Raw tool output still lands under raw/ for audit; parsed rows go to SQLite;
per-stage JSON snapshots go under stages/ for quick eyeballing / resume.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    domain        TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    status        TEXT
);

CREATE TABLE IF NOT EXISTS subdomains (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id   INTEGER NOT NULL,
    name     TEXT NOT NULL,
    source   TEXT,
    resolves INTEGER DEFAULT 0,
    UNIQUE(run_id, name)
);

CREATE TABLE IF NOT EXISTS dns_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL,
    subdomain   TEXT NOT NULL,
    record_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    UNIQUE(run_id, subdomain, record_type, value)
);

CREATE TABLE IF NOT EXISTS hosts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       INTEGER NOT NULL,
    ip           TEXT NOT NULL,
    is_cdn       INTEGER DEFAULT 0,
    cdn_name     TEXT,
    is_scannable INTEGER DEFAULT 1,
    UNIQUE(run_id, ip)
);

CREATE TABLE IF NOT EXISTS subdomain_hosts (
    run_id    INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    ip        TEXT NOT NULL,
    UNIQUE(run_id, subdomain, ip)
);

CREATE TABLE IF NOT EXISTS http_probes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER NOT NULL,
    subdomain      TEXT,
    url            TEXT,
    status_code    INTEGER,
    title          TEXT,
    webserver      TEXT,
    tech           TEXT,
    ip             TEXT,
    cname          TEXT,
    cdn_name       TEXT,
    content_type   TEXT,
    content_length INTEGER,
    location       TEXT,
    favicon        TEXT,
    jarm           TEXT,
    asn            TEXT,
    response_time  TEXT
);

CREATE TABLE IF NOT EXISTS ports (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id   INTEGER NOT NULL,
    ip       TEXT NOT NULL,
    port     INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    state    TEXT DEFAULT 'open',
    service  TEXT,
    product  TEXT,
    version  TEXT,
    UNIQUE(run_id, ip, port, protocol)
);

CREATE TABLE IF NOT EXISTS nmap_findings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id    INTEGER NOT NULL,
    ip        TEXT NOT NULL,
    port      INTEGER,
    script_id TEXT,
    output    TEXT,
    raw_ref   TEXT
);

CREATE TABLE IF NOT EXISTS fuzz_results (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER NOT NULL,
    target_url     TEXT NOT NULL,
    found_url      TEXT NOT NULL,
    status         INTEGER,
    content_length INTEGER,
    UNIQUE(run_id, found_url)
);

CREATE TABLE IF NOT EXISTS nuclei_findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER NOT NULL,
    host           TEXT NOT NULL,
    url            TEXT,
    template_id    TEXT NOT NULL,
    template_name  TEXT,
    severity       TEXT,
    matched_at     TEXT,
    extracted      TEXT,
    curl_command   TEXT,
    description    TEXT,
    reference      TEXT,
    tags           TEXT,
    UNIQUE(run_id, host, template_id, matched_at)
);
"""


class Storage:
    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- run lifecycle ----------------------------------------------------
    def start_run(self, domain: str, started_at: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO runs(domain, started_at, status) VALUES (?,?,?)",
            (domain, started_at, "running"),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_run(self, run_id: int, finished_at: str, status: str) -> None:
        self.conn.execute(
            "UPDATE runs SET finished_at=?, status=? WHERE id=?",
            (finished_at, status, run_id),
        )
        self.conn.commit()

    # -- inserts (idempotent where a UNIQUE exists) -----------------------
    def add_subdomain(self, run_id: int, name: str, source: str, resolves: bool) -> None:
        self.conn.execute(
            "INSERT INTO subdomains(run_id,name,source,resolves) VALUES (?,?,?,?) "
            "ON CONFLICT(run_id,name) DO UPDATE SET "
            "resolves=MAX(resolves,excluded.resolves), "
            "source=source||','||excluded.source",
            (run_id, name, source, int(resolves)),
        )

    def add_dns_record(self, run_id: int, subdomain: str, rtype: str, value: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO dns_records(run_id,subdomain,record_type,value) "
            "VALUES (?,?,?,?)",
            (run_id, subdomain, rtype, value),
        )

    def add_host(self, run_id: int, ip: str, is_cdn: bool, cdn_name: Optional[str],
                 is_scannable: bool) -> None:
        self.conn.execute(
            "INSERT INTO hosts(run_id,ip,is_cdn,cdn_name,is_scannable) VALUES (?,?,?,?,?) "
            "ON CONFLICT(run_id,ip) DO UPDATE SET "
            "is_cdn=excluded.is_cdn, cdn_name=excluded.cdn_name, "
            "is_scannable=excluded.is_scannable",
            (run_id, ip, int(is_cdn), cdn_name, int(is_scannable)),
        )

    def map_subdomain_host(self, run_id: int, subdomain: str, ip: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO subdomain_hosts(run_id,subdomain,ip) VALUES (?,?,?)",
            (run_id, subdomain, ip),
        )

    def add_http_probe(self, run_id: int, rec: Dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO http_probes(run_id,subdomain,url,status_code,title,webserver,"
            "tech,ip,cname,cdn_name,content_type,content_length,location,favicon,jarm,"
            "asn,response_time) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, rec.get("subdomain"), rec.get("url"), rec.get("status_code"),
             rec.get("title"), rec.get("webserver"), rec.get("tech"), rec.get("ip"),
             rec.get("cname"), rec.get("cdn_name"), rec.get("content_type"),
             rec.get("content_length"), rec.get("location"), rec.get("favicon"),
             rec.get("jarm"), rec.get("asn"), rec.get("response_time")),
        )

    def add_port(self, run_id: int, ip: str, port: int, service: Optional[str] = None,
                 product: Optional[str] = None, version: Optional[str] = None) -> None:
        self.conn.execute(
            "INSERT INTO ports(run_id,ip,port,service,product,version) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(run_id,ip,port,protocol) DO UPDATE SET "
            "service=COALESCE(excluded.service,service), "
            "product=COALESCE(excluded.product,product), "
            "version=COALESCE(excluded.version,version)",
            (run_id, ip, port, service, product, version),
        )

    def add_nmap_finding(self, run_id: int, ip: str, port: Optional[int],
                         script_id: str, output: str, raw_ref: str) -> None:
        self.conn.execute(
            "INSERT INTO nmap_findings(run_id,ip,port,script_id,output,raw_ref) "
            "VALUES (?,?,?,?,?,?)",
            (run_id, ip, port, script_id, output, raw_ref),
        )

    def port_count(self, run_id: int, ip: str) -> int:
        """Number of open ports recorded for an IP in this run."""
        row = self.conn.execute(
            "SELECT COUNT(*) FROM ports WHERE run_id=? AND ip=?",
            (run_id, ip),
        ).fetchone()
        return int(row[0])

    def purge_ports(self, run_id: int, ip: str) -> int:
        """Delete all port rows for an IP (used when post-scan tarpit detection
        identifies fake open ports). Returns the number of rows deleted."""
        cur = self.conn.execute(
            "DELETE FROM ports WHERE run_id=? AND ip=?",
            (run_id, ip),
        )
        return cur.rowcount

    def add_fuzz_result(self, run_id: int, target_url: str, found_url: str,
                        status: Optional[int] = None,
                        content_length: Optional[int] = None) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO fuzz_results(run_id,target_url,found_url,"
            "status,content_length) VALUES (?,?,?,?,?)",
            (run_id, target_url, found_url, status, content_length),
        )

    def add_nuclei_finding(self, run_id: int, host: str, url: Optional[str],
                           template_id: str, template_name: Optional[str],
                           severity: Optional[str], matched_at: Optional[str],
                           extracted: Optional[str], curl_command: Optional[str],
                           description: Optional[str], reference: Optional[str],
                           tags: Optional[str]) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO nuclei_findings(run_id,host,url,template_id,"
            "template_name,severity,matched_at,extracted,curl_command,"
            "description,reference,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, host, url, template_id, template_name, severity,
             matched_at, extracted, curl_command, description, reference, tags),
        )

    def commit(self) -> None:
        self.conn.commit()

    # -- summary readback for the report ----------------------------------
    def counts(self, run_id: int) -> Dict[str, int]:
        q = lambda sql: int(self.conn.execute(sql, (run_id,)).fetchone()[0])
        return {
            "subdomains": q("SELECT COUNT(*) FROM subdomains WHERE run_id=?"),
            "resolvable": q("SELECT COUNT(*) FROM subdomains WHERE run_id=? AND resolves=1"),
            "hosts": q("SELECT COUNT(*) FROM hosts WHERE run_id=?"),
            "scannable_hosts": q("SELECT COUNT(*) FROM hosts WHERE run_id=? AND is_scannable=1"),
            "cdn_hosts": q("SELECT COUNT(*) FROM hosts WHERE run_id=? AND is_cdn=1"),
            "open_ports": q("SELECT COUNT(*) FROM ports WHERE run_id=?"),
            "http_services": q("SELECT COUNT(*) FROM http_probes WHERE run_id=?"),
            "nmap_findings": q("SELECT COUNT(*) FROM nmap_findings WHERE run_id=?"),
            "fuzz_results": q("SELECT COUNT(*) FROM fuzz_results WHERE run_id=?"),
            "nuclei_findings": q("SELECT COUNT(*) FROM nuclei_findings WHERE run_id=?"),
        }

    def open_ports_summary(self, run_id: int) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT ip, port, service, product, version FROM ports "
            "WHERE run_id=? ORDER BY ip, port",
            (run_id,),
        ).fetchall()

    def active_subdomains(self, run_id: int) -> Dict[str, List[str]]:
        """Active (resolving) subdomains → their resolved IP(s)."""
        rows = self.conn.execute(
            "SELECT subdomain, ip FROM subdomain_hosts WHERE run_id=? "
            "ORDER BY subdomain, ip",
            (run_id,),
        ).fetchall()
        out: Dict[str, List[str]] = {}
        for r in rows:
            out.setdefault(r["subdomain"], []).append(r["ip"])
        return out

    def inactive_subdomains(self, run_id: int) -> List[str]:
        """Discovered subdomains that did NOT resolve (no A record). Possible
        dangling DNS / subdomain-takeover candidates."""
        rows = self.conn.execute(
            "SELECT name FROM subdomains WHERE run_id=? AND resolves=0 ORDER BY name",
            (run_id,),
        ).fetchall()
        return [r["name"] for r in rows]

    def fuzz_results_summary(self, run_id: int) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT target_url, found_url, status, content_length "
            "FROM fuzz_results WHERE run_id=? ORDER BY target_url, found_url",
            (run_id,),
        ).fetchall()

    def nuclei_findings_summary(self, run_id: int) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT host, url, template_id, template_name, severity, "
            "matched_at, description, reference, tags "
            "FROM nuclei_findings WHERE run_id=? ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END, host",
            (run_id,),
        ).fetchall()

    def close(self) -> None:
        self.conn.close()
