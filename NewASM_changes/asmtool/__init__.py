"""NewASM — a staged Attack Surface Management recon pipeline for Kali.

Purpose : Enumerate → resolve → HTTP-probe → CDN-filter → port-scan → deep-scan
          an external attack surface, persisting every stage to SQLite + JSON.
Run on  : Kali Linux (needs findomain, subdominator, dnsx, httpx-toolkit, cdncheck,
          rustscan, nmap on PATH). Developed cross-platform via pathlib.
"""

__version__ = "0.1.0"
