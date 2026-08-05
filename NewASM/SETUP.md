# NewASM — End-to-End Setup (Ubuntu)

Get NewASM running from a clean Ubuntu box (20.04 / 22.04 / 24.04, amd64 or
arm64). The orchestrator itself is pure Python standard library; the work is
installing the external recon tools it drives.

> ⚠️ **Authorized use only.** Only run NewASM against assets you own or have
> explicit written permission to test.

---

## 0. What gets installed

| Tool | Stage | Language | Install method |
|------|-------|----------|----------------|
| `findomain` | 1 — discover | Rust binary | GitHub release |
| `subdominator` | 1 — discover | Python | pip (dedicated venv) |
| `dnsx` | 2 — resolve | Go | `go install` |
| `httpx` | 3 — profile | Go | `go install` |
| `cdncheck` | 4 — CDN filter | Go | `go install` |
| `rustscan` | 5 — port scan | Rust | `.deb` / `cargo` |
| `nmap` | 6 — deep scan | C | `apt` |
| `naabu` | (deprecated) | Go | `go install` (optional) |

> **httpx naming:** on Ubuntu the ProjectDiscovery binary is `httpx`. (Kali renames
> it `httpx-toolkit` to avoid the Python `httpx` HTTP-client library.) NewASM
> auto-detects both — `config.TOOL_BINARIES["httpx"] = ["httpx-toolkit", "httpx"]`.

---

## 1. Quick start (automated)

```bash
git clone <your-repo> NewASM   # or copy the NewASM/ directory to the box
cd NewASM
bash setup.sh                  # installs everything, persists PATH, verifies
source ~/.bashrc               # or open a new shell
```

`setup.sh` is safe to re-run. It ends with a tool-by-tool `OK/MISS` check. If
anything shows `MISS`, do that step manually below.

---

## 2. Manual setup (step by step)

### 2.1 Base system packages
```bash
sudo apt-get update
sudo apt-get install -y nmap git curl wget unzip build-essential libpcap-dev \
    python3 python3-venv python3-pip
```
`libpcap-dev` is required to build `naabu`; `build-essential` for the Go tools.

### 2.2 Go (needed for the ProjectDiscovery tools)
Ubuntu's `golang-go` is often too old for `go install @latest`. Install the
current Go:
```bash
GO_VERSION=$(curl -s https://go.dev/VERSION?m=text | head -1)
curl -sSL "https://go.dev/dl/${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" -o /tmp/go.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tar.gz
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
go version
```

### 2.3 ProjectDiscovery tools (dnsx, httpx, cdncheck, naabu)
```bash
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest   # optional/deprecated
```
These land in `~/go/bin`. Confirm `httpx -version` prints **projectdiscovery**.

### 2.4 findomain
```bash
curl -sSL https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -o /tmp/findomain.zip
unzip -o /tmp/findomain.zip -d /tmp/findomain-dir
sudo install -m755 /tmp/findomain-dir/findomain /usr/local/bin/findomain
findomain --version
```

### 2.5 rustscan
Prefer the release `.deb`:
```bash
RS_DEB=$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest \
         | grep -o "https://[^\"]*$(dpkg --print-architecture)\.deb" | head -1)
curl -sSL "$RS_DEB" -o /tmp/rustscan.deb
sudo dpkg -i /tmp/rustscan.deb || sudo apt-get install -f -y
```
No `.deb` for your arch? Use cargo:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
cargo install rustscan
```
NewASM relies on `--tries`, `-t`, `-b`, `--ulimit`, `-g` — all present in
rustscan 2.x, so use a recent version.

### 2.6 subdominator (Python, in its own venv)
Install into the exact path NewASM looks for by default:
```bash
python3 -m venv ~/Tools/Subdominator/sub
~/Tools/Subdominator/sub/bin/pip install --upgrade pip
~/Tools/Subdominator/sub/bin/pip install subdominator
~/Tools/Subdominator/sub/bin/subdominator --help
```
(If you install it elsewhere or on PATH, pass `--subdominator-bin /path/to/subdominator`.)

### 2.7 Persist PATH
```bash
echo 'export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:/usr/local/bin"' >> ~/.bashrc
source ~/.bashrc
```

---

## 3. Python requirements

NewASM's core needs **no** pip packages (standard library only). `requirements.txt`
lists just `subdominator`; section 2.6 already installs it into its own venv. If
you prefer a single venv on PATH instead:
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

## 4. Verify the toolchain
```bash
for t in findomain subdominator dnsx httpx cdncheck naabu rustscan nmap; do
  command -v "$t" >/dev/null && echo "OK   $t" || echo "MISS $t"
done
# subdominator in its venv:
[ -x ~/Tools/Subdominator/sub/bin/subdominator ] && echo "OK   subdominator (venv)"
```

---

## 5. Run
```bash
# Fast hybrid (refined rustscan → nmap)
python3 asm.py -d example.com -v

# Recommended for accuracy: SYN scan, nmap does all discovery
sudo python3 asm.py -d example.com --nmap-only

# With real service/version detection
sudo python3 asm.py -d example.com --nmap-only --nmap-flags "-Pn --min-rate 10000 -sV"
```
Outputs land in `output/<domain>_<timestamp>/` — `asm.db`, `report.md`,
`report.json`, `stages/`, `raw/`, `asm.log`.

---

## 6. Notes

- **Run with `sudo` for a SYN scan.** Unprivileged, nmap falls back to a TCP
  connect scan (lossy on filtered hosts) and NewASM prints a warning. SYN (root)
  is the accurate, zero-false-negative choice.
- **`cdncheck -update`** downloads provider IP ranges; NewASM runs it automatically
  each run (disable with `--no-cdncheck-update`). The first run needs internet.
- **API keys (optional).** `subdominator` and `findomain` return more subdomains
  with provider API keys configured (see each tool's docs); NewASM works without them.
- **Updating tools:** re-run `go install ...@latest` for the PD tools, and
  `~/Tools/Subdominator/sub/bin/pip install -U subdominator`.
- **Python:** 3.8+ (3.10+ recommended). No third-party packages for the core tool.
