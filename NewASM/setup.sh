#!/usr/bin/env bash
#
# NewASM — end-to-end setup for Ubuntu (20.04 / 22.04 / 24.04, amd64 or arm64).
# Installs every external tool the pipeline orchestrates + the Python
# subdominator tool, persists PATH, and verifies the result.
#
# Usage:    bash setup.sh
# Notes:    uses sudo for apt and /usr/local installs; safe to re-run.
#           Do NOT run the whole script as root — subdominator/Go go in your $HOME.
# ---------------------------------------------------------------------------

set -uo pipefail

log()  { printf '\n\033[1;32m[+] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }

ARCH="$(dpkg --print-architecture)"        # amd64 | arm64
SUB_DIR="$HOME/Tools/Subdominator/sub"      # matches asmtool/config.py default

# ------------------------------------------------------------- 1. apt base ---
log "Installing base system packages (apt)"
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
    nmap git curl wget unzip build-essential libpcap-dev ca-certificates \
    python3 python3-venv python3-pip

# ------------------------------------------------------------- 2. Go ---------
if ! command -v go >/dev/null 2>&1 && [ ! -x /usr/local/go/bin/go ]; then
    log "Installing latest Go"
    GO_VERSION="$(curl -s https://go.dev/VERSION?m=text | head -1)"
    curl -sSL "https://go.dev/dl/${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
else
    log "Go already present"
fi
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

# ------------------------------------------ 3. ProjectDiscovery tools (Go) ---
log "Installing ProjectDiscovery tools (dnsx, httpx, cdncheck, naabu)"
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest   # deprecated in NewASM, harmless

# ------------------------------------------------------------- 4. findomain --
if ! command -v findomain >/dev/null 2>&1; then
    log "Installing findomain"
    curl -sSL https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip \
        -o /tmp/findomain.zip
    unzip -o /tmp/findomain.zip -d /tmp/findomain-dir
    chmod +x /tmp/findomain-dir/findomain
    sudo mv /tmp/findomain-dir/findomain /usr/local/bin/findomain
    rm -rf /tmp/findomain.zip /tmp/findomain-dir
else
    log "findomain already present"
fi

# ------------------------------------------------------------- 5. rustscan ---
if ! command -v rustscan >/dev/null 2>&1; then
    log "Installing rustscan"
    RS_DEB="$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest \
              | grep -o "https://[^\"]*${ARCH}\.deb" | head -1)"
    if [ -n "$RS_DEB" ]; then
        curl -sSL "$RS_DEB" -o /tmp/rustscan.deb
        sudo dpkg -i /tmp/rustscan.deb || sudo apt-get install -f -y
        rm -f /tmp/rustscan.deb
    else
        warn "No rustscan .deb for ${ARCH} — installing via cargo"
        if ! command -v cargo >/dev/null 2>&1; then
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            # shellcheck disable=SC1091
            source "$HOME/.cargo/env"
        fi
        cargo install rustscan
    fi
else
    log "rustscan already present"
fi

# ---------------------------------------------------- 6. subdominator (venv) --
log "Installing subdominator into ${SUB_DIR}"
python3 -m venv "$SUB_DIR"
"$SUB_DIR/bin/pip" install --quiet --upgrade pip
"$SUB_DIR/bin/pip" install --quiet subdominator

# ------------------------------------------------------------- 7. PATH -------
log "Persisting PATH to ~/.bashrc"
LINE='export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:/usr/local/bin"'
grep -qxF "$LINE" "$HOME/.bashrc" 2>/dev/null || echo "$LINE" >> "$HOME/.bashrc"

# ------------------------------------------------------------- 8. verify -----
log "Verifying toolchain"
status=0
check() {
    if command -v "$1" >/dev/null 2>&1 || [ -x "$1" ]; then
        printf '  \033[1;32mOK  \033[0m %s\n' "$1"
    else
        printf '  \033[1;31mMISS\033[0m %s\n' "$1"; status=1
    fi
}
for t in findomain "$SUB_DIR/bin/subdominator" dnsx httpx cdncheck naabu rustscan nmap; do
    check "$t"
done

log "Setup complete. Open a NEW shell (or: source ~/.bashrc), then:"
echo "    python3 asm.py -d example.com -v"
echo "    sudo python3 asm.py -d example.com --nmap-only   # SYN scan (recommended for accuracy)"
[ "$status" -eq 0 ] || warn "Some tools are missing — re-run this section or install them manually (see SETUP.md)."
