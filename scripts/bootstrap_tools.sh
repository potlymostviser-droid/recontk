#!/usr/bin/env bash
# recontk/scripts/bootstrap_tools.sh
# Install Go-based and system tools needed by recontk.
#
# This script is INFORMATIONAL: it shows recommended install commands.
# It does NOT blindly execute them — you must review and run manually
# or set AUTO_INSTALL=1 to attempt automatic installation.
#
# AUTHORIZED USE ONLY — see README.md

set -euo pipefail

AUTO_INSTALL="${AUTO_INSTALL:-0}"
GO="${GO:-go}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${GREEN}[bootstrap]${NC} $*"; }
warn()    { echo -e "${YELLOW}[bootstrap]${NC} $*"; }
cmd_info(){ echo -e "${CYAN}  →${NC} $*"; }
error()   { echo -e "${RED}[bootstrap]${NC} $*" >&2; }

require_go() {
    if ! command -v "$GO" &>/dev/null; then
        error "Go is required for Go-based tools. Install from https://go.dev/dl/"
        return 1
    fi
    GO_VERSION=$("$GO" version | awk '{print $3}')
    info "Go version: ${GO_VERSION}"
}

maybe_run() {
    local description="$1"; shift
    info "${description}"
    cmd_info "$*"
    if [[ "$AUTO_INSTALL" == "1" ]]; then
        "$@"
    fi
}

# ---------------------------------------------------------------------------
echo ""
info "=== recontk external tool bootstrap ==="
echo ""
warn "Review each command before running. Set AUTO_INSTALL=1 to auto-install."
echo ""

# ---------------------------------------------------------------------------
# System tools (apt-based; adjust for your distro)
# ---------------------------------------------------------------------------
info "--- System tools ---"
maybe_run "nmap" sudo apt-get install -y nmap
maybe_run "masscan" sudo apt-get install -y masscan
maybe_run "whois" sudo apt-get install -y whois
maybe_run "dnsutils (dig)" sudo apt-get install -y dnsutils
maybe_run "testssl.sh" sudo apt-get install -y testssl  # VERIFY: package name varies by distro
maybe_run "whatweb" sudo apt-get install -y whatweb
maybe_run "wafw00f" pip install wafw00f
maybe_run "sslyze" pip install sslyze
maybe_run "theHarvester" pip install theHarvester

# ---------------------------------------------------------------------------
# Go-based tools
# ---------------------------------------------------------------------------
info ""
info "--- Go-based tools (requires Go >= 1.21) ---"
if require_go; then
    maybe_run "subfinder" "$GO" install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    maybe_run "httpx" "$GO" install github.com/projectdiscovery/httpx/cmd/httpx@latest
    maybe_run "nuclei" "$GO" install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    maybe_run "naabu" "$GO" install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    maybe_run "dnsx" "$GO" install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    maybe_run "amass" "$GO" install github.com/owasp-amass/amass/v4/...@latest
    maybe_run "gowitness" "$GO" install github.com/sensepost/gowitness@latest
    maybe_run "ffuf" "$GO" install github.com/ffuf/ffuf/v2@latest
    maybe_run "gobuster" "$GO" install github.com/OJ/gobuster/v3@latest
    maybe_run "gau" "$GO" install github.com/lc/gau/v2/cmd/gau@latest
    maybe_run "waybackurls" "$GO" install github.com/tomnomnom/waybackurls@latest
fi

echo ""
info "After installation, run: recontk doctor"
info "AUTHORIZED USE ONLY: scan only systems you own or have written permission to scan."
