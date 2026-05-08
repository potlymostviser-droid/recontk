#!/usr/bin/env bash
# recontk/scripts/verify.sh
# Run --version on every registered tool and print a status table.
# Exit code: 0 if all tools found, 1 if any are missing.
#
# AUTHORIZED USE ONLY — see README.md

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

MISSING=0

# Tool name → version flag (must match registry.py _VERSION_FLAGS)
declare -A TOOLS
TOOLS["nmap"]="--version"
TOOLS["masscan"]="--version"
TOOLS["subfinder"]="-version"
TOOLS["amass"]="version"
TOOLS["httpx"]="-version"
TOOLS["nuclei"]="-version"
TOOLS["naabu"]="-version"
TOOLS["gowitness"]="version"
TOOLS["whatweb"]="--version"
TOOLS["wafw00f"]="--version"
TOOLS["dnsx"]="-version"
TOOLS["gau"]="--version"
TOOLS["waybackurls"]=""          # no --version flag
TOOLS["ffuf"]="-V"
TOOLS["gobuster"]="version"
TOOLS["testssl.sh"]="--version"
TOOLS["sslyze"]="--version"
TOOLS["theHarvester"]="--version"
TOOLS["whois"]="--version"
TOOLS["dig"]="-v"

printf "\n${BOLD}%-20s %-10s %s${NC}\n" "TOOL" "STATUS" "VERSION"
printf "%-20s %-10s %s\n" "----" "------" "-------"

for tool in "${!TOOLS[@]}"; do
    flag="${TOOLS[$tool]}"
    if ! command -v "$tool" &>/dev/null; then
        printf "%-20s ${RED}%-10s${NC} %s\n" "$tool" "MISSING" "-"
        MISSING=$((MISSING + 1))
        continue
    fi

    if [[ -z "$flag" ]]; then
        # Tool exists but has no version flag (e.g. waybackurls)
        printf "%-20s ${YELLOW}%-10s${NC} %s\n" "$tool" "PRESENT" "(no --version)"
        continue
    fi

    VERSION=$(timeout 5 "$tool" $flag 2>&1 | head -1 || true)
    if [[ -z "$VERSION" ]]; then
        VERSION="(no output)"
    fi
    printf "%-20s ${GREEN}%-10s${NC} %s\n" "$tool" "OK" "$VERSION"
done

echo ""
if [[ "$MISSING" -gt 0 ]]; then
    echo -e "${RED}${MISSING} tool(s) missing. Run: scripts/bootstrap_tools.sh${NC}"
    exit 1
else
    echo -e "${GREEN}All tools present.${NC}"
    exit 0
fi
