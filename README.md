# recontk

> **AUTHORIZED USE ONLY**
>
> This tool may only be used on:
> - Systems you own
> - CTF / lab environments
> - Bug bounty programs with **explicit written scope**
> - Systems with **documented written permission**
>
> **Unauthorized scanning may be illegal.** The authors accept no liability
> for misuse of this software.

---

A self-hosted, Python-first, terminal-focused security scanning and
reconnaissance toolkit. Modular, reliable, and built for advanced CLI users.

## Features

- Modular capability system with automatic tool detection and native fallbacks
- Async subprocess orchestration with configurable rate limiting
- Structured JSONL logging + Rich terminal output
- Reproducible workspaces with resume support
- Plugin system via Python entry-points
- Multi-format reporting (JSON, Markdown, HTML, CSV)

## Requirements

- Python 3.11+
- Linux or macOS

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/your-org/recontk
cd recontk
bash scripts/install.sh

# 2. Activate the virtual environment
source .venv/bin/activate

# 3. Install external tools
bash scripts/bootstrap_tools.sh    # review first; set AUTO_INSTALL=1 to run

# 4. Verify installation

CLI Reference
text

recontk init
recontk doctor
recontk scan --profile <name> --target <host>
recontk scan --profile <name> --targets <file> --workspace <name>
recontk resume <workspace-path>
recontk reimport <workspace-path>
recontk report <workspace-path> --format [json|md|html|csv]
recontk profiles [list | show <name>]
recontk plugins list
Global flags: --dry-run, --verbose, --proxy <url>,
--allow-private, --confirm

Configuration
Copy examples/config.example.yml to config.yml and adjust. See also
.env.example for environment variable overrides.

Profiles
Profile	Description
recon	Full passive + active recon
bugbounty	Scope-aware, rate-limited
stealth	Minimal footprint
normal	Balanced defaults
web	Web-focused (HTTP, TLS, content)
vuln	Vulnerability scanning (nuclei)
ctf	CTF/lab — relaxed rate limits
Safety Defaults
RFC1918 / loopback ranges blocked unless --allow-private is set
Target lists > 50 entries require --confirm
All outbound traffic respects --proxy and HTTP_PROXY / HTTPS_PROXY
Conservative default concurrency and rate limits
Plugin Development
See examples/plugin-skeleton/ for a complete example.
recontk doctor

# 5. Run a scan
recontk scan --profile recon --target example.com
