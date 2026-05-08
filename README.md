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
recontk doctor

# 5. Run a scan
recontk scan --profile recon --target example.com
