#!/usr/bin/env bash
# recontk/scripts/install.sh
# Idempotent installer for the Python package.
# Exits non-zero if required Python version is not met.
#
# AUTHORIZED USE ONLY — see README.md

set -euo pipefail

REQUIRED_PYTHON_MAJOR=3
REQUIRED_PYTHON_MINOR=11

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[install]${NC} $*"; }
warn()    { echo -e "${YELLOW}[install]${NC} $*"; }
error()   { echo -e "${RED}[install]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Python version check
# ---------------------------------------------------------------------------
PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" &>/dev/null; then
    die "Python interpreter not found. Set PYTHON= or install python3 >= ${REQUIRED_PYTHON_MAJOR}.${REQUIRED_PYTHON_MINOR}."
fi

PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$("$PYTHON" -c "import sys; print(sys.version_info.major)")
PY_MINOR=$("$PYTHON" -c "import sys; print(sys.version_info.minor)")

if [[ "$PY_MAJOR" -lt "$REQUIRED_PYTHON_MAJOR" ]] || \
   [[ "$PY_MAJOR" -eq "$REQUIRED_PYTHON_MAJOR" && "$PY_MINOR" -lt "$REQUIRED_PYTHON_MINOR" ]]; then
    die "Python ${REQUIRED_PYTHON_MAJOR}.${REQUIRED_PYTHON_MINOR}+ required; found ${PY_VERSION}."
fi

info "Python ${PY_VERSION} OK"

# ---------------------------------------------------------------------------
# Virtual environment
# ---------------------------------------------------------------------------
VENV_DIR="${VENV_DIR:-.venv}"

if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment at ${VENV_DIR}"
    "$PYTHON" -m venv "$VENV_DIR"
else
    info "Virtual environment already exists at ${VENV_DIR}"
fi

# Activate
# shellcheck disable=SC1090
source "${VENV_DIR}/bin/activate"

# ---------------------------------------------------------------------------
# Upgrade pip + install package
# ---------------------------------------------------------------------------
info "Upgrading pip"
pip install --quiet --upgrade pip

info "Installing recontk (editable)"
pip install --quiet -e ".[dev]"

# ---------------------------------------------------------------------------
# Verify entry-point
# ---------------------------------------------------------------------------
if ! command -v recontk &>/dev/null; then
    die "recontk entry-point not found after install. Check pyproject.toml."
fi

info "recontk installed: $(recontk --version 2>/dev/null || echo '(version flag not yet available)')"
info "Run 'recontk doctor' to check external tool availability."
info ""
info "AUTHORIZED USE ONLY: scan only systems you own or have written permission to scan."
