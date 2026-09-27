#!/usr/bin/env bash
# ===========================================================================
# build_nuitka.sh — Compile Vespid binaries with Nuitka
#
# Usage:
#   ./build_nuitka.sh                        # build all (onefile)
#   ./build_nuitka.sh daemon                 # build only vespid daemon
#   ./build_nuitka.sh cli                    # build only vespid-cli
#   ./build_nuitka.sh server                 # build only vespid-server
#   ./build_nuitka.sh daemon cli             # build daemon + cli
#   ./build_nuitka.sh --standalone server    # standalone mode, server only
#
# Targets: daemon, cli, server, all (default)
# Output:  dist/nuitka/
# ===========================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/dist/nuitka"
LOG_FILE="${OUTPUT_DIR}/build.log"
MODE="--onefile"
TARGETS=()

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --standalone)
            MODE="--standalone"
            shift
            ;;
        --onefile)
            MODE="--onefile"
            shift
            ;;
        daemon|cli|server|all)
            TARGETS+=("$1")
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--standalone|--onefile] [targets...]"
            echo ""
            echo "Targets:"
            echo "  daemon    Build vespid daemon"
            echo "  cli       Build vespid-cli management tool"
            echo "  server    Build vespid-server Flask app"
            echo "  all       Build everything (default)"
            echo ""
            echo "Options:"
            echo "  --onefile      Single executable per target (default)"
            echo "  --standalone   Folder-based build (faster startup)"
            echo ""
            echo "Examples:"
            echo "  $0                       # build all, onefile"
            echo "  $0 server               # build only server"
            echo "  $0 --standalone daemon cli"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1 (use -h for help)"
            exit 1
            ;;
    esac
done

# Default to all targets if none specified
if [[ ${#TARGETS[@]} -eq 0 ]] || [[ " ${TARGETS[*]} " == *" all "* ]]; then
    TARGETS=(daemon cli server)
fi

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

separator() {
    echo -e "${BOLD}─────────────────────────────────────────────────────────────${NC}"
}

elapsed() {
    local start=$1
    local end
    end=$(date +%s)
    local diff=$((end - start))
    local min=$((diff / 60))
    local sec=$((diff % 60))
    echo "${min}m ${sec}s"
}

# ---------------------------------------------------------------------------
# Build venv — self-contained virtual environment for Nuitka compilation
# ---------------------------------------------------------------------------
BUILD_VENV="${SCRIPT_DIR}/.build-venv"
PYTHON="${BUILD_VENV}/bin/python3"
PIP="${BUILD_VENV}/bin/pip"

setup_venv() {
    if [[ ! -d "${BUILD_VENV}" ]]; then
        info "Creating build venv..."
        python3 -m venv "${BUILD_VENV}" || fail "Failed to create venv"
    fi

    # Always ensure Nuitka is installed
    "${PIP}" install -q nuitka ordered-set 2>/dev/null \
        || "${PIP}" install nuitka ordered-set

    # Target-specific dependencies
    NEEDS_CLIENT=false
    NEEDS_SERVER=false
    for t in "${TARGETS[@]}"; do
        [[ "${t}" == "daemon" || "${t}" == "cli" ]] && NEEDS_CLIENT=true
        [[ "${t}" == "server" ]] && NEEDS_SERVER=true
    done

    if [[ "${NEEDS_CLIENT}" == true ]]; then
        info "Installing client deps (typer, rich, httpx, inotify, zstd...)..."
        "${PIP}" install -q -e "${SCRIPT_DIR}" 2>/dev/null || "${PIP}" install -e "${SCRIPT_DIR}"
        if [[ "$(uname -s)" == "Linux" ]]; then
            "${PIP}" install -q inotify-simple 2>/dev/null || "${PIP}" install inotify-simple
        fi
        "${PIP}" install -q zstandard 2>/dev/null || "${PIP}" install zstandard
    fi

    if [[ "${NEEDS_SERVER}" == true ]]; then
        info "Installing server deps (Flask, pydantic, redis...)..."
        "${PIP}" install -q -r "${SCRIPT_DIR}/vespid-server/requirements.txt" 2>/dev/null \
            || "${PIP}" install -r "${SCRIPT_DIR}/vespid-server/requirements.txt"

        # Add vespid-server/ to the build venv's sys.path so Nuitka can resolve
        # --include-package=app and the vespid_server module at compile time.
        local SITE_PKG
        SITE_PKG=$("${PYTHON}" -c "import site; print(site.getsitepackages()[0])")
        echo "${SCRIPT_DIR}/vespid-server" > "${SITE_PKG}/vespid-server.pth"
    fi
}

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
separator
if [[ "${MODE}" == "--standalone" ]]; then
    info "Build mode: standalone (folder per binary)"
else
    info "Build mode: onefile (single executable)"
fi
info "Targets:  ${TARGETS[*]}"
echo ""
info "Preflight checks..."

command -v python3 >/dev/null 2>&1 || fail "python3 not found in PATH"
command -v cc >/dev/null 2>&1 || fail "C compiler (cc) not found. Install: yum groupinstall 'Development Tools' (RHEL) / apt install build-essential (Debian)"

# Python dev headers (needed by Nuitka to compile C extension modules)
PYTHON_INCLUDE=$(python3 -c "import sysconfig; print(sysconfig.get_config_var('INCLUDEPY'))" 2>/dev/null)
if [[ -z "${PYTHON_INCLUDE}" ]] || [[ ! -d "${PYTHON_INCLUDE}" ]]; then
    fail "Python development headers not found (INCLUDEPY=${PYTHON_INCLUDE:-<empty>}). Install: yum install python3-devel (RHEL) / apt install python3-dev (Debian)"
fi

# patchelf is required by Nuitka for --onefile mode on Linux
if [[ "${MODE}" == "--onefile" ]]; then
    command -v patchelf >/dev/null 2>&1 || fail "patchelf not found (required for --onefile mode). Install: yum install patchelf (RHEL) / apt install patchelf (Debian)"
fi

# Set up the build venv (creates + installs deps)
setup_venv

PYTHON_VER=$("${PYTHON}" --version 2>&1)
NUITKA_VER=$("${PYTHON}" -m nuitka --version 2>&1 | head -1)

info "Python:  ${PYTHON_VER}"
info "Nuitka:  ${NUITKA_VER}"
info "Output:  ${OUTPUT_DIR}"

# ---------------------------------------------------------------------------
# Prepare output directory
# ---------------------------------------------------------------------------
mkdir -p "${OUTPUT_DIR}"
: > "${LOG_FILE}"

# ---------------------------------------------------------------------------
# Extra includes for dynamic imports
#
# Nuitka's static analysis finds top-level imports automatically, but misses
# modules imported inside function bodies, conditionals, or try/except blocks.
# We list those here so they're bundled into the binary.
# ---------------------------------------------------------------------------
EXTRA_INCLUDES_CLIENT=(
    --include-module=typer
    --include-package=rich
    --include-module=click
    --include-module=httpx
    --include-module=httpcore
    --include-module=inotify_simple
    --include-module=zstandard
    --include-package=vespid.cli
)

# Third-party modules imported lazily (inside functions / if-blocks) by the server.
# Ordered by likelihood of being missed: maxminddb and redis are inside
# try/except blocks; mysql.connector and yaml are behind optional-feature branches.
# gevent/greenlet are used by connection_debug blueprint at runtime.
EXTRA_INCLUDES_SERVER=(
    --include-module=jinja2.ext
    --include-module=markupsafe
    --include-module=werkzeug.serving
    --include-module=flask_login
    --include-module=flask_limiter
    --include-module=maxminddb
    --include-module=redis
    --include-module=mysql.connector
    --include-module=yaml
    --include-module=gevent
    --include-module=greenlet
)

# Build flags shared by all server builds
BASE_SERVER_FLAGS=(
    --include-package=app
    "${EXTRA_INCLUDES_SERVER[@]}"
    --include-data-dir="${SCRIPT_DIR}/vespid-server/app/templates=app/templates"
    --include-data-dir="${SCRIPT_DIR}/vespid-server/app/static=app/static"
    --include-data-dir="${SCRIPT_DIR}/vespid-server/packs=packs"
    --include-data-dir="${SCRIPT_DIR}/data=data"
    --nofollow-import-to=gunicorn
)

# ---------------------------------------------------------------------------
# Build functions
# ---------------------------------------------------------------------------
build_daemon() {
    separator
    info "Building ${BOLD}vespid${NC} (daemon)..."
    local start
    start=$(date +%s)

    "${PYTHON}" -m nuitka \
        ${MODE} \
        --include-package=vespid \
        "${EXTRA_INCLUDES_CLIENT[@]}" \
        --include-data-dir="${SCRIPT_DIR}/data=data" \
        --output-dir="${OUTPUT_DIR}" \
        --output-filename=vespid \
        --remove-output \
        --assume-yes-for-downloads \
        "${SCRIPT_DIR}/entry_vespid.py" \
        >> "${LOG_FILE}" 2>&1 \
        && success "vespid built ($(elapsed ${start}))" \
        || fail "vespid build failed — check ${LOG_FILE}"
}

build_cli() {
    separator
    info "Building ${BOLD}vespid-cli${NC} (management CLI)..."
    local start
    start=$(date +%s)

    "${PYTHON}" -m nuitka \
        ${MODE} \
        --include-package=vespid \
        "${EXTRA_INCLUDES_CLIENT[@]}" \
        --include-data-dir="${SCRIPT_DIR}/data=data" \
        --output-dir="${OUTPUT_DIR}" \
        --output-filename=vespid-cli \
        --remove-output \
        --assume-yes-for-downloads \
        "${SCRIPT_DIR}/entry_vespid_cli.py" \
        >> "${LOG_FILE}" 2>&1 \
        && success "vespid-cli built ($(elapsed ${start}))" \
        || fail "vespid-cli build failed — check ${LOG_FILE}"
}

build_server() {
    separator
    info "Building ${BOLD}vespid-server${NC} (Flask dashboard)..."
    local start
    start=$(date +%s)

    "${PYTHON}" -m nuitka \
        ${MODE} \
        "${BASE_SERVER_FLAGS[@]}" \
        --output-dir="${OUTPUT_DIR}" \
        --output-filename=vespid-server \
        --remove-output \
        --assume-yes-for-downloads \
        "${SCRIPT_DIR}/entry_vespid_server.py" \
        >> "${LOG_FILE}" 2>&1 \
        && success "vespid-server built ($(elapsed ${start}))" \
        || fail "vespid-server build failed — check ${LOG_FILE}"
}

# ---------------------------------------------------------------------------
# Run selected builds
# ---------------------------------------------------------------------------
BUILT=()

for target in "${TARGETS[@]}"; do
    case "$target" in
        daemon) build_daemon; BUILT+=(vespid) ;;
        cli)    build_cli;    BUILT+=(vespid-cli) ;;
        server) build_server; BUILT+=(vespid-server) ;;
    esac
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
separator
echo ""
echo -e "${GREEN}${BOLD}Build complete!${NC}"
echo ""
echo -e "  Output directory: ${BOLD}${OUTPUT_DIR}${NC}"
echo ""

echo -e "  ${BOLD}Binaries:${NC}"
for bin in "${BUILT[@]}"; do
    if [[ "${MODE}" == "--onefile" ]]; then
        if [[ -f "${OUTPUT_DIR}/${bin}" ]]; then
            SIZE=$(du -h "${OUTPUT_DIR}/${bin}" | cut -f1)
            echo -e "    ${GREEN}${bin}  (${SIZE})"
        else
            echo -e "    ${RED}${bin}  (missing)"
        fi
    else
        if [[ -d "${OUTPUT_DIR}/${bin}.dist" ]]; then
            SIZE=$(du -sh "${OUTPUT_DIR}/${bin}.dist" | cut -f1)
            echo -e "    ${GREEN}${bin}.dist/  (${SIZE})"
        else
            echo -e "    ${RED}${bin}.dist/  (missing)"
        fi
    fi
done

echo ""
echo -e "  ${BOLD}Build log:${NC} ${LOG_FILE}"
echo ""
separator
