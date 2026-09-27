#!/usr/bin/env bash
# ===========================================================================
# build_freeze.sh — Compile Vespid binaries with cx_Freeze
#
# Usage:
#   ./build_freeze.sh                        # build all
#   ./build_freeze.sh daemon                 # build only vespid daemon
#   ./build_freeze.sh cli                    # build only vespid-cli
#   ./build_freeze.sh server                 # build only vespid-server
#
# Targets: daemon, cli, server, all (default)
# Output:  dist/freeze/
# ===========================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/dist/freeze"

TARGET_NAMES=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        daemon) TARGET_NAMES+=(vespid); shift ;;
        cli)    TARGET_NAMES+=(vespid-cli); shift ;;
        server) TARGET_NAMES+=(vespid-server); shift ;;
        all|"") TARGET_NAMES=(vespid vespid-cli vespid-server); shift ;;
        -h|--help)
            echo "Usage: $0 [daemon|cli|server|all]"; exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done
[[ ${#TARGET_NAMES[@]} -eq 0 ]] && TARGET_NAMES=(vespid vespid-cli vespid-server)

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }
separator() { echo -e "${BOLD}─────────────────────────────────────────────────────${NC}"; }

# ── Build venv ────────────────────────────────────────────────────────
BUILD_VENV="${SCRIPT_DIR}/.build-venv"
PYTHON="${BUILD_VENV}/bin/python3"
PIP="${BUILD_VENV}/bin/pip"

separator
info "Targets: ${TARGET_NAMES[*]}"; echo ""

if [[ ! -d "${BUILD_VENV}" ]]; then
    info "Creating build venv..."
    python3 -m venv "${BUILD_VENV}" || fail "venv failed"
fi

"${PIP}" install -q cx-freeze 2>/dev/null || "${PIP}" install cx-freeze

NEEDS_CLIENT=false; NEEDS_SERVER=false
for t in "${TARGET_NAMES[@]}"; do
    [[ "$t" == vespid || "$t" == vespid-cli ]] && NEEDS_CLIENT=true
    [[ "$t" == vespid-server ]] && NEEDS_SERVER=true
done

if [[ "${NEEDS_CLIENT}" == true ]]; then
    info "Installing client deps..."
    "${PIP}" install -q -e "${SCRIPT_DIR}" 2>/dev/null || "${PIP}" install -e "${SCRIPT_DIR}"
    [[ "$(uname -s)" == "Linux" ]] && "${PIP}" install -q inotify-simple 2>/dev/null || true
    "${PIP}" install -q zstandard 2>/dev/null || true
fi

if [[ "${NEEDS_SERVER}" == true ]]; then
    info "Installing server deps..."
    "${PIP}" install -q -r "${SCRIPT_DIR}/vespid-server/requirements.txt" 2>/dev/null \
        || "${PIP}" install -r "${SCRIPT_DIR}/vespid-server/requirements.txt"
fi

PY_VER=$("${PYTHON}" --version 2>&1)
CX_VER=$("${PYTHON}" -c "import cx_Freeze; print(cx_Freeze.__version__)" 2>/dev/null || echo "?")
info "Python: ${PY_VER}   cx_Freeze: ${CX_VER}"
info "Output: ${OUTPUT_DIR}"; echo ""

# ── Build via Python helper ────────────────────────────────────────────
# Each target runs in its own process so a failure doesn't cascade.
mkdir -p "${OUTPUT_DIR}"

for target in "${TARGET_NAMES[@]}"; do
    separator
    info "Building ${BOLD}${target}${NC}..."
    if "${PYTHON}" "${SCRIPT_DIR}/build_freeze.py" "${target}"; then
        success "${target} built → ${OUTPUT_DIR}/${target}"
    else
        fail "${target} build failed"
    fi
done

# ── Summary ───────────────────────────────────────────────────────────
separator; echo ""
echo -e "${GREEN}${BOLD}Build complete!${NC}"; echo ""
for d in "${OUTPUT_DIR}"/*/; do
    if [[ -d "${d}" ]]; then
        b=$(basename "${d}")
        du -sh "${d}" 2>/dev/null | awk -v name="$b" '{printf "  %s %s  (%s)\n", "\033[32m●\033[0m", name, $1}'
    fi
done
echo ""; separator
