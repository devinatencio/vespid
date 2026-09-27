#!/usr/bin/env bash
# ===========================================================================
# build_deb.sh — Build .deb packages for Vespid (client + server)
#
# Usage:
#   ./build_deb.sh              # build both packages
#   ./build_deb.sh client       # build only vespid client package
#   ./build_deb.sh server       # build only vespid-server package
#
# Output: dist/deb/
# ===========================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/dist/deb"
VERSION="$(cat "${SCRIPT_DIR}/vespid-server/VERSION" 2>/dev/null || echo 1.0.0)"
TARGETS=()

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        client|server|all)
            TARGETS+=("$1")
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [targets...]"
            echo ""
            echo "Targets:"
            echo "  client    Build vespid client .deb (daemon + CLI)"
            echo "  server    Build vespid-server .deb (Flask dashboard)"
            echo "  all       Build both packages (default)"
            echo ""
            echo "Output: dist/deb/"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1 (use -h for help)"
            exit 1
            ;;
    esac
done

# Default to all targets
if [[ ${#TARGETS[@]} -eq 0 ]] || [[ " ${TARGETS[*]} " == *" all "* ]]; then
    TARGETS=(client server)
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

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

separator() {
    echo -e "${BOLD}─────────────────────────────────────────────────────────────${NC}"
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
separator
info "Vespid .deb Package Builder"
info "Version: ${VERSION}"
info "Targets: ${TARGETS[*]}"
echo ""

# Check for dpkg-deb (available on Debian/Ubuntu, or via dpkg on macOS with brew)
if ! command -v dpkg-deb >/dev/null 2>&1; then
    if command -v fakeroot >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
        : # OK
    else
        fail "dpkg-deb not found. Install dpkg (apt install dpkg or brew install dpkg)"
    fi
fi

# ---------------------------------------------------------------------------
# Clean output
# ---------------------------------------------------------------------------
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

# ===========================================================================
# Build vespid client .deb
# ===========================================================================
build_client() {
    separator
    info "Building ${BOLD}vespid_${VERSION}_all.deb${NC} ..."

    local PKG_ROOT="${OUTPUT_DIR}/vespid_${VERSION}_all"
    rm -rf "${PKG_ROOT}"

    # -- DEBIAN control files --
    mkdir -p "${PKG_ROOT}/DEBIAN"
    cp "${SCRIPT_DIR}/debian/vespid/DEBIAN/control"   "${PKG_ROOT}/DEBIAN/"
    cp "${SCRIPT_DIR}/debian/vespid/DEBIAN/conffiles" "${PKG_ROOT}/DEBIAN/"
    cp "${SCRIPT_DIR}/debian/vespid/DEBIAN/postinst"  "${PKG_ROOT}/DEBIAN/"
    cp "${SCRIPT_DIR}/debian/vespid/DEBIAN/prerm"     "${PKG_ROOT}/DEBIAN/"
    cp "${SCRIPT_DIR}/debian/vespid/DEBIAN/postrm"    "${PKG_ROOT}/DEBIAN/"
    chmod 0755 "${PKG_ROOT}/DEBIAN/postinst"
    chmod 0755 "${PKG_ROOT}/DEBIAN/prerm"
    chmod 0755 "${PKG_ROOT}/DEBIAN/postrm"

    # -- Application files: /opt/vespid/ --
    local APP_DIR="${PKG_ROOT}/opt/vespid"
    mkdir -p "${APP_DIR}"
    cp -a "${SCRIPT_DIR}/vespid" "${APP_DIR}/"
    cp "${SCRIPT_DIR}/pyproject.toml" "${APP_DIR}/"

    # Country-code data (used by vespid.cli.app's country_name filter)
    mkdir -p "${APP_DIR}/data"
    cp "${SCRIPT_DIR}/data/country_codes.json" "${APP_DIR}/data/"

    # Remove __pycache__ from packaged source
    find "${APP_DIR}" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

    # -- Configuration: /etc/vespid/ --
    local CONF_DIR="${PKG_ROOT}/etc/vespid"
    mkdir -p "${CONF_DIR}"
    cp "${SCRIPT_DIR}/config/vespid-normal-mode.yml" "${CONF_DIR}/vespid.yaml"
    cp "${SCRIPT_DIR}/config/vespid-fully-managed.yml" "${CONF_DIR}/vespid-managed.yaml.example"
    cp "${SCRIPT_DIR}/config/auditd-execve.rules" "${CONF_DIR}/auditd-execve.rules"
    chmod 0640 "${CONF_DIR}/vespid.yaml"
    chmod 0640 "${CONF_DIR}/vespid-managed.yaml.example"
    chmod 0644 "${CONF_DIR}/auditd-execve.rules"

    # -- Systemd unit: /lib/systemd/system/ --
    mkdir -p "${PKG_ROOT}/lib/systemd/system"
    cp "${SCRIPT_DIR}/vespid.service" "${PKG_ROOT}/lib/systemd/system/"

    # -- rsyslog drop-in: /etc/rsyslog.d/ --
    # Stops rsyslog from mirroring vespid's own log lines into /var/log/syslog
    # (and /var/log/messages on RHEL-family) via journald, avoiding a
    # self-tailing feedback loop. Requires SyslogIdentifier=vespid in the unit.
    mkdir -p "${PKG_ROOT}/etc/rsyslog.d"
    cp "${SCRIPT_DIR}/packaging/20-vespid.conf" "${PKG_ROOT}/etc/rsyslog.d/"

    # -- CLI wrappers: /usr/bin/ --
    mkdir -p "${PKG_ROOT}/usr/bin"

    cat > "${PKG_ROOT}/usr/bin/vespid" <<'WRAPPER'
#!/bin/bash
# Vespid daemon wrapper
export PYTHONPATH=/opt/vespid
exec /opt/vespid/.venv/bin/python -m vespid.daemon "$@"
WRAPPER
    chmod 0755 "${PKG_ROOT}/usr/bin/vespid"

    cat > "${PKG_ROOT}/usr/bin/vespid-cli" <<'WRAPPER'
#!/bin/bash
# Vespid local management CLI wrapper
export PYTHONPATH=/opt/vespid
exec /opt/vespid/.venv/bin/python -m vespid.cli "$@"
WRAPPER
    chmod 0755 "${PKG_ROOT}/usr/bin/vespid-cli"

    # -- State and log directories --
    mkdir -p "${PKG_ROOT}/var/lib/vespid"
    mkdir -p "${PKG_ROOT}/var/log/vespid"

    # -- License / copyright --
    mkdir -p "${PKG_ROOT}/usr/share/doc/vespid"
    cp "${SCRIPT_DIR}/LICENSE" "${PKG_ROOT}/usr/share/doc/vespid/copyright"

    # -- Build the .deb --
    dpkg-deb --build --root-owner-group "${PKG_ROOT}" \
        "${OUTPUT_DIR}/vespid_${VERSION}_all.deb"

    # Clean up staging
    rm -rf "${PKG_ROOT}"

    success "vespid_${VERSION}_all.deb"
}

# ===========================================================================
# Build vespid-server .deb
# ===========================================================================
build_server() {
    separator
    info "Building ${BOLD}vespid-server_${VERSION}_all.deb${NC} ..."

    local PKG_ROOT="${OUTPUT_DIR}/vespid-server_${VERSION}_all"
    rm -rf "${PKG_ROOT}"

    # -- DEBIAN control files --
    mkdir -p "${PKG_ROOT}/DEBIAN"
    cp "${SCRIPT_DIR}/debian/vespid-server/DEBIAN/control"   "${PKG_ROOT}/DEBIAN/"
    cp "${SCRIPT_DIR}/debian/vespid-server/DEBIAN/conffiles" "${PKG_ROOT}/DEBIAN/"
    cp "${SCRIPT_DIR}/debian/vespid-server/DEBIAN/preinst"   "${PKG_ROOT}/DEBIAN/"
    cp "${SCRIPT_DIR}/debian/vespid-server/DEBIAN/postinst"  "${PKG_ROOT}/DEBIAN/"
    cp "${SCRIPT_DIR}/debian/vespid-server/DEBIAN/prerm"     "${PKG_ROOT}/DEBIAN/"
    cp "${SCRIPT_DIR}/debian/vespid-server/DEBIAN/postrm"    "${PKG_ROOT}/DEBIAN/"
    chmod 0755 "${PKG_ROOT}/DEBIAN/preinst"
    chmod 0755 "${PKG_ROOT}/DEBIAN/postinst"
    chmod 0755 "${PKG_ROOT}/DEBIAN/prerm"
    chmod 0755 "${PKG_ROOT}/DEBIAN/postrm"

    # -- Application files: /opt/vespid-server/ --
    local APP_DIR="${PKG_ROOT}/opt/vespid-server"
    mkdir -p "${APP_DIR}"
    cp -a "${SCRIPT_DIR}/vespid-server/app" "${APP_DIR}/"
    cp -a "${SCRIPT_DIR}/vespid-server/packs" "${APP_DIR}/"
    cp "${SCRIPT_DIR}/vespid-server/vespid_server.py" "${APP_DIR}/"
    cp "${SCRIPT_DIR}/vespid-server/gunicorn.conf.py" "${APP_DIR}/"
    cp "${SCRIPT_DIR}/vespid-server/requirements.txt" "${APP_DIR}/"
    cp "${SCRIPT_DIR}/vespid-server/schema_mysql.sql" "${APP_DIR}/"
    cp "${SCRIPT_DIR}/vespid-server/CHANGELOG.md" "${APP_DIR}/"

    # Country-code data (required at import time by app.country_codes)
    mkdir -p "${APP_DIR}/data"
    cp "${SCRIPT_DIR}/data/country_codes.json" "${APP_DIR}/data/"

    # Remove __pycache__ from packaged source
    find "${APP_DIR}" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    # Strip macOS metadata junk (AppleDouble companions, .DS_Store, __MACOSX)
    find "${APP_DIR}" -name '._*' -delete 2>/dev/null || true
    find "${APP_DIR}" -name '.DS_Store' -delete 2>/dev/null || true
    find "${APP_DIR}" -type d -name '__MACOSX' -exec rm -rf {} + 2>/dev/null || true

    # -- Configuration: /etc/vespid-server/ --
    local CONF_DIR="${PKG_ROOT}/etc/vespid-server"
    mkdir -p "${CONF_DIR}"
    cp "${SCRIPT_DIR}/vespid-server/config.example.yaml" "${CONF_DIR}/config.yaml"
    chmod 0640 "${CONF_DIR}/config.yaml"

    # Environment file for systemd overrides
    cat > "${CONF_DIR}/environment" <<'EOF'
# Environment overrides for vespid-server.service
# See gunicorn.conf.py for full documentation on each setting.
#
# Uncomment ONE section below based on your database backend.

# --- SQLite backend (gevent) ---
# SQLite serializes writes, so keep workers minimal. Gevent still helps
# because SSE and reads don't block each other.
# GUNICORN_WORKERS=1
# GUNICORN_WORKER_CONNECTIONS=1000

# --- MySQL / MariaDB backend (gevent) ---
# One worker per CPU core. Gevent handles concurrency within each worker.
# For a 2-core box use 2, for 4-core use 4.
# GUNICORN_WORKERS=2
# GUNICORN_WORKER_CONNECTIONS=1000

# --- Common settings (apply regardless of backend) ---
# GUNICORN_BIND=127.0.0.1:8000
# GUNICORN_WORKER_CLASS=gevent
# GUNICORN_TIMEOUT=120
# GUNICORN_KEEPALIVE=65
# GUNICORN_MAX_REQUESTS=8000
# GUNICORN_MAX_REQUESTS_JITTER=800
EOF
    chmod 0640 "${CONF_DIR}/environment"

    # GeoIP database directory with DB-IP Lite databases (CC BY 4.0)
    mkdir -p "${CONF_DIR}/geoip"
    # Download DB-IP Lite databases if not already present
    local GEOIP_TMP="/tmp/vespid-server-geoip"
    if ! ls "${GEOIP_TMP}"/dbip-*.mmdb >/dev/null 2>&1; then
        info "Downloading DB-IP Lite GeoIP databases ..."
        rm -rf "${GEOIP_TMP}"
        bash "${SCRIPT_DIR}/vespid-server/download_geoip.sh" "${GEOIP_TMP}"
    fi
    if ls "${GEOIP_TMP}"/dbip-*.mmdb >/dev/null 2>&1; then
        cp -a "${GEOIP_TMP}"/dbip-*.mmdb "${CONF_DIR}/geoip/"
    else
        warn "No GeoIP databases found — package will be built without them"
    fi

    # -- Systemd unit: /lib/systemd/system/ --
    mkdir -p "${PKG_ROOT}/lib/systemd/system"
    cp "${SCRIPT_DIR}/vespid-server/vespid-server.service" "${PKG_ROOT}/lib/systemd/system/"

    # -- CLI wrapper: /usr/bin/ --
    mkdir -p "${PKG_ROOT}/usr/bin"
    cat > "${PKG_ROOT}/usr/bin/vespid-server-admin" <<'WRAPPER'
#!/bin/bash
# Wrapper for vespid_server.py CLI commands.
CONFIG_DIR="/etc/vespid-server"
CONFIG=""
for candidate in "$CONFIG_DIR/config.yaml" "$CONFIG_DIR/config.yml" "$CONFIG_DIR/config.json"; do
    if [ -f "$candidate" ]; then
        CONFIG="$candidate"
        break
    fi
done
if [ -z "$CONFIG" ]; then
    echo "Warning: no config file found in $CONFIG_DIR, using defaults" >&2
fi
exec /opt/vespid-server/.venv/bin/python \
    /opt/vespid-server/vespid_server.py \
    ${CONFIG:+--config "$CONFIG"} "$@"
WRAPPER
    chmod 0755 "${PKG_ROOT}/usr/bin/vespid-server-admin"

    # -- Data and log directories --
    mkdir -p "${PKG_ROOT}/var/lib/vespid-server"
    mkdir -p "${PKG_ROOT}/var/log/vespid-server"

    # -- License / copyright --
    mkdir -p "${PKG_ROOT}/usr/share/doc/vespid-server"
    cp "${SCRIPT_DIR}/LICENSE" "${PKG_ROOT}/usr/share/doc/vespid-server/copyright"

    # -- Build the .deb --
    dpkg-deb --build --root-owner-group "${PKG_ROOT}" \
        "${OUTPUT_DIR}/vespid-server_${VERSION}_all.deb"

    # Clean up staging
    rm -rf "${PKG_ROOT}"

    success "vespid-server_${VERSION}_all.deb"
}

# ===========================================================================
# Run selected builds
# ===========================================================================
for target in "${TARGETS[@]}"; do
    case "$target" in
        client) build_client ;;
        server) build_server ;;
    esac
done

# ===========================================================================
# Summary
# ===========================================================================
separator
echo ""
echo -e "${GREEN}${BOLD}✅ Build complete!${NC}"
echo ""
echo -e "  Output directory: ${BOLD}${OUTPUT_DIR}${NC}"
echo ""
echo -e "  ${BOLD}Packages:${NC}"
for deb in "${OUTPUT_DIR}"/*.deb; do
    if [[ -f "$deb" ]]; then
        SIZE=$(du -h "$deb" | cut -f1)
        echo -e "    ${GREEN}●${NC} $(basename "$deb")  (${SIZE})"
    fi
done
echo ""
echo -e "  ${BOLD}Install:${NC}"
echo -e "    sudo dpkg -i ${OUTPUT_DIR}/vespid_${VERSION}_all.deb"
echo -e "    sudo dpkg -i ${OUTPUT_DIR}/vespid-server_${VERSION}_all.deb"
echo ""
echo -e "  ${BOLD}Or install both:${NC}"
echo -e "    sudo dpkg -i ${OUTPUT_DIR}/*.deb"
echo -e "    sudo apt-get install -f   # resolve any missing dependencies"
echo ""
separator
