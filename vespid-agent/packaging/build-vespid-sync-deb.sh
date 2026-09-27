#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="1.0.0"
PACKAGE="vespid-sync"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo "amd64")"
DEB_NAME="${PACKAGE}_${VERSION}_${ARCH}.deb"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Build a .deb package for the Vespid Sync Agent.

Options:
  -o, --output DIR  Output directory for .deb (default: $SCRIPT_DIR)
  --help            Show this help

Prerequisites (build host):
  - dpkg-deb, python3
EOF
    exit 0
}

err()  { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; exit 1; }
log()  { printf "${GREEN}[INFO]${NC} %s\n" "$*" >&2; }

check_prereqs() {
    for cmd in dpkg-deb python3; do
        command -v "$cmd" &>/dev/null || err "$cmd is required but not installed"
    done
}

build_deb() {
    local out_dir="$1"
    local tmpdir
    tmpdir=$(mktemp -d)
    local debdir="${tmpdir}/${PACKAGE}_${VERSION}"
    local installdir="${debdir}/opt/vespid-sync"
    local configdir="${debdir}/etc/vespid-sync"
    local unitdir="${debdir}/lib/systemd/system"

    log "Building .deb package: $DEB_NAME"

    # Create directory structure
    mkdir -p "$debdir/DEBIAN"
    mkdir -p "$installdir/providers"
    mkdir -p "$configdir"
    mkdir -p "$unitdir"

    # Copy source files
    cp -a "$PROJECT_DIR/vespid-sync/sync.py" "$installdir/sync.py"
    cp -a "$PROJECT_DIR/vespid-sync/providers/" "$installdir/providers/"
    cp -a "$PROJECT_DIR/vespid-sync/setup.py" "$installdir/setup.py"

    # Install default config
    cp -a "$PROJECT_DIR/vespid-sync/config.yaml.example" "$configdir/config.yaml"
    chmod 600 "$configdir/config.yaml"

    # Install systemd units
    cp -a "$PROJECT_DIR/systemd/vespid-sync-agent.service" "$unitdir/"
    cp -a "$PROJECT_DIR/systemd/vespid-sync-agent.timer" "$unitdir/"

    # --- DEBIAN/control ---
    cat > "$debdir/DEBIAN/control" <<CONTROL
Package: vespid-sync
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Depends: python3 (>= 3.9), python3-venv
Maintainer: Vespid Team <dev@vespid.io>
Description: Vespid Sync Agent — infrastructure asset discovery
 Discovers infrastructure assets from hypervisors (Proxmox, VMware, etc.)
 and pushes them to the Vespid inventory service. Runs every 5 minutes
 via systemd timer.
 .
 Supports:
  - Proxmox PVE (QEMU VMs + LXC containers)
  - Hypervisor node discovery
  - Guest agent data (hostname, IPs, MAC addresses)
  - Resource pool mapping
  - Entity resolution against existing assets
CONTROL

    # --- DEBIAN/conffiles ---
    cat > "$debdir/DEBIAN/conffiles" <<CONFFILES
/etc/vespid-sync/config.yaml
CONFFILES

    # --- DEBIAN/postinst ---
    cat > "$debdir/DEBIAN/postinst" <<'POSTINST'
#!/bin/bash
set -e

INSTALL_DIR="/opt/vespid-sync"

case "$1" in
    configure)
        # Create log directory
        mkdir -p /var/log/vespid-sync
        chmod 750 /var/log/vespid-sync

        # Create virtual environment and install dependencies
        python3 -m venv --system-site-packages "$INSTALL_DIR/.venv"
        "$INSTALL_DIR/.venv/bin/pip" install --no-cache-dir \
            requests pyyaml proxmoxer 2>&1 || true

        # Reload systemd
        systemctl daemon-reload 2>/dev/null || true

        echo ""
        echo "=== Vespid Sync Agent installed ==="
        echo ""
        echo "1. Create an API key in the Vespid dashboard"
        echo "   (Admin -> API Keys -> Create Key -> role: agent)"
        echo ""
        echo "2. Edit /etc/vespid-sync/config.yaml and set:"
        echo "   - sync.server_url (your Vespid server)"
        echo "   - sync.api_key (the key you created)"
        echo "   - providers[].token_id and token_secret (Proxmox credentials)"
        echo ""
        echo "3. Enable and start the timer:"
        echo "   systemctl enable --now vespid-sync-agent.timer"
        echo ""
        echo "   To test discovery without waiting for the timer:"
        echo "   systemctl start vespid-sync-agent"
        echo ""
        ;;
esac
POSTINST

    # --- DEBIAN/prerm ---
    cat > "$debdir/DEBIAN/prerm" <<'PRERM'
#!/bin/bash
set -e

case "$1" in
    remove|purge)
        # Stop and disable systemd units
        systemctl stop vespid-sync-agent.timer 2>/dev/null || true
        systemctl stop vespid-sync-agent.service 2>/dev/null || true
        systemctl disable vespid-sync-agent.timer 2>/dev/null || true
        systemctl disable vespid-sync-agent.service 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
        ;;
esac
PRERM

    # --- DEBIAN/postrm ---
    cat > "$debdir/DEBIAN/postrm" <<'POSTRM'
#!/bin/bash
set -e

case "$1" in
    purge)
        rm -rf /opt/vespid-sync
        rm -rf /var/log/vespid-sync
        ;;
esac
POSTRM

    # Make maintainer scripts executable
    chmod 755 "$debdir/DEBIAN/postinst"
    chmod 755 "$debdir/DEBIAN/prerm"
    chmod 755 "$debdir/DEBIAN/postrm"

    # Build the .deb
    fakeroot dpkg-deb --build "$debdir" "$out_dir/$DEB_NAME"

    rm -rf "$tmpdir"

    echo ""
    log "DEB built:"
    echo "    $out_dir/$DEB_NAME"
    echo ""
    log "Install:"
    echo "    sudo dpkg -i $out_dir/$DEB_NAME"
    echo "    sudo apt-get install -f   # install dependencies if missing"
}

main() {
    local output_dir="$SCRIPT_DIR"

    while [ $# -gt 0 ]; do
        case "$1" in
            -o|--output) output_dir="$2"; shift 2 ;;
            --help)      usage ;;
            *) err "Unknown option: $1" ;;
        esac
    done

    mkdir -p "$output_dir"

    check_prereqs
    build_deb "$output_dir"

    log "Done!"
}

main "$@"
