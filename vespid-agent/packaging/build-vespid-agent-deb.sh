#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="1.0.0"
PACKAGE="vespid-agent"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo "amd64")"
DEB_NAME="${PACKAGE}_${VERSION}_${ARCH}.deb"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Build a .deb package for the Vespid Agent.

Options:
  -o, --output DIR  Output directory for .deb (default: $SCRIPT_DIR)
  --help            Show this help

Prerequisites (build host):
  - rustc, cargo, protobuf-compiler
  - dpkg-deb, fakeroot
EOF
    exit 0
}

err()  { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; exit 1; }
log()  { printf "${GREEN}[INFO]${NC} %s\n" "$*" >&2; }

check_prereqs() {
    for cmd in dpkg-deb cargo rustc; do
        command -v "$cmd" &>/dev/null || err "$cmd is required but not installed"
    done
    command -v fakeroot &>/dev/null || err "fakeroot is required but not installed"
}

build_deb() {
    local out_dir="$1"
    local tmpdir
    tmpdir=$(mktemp -d)
    local debdir="${tmpdir}/${PACKAGE}_${VERSION}_${ARCH}"
    local unitdir="${debdir}/lib/systemd/system"

    log "Building .deb package: $DEB_NAME"

    # Build the Rust binary
    log "Compiling vespid-agent (release)..."
    cd "$PROJECT_DIR"
    cargo build --release --bin vespid-agent

    # Create directory structure
    mkdir -p "$debdir/DEBIAN"
    mkdir -p "$debdir/usr/bin"
    mkdir -p "$debdir/etc/vespid-agent"
    mkdir -p "$debdir/var/lib/vespid-agent"
    mkdir -p "$debdir/var/log/vespid-agent"
    mkdir -p "$unitdir"

    # Install binary
    install -D -m 755 target/release/vespid-agent "$debdir/usr/bin/vespid-agent"

    # Install systemd units
    install -D -m 644 "$PROJECT_DIR/systemd/vespid-agent.service" "$unitdir/"
    install -D -m 644 "$PROJECT_DIR/systemd/vespid-worker.service" "$unitdir/"

    # Install default agent config
    cat > "$debdir/etc/vespid-agent/agent.yaml" <<CONFIGEOF
log_level: "info"
log_retention_days: 30

server:
  url: "https://localhost:8443"
  api_key: ""

agent:
  labels: {}

collectors:
  cpu:
    enabled: true
    interval_secs: 60
  memory:
    enabled: true
    interval_secs: 60
  disk:
    enabled: true
    interval_secs: 60
  network:
    enabled: true
    interval_secs: 60
    exclude_interfaces:
      - "lo"
  systemd:
    enabled: true
    interval_secs: 60
  process:
    enabled: true
    interval_secs: 120
    top_n: 20
  psi:
    enabled: true
    interval_secs: 60
  loadavg:
    enabled: true
    interval_secs: 60
  procfs:
    enabled: false
    interval_secs: 60
    metrics: []
  exec:
    enabled: false
    interval_secs: 300
    timeout_secs: 30
    scripts: []

buffer:
  path: "/var/lib/vespid-agent/buffer"
  max_total_size: 67108864
  max_file_size: 8388608

transport:
  batch_size: 500
  flush_interval_secs: 30
  request_timeout_secs: 30
CONFIGEOF
    chmod 640 "$debdir/etc/vespid-agent/agent.yaml"

    # Install default worker config
    cat > "$debdir/etc/vespid-agent/worker.yaml" <<WORKEREOF
server:
  url: "https://localhost:8443"
  api_key: ""

agent:
  labels: {}

worker:
  capabilities: ["http", "icmp", "tcp", "dns"]
  labels:
    location: "default"
  max_concurrent: 10
  poll_interval_secs: 5
WORKEREOF
    chmod 640 "$debdir/etc/vespid-agent/worker.yaml"

    # --- DEBIAN/control ---
    cat > "$debdir/DEBIAN/control" <<CONTROL
Package: vespid-agent
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Depends: systemd
Maintainer: Vespid Team <dev@vespid.io>
Description: Vespid Agent — system metrics collection agent
 Collects system metrics (CPU, memory, disk, network, systemd, process,
 PSI, load average) from Linux hosts and ships them to a Vespid server.
 .
 Lightweight, secure Rust-based agent with zero-touch auto-enrollment
 and offline-local buffering for network resilience.
 .
 Features:
  - 10 built-in collectors with configurable intervals
  - HTTP batch transport with Prometheus remote write format
  - Local file buffer for offline resilience
  - systemd watchdog integration
  - Synthetic monitoring worker mode (HTTP, ICMP, TCP, DNS)
CONTROL

    # --- DEBIAN/conffiles ---
    cat > "$debdir/DEBIAN/conffiles" <<CONFFILES
/etc/vespid-agent/agent.yaml
/etc/vespid-agent/worker.yaml
CONFFILES

    # --- DEBIAN/preinst ---
    cat > "$debdir/DEBIAN/preinst" <<'PREINST'
#!/bin/bash
set -e

case "$1" in
    install|upgrade)
        # Create vespid-agent user and group if they don't exist
        if ! getent group vespid-agent &>/dev/null; then
            groupadd -r vespid-agent
        fi
        if ! getent passwd vespid-agent &>/dev/null; then
            useradd -r -g vespid-agent -d /var/lib/vespid-agent -s /sbin/nologin vespid-agent
        fi
        ;;
esac
PREINST

    # --- DEBIAN/postinst ---
    cat > "$debdir/DEBIAN/postinst" <<'POSTINST'
#!/bin/bash
set -e

case "$1" in
    configure)
        # Set ownership on state and log directories
        chown vespid-agent:vespid-agent /var/lib/vespid-agent
        chown vespid-agent:vespid-agent /var/log/vespid-agent
        chmod 750 /var/lib/vespid-agent
        chmod 750 /var/log/vespid-agent

        # Reload systemd and enable services
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable vespid-agent.service 2>/dev/null || true

        echo ""
        echo "=== Vespid Agent installed ==="
        echo ""
        echo "1. Edit /etc/vespid-agent/agent.yaml and set:"
        echo "   - server.url (your Vespid server)"
        echo "   - server.api_key (enrollment token)"
        echo ""
        echo "2. Start the agent:"
        echo "   systemctl enable --now vespid-agent"
        echo ""
        echo "3. For synthetic monitoring checks, start the worker:"
        echo "   Edit /etc/vespid-agent/worker.yaml and set:"
        echo "   - server.url, server.api_key, worker.labels.location"
        echo "   systemctl enable --now vespid-worker"
        echo ""
        ;;
esac
POSTINST

    # --- DEBIAN/prerm ---
    cat > "$debdir/DEBIAN/prerm" <<'PRERM'
#!/bin/bash
set -e

case "$1" in
    remove|upgrade|purge)
        systemctl stop vespid-agent.service 2>/dev/null || true
        systemctl stop vespid-worker.service 2>/dev/null || true
        systemctl disable vespid-agent.service 2>/dev/null || true
        systemctl disable vespid-worker.service 2>/dev/null || true
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
        rm -rf /var/lib/vespid-agent
        rm -rf /var/log/vespid-agent
        rm -rf /etc/vespid-agent
        userdel -r vespid-agent 2>/dev/null || true
        groupdel vespid-agent 2>/dev/null || true
        ;;
esac
POSTRM

    # Make maintainer scripts executable
    chmod 755 "$debdir/DEBIAN/preinst"
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
