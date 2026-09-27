#!/bin/bash
set -euo pipefail

VM_VERSION="1.144.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR}"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --version VERSION  VictoriaMetrics version (default: $VM_VERSION)
  -o, --output DIR   Output directory for RPM (default: $SCRIPT_DIR)
  --help             Show this help

Examples:
  $0                                        # Build RPM for default version
  $0 --version 1.114.0 -o /tmp/rpms        # Specific version and output
EOF
    exit 0
}

err()  { printf "${RED}[ERROR]${NC} %s\n" "$*"; exit 1; }
log()  { printf "${GREEN}[INFO]${NC} %s\n" "$*"; }

detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)     echo "amd64" ;;
        aarch64)    echo "arm64" ;;
        armv7l)     echo "arm" ;;
        i686|i386)  echo "386" ;;
        *)          err "Unsupported architecture: $arch" ;;
    esac
}

download_binary() {
    local version="$1"
    local arch="$2"
    local dest="$3"

    local url="https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v${version}/victoria-metrics-linux-${arch}-v${version}.tar.gz"

    log "Downloading VictoriaMetrics ${version} (${arch})..."
    log "  $url"

    curl -fsSL "$url" -o "$dest" || {
        err "Failed to download VictoriaMetrics. Check version and internet connection."
    }

    log "Downloaded: $dest"
}

build_rpm() {
    local version="$1"
    local arch="$2"
    local tarball="$3"
    local out_dir="$4"

    check_prereqs

    local tmp_topdir
    tmp_topdir=$(mktemp -d)
    local spec_src="$SCRIPT_DIR/victoria-metrics.spec"
    local service_src="$SCRIPT_DIR/victoria-metrics.service"

    [ -f "$spec_src" ] || err "Spec file not found: $spec_src"
    [ -f "$service_src" ] || err "Service file not found: $service_src"

    mkdir -p "$tmp_topdir/SOURCES"

    cp "$tarball" "$tmp_topdir/SOURCES/"
    cp "$service_src" "$tmp_topdir/SOURCES/"

    log "Building RPM..."

    rpmbuild \
        -ba "$spec_src" \
        --define "_topdir $tmp_topdir" \
        --define "vm_version $version" \
        --define "vm_arch $arch"

    local found
    found=$(find "$tmp_topdir/RPMS" -name '*.rpm' 2>/dev/null || true)

    if [ -z "$found" ]; then
        rm -rf "$tmp_topdir"
        err "No RPM files produced"
    fi

    for rpm in $found; do
        cp "$rpm" "$out_dir/"
    done

    rm -rf "$tmp_topdir"

    log "Done!"
    ls -la "$out_dir"/victoria-metrics-*.rpm 2>/dev/null || true
    echo ""
    echo "  Install: dnf install $out_dir/victoria-metrics-${version}*.rpm"
    echo ""
}

check_prereqs() {
    for cmd in rpmbuild curl tar; do
        command -v "$cmd" &>/dev/null || err "$cmd is required but not installed"
    done
    rpm -q systemd-rpm-macros &>/dev/null || {
        log "Installing systemd-rpm-macros..."
        dnf install -y systemd-rpm-macros || err "Failed"
    }
}

main() {
    local arch
    arch=$(detect_arch)

    while [ $# -gt 0 ]; do
        case "$1" in
            --version) VM_VERSION="$2"; shift 2 ;;
            -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
            --help) usage ;;
            *) err "Unknown option: $1" ;;
        esac
    done

    mkdir -p "$OUTPUT_DIR"

    local tarball="$OUTPUT_DIR/victoria-metrics-linux-${arch}-v${VM_VERSION}.tar.gz"

    if [ ! -f "$tarball" ]; then
        download_binary "$VM_VERSION" "$arch" "$tarball"
    else
        log "Using existing binary: $tarball"
    fi

    build_rpm "$VM_VERSION" "$arch" "$tarball" "$OUTPUT_DIR"
}

main "$@"
