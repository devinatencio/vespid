#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="1.0.0"
PACKAGE="vespid-sync"

ARCH="$(uname -m)"
DIST="$(rpm -E '%{?dist}' 2>/dev/null || echo '.el9')"
RPM_NAME="${PACKAGE}-${VERSION}-1${DIST}.${ARCH}.rpm"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Build an RPM for the Vespid Sync Agent.

Options:
  -o, --output DIR  Output directory for RPM (default: $SCRIPT_DIR)
  --help            Show this help

Prerequisites (build host):
  - rpm-build, systemd-rpm-macros, python3-devel
  - dnf install rpm-build systemd-rpm-macros python3-devel
EOF
    exit 0
}

# Log to stderr: these functions are used inside command substitutions
# (e.g. tarball=$(create_tarball ...)), so stdout must stay clean.
err()  { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; exit 1; }
log()  { printf "${GREEN}[INFO]${NC} %s\n" "$*" >&2; }

check_prereqs() {
    for cmd in rpmbuild python3; do
        command -v "$cmd" &>/dev/null || err "$cmd is required but not installed"
    done
    rpm -q systemd-rpm-macros &>/dev/null || {
        log "Installing systemd-rpm-macros..."
        dnf install -y systemd-rpm-macros || err "Failed to install systemd-rpm-macros"
    }
}

create_tarball() {
    local out_dir="$1"
    local tarball="${out_dir}/${PACKAGE}-${VERSION}.tar.gz"
    local tmpdir
    tmpdir=$(mktemp -d)
    local srcdir="${tmpdir}/${PACKAGE}-${VERSION}"

    log "Creating source tarball: $tarball"

    mkdir -p "$srcdir"

    # Copy vespid-sync source files
    cp -a "$PROJECT_DIR/vespid-sync/sync.py"         "$srcdir/sync.py"
    cp -a "$PROJECT_DIR/vespid-sync/providers"        "$srcdir/providers"
    cp -a "$PROJECT_DIR/vespid-sync/setup.py"         "$srcdir/setup.py"
    cp -a "$PROJECT_DIR/vespid-sync/config.yaml.example" "$srcdir/config.yaml.example"

    # Copy systemd units
    mkdir -p "$srcdir/systemd"
    cp -a "$PROJECT_DIR/systemd/vespid-sync-agent.service" "$srcdir/systemd/"
    cp -a "$PROJECT_DIR/systemd/vespid-sync-agent.timer"   "$srcdir/systemd/"

    # Copy spec file under packaging/
    mkdir -p "$srcdir/packaging"
    cp -a "$PROJECT_DIR/packaging/vespid-sync.spec"   "$srcdir/packaging/"

    tar czf "$tarball" -C "$tmpdir" "${PACKAGE}-${VERSION}"
    rm -rf "$tmpdir"
    echo "$tarball"
}

build_rpm() {
    local tarball="$1"
    local out_dir="$2"
    local spec="$PROJECT_DIR/packaging/vespid-sync.spec"

    log "Building RPM from $tarball ..."

    local tmp_topdir
    tmp_topdir=$(mktemp -d)

    rpmbuild \
        -tb "$tarball" \
        --define "_topdir $tmp_topdir"

    local found
    found=$(find "$tmp_topdir/RPMS" -name '*.rpm' 2>/dev/null || true)

    if [ -z "$found" ]; then
        rm -rf "$tmp_topdir"
        err "No RPM files produced by rpmbuild"
    fi

    for rpm in $found; do
        cp "$rpm" "$out_dir/"
    done

    rm -rf "$tmp_topdir"

    echo ""
    log "RPM built:"
    for rpm in "$out_dir"/*.rpm; do
        [ -f "$rpm" ] && echo "    $(basename "$rpm")"
    done
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
    local tarball
    tarball=$(create_tarball "$output_dir")
    build_rpm "$tarball" "$output_dir"

    log "Done!"
    echo "  Install: dnf install $output_dir/${PACKAGE}-${VERSION}*.rpm"
}

main "$@"
