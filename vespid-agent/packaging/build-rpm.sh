#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# Derive the version from the RPM spec so the source tarball name always
# matches the spec's %{version}. Hardcoding it here previously drifted from
# the spec and broke `make package` (rpmbuild extracts %{name}-%{version}.tar.gz).
VERSION="$(awk '/^Version:/{print $2; exit}' "$SCRIPT_DIR/vespid-agent.spec")"
PACKAGE="vespid-agent"

ARCH="$(uname -m)"
DIST="$(rpm -E '%{?dist}' 2>/dev/null || echo '.el9')"
RPM_NAME="${PACKAGE}-${VERSION}-1${DIST}.${ARCH}.rpm"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --archive-only  Create source tarball only, skip RPM build
  -o, --output DIR  Output directory for RPM (default: $SCRIPT_DIR)
  --help          Show this help

Examples:
  $0                            # Build RPM from HEAD
  $0 --output /tmp/rpms         # Output to specific directory
  $0 --archive-only             # Just create the tarball

Prerequisites (build host):
  - rpm-build, systemd-rpm-macros, rustc, cargo, protobuf-compiler
  - dnf install rpm-build systemd-rpm-macros protobuf-compiler
EOF
    exit 0
}

err()  { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; exit 1; }
log()  { printf "${GREEN}[INFO]${NC} %s\n" "$*" >&2; }

check_prereqs() {
    for cmd in rpmbuild cargo rustc; do
        command -v "$cmd" &>/dev/null || err "$cmd is required but not installed"
    done

    if ! command -v protoc &>/dev/null; then
        log "Installing protobuf-compiler..."
        dnf install -y protobuf-compiler || err "Failed to install protobuf-compiler"
    fi

    rpm -q systemd-rpm-macros &>/dev/null || {
        log "Installing systemd-rpm-macros..."
        dnf install -y systemd-rpm-macros || err "Failed to install systemd-rpm-macros"
    }
}

create_tarball() {
    local out_dir="$1"
    local tarball="${out_dir}/${PACKAGE}-${VERSION}.tar.gz"

    printf "${GREEN}[INFO]${NC} Creating source tarball: %s\n" "$tarball" >&2

    cd "$PROJECT_DIR"

    if git rev-parse --git-dir &>/dev/null; then
        printf "${GREEN}[INFO]${NC} Using git archive...\n" >&2
        git archive \
            --prefix="${PACKAGE}-${VERSION}/" \
            -o "$tarball" \
            HEAD
        echo "$tarball"
        return
    fi

    printf "${GREEN}[INFO]${NC} Not a git repo, creating tarball from working tree...\n" >&2

    local tmpdir
    tmpdir=$(mktemp -d)
    local srcdir="${tmpdir}/${PACKAGE}-${VERSION}"
    mkdir -p "$srcdir"

    for item in Cargo.toml Cargo.lock crates packaging/vespid-agent.spec; do
        if [ -e "$item" ]; then
            mkdir -p "$(dirname "$srcdir/$item")"
            cp -a "$item" "$srcdir/$item"
        fi
    done

    for subdir in systemd deploy; do
        if [ -d "$subdir" ]; then
            mkdir -p "$srcdir/$subdir"
            cp -a "$subdir"/* "$srcdir/$subdir/"
        fi
    done

    tar czf "$tarball" -C "$tmpdir" "${PACKAGE}-${VERSION}"
    rm -rf "$tmpdir"

    echo "$tarball"
}

build_rpm() {
    local tarball="$1"
    local out_dir="$2"

    log "Building RPM..."

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
    echo "  RPMs built:"
    for rpm in "$out_dir"/*.rpm; do
        [ -f "$rpm" ] && echo "    $(basename "$rpm")"
    done
}

main() {
    local archive_only=""
    local output_dir="$SCRIPT_DIR"

    while [ $# -gt 0 ]; do
        case "$1" in
            --archive-only) archive_only=1; shift ;;
            -o|--output)    output_dir="$2"; shift 2 ;;
            --help)         usage ;;
            *) err "Unknown option: $1" ;;
        esac
    done

    mkdir -p "$output_dir"

    local tarball
    tarball=$(create_tarball "$output_dir")

    if [ -n "$archive_only" ]; then
        log "Tarball created: $tarball"
        exit 0
    fi

    check_prereqs
    build_rpm "$tarball" "$output_dir"

    log "Done!"
    echo "  Install: dnf install $output_dir/${PACKAGE}-${VERSION}*.rpm"
}

main "$@"
