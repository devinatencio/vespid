#!/usr/bin/env bash
# Install the packaging toolchain for the host's native package format.
#
#   rpm hosts : rpm-build, protobuf-compiler, common build tools
#   deb hosts : dpkg-dev, fakeroot, protobuf-compiler, common build tools
#
# Also ensures a Rust toolchain (>= 1.85, for edition 2024) is available via
# rustup when one is not already installed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORMAT="$(sh "${SCRIPT_DIR}/detect-pkg-format.sh")"

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

case "${FORMAT}" in
    rpm)
        if command -v dnf >/dev/null 2>&1; then
            ${SUDO} dnf install -y rpm-build protobuf-compiler gcc make curl gzip tar
        elif command -v yum >/dev/null 2>&1; then
            ${SUDO} yum install -y rpm-build protobuf-compiler gcc make curl gzip tar
        else
            echo "ERROR: no dnf/yum found; install rpm-build and protobuf-compiler manually." >&2
            exit 1
        fi
        ;;
    deb)
        if command -v apt-get >/dev/null 2>&1; then
            ${SUDO} apt-get update
            ${SUDO} apt-get install -y --no-install-recommends \
                dpkg-dev fakeroot protobuf-compiler gcc make curl gzip tar ca-certificates
        else
            echo "ERROR: apt-get not found; install dpkg-dev, fakeroot and protobuf-compiler manually." >&2
            exit 1
        fi
        ;;
    *)
        echo "ERROR: unsupported host for native packaging (no rpm/deb detected)." >&2
        echo "       Use 'make package-docker' to build both formats in containers." >&2
        exit 1
        ;;
esac

# Rust toolchain (runtime: the Rust agent). rustup is used so we always get a
# recent stable compiler; distro packages are often older than edition 2024.
if ! command -v cargo >/dev/null 2>&1; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable
    # shellcheck disable=SC1091
    . "${HOME}/.cargo/env"
else
    CARGO_MAJOR_MINOR="$(cargo --version | awk '{print $2}' | cut -d. -f1,2)"
    echo "Found cargo ${CARGO_MAJOR_MINOR} (edition 2024 needs >= 1.85)."
fi

echo
echo "Packaging toolchain ready for format: ${FORMAT}"
