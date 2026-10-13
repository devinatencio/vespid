#!/usr/bin/env bash
# Install the packaging toolchain for the host's native package format.
#
# Idempotent: only packages that are actually missing are installed, so it is
# safe (and cheap) to run before every build. `make package`, `make package-rpm`
# and `make package-deb` invoke this automatically.
#
#   rpm hosts : rpm-build, systemd-rpm-macros, python3-devel,
#               protobuf-compiler, common build tools
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
        REQ_PKGS=(rpm-build systemd-rpm-macros python3-devel \
                  protobuf-compiler gcc make curl gzip tar)
        ;;
    deb)
        REQ_PKGS=(dpkg-dev fakeroot protobuf-compiler \
                  gcc make curl gzip tar ca-certificates)
        ;;
    *)
        echo "ERROR: unsupported host for native packaging (no rpm/deb detected)." >&2
        echo "       Use 'make package-docker' to build both formats in containers." >&2
        exit 1
        ;;
esac

pkg_installed() {
    case "${FORMAT}" in
        rpm) rpm -q "$1" >/dev/null 2>&1 ;;
        deb) dpkg -s "$1" >/dev/null 2>&1 ;;
    esac
}

missing=()
for pkg in "${REQ_PKGS[@]}"; do
    pkg_installed "${pkg}" || missing+=("${pkg}")
done

if [ "${#missing[@]}" -eq 0 ]; then
    echo "System packaging toolchain already present for ${FORMAT}."
else
    echo "Installing missing ${FORMAT} packages: ${missing[*]}"
    case "${FORMAT}" in
        rpm)
            if command -v dnf >/dev/null 2>&1; then
                ${SUDO} dnf install -y "${missing[@]}"
            elif command -v yum >/dev/null 2>&1; then
                ${SUDO} yum install -y "${missing[@]}"
            elif command -v zypper >/dev/null 2>&1; then
                ${SUDO} zypper --non-interactive install "${missing[@]}"
            else
                echo "ERROR: no dnf/yum/zypper found; install manually: ${missing[*]}" >&2
                exit 1
            fi
            ;;
        deb)
            if command -v apt-get >/dev/null 2>&1; then
                ${SUDO} apt-get update
                ${SUDO} apt-get install -y --no-install-recommends "${missing[@]}"
            else
                echo "ERROR: apt-get not found; install manually: ${missing[*]}" >&2
                exit 1
            fi
            ;;
    esac
fi

# Rust toolchain (runtime: the Rust agent). rustup is used so we always get a
# recent stable compiler; distro packages are often older than edition 2024.
if ! command -v cargo >/dev/null 2>&1; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable
fi

# Make a freshly-installed toolchain visible here and to the build recipes that
# follow (the Makefile also prepends ~/.cargo/bin to PATH).
if [ -f "${HOME}/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "${HOME}/.cargo/env"
fi

if command -v cargo >/dev/null 2>&1; then
    CARGO_VERSION="$(cargo --version | awk '{print $2}')"
    echo "Found cargo ${CARGO_VERSION} (edition 2024 needs >= 1.85)."
    if ! awk -F. '{ exit !($1 > 1 || ($1 == 1 && $2 >= 85)) }' <<<"${CARGO_VERSION}"; then
        echo "WARNING: cargo ${CARGO_VERSION} is older than 1.85, but the Rust" >&2
        echo "         agent uses edition 2024. Run 'rustup update stable'." >&2
    fi
else
    echo "WARNING: cargo is still not on PATH. Add \$HOME/.cargo/bin to PATH" >&2
    echo "         (or run 'source \$HOME/.cargo/env') and retry." >&2
fi

echo
echo "Packaging toolchain ready for format: ${FORMAT}"
