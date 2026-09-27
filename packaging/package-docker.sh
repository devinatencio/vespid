#!/usr/bin/env bash
# Build both RPM and DEB packages for every component using Docker.
#
# This is the "any machine" path: it works on macOS or any Linux host without
# the native packaging toolchains, by building each format in its own
# container. Artifacts land in ./dist/rpm and ./dist/deb.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is required for 'make package-docker'." >&2
    echo "       Install Docker Desktop (https://docs.docker.com/get-docker/)." >&2
    exit 1
fi

build_and_run() {
    local image="$1" dockerfile="$2" target="$3"
    echo
    echo "==> Building image ${image} (${dockerfile})"
    docker build -t "${image}" -f "${SCRIPT_DIR}/docker/${dockerfile}" "${REPO_DIR}"
    echo "==> Running 'make ${target}' in ${image}"
    docker run --rm \
        -u "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -v "${REPO_DIR}":/src \
        -w /src \
        "${image}" make "${target}"
}

build_and_run vespid-rpmbuild rpm.Dockerfile package-rpm
build_and_run vespid-debbuild deb.Dockerfile package-deb

echo
echo "Artifacts:"
echo "  ${REPO_DIR}/dist/rpm"
echo "  ${REPO_DIR}/dist/deb"
