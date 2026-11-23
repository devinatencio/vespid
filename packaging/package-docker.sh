#!/usr/bin/env bash
# Build both RPM and DEB packages for every component using Docker.
#
# This is the "any machine" path: it works on macOS or any Linux host without
# the native packaging toolchains, by building each format in its own
# container. Artifacts land in ./dist/rpm and ./dist/deb.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ENGINE=${CONTAINER_ENGINE:-}
if [ -z "${ENGINE}" ]; then
    if command -v docker >/dev/null 2>&1; then
        ENGINE=docker
    elif command -v podman >/dev/null 2>&1; then
        ENGINE=podman
    else
        echo "ERROR: docker or podman is required for 'make package-docker'." >&2
        echo "       Install Docker Desktop (https://docs.docker.com/get-docker/) or podman." >&2
        exit 1
    fi
fi

# Optional: PLATFORM=linux/amd64 on Apple Silicon, or linux/arm64 for ARM hosts.
PLATFORM=${PLATFORM:-}

build_and_run() {
    local image="$1" dockerfile="$2" target="$3"
    local -a build_args=() run_args=()
    if [ -n "${PLATFORM}" ]; then
        build_args+=(--platform "${PLATFORM}")
        run_args+=(--platform "${PLATFORM}")
    fi
    if [ "${ENGINE}" = "podman" ]; then
        # Rootless podman maps container root to the invoking host user. That
        # lets the container write build output into the bind mount without
        # the host/container UID mismatch that `-u $(id -u)` causes.
        run_args+=(--security-opt label=disable)
    else
        run_args+=(-u "$(id -u):$(id -g)")
    fi

    echo
    echo "==> Building image ${image} (${dockerfile})"
    "${ENGINE}" build ${build_args[@]+"${build_args[@]}"} -t "${image}" -f "${SCRIPT_DIR}/docker/${dockerfile}" "${REPO_DIR}"
    echo "==> Running 'make ${target}' in ${image}"
    "${ENGINE}" run --rm ${run_args[@]+"${run_args[@]}"} \
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
