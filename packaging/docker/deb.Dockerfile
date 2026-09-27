# Build Vespid .deb packages on a Debian base.
#
# Used by `make package-docker`. The repository is bind-mounted at /src and
# `make package-deb` is run inside.
FROM debian:12

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        dpkg-dev fakeroot protobuf-compiler gcc make curl gzip tar ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Rust is installed via rustup (not apt) so edition 2024 (Rust >= 1.85) works.
# CARGO_HOME/RUSTUP_HOME are world-writable so the container can run as the
# host UID and avoid root-owned build output.
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable \
    && chmod -R 777 /opt/rustup /opt/cargo

WORKDIR /src
CMD ["make", "package-deb"]
