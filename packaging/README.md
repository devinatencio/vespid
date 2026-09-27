# Packaging

Build installable packages for every Vespid component from one entry point.

## Entry points

Run these from the repository root.

| Command | What it does | Output |
| --- | --- | --- |
| `make package` | Detect the host and build its **native** format for all components | `dist/rpm/` **or** `dist/deb/` |
| `make package-rpm` | Force an RPM build for all components | `dist/rpm/*.rpm` |
| `make package-deb` | Force a `.deb` build for all components | `dist/deb/*.deb` |
| `make package-docker` | Build **both** formats in containers (works on any host) | `dist/rpm/`, `dist/deb/` |
| `make package-deps` | Install this host's packaging toolchain | — |
| `make package-clean` | Remove `dist/` and generated `rpmbuild/` trees | — |

```bash
make package          # rpm on RHEL/Alma/Rocky/Fedora, deb on Debian/Ubuntu
make package-docker   # no local toolchain needed (requires Docker)
```

## What gets packaged

| Component | Source | Package |
| --- | --- | --- |
| Python agent | `vespid/` | `vespid` |
| Server | `vespid-server/` | `vespid-server` |
| Rust agent | `vespid-agent/` | `vespid-agent` |
| Sync agent | `vespid-agent/vespid-sync/` | `vespid-sync` |

## How detection works

`make package` runs `packaging/detect-pkg-format.sh`, which checks
`/etc/os-release` (`ID`/`ID_LIKE`) and then the available tooling:

- Red Hat family (RHEL, AlmaLinux, Rocky, Fedora, CentOS, …) or `rpmbuild` → **RPM**
- Debian family (Debian, Ubuntu, Mint, …) or `dpkg-deb` → **DEB**
- neither (for example macOS) → stops with guidance to use `package-deps` or `package-docker`

Force a format explicitly with `make package-rpm` / `make package-deb`.

## Output layout

```
dist/
  rpm/   *.rpm
  deb/   *.deb
```

## Build requirements

- **RPM**: `rpm-build`, `protobuf-compiler` (the Rust agent compiles a `.proto`).
- **DEB**: `dpkg-dev`, `fakeroot`, `protobuf-compiler`.
- **Rust agent**: Rust with edition-2024 support (>= 1.85). `make package-deps`
  installs a toolchain via rustup if `cargo` is missing.

`make package-deps` installs the right set for the detected host.

## Docker (build both formats anywhere)

`make package-docker` builds the `.rpm` set in an `almalinux:9` container and
the `.deb` set in a `debian:12` container, each with a current Rust toolchain.
The repository is bind-mounted and artifacts are written back to `dist/`.
Requires Docker.

## Signing RPMs

```bash
gpg --gen-key                                   # one-time
echo '%_gpg_name Vespid Security' >> ~/.rpmmacros
make rpm SIGN_KEY="Vespid Security"             # build + sign
make sign-rpms SIGN_KEY="Vespid Security"       # sign an existing build
```

## Per-component commands

The unified targets wrap these scripts; you can still call them directly:

```bash
make rpm                                         # Python agent (RPM)
make deb                                         # Python agent + server (DEB)
make -C vespid-server rpm                        # server (RPM)
vespid-agent/packaging/build-rpm.sh -o dist/rpm  # Rust agent (RPM)
vespid-agent/packaging/build-vespid-agent-deb.sh -o dist/deb
vespid-agent/packaging/build-vespid-sync-rpm.sh -o dist/rpm
vespid-agent/packaging/build-vespid-sync-deb.sh -o dist/deb
```
