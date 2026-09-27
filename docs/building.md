# Building & Packaging

Vespid is split across two repositories and produces three packages:

| Package | Language | Repo | Description |
|---------|----------|------|-------------|
| `vespid` | Python | `vespid/` | Agent daemon + CLI (Nuitka-compiled) |
| `vespid-server` | Python | `vespid/` | Flask dashboard server |
| `vespid-agent` | Rust | `vespid-agent/` | Native metrics collector (CPU, memory, disk, network) |

- The **Python packages** live in this repo and are built via `build_deb.sh`,
  `Makefile` (RPM), or Nuitka.
- The **Rust agent** is in a [separate repository](https://github.com/vespid/vespid-agent)
  with its own build scripts.

---

## Python Packages (this repo)

### Debian (.deb)

Two packages are built via `build_deb.sh`:

| Package | Contents |
|---------|----------|
| `vespid_1.0.0_all.deb` | Python agent daemon + CLI |
| `vespid-server_1.0.0_all.deb` | Flask dashboard server |

#### Building

```bash
# Build both packages
./build_deb.sh

# Build only the agent
./build_deb.sh client

# Build only the server
./build_deb.sh server
```

#### Installing

```bash
sudo dpkg -i vespid_1.0.0_all.deb
sudo apt-get install -f   # resolve dependencies
```

#### Package layout

**Agent package:**

| Path | Contents |
|------|----------|
| `/opt/vespid/` | Python source and virtualenv |
| `/etc/vespid/` | Configuration files (preserved on upgrade) |
| `/var/lib/vespid/` | Runtime state (credentials, fleet queue) |
| `/var/log/vespid/` | Log files |
| `/usr/bin/vespid` | Daemon binary |
| `/usr/bin/vespid-cli` | CLI binary |
| `/etc/systemd/system/vespid.service` | systemd unit |

**Server package:**

| Path | Contents |
|------|----------|
| `/opt/vespid-server/` | Python source and virtualenv |
| `/etc/vespid-server/` | Configuration files |
| `/var/lib/vespid-server/` | Database and backups |
| `/var/log/vespid-server/` | Log files |
| `/etc/systemd/system/vespid-server.service` | systemd unit |

#### Lifecycle

- **postinst**: Creates virtualenv, installs dependencies, enables systemd service
- **Upgrade**: Config files are protected (not overwritten)
- **Purge**: Removes all files including config and state

### RPM

#### Agent RPM

```bash
make rpm
sudo rpm -ivh rpmbuild/RPMS/noarch/vespid-1.0.0-1.*.noarch.rpm
```

#### Server RPM

```bash
cd vespid-server/
make rpm
sudo rpm -ivh rpmbuild/RPMS/noarch/vespid-server-1.0.0-1.*.noarch.rpm
```

RPM specs are at `vespid.spec` (agent) and `vespid-server/vespid-server.spec`
(server).

---

## Rust Agent (`vespid-agent/` repo)

A standalone Rust binary that collects CPU, memory, disk, network, and
systemd metrics and reports them to the Vespid server. It is developed in a
[separate repository](https://github.com/vespid/vespid-agent).

### Prerequisites

```bash
# Build host
rustc cargo protobuf-compiler dpkg-deb fakeroot
```

### Debian package

```bash
# From the vespid-agent repo root
./packaging/build-vespid-agent-deb.sh
```

Produces `vespid-agent_1.0.0_amd64.deb` (arch-specific, not `all`).

### RPM package

```bash
# From the vespid-agent repo root
./packaging/build-rpm.sh
```

RPM spec at `packaging/vespid-agent.spec`.

### Package layout

| Path | Contents |
|------|----------|
| `/usr/bin/vespid-agent` | Rust compiled binary |
| `/etc/vespid-agent/agent.yaml` | Agent configuration |
| `/var/lib/vespid-agent/` | Runtime state |
| `/var/log/vespid-agent/` | Log files |
| `/lib/systemd/system/vespid-agent.service` | systemd unit |
| `/lib/systemd/system/vespid-worker.service` | Worker service |

### Build requirements

The Rust agent has no Python dependency — it is a fully self-contained native
binary. The only build-time dependencies are `rustc`, `cargo`, and
`protobuf-compiler` (for protobuf wire format).

## Nuitka compilation

Compile Vespid into standalone native binaries for deployment without
Python installed on target hosts.

### Prerequisites

```bash
pip install nuitka ordered-set
sudo apt install patchelf   # or equivalent for your distro
```

### Building

```bash
./build_nuitka.sh
```

Output binaries are placed in `dist/nuitka/`:

| Binary | Source | Description |
|--------|--------|-------------|
| `vespid` | `entry_vespid.py` | Agent daemon |
| `vespid-cli` | `entry_vespid_cli.py` | CLI tool |
| `vespid-server` | `entry_vespid_server.py` | Server (development only) |

### Build modes

| Mode | Flag | Description |
|------|------|-------------|
| Onefile (default) | `--onefile` | Single portable binary, slightly slower startup |
| Standalone | `--standalone` | Directory of files, faster startup |

### Notes

- Flask, Jinja2, and Rich require explicit module includes (handled by
  `build_nuitka.sh`)
- Gunicorn cannot be compiled into a Nuitka binary — use the standard
  Python-based Gunicorn for production server deployments
- Templates and static files must be included via `--include-data-dir`

## Makefile targets

The root `Makefile` provides common development and build tasks:

```bash
make install       # Install agent in development mode
make test          # Run agent test suite
make lint          # Run linter
make rpm           # Build agent RPM
make docs          # Build MkDocs documentation
make clean         # Remove build artifacts
```

The server has its own `Makefile` in `vespid-server/`:

```bash
make install       # Install server dependencies
make test          # Run server tests
make rpm           # Build server RPM
make run           # Start development server
```

See `README_Makefile.md` for the full target reference.
