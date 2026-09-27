# Agent — Getting Started

## Requirements

- Linux kernel 4.x+ with `/proc` filesystem
- systemd (for service management)
- Network access to the Vespid server

## Installation

### RPM (AlmaLinux, RHEL, Rocky, Fedora)

```bash
# Build the RPM
git clone https://github.com/vespid/hivemonitor
cd vespid-agent
./packaging/build-rpm.sh

# Install
dnf install packaging/vespid-agent-1.0.0-1.*.rpm

# Or from a prebuilt RPM
dnf install https://releases.vespid.io/el9/vespid-agent-1.0.0-1.el9.x86_64.rpm
```

### Static binary (any Linux)

```bash
# Download
curl -L https://releases.vespid.io/vespid-agent-linux-amd64 -o /usr/bin/vespid-agent
chmod 755 /usr/bin/vespid-agent

# Install systemd unit
cp systemd/vespid-agent.service /usr/lib/systemd/system/
```

### From source

```bash
git clone https://github.com/vespid/hivemonitor
cd vespid-agent
cargo build --release
install -m 755 target/release/vespid-agent /usr/bin/vespid-agent
```

## Configuration

Create `/etc/vespid-agent/agent.yaml`:

```yaml
server:
  url: "https://vespid.example.com"   # Your Vespid server
  api_key: "ue_your-enrollment-key"       # API key with agent role
```

All other settings have sensible defaults. See the [configuration reference](configuration.md) for full details.

## Running

### System agent (metrics collection)

```bash
systemctl enable --now vespid-agent
systemctl status vespid-agent
journalctl -u vespid-agent -f
```

### Worker (synthetic monitoring)

```bash
# Edit the worker config first
vim /etc/vespid-agent/worker.yaml

systemctl enable --now vespid-worker
systemctl status vespid-worker
journalctl -u vespid-worker -f
```

The same binary handles both modes via the `--mode` flag. You can run both
services on the same host with separate config files.

### Manual (testing)

```bash
# System agent
vespid-agent --config /path/to/agent.yaml --log-level debug

# Worker
vespid-agent --mode=worker --config /path/to/worker.yaml --log-level debug
```

## Directory layout

| Path | Purpose |
|------|---------|
| `/usr/bin/vespid-agent` | Static binary |
| `/etc/vespid-agent/agent.yaml` | Configuration |
| `/var/lib/vespid-agent/` | State directory (agent ID, buffer) |
| `/var/log/vespid-agent/` | Log files (daily rolling) |

## Security

The agent runs as an unprivileged `vespid-agent` user with only the capabilities
it needs:

- `CAP_DAC_READ_SEARCH` — read `/proc` and `/sys`
- All other capabilities dropped via `NoNewPrivileges=true`
- No open network ports — outbound HTTP only
- `/proc`, `/sys`, `/usr`, `/boot` mounted read-only via `ProtectSystem=strict`
- Home directories inaccessible via `ProtectHome=true`

## Next

- [Full configuration reference](configuration.md)
- [Collector details](collectors.md)
