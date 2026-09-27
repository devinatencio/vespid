# Agent — Configuration Reference

## Config file

Default path: `/etc/vespid-agent/agent.yaml`

All values have defaults. An empty config file uses all defaults. Only override
what you need.

## Full reference

```yaml
# ── Logging ───────────────────────────────────────────────────────────────
log_level: "info"                           # trace, debug, info, warn, error
log_retention_days: 30                      # keep daily agent.log.* files for this many days (0 = keep forever)

# ── Server connection ──────────────────────────────────────────────────
server:
  url: "https://vespid.example.com"   # Vespid server URL (required in production)
  api_key: ""                             # API key with agent role (required in production)

# ── Agent identity ─────────────────────────────────────────────────────
agent:
  agent_id: ""                            # Auto-generated on first run if empty
  hostname_override: ""                   # Auto-detected via hostname if empty
  labels:                                 # Arbitrary key-value labels attached to all metrics
    environment: "production"
    role: "webserver"
    datacenter: "us-east"

# ── Collectors ─────────────────────────────────────────────────────────
collectors:

  cpu:
    enabled: true
    interval_secs: 60                     # Seconds between collections

  memory:
    enabled: true
    interval_secs: 60

  disk:
    enabled: true
    interval_secs: 60
    exclude_mounts:                       # Mountpoints to skip (glob-style * supported)
      - "/snap/*"
      - "/var/lib/docker/*"

  network:
    enabled: true
    interval_secs: 60
    exclude_interfaces:                   # Interfaces to skip (loopback always excluded)
      - "docker0"
      - "veth*"

  systemd:
    enabled: true
    interval_secs: 60
    watch_units: []                       # Always report these units even if active
                                          # When empty, only failed units are reported

  process:
    enabled: false                        # Opt-in — adds cardinality per process
    interval_secs: 120                    # Longer interval for process scanning
    top_n: 20                             # Top-N processes reported by CPU and memory

  psi:
    enabled: true
    interval_secs: 60                     # Reads /proc/pressure/{cpu,memory,io}

  loadavg:
    enabled: true                         # On by default — reads /proc/loadavg
    interval_secs: 60

  procfs:
    enabled: false                        # Opt-in with metric definitions
    interval_secs: 60
    metrics: []                           # Custom /proc metrics (see collectors doc)

  swap:
    enabled: true                         # On by default — reads /proc/meminfo swap fields
    interval_secs: 60

  logfile:
    enabled: false                        # Opt-in with watch definitions
    interval_secs: 10                     # Near-real-time polling for log patterns
    state_path: "/var/lib/vespid-agent/logfile-state.json"
    watches: []                           # Watch definitions (see collectors doc)

  exec:
    enabled: false                        # Opt-in with script definitions
    interval_secs: 300                    # 5-minute default for health checks
    timeout_secs: 30                      # Max seconds per script
    scripts: []                           # Script definitions (see collectors doc)

# ── Local buffering ────────────────────────────────────────────────────
buffer:
  path: "/var/lib/vespid-agent/buffer"
  max_total_size: 67108864                # 64MB total across all buffer files
  max_file_size: 8388608                  # 8MB per file, rotates when exceeded

# ── Synthetic monitoring worker ─────────────────────────────────────────
worker:
  capabilities: ["http", "icmp", "tcp", "dns", "ssl"]  # Check types this worker can run
  labels:
    location: "default"                          # Required — where this worker is located
  max_concurrent: 10                             # Max simultaneous checks
  poll_interval_secs: 5                          # How often to ask for new jobs

# ── Transport ──────────────────────────────────────────────────────────
transport:
  batch_size: 500                         # Max metrics per HTTP POST
  flush_interval_secs: 30                 # Max seconds before sending a partial batch
  request_timeout_secs: 30                # HTTP request timeout
  retry_backoff: [1, 5, 15, 60, 300]     # Seconds between retries on failure
```

## Collector intervals

| Collector | Default | Why |
|-----------|---------|-----|
| cpu | 60s | CPU averages smooth over this window naturally |
| memory | 60s | Memory changes slowly |
| disk | 60s | Disk usage changes slowly, I/O rates need at least this |
| network | 60s | Throughput rates smooth over this window |
| systemd | 60s | Service state changes infrequently |
| process | 120s | Process scanning is expensive, 2 min is fine for trends |
| psi | 60s | Pressure averages smooth over this window naturally |
| loadavg | 60s | Load averages are natural 1/5/15 minute values, 60s sampling is fine |
| procfs | 60s | Custom /proc metrics, same as other system collectors |
| swap | 60s | Swap changes at memory speed, same interval as memory |
| logfile | 10s | Near-real-time for pattern detection, configurable |
| exec | 300s | Script execution is expensive, 5 min is fine for health checks |

## Label cardinality

Every metric carries these labels:

| Label | Value | Cardinality |
|-------|-------|-------------|
| `agent_id` | UUID | 1 per host |
| `hostname` | FQDN | 1 per host |
| `cpu` | core number | N per host (CPU cores) |
| `device` | block device name | ~5-20 per host |
| `mountpoint` | filesystem path | ~5-20 per host |
| `interface` | network interface | ~5-10 per host |
| `unit` | systemd unit name | ~1-50 per host |
| `pid` / `comm` | process ID + name | up to `top_n` per host (process collector only) |

The process collector is disabled by default because it adds significant label
cardinality. Only enable it if you need per-process visibility.
