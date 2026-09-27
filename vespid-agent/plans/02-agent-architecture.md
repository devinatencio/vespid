# 02 — Agent Architecture

## Overview

The HiveMonitor agent is a lightweight Rust binary that runs on Linux hosts, collects
system metrics from /proc and /sys, and ships them to the Vespid server via HTTP
batch POST using the Prometheus remote write format.

## Design Goals

- Static binary, zero runtime dependencies
- <20MB memory idle, <2% CPU
- async I/O for efficient /proc polling and network
- Offline-resilient with local file buffer
- Non-root operation with Linux capabilities
- Clean shutdown via systemd notify + watchdog

## Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│              hivemonitor-agent                        │
├─────────────────────────────────────────────────────┤
│                                                       │
│  ┌─────────────────────────────────────────────────┐ │
│  │              Runtime / Scheduler                  │ │
│  │  (tokio async, interval-driven collection)       │ │
│  │  - CancellationToken for graceful shutdown       │ │
│  │  - systemd notify watchdog                       │ │
│  └─────────────────────────────────────────────────┘ │
│                                                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │
│  │   CPU    │ │  Memory  │ │   Disk   │ │Network │ │
│  │Collector │ │Collector │ │Collector │ │Collect.│ │
│  └──────────┘ └──────────┘ └──────────┘ └────────┘ │
│  ┌──────────┐                                        │
│  │ systemd  │    All compiled-in, trait-based       │
│  │Collector │    Source: /proc, /sys, /run/dbus     │
│  └──────────┘                                        │
│                                                       │
│  ┌─────────────────────────────────────────────────┐ │
│  │         Local Buffer (file-based spool)          │ │
│  │    Append-only JSON lines file                  │ │
│  │    File rotation at size threshold              │ │
│  │    Replay on reconnect (oldest first)           │ │
│  │    Fixed max size (default 64MB)                │ │
│  └─────────────────────────────────────────────────┘ │
│                                                       │
│  ┌─────────────────────────────────────────────────┐ │
│  │            Transport Layer                        │ │
│  │  - Prometheus remote write (snappy + protobuf)   │ │
│  │  - HTTP batch POST to server /api/v1/write       │ │
│  │  - Configurable batch size + flush interval      │ │
│  │  - Exponential backoff on failure                │ │
│  └─────────────────────────────────────────────────┘ │
│                                                       │
│  ┌─────────────────────────────────────────────────┐ │
│  │          Config / Enrollment                      │ │
│  │  - Read /etc/hivemonitor/agent.yaml              │ │
│  │  - API key from config (or environment)          │ │
│  │  - Server URL from config                        │ │
│  │  - Remote config (future, via server poll)       │ │
│  └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

## Collector Interface

```rust
#[async_trait]
pub trait Collector: Send + Sync {
    /// Unique name for this collector (used as metric prefix)
    fn name(&self) -> &'static str;

    /// Default collection interval
    fn default_interval(&self) -> Duration;

    /// Perform collection, returning structured metrics
    async fn collect(&self, ctx: &CollectorContext) -> Result<Vec<Metric>>;

    /// Whether this collector is enabled given the current config
    fn enabled(&self, config: &AgentConfig) -> bool;
}

pub struct CollectorContext {
    pub hostname: String,
    pub agent_id: String,
    pub clock: chrono::DateTime<chrono::Utc>,
}
```

## V1 Collectors (5)

### 1. CPU Collector
- **Source:** `/proc/stat` (per-CPU and aggregate)
- **Metrics:** usage_percent, user_percent, system_percent, iowait_percent, steal_percent
- **Computed:** Rate over collection interval (delta / ticks)
- **Labels:** cpu="cpu0", cpu="total"
- **Frequency:** Every 60s

### 2. Memory Collector
- **Source:** `/proc/meminfo`
- **Metrics:** total_bytes, available_bytes, used_bytes, used_percent, swap_total_bytes, swap_used_bytes, swap_used_percent
- **Labels:** None (per-host)
- **Frequency:** Every 60s

### 3. Disk Collector
- **Source:** `/proc/mounts` + `statfs()` for usage, `/proc/diskstats` for I/O
- **Metrics:** total_bytes, used_bytes, used_percent, inodes_used_percent, read_bytes, write_bytes, read_ops, write_ops, io_time_ms
- **Labels:** device="sda", mountpoint="/"
- **Excludes:** tmpfs, devtmpfs, cgroup, squashfs by default
- **Frequency:** Every 60s

### 4. Network Collector
- **Source:** `/proc/net/dev`, `/sys/class/net/*/statistics/*`
- **Metrics:** bytes_sent, bytes_recv, packets_sent, packets_recv, errors_sent, errors_recv, drops_sent, drops_recv
- **Computed:** Rate over collection interval
- **Labels:** interface="eth0"
- **Frequency:** Every 60s

### 5. systemd Collector
- **Source:** D-Bus `org.freedesktop.systemd1` or `systemctl show --all`
- **Metrics:** unit_active (1/0), unit_sub_state (string label), unit_restart_count
- **Default:** Only reports failed/inactive units
- **Configurable:** watch list of units to always report
- **Frequency:** Every 60s

## Local Buffering

```
┌────────────────────────────────────────────────┐
│  /var/lib/hivemonitor/buffer/                    │
│                                                  │
│  buffer_000001.jsonl  ← new writes here         │
│  buffer_000000.jsonl  ← being replayed          │
│                                                  │
│  Format: one JSON object per line               │
│  {"ts":"...", "agent_id":"...", "metrics":[...]}│
│                                                  │
│  - Each file capped at 8MB                       │
│  - Total buffer capped at 64MB (8 files)         │
│  - Oldest files deleted when cap exceeded        │
│  - Replay order: oldest file first               │
│  - Write checkpoint: last successful POST offset │
└────────────────────────────────────────────────┘
```

A simple append-only file approach rather than a ring buffer (mmap):
- Simpler to implement and debug
- Sufficient for short-term buffering (64MB = ~hours at 60s interval)
- Survives process crash (fsync on writes)
- Easily readable with `cat` for debugging

## Transport Strategy

### Protocol: Prometheus Remote Write

The agent batches metrics into Prometheus remote write format (snappy-compressed
protobuf) and sends via HTTP POST.

### Batch and Flush Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| batch_size | 500 | Max metrics per batch |
| flush_interval | 30s | Max time before sending partial batch |
| retry_backoff | [1s, 5s, 15s, 60s, 300s] | Exponential backoff on failure |
| max_retry_attempts | 5 | After which, buffer to disk and continue collecting |

### Flow

1. Collectors produce metrics → internal bounded channel (capacity 1000)
2. Batch builder reads from channel, accumulates up to batch_size or flush_interval
3. Batch is converted to Prometheus remote write protobuf + snappy
4. HTTP POST to server
5. On success: ack to buffer (mark sent)
6. On failure: append to buffer file, retry with backoff
7. On reconnect (after offline period): replay all buffered files before new metrics

## Configuration

```yaml
# /etc/hivemonitor/agent.yaml

server:
  url: "https://vespid.example.com:8443"
  api_key: "${HIVE_API_KEY}"        # or inline, or environment variable

agent:
  agent_id: ""                        # auto-generated on first run if empty
  hostname_override: ""               # auto-detected via hostname if empty
  labels:
    environment: "production"
    role: "webserver"

collectors:
  cpu:
    enabled: true
    interval: 60s
  memory:
    enabled: true
    interval: 60s
  disk:
    enabled: true
    interval: 60s
    exclude_mounts:
      - "/snap/*"
      - "/var/lib/docker/*"
  network:
    enabled: true
    interval: 60s
    exclude_interfaces:
      - "lo"
  systemd:
    enabled: true
    interval: 60s
    watch_units: []                   # always report these; empty = failed only

buffer:
  path: "/var/lib/hivemonitor/buffer"
  max_total_size: 64MB
  max_file_size: 8MB

transport:
  batch_size: 500
  flush_interval: 30s
  retry_backoff: [1s, 5s, 15s, 60s, 300s]
  request_timeout: 30s
```

## systemd Service

```ini
[Unit]
Description=HiveMonitor Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/hivemonitor-agent --config /etc/hivemonitor/agent.yaml
Restart=always
RestartSec=5
WatchdogSec=60
User=hivemonitor
Group=hivemonitor
AmbientCapabilities=CAP_DAC_READ_SEARCH
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/hivemonitor /var/log/hivemonitor
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

## Rust Crate Structure

```
crates/hivemonitor-agent/
├── Cargo.toml
└── src/
    ├── main.rs              # Entry point, CLI arg parsing, signal handling
    ├── config.rs            # YAML config parsing, defaults, env resolution
    ├── runtime.rs           # Scheduler: spawns collector tasks, manages lifecycle
    ├── buffer.rs            # Append-only jsonl spool with replay
    ├── transport.rs         # HTTP client, Prom remote write encoding, retry logic
    ├── enrollment.rs        # Optional enrollment: POST credentials, get agent_id
    └── collectors/
        ├── mod.rs           # Collector trait definition
        ├── cpu.rs           # /proc/stat parser
        ├── memory.rs        # /proc/meminfo parser
        ├── disk.rs          # /proc/mounts, statfs, /proc/diskstats
        ├── network.rs       # /proc/net/dev, /sys/class/net/*/statistics
        └── systemd.rs       # D-Bus or systemctl wrapper
```

## Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
chrono = { version = "0.4", features = ["serde"] }
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tracing-journald = "0.3"
thiserror = "1"
anyhow = "1"
prometheus-remote-write = "0.1"  # or implement manually (small protocol)
snap = "1"                        # snappy compression for remote write
```

## Resource Budget

| Resource | Target |
|----------|--------|
| Binary size | <10MB (static, stripped) |
| Memory idle | <20MB |
| Memory collecting | <30MB |
| CPU | <2% of one core |
| Disk buffer | <64MB |
| Network per push | ~50KB compressed (5 metrics, typical) |
