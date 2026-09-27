# Vespid Agent

Lightweight Linux monitoring agent that collects system metrics and ships them
to a [Vespid](https://github.com/vespid) server for storage in VictoriaMetrics
and display in HTMX-powered dashboards.

## What it monitors

| Category | Metrics | Source |
|----------|---------|--------|
| **CPU** | Usage %, user/system/iowait/steal breakdown | `/proc/stat` |
| **Memory** | Total, available, used, swap | `/proc/meminfo` |
| **Disk** | Space %, inodes %, I/O throughput | `/proc/mounts`, `/proc/diskstats` |
| **Network** | Bytes, packets, errors, drops per interface | `/proc/net/dev` |
| **systemd** | Service state, restart counts | `systemctl` |
| **Processes** | Top-N CPU/mem, zombie count, state counts | `/proc/*/stat` |
| **PSI** | CPU, memory, I/O pressure stall information | `/proc/pressure/*` |
| **Procfs** | Custom metrics from any /proc or /sys path | Config-driven |
| **Exec** | Nagios-style script checks with exit code capture | Subprocess |
| **Synthetic** | ICMP, HTTP, TCP, DNS, SSL checks from worker nodes | Distributed workers |

## Quick start

1. **Start VictoriaMetrics** on your Vespid server:

    ```bash
    curl -L https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v1.144.0/victoria-metrics-linux-amd64-v1.144.0.tar.gz | tar xz
    ./victoria-metrics-prod -retentionPeriod=90d -httpListenAddr=:8428 &
    ```

2. **Enable metrics** in your Vespid server config:

    ```yaml
    # /etc/vespid-server/config.yaml
    METRICS_ENABLED: true
    VICTORIAMETRICS_URL: "http://localhost:8428"
    ```

    Restart the server:
    ```bash
    systemctl restart vespid-server
    ```

3. **Build and install the agent** on a target host:

    ```bash
    # Build the RPM
    cd vespid-agent
    ./packaging/build-rpm.sh

    # Install
    dnf install packaging/vespid-agent-*.rpm
    ```

4. **Configure the agent:**

    ```yaml
    # /etc/vespid-agent/agent.yaml
    server:
      url: "https://vespid.example.com"
      api_key: "your-api-key"
    ```

5. **Start:**

    ```bash
    systemctl enable --now vespid-agent
    systemctl status vespid-agent
    ```

6. **View metrics** at `https://vespid.example.com/metrics`

## Design principles

- **Static binary** — single file, zero runtime dependencies, ~10MB
- **Linux-native** — parses `/proc` directly, no system libraries
- **Offline-resilient** — buffers metrics to disk when the server is unreachable
- **Low resource** — <20MB memory idle, <2% CPU
- **Secure** — non-root operation, systemd hardening, Bearer token auth
- **No build step for UI** — server-rendered HTML with vendored chart.js

## Architecture

```
┌──────────────────┐     HTTP POST      ┌──────────────┐     /api/v1/write     ┌──────────────────┐
│ vespid-       │──────────────────►│  Vespid   │─────────────────────►│ VictoriaMetrics  │
│ monitor-agent    │  JSON metric batch │  Server      │  Prometheus text      │                  │
│ (Rust, /proc)    │  every 60s         │  (Flask)     │                       │  (single binary) │
└──────────────────┘                    └──────────────┘                       └──────────────────┘
                                               │
                                               │ PromQL
                                               ▼
                                        ┌──────────────┐
                                        │  Dashboard   │
                                        │  (HTMX +     │
                                        │   chart.js)  │
                                        └──────────────┘
```

## Next steps

- [Agent setup guide](agent/getting-started.md)
- [Configuration reference](agent/configuration.md)
- [Collector details](agent/collectors.md)
- [Synthetic monitoring](agent/synthetic-monitoring.md)
- [Server integration](server/integration.md)
- [Dashboard guide](dashboard/guide.md)
