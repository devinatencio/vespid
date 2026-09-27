# Dashboard Guide

The Vespid server renders monitoring dashboards using HTMX templates and
vendored chart.js. No JavaScript build tooling required.

## Fleet Overview

**URL:** `/metrics`

The landing page shows all monitored hosts with:

- **Fleet stats** — average CPU, memory, and root disk usage across all hosts
- **Search filter** — type to narrow down hosts by name
- **Host cards** — one card per monitored host with:
    - Hostname (click to drill into detail)
    - Live/dead indicator (green pulsing dot)
    - Color-coded progress bars for CPU, memory, disk
    - Left border color indicates worst metric (green <75%, yellow 75-90%, red >90%)
- **Pulse animation** — green pulsing dot = agent has reported recently

## Host Detail

**URL:** `/metrics/<agent_id>`

The per-host detail view includes:

### Ring Gauges
Four SVG donut charts showing current values:
- **CPU** — overall CPU usage %
- **Memory** — used memory %
- **Disk** — root filesystem usage %
- **Net RX** — network receive throughput (auto-scaled to bytes/s, KB/s, MB/s)

Colors: green (<75%), yellow (<90%), red (90%+). Gauges refresh every 15 seconds.

### Line Charts
Four time-series charts (2-column grid):
- **CPU Usage** — line chart, blue
- **Memory Usage** — line chart, amber
- **Disk Usage** — line chart, red
- **Network Throughput** — line chart, green

### Time Range
Three time pills above the charts:
- **1h** — last hour at 60s resolution (default)
- **6h** — last 6 hours at 60s resolution
- **24h** — last 24 hours at 60s resolution

Click any pill to switch — charts reload with the new range.

## Health Checks

**URL:** `/metrics/checks`

Shows the latest status of all exec collector scripts across all hosts:

- **Cards** — one per check name + hostname
- **Severity badges** — OK (green), WARNING (yellow), CRITICAL (red), UNKNOWN (gray)
- **Left border** — color-coded by severity
- **Output** — last captured stdout/stderr from the script (monospace, scrollable)
- **Timestamp** — when the check last ran

Check results are stored in the `check_results` table in MariaDB/SQLite and persist
across restarts. The dashboard shows only the latest result per check+agent.

### Enabling

Add `exec` collector scripts to your agent config and deploy the updated binary:

```yaml
collectors:
  exec:
    enabled: true
    scripts:
      - name: "disk_usage"
        command: ["/usr/local/bin/check-disk.sh"]
      - name: "ssl_cert"
        command: ["/usr/local/bin/check-ssl-cert", "example.com"]
```

See the [Exec collector documentation](../agent/collectors.md#exec-subprocess-nagios-style-checks)
for script requirements and example checks.

## Custom dashboards

VictoriaMetrics supports full PromQL. You can use any Prometheus-compatible
tool (Grafana, Alertmanager, custom scripts) by querying the VictoriaMetrics
API directly at `http://your-server:8428`.

### Example queries

```promql
# CPU usage %
100 - (avg(rate(vespid_monitor_cpu_idle_seconds_total{hostname="web-01"}[2m])) * 100)

# Memory usage GB
vespid_monitor_memory_used_bytes{hostname="web-01"} / 1024 / 1024 / 1024

# Disk space alert
vespid_monitor_disk_used_percent{mountpoint="/"} > 85

# Network throughput (MB/s)
rate(vespid_monitor_network_bytes_recv_total[2m]) / 1024 / 1024

# Failed systemd units
vespid_monitor_systemd_unit_active == 0

# Top 5 memory consumers
topk(5, vespid_monitor_process_resident_bytes{rank="1"})
```

### API access

```bash
# Instant query
curl 'http://localhost:8428/api/v1/query?query=vespid_monitor_cpu_idle_seconds_total'

# Range query
curl 'http://localhost:8428/api/v1/query_range?query=rate(vespid_monitor_cpu_idle_seconds_total[2m])&start=-1h&step=60s'

# List all metric names
curl 'http://localhost:8428/api/v1/label/__name__/values'
```

## Adding metrics to Grafana

1. Add a Prometheus data source pointing to `http://your-server:8428`
2. Use the PromQL examples above in panels
3. All metrics carry `agent_id`, `hostname`, and collector-specific labels
