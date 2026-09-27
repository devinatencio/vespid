# Agent — Collectors

Each collector reads Linux kernel interfaces and emits Prometheus-compatible
metrics with the `vespid_monitor_` prefix. All counters (`*_total` suffix)
are monotonically increasing and designed for use with `rate()` in PromQL.

## CPU

**Source:** `/proc/stat`
**Default interval:** 60s
**Per-core:** Yes (`cpu="cpu0"`, `cpu="cpu1"`, etc.)

| Metric | Type | Description |
|--------|------|-------------|
| `vespid_monitor_cpu_user_seconds_total` | counter | Time in user mode |
| `vespid_monitor_cpu_system_seconds_total` | counter | Time in kernel mode |
| `vespid_monitor_cpu_iowait_seconds_total` | counter | Time waiting for I/O |
| `vespid_monitor_cpu_idle_seconds_total` | counter | Time idle |
| `vespid_monitor_cpu_steal_seconds_total` | counter | Time stolen by hypervisor |

**Common queries:**

```promql
# Overall CPU usage %
100 - (avg(rate(vespid_monitor_cpu_idle_seconds_total[2m])) * 100)

# Per-core CPU usage
100 - (rate(vespid_monitor_cpu_idle_seconds_total[2m]) * 100)

# I/O wait %
avg(rate(vespid_monitor_cpu_iowait_seconds_total[2m])) * 100
```

## Memory

**Source:** `/proc/meminfo`
**Default interval:** 60s

| Metric | Type | Description |
|--------|------|-------------|
| `vespid_monitor_memory_total_bytes` | gauge | Total physical memory |
| `vespid_monitor_memory_available_bytes` | gauge | Available for new allocations |
| `vespid_monitor_memory_used_bytes` | gauge | Used (total - available) |
| `vespid_monitor_memory_used_percent` | gauge | Used percentage |
| `vespid_monitor_memory_buffers_bytes` | gauge | Kernel buffers |
| `vespid_monitor_memory_cached_bytes` | gauge | Page cache + reclaimable slab |
| `vespid_monitor_memory_swap_total_bytes` | gauge | Total swap space |
| `vespid_monitor_memory_swap_used_bytes` | gauge | Swap in use |
| `vespid_monitor_memory_swap_used_percent` | gauge | Swap used percentage |

**Common queries:**

```promql
# Memory usage %
vespid_monitor_memory_used_percent

# Available memory GB
vespid_monitor_memory_available_bytes / 1024 / 1024 / 1024
```

## Disk

**Source:** `/proc/mounts`, `statvfs()`, `/proc/diskstats`
**Default interval:** 60s
**Per-mount:** Yes (`device`, `mountpoint`, `fstype` labels)
**Per-device:** Yes (I/O metrics)

### Space metrics

| Metric | Type | Labels |
|--------|------|--------|
| `vespid_monitor_disk_total_bytes` | gauge | device, mountpoint, fstype |
| `vespid_monitor_disk_used_bytes` | gauge | device, mountpoint, fstype |
| `vespid_monitor_disk_available_bytes` | gauge | device, mountpoint, fstype |
| `vespid_monitor_disk_used_percent` | gauge | device, mountpoint, fstype |
| `vespid_monitor_disk_inodes_used_percent` | gauge | device, mountpoint, fstype |

### I/O metrics

| Metric | Type | Labels |
|--------|------|--------|
| `vespid_monitor_disk_read_bytes_total` | counter | device |
| `vespid_monitor_disk_write_bytes_total` | counter | device |
| `vespid_monitor_disk_read_ops_total` | counter | device |
| `vespid_monitor_disk_write_ops_total` | counter | device |
| `vespid_monitor_disk_io_time_ms_total` | counter | device |

**Notes:**
- Tmpfs, devtmpfs, cgroup, and other virtual filesystems are always excluded
- Additional mountpoints can be excluded via `disk.exclude_mounts` config
- I/O metrics use block device names (`sda`, `nvme0n1`), not mountpoints

**Common queries:**

```promql
# Root disk usage %
vespid_monitor_disk_used_percent{mountpoint="/"}

# Any disk over 85%
vespid_monitor_disk_used_percent > 85

# Disk read throughput (bytes/sec)
rate(vespid_monitor_disk_read_bytes_total[2m])
```

## Network

**Source:** `/proc/net/dev`
**Default interval:** 60s
**Per-interface:** Yes (`interface` label)

| Metric | Type | Description |
|--------|------|-------------|
| `vespid_monitor_network_bytes_recv_total` | counter | Bytes received |
| `vespid_monitor_network_bytes_sent_total` | counter | Bytes sent |
| `vespid_monitor_network_packets_recv_total` | counter | Packets received |
| `vespid_monitor_network_packets_sent_total` | counter | Packets sent |
| `vespid_monitor_network_errors_recv_total` | counter | Receive errors |
| `vespid_monitor_network_errors_sent_total` | counter | Transmit errors |
| `vespid_monitor_network_drops_recv_total` | counter | Receive drops |
| `vespid_monitor_network_drops_sent_total` | counter | Transmit drops |

**Notes:**
- Loopback (`lo`) is always excluded
- Additional interfaces can be excluded via `network.exclude_interfaces`

**Common queries:**

```promql
# Network throughput by interface
rate(vespid_monitor_network_bytes_recv_total[2m])

# Interface error rate
rate(vespid_monitor_network_errors_recv_total[5m]) > 0
```

## systemd

**Source:** `systemctl list-units --type=service`
**Default interval:** 60s

| Metric | Type | Labels |
|--------|------|--------|
| `vespid_monitor_systemd_unit_active` | gauge | unit, sub_state |

**Behavior:**
- By default, only failed/inactive units are reported
- To always report specific units regardless of state, add them to `systemd.watch_units`
- `unit_active` is 1 if active, 0 otherwise
- `sub_state` captures the unit's substate (`running`, `dead`, `failed`, `exited`, etc.)

**Common queries:**

```promql
# Count of failed units
count(vespid_monitor_systemd_unit_active == 0)

# List failed units by name
vespid_monitor_systemd_unit_active == 0
```

## Process

**Source:** `/proc/*/stat`
**Default interval:** 120s
**Disabled by default:** Opt-in due to added label cardinality

### State metrics (per-agent)

| Metric | Type | Description |
|--------|------|-------------|
| `vespid_monitor_process_count_total` | gauge | Total process count |
| `vespid_monitor_process_running` | gauge | Processes in R state |
| `vespid_monitor_process_sleeping` | gauge | Processes in S or D state |
| `vespid_monitor_process_zombies` | gauge | Processes in Z state (counting toward zombie count) |
| `vespid_monitor_process_zombies_count` | gauge | Same value, simpler metric name |
| `vespid_monitor_process_stopped` | gauge | Processes in T state |

### Top-N metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `vespid_monitor_process_cpu_ticks_delta` | gauge | pid, comm, rank | CPU tick delta since last collection |
| `vespid_monitor_process_resident_bytes` | gauge | pid, comm, rank | Resident memory (RSS) in bytes |

**Common queries:**

```promql
# Zombie process count
vespid_monitor_process_zombies_count

# Top CPU consumer (rank 1)
vespid_monitor_process_cpu_ticks_delta{rank="1"}

# Process using most memory
vespid_monitor_process_resident_bytes{rank="1"} / 1024 / 1024
```

## PSI (Pressure Stall Information)

**Source:** `/proc/pressure/cpu`, `/proc/pressure/memory`, `/proc/pressure/io`
**Default interval:** 60s
**Requires:** Kernel 5.2+ with `CONFIG_PSI=y`

PSI metrics quantify resource pressure — how much time tasks spend stalled
waiting for CPU, memory, or I/O. Unlike raw utilization percentages, pressure
indicates whether the system is actually struggling.

### Metrics

For each resource (cpu, memory, io) and each stall level (some, full):

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `vespid_monitor_psi_avg10` | gauge | resource, level | Average pressure over 10 seconds |
| `vespid_monitor_psi_avg60` | gauge | resource, level | Average pressure over 60 seconds |
| `vespid_monitor_psi_avg300` | gauge | resource, level | Average pressure over 300 seconds |
| `vespid_monitor_psi_total` | counter | resource, level | Cumulative stall time in microseconds |

### Stall levels

| Level | Meaning |
|-------|---------|
| `some` | At least one task was stalled |
| `full` | All non-idle tasks were stalled simultaneously |

### Common queries

```promql
# Memory pressure (10s window) — > 10 means the system is struggling
vespid_monitor_psi_avg10{resource="memory",level="some"}

# I/O pressure over last minute
vespid_monitor_psi_avg60{resource="io",level="full"}

# CPU pressure trend
vespid_monitor_psi_avg300{resource="cpu",level="some"}
```

### Notes

- If `/proc/pressure/` files don't exist (kernel < 5.2 or CONFIG_PSI not set),
  the collector silently returns no metrics — no errors, no crashes.
- "some" pressure is common under normal load; "full" pressure > 0 indicates
  the system is saturated and tasks are being completely blocked.

## Loadavg

**Source:** `/proc/loadavg`
**Default interval:** 60s
**Enabled by default**

System load averages indicating the number of tasks in the run queue or in
uninterruptible sleep (D state), averaged over three time windows.

| Metric | Type | Description |
|--------|------|-------------|
| `vespid_monitor_loadavg_1min` | gauge | Load average over 1 minute |
| `vespid_monitor_loadavg_5min` | gauge | Load average over 5 minutes |
| `vespid_monitor_loadavg_15min` | gauge | Load average over 15 minutes |

**Common queries:**

```promql
# Current 1-minute load
vespid_monitor_loadavg_1min

# Load > number of cores suggests contention
vespid_monitor_loadavg_5min > 4

# Load trend (15min vs 1min)
vespid_monitor_loadavg_1min - vespid_monitor_loadavg_15min
```

## Procfs (Config-driven custom metrics)

**Source:** Any `/proc` or `/sys` path, configured via YAML
**Default interval:** 60s
**Disabled by default:** Opt-in with metric definitions

Define custom metrics in the agent config without writing Rust. The collector
reads a file path and applies a parse strategy to extract a number.

### Configuration

```yaml
collectors:
  procfs:
    enabled: true
    metrics:
      - name: "vespid_conntrack_count"
        path: "/proc/sys/net/netfilter/nf_conntrack_count"
        help: "Active connection tracking entries"
        # parse defaults to "value"

      - name: "vespid_file_handles"
        path: "/proc/sys/fs/file-nr"
        help: "Allocated file handles"
        parse: first_field

      - name: "vespid_oom_kills"
        path: "/proc/vmstat"
        help: "Out-of-memory killer invocations"
        parse: snmp
        key: "oom_kill"
```

### Parse strategies

| Strategy | Use case | Example file | Extracts |
|----------|----------|-------------|----------|
| `value` (default) | Single number | `/proc/sys/...` | `42` → 42.0 |
| `first_field` | First whitespace-separated value | `/proc/sys/fs/file-nr` | `7040 0 9223372...` → 7040.0 |
| `line_count` | Count non-empty lines | Any | 1500 lines → 1500.0 |
| `snmp` | `/proc/net/snmp`-style key-value | `/proc/net/snmp`, `/proc/vmstat` | Uses `key` field to locate value |

### Common metrics to monitor

```yaml
# Connection tracking
- name: "vespid_conntrack_count"
  path: "/proc/sys/net/netfilter/nf_conntrack_count"
  help: "Active conntrack entries"

# File handle usage
- name: "vespid_file_handles_allocated"
  path: "/proc/sys/fs/file-nr"
  parse: first_field
  help: "Current allocated file handles"

# OOM events
- name: "vespid_oom_kills"
  path: "/proc/vmstat"
  parse: snmp
  key: "oom_kill"
  help: "OOM killer invocations since boot"

# TCP TIME_WAIT count
- name: "vespid_tcp_timewait"
  path: "/proc/net/snmp"
  parse: snmp
  key: "Tcp.TW"
  help: "Sockets in TIME_WAIT state"

# Process count
- name: "vespid_process_count"
  path: "/proc/loadavg"
  parse: snmp
  key: "nr_threads"
  help: "Total threads on the system"
```

### Behavior

- If a file doesn't exist or is unreadable, the metric is silently skipped
- Parse failures are logged at warn level and the metric is skipped
- Metrics carry `path` and `key` labels for disambiguation
- Each definition produces exactly one metric

## Swap

**Source:** `/proc/meminfo`
**Default interval:** 60s
**Enabled by default**

A dedicated swap monitor that reads swap fields from `/proc/meminfo` independently
of the memory collector. On hosts without swap, all metrics report zero.

| Metric | Type | Description |
|--------|------|-------------|
| `vespid_monitor_swap_total_bytes` | gauge | Total swap space |
| `vespid_monitor_swap_free_bytes` | gauge | Free swap space |
| `vespid_monitor_swap_used_bytes` | gauge | Swap in use (total - free - cached) |
| `vespid_monitor_swap_used_percent` | gauge | Swap used percentage |
| `vespid_monitor_swap_cached_bytes` | gauge | Swap cached in memory |

**Common queries:**

```promql
# Swap usage %
vespid_monitor_swap_used_percent

# Swap usage in GB
vespid_monitor_swap_used_bytes / 1024 / 1024 / 1024

# Any swap in use
vespid_monitor_swap_used_bytes > 0
```

## Logfile (Regex pattern monitoring)

**Source:** Any local log file
**Default interval:** 10s
**Disabled by default:** Opt-in with watch definitions

Monitors log files for regex pattern matches. Tracks file position across
restarts so each line is checked exactly once. Supports file rotation and
truncation detection via inode tracking.

### Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `vespid_monitor_logfile_matches_total` | counter | name, file, pattern | Lines matching the pattern |
| `vespid_monitor_logfile_state` | gauge | name, file, pattern | 0 = clean, 1 = match active |

### Alert behaviour

When `alert_on_match: true` and a watch transitions from clean → match:

1. The metric `_state` flips to 1
2. The matched line text is POSTed to `/api/v1/metrics/checks` with exit_code=1
3. The Health Checks dashboard shows it as a CRITICAL check

When the log returns to clean (match → clean):

1. `_state` returns to 0
2. A clear result is POSTed with exit_code=0
3. The dashboard returns to OK status

This means each **transition** fires exactly one alert — repeated ERROR lines
within the same matched state are tracked by the counter but don't re-trigger.

### File position tracking

State is persisted to a JSON file (default `/var/lib/vespid-agent/logfile-state.json`):

- **Inode** — detects file rotation (new file → reset position)
- **Byte offset** — resumes reading from where it left off
- **Match state** — remembers clean/match for transition detection

If a log file is deleted or rotated away, the agent resets to position 0 on the
new file and starts fresh.

### WebUI / Server-side configuration

The agent polls `GET {server}/api/v1/agent/{agent_id}/logfile-watches` every
60 seconds for watches configured via the Vespid WebUI. Server-configured
watches are merged with YAML-defined watches by name (server wins on conflict).

If the Vespid server doesn't expose this endpoint yet, the agent gracefully
falls back to YAML-only configuration.

### Common queries

```promql
# Which hosts currently have active matches
vespid_monitor_logfile_state == 1

# Match rate over time
rate(vespid_monitor_logfile_matches_total[5m])

# Error rate for a specific watch
rate(vespid_monitor_logfile_matches_total{name="app-errors"}[5m])
```

### Example

```yaml
collectors:
  logfile:
    enabled: true
    interval_secs: 10
    watches:
      - name: "application-errors"
        path: "/var/log/myapp/error.log"
        pattern: "ERROR|FATAL|CRITICAL"
        alert_on_match: true

      - name: "auth-failures"
        path: "/var/log/secure"
        pattern: "Failed password|authentication failure"
        alert_on_match: true
```

## Exec (Subprocess / Nagios-style checks)

**Source:** Arbitrary scripts or binaries
**Default interval:** 300s (5 minutes)
**Disabled by default:** Opt-in with script definitions

Runs user-provided scripts and captures their exit code and output. Designed
for Nagios-compatible check scripts — exit code 0 = OK, 1 = WARNING, 2 = CRITICAL.

### Configuration

```yaml
collectors:
  exec:
    enabled: true
    interval_secs: 300
    timeout_secs: 30
    scripts:
      - name: "disk_usage"
        command: ["/usr/local/bin/check-disk.sh"]

      - name: "ssl_cert"
        command: ["/usr/local/bin/check-ssl-cert", "example.com"]
```

### Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `vespid_monitor_exec_exit_code` | gauge | name | Script exit code (0=OK, 1=WARN, 2=CRIT, -1=error) |
| `vespid_monitor_exec_duration_ms` | gauge | name | Script execution time in milliseconds |

### Failure reporting

When a script exits non-zero:

1. The exit code + duration metrics go to VictoriaMetrics via normal transport
2. The full output is logged at WARN level in the agent log
3. The result is POSTed to `/api/v1/metrics/checks` on the Vespid server
4. The server stores it in the `check_results` table
5. The Health Checks dashboard shows the latest status for each check

### Script requirements

- Executable files or scripts with a shebang (`#!/bin/bash`, `#!/usr/bin/python3`)
- Available on the filesystem at the specified path
- Exit code 0 = OK, 1 = WARNING, 2 = CRITICAL, any other = UNKNOWN
- stdout and stderr are captured as the output (combined)
- Timeout is configurable (default 30 seconds)
- Scripts run sequentially, not concurrently

### Common queries

```promql
# Check result (0=OK, >0 = problem)
vespid_monitor_exec_exit_code

# Any check failing
vespid_monitor_exec_exit_code > 0

# Critical checks only
vespid_monitor_exec_exit_code >= 2

# Check execution time (ms)
vespid_monitor_exec_duration_ms
```

### Example check script

```bash
#!/bin/bash
# /usr/local/bin/check-disk.sh
# Nagios-compatible disk usage check

USAGE=$(df / | tail -1 | awk '{print $5}' | tr -d '%')

if [ "$USAGE" -gt 90 ]; then
    echo "CRITICAL: / is at ${USAGE}%"
    exit 2
elif [ "$USAGE" -gt 80 ]; then
    echo "WARNING: / is at ${USAGE}%"
    exit 1
else
    echo "OK: / is at ${USAGE}%"
    exit 0
fi
```

### Viewing check results

Navigate to **Metrics → Health Checks** in the Vespid dashboard. Cards show:
- Check name and hostname
- Severity badge (OK / WARNING / CRITICAL / UNKNOWN)
- Color-coded left border (green/yellow/red)
- Last output from the script
- Timestamp of the last run
