# 04 — Data Storage

## Overview

Two storage backends with clear separation of concerns:

| Store | Purpose | Contents |
|-------|---------|----------|
| **VictoriaMetrics** | Time-series metrics | CPU, memory, disk, network, systemd metrics |
| **MariaDB** | Metadata, configuration, events | Agent inventory, users, API keys, alert rules, audit log |

**No time-series data in MariaDB.** No metadata in VictoriaMetrics.

## VictoriaMetrics

### Deployment

```bash
# Single binary, single command
./victoria-metrics-prod \
    -retentionPeriod=90d \
    -storageDataPath=/var/lib/victoria-metrics \
    -httpListenAddr=:8428 \
    -loggerLevel=INFO
```

### Resource Profile

| Metric | Expected |
|--------|----------|
| Binary size | ~10MB |
| Memory idle | ~50MB |
| Memory with 50 agents, 90d retention | ~200MB |
| Disk (50 agents, 90d, 60s interval) | ~50GB |

### Retention

90 days of raw data at 60s intervals. For longer-term data (1yr+), configure
VictoriaMetrics to downsample: 5m or 1h rollups stored alongside raw data.

### Backup

VictoriaMetrics supports instant backups via `/internal/resetRollupResultCache` and
filesystem snapshots (rsync the data directory when VM is stopped, or use `vmbackup`).

**Recommended:** Nightly `rsync` of the data directory to cold storage. VM can tolerate
brief write pauses during backup.

### Monitoring VictoriaMetrics Itself

VictoriaMetrics exposes its own metrics at `/metrics` (Prometheus format):

```
# Key metrics to watch:
vm_rows{type="storage/new"}         # ingestion rate
vm_free_disk_space_bytes            # available disk
vm_slow_row_inserts_total           # performance degradation
vm_cache_size_bytes{type="storage/tsid"}  # cache health
```

The Flask server can scrape these and alert on them (meta-monitoring).

## MariaDB

### Schema Extensions

**Option A: Add columns to existing `nodes` table**

```sql
-- Extend existing Vespid nodes table
ALTER TABLE nodes
    ADD COLUMN agent_type ENUM('security', 'monitor', 'both') NOT NULL DEFAULT 'security',
    ADD COLUMN monitor_last_seen TIMESTAMP NULL,
    ADD COLUMN monitor_version VARCHAR(32) NULL,
    ADD COLUMN monitor_labels JSON NULL,
    ADD COLUMN monitor_config JSON NULL;

CREATE INDEX idx_monitor_last_seen ON nodes(monitor_last_seen);
```

**Option B: Separate monitored_agents table** (if schema separation is desired)

```sql
CREATE TABLE monitored_agents (
    id CHAR(36) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    agent_version VARCHAR(32),
    labels JSON,
    enrolled_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP NULL,
    status ENUM('active', 'stale', 'decommissioned') NOT NULL DEFAULT 'active',
    api_key_hash VARCHAR(255) NOT NULL,
    config JSON,
    INDEX idx_status (status),
    INDEX idx_last_seen (last_seen_at)
);
```

**Recommendation: Option A** — unified fleet view. When both agents report on the
same host, the dashboard shows both security and monitoring status in one row.

### Optional: Alert Rules Table

```sql
-- V1.5+: Alert rules storage
CREATE TABLE alert_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    promql VARCHAR(1024) NOT NULL,
    threshold DOUBLE,
    comparison ENUM('gt', 'lt', 'gte', 'lte', 'eq') NOT NULL,
    duration_seconds INT NOT NULL DEFAULT 60,
    severity ENUM('info', 'warning', 'critical') NOT NULL DEFAULT 'warning',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- V1.5+: Alert event history
CREATE TABLE alert_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    rule_id INT NOT NULL,
    agent_id CHAR(36) NULL,
    fired_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    current_value DOUBLE NOT NULL,
    status ENUM('firing', 'resolved', 'acknowledged') NOT NULL DEFAULT 'firing',
    labels JSON,
    INDEX idx_status (status),
    INDEX idx_agent_fired (agent_id, fired_at),
    FOREIGN KEY (rule_id) REFERENCES alert_rules(id)
);
```

**Deferred to V1.5.** V1 can show simple threshold indicators computed by the
dashboard JavaScript (e.g., "if disk_percent > 90, show red") without needing
a server-side alert engine.

### Enrollment Tokens

Reuse existing Vespid enrollment mechanisms. The monitoring agent uses the same
API key authentication model as the security agent. New monitoring agents get
their own API keys (separate from security agent keys).

## Prometheus Remote Write Format

The wire protocol between agent and server:

```
[snappy-compressed protobuf]

message WriteRequest {
  repeated TimeSeries timeseries = 1;
}

message TimeSeries {
  repeated Label labels = 1;
  repeated Sample samples = 2;
}

message Label {
  string name = 1;
  string value = 2;
}

message Sample {
  double value = 1;
  int64 timestamp = 2;   // milliseconds since epoch
}
```

### Example Metric (serialized as JSON for illustration)

```json
{
  "labels": [
    {"name": "__name__", "value": "hivemonitor_cpu_usage_percent"},
    {"name": "agent_id", "value": "a1b2c3d4-..."},
    {"name": "hostname", "value": "web-01"},
    {"name": "cpu", "value": "cpu0"}
  ],
  "samples": [
    {"value": 23.5, "timestamp": 1716904200000}
  ]
}
```

This standard format means:
- The agent is compatible with any Prometheus-remote-write endpoint
- VictoriaMetrics is replacable with Prometheus/Thanos/Mimir/Cortex
- No custom serialization format to maintain
- Existing tools (Grafana, Alertmanager) work natively

## Data Flow Summary

```
Agent collects                  VictoriaMetrics            MariaDB
from /proc ─────────► Server ──────────► stores metrics    stores agents
    │                    │                    │                  │
    │  60s interval      │  forward           │  queryable       │  inventory
    │  batch every 30s   │  immediately       │  via PromQL       │  config
    │  buffer if offline  │                    │  90d retention    │  users
    │                    │                    │                  │
    ▼                    ▼                    ▼                  ▼
  /proc/*           Flask blueprint       victoria-metrics     mysqld
```

## Key Design Decisions

1. **Metrics never touch MariaDB.** They go agent → Flask → VictoriaMetrics in one shot.
2. **Agent inventory is the only schema addition.** Alert rules deferred.
3. **Prometheus remote write format everywhere.** No internal format translation.
4. **VictoriaMetrics on localhost only.** No external exposure. Flask mediates all access.
5. **No caching layer.** VictoriaMetrics is fast enough for direct queries for V1 scale.
