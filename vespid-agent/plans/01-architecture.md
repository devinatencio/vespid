# 01 — Overall Architecture

## System Overview

HiveMonitor is a modular observability subsystem within the Vespid ecosystem. It
extends the existing Vespid Flask server with metrics collection and visualization
capabilities. A lightweight Rust agent collects system metrics from Linux hosts and
ships them via standard Prometheus remote write protocol to the server, which forwards
to VictoriaMetrics for efficient time-series storage and querying.

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                     Vespid Ecosystem                            │
│                                                                    │
│  ┌────────────────────── Monitored Hosts ──────────────────────┐  │
│  │                                                               │  │
│  │  ┌─────────────────────┐   ┌──────────────────────────────┐ │  │
│  │  │ vespid-scout     │   │ hivemonitor-agent (Rust)      │ │  │
│  │  │ (Go, security)      │   │                                │ │  │
│  │  │ - log monitoring    │   │ - CPU / Memory / Disk / Net  │ │  │
│  │  │ - nftables blocking │   │ - systemd service state       │ │  │
│  │  │ - fleet block sync  │   │ - local file buffer          │ │  │
│  │  └─────────────────────┘   │ - 60s interval (default)      │ │  │
│  │                             └──────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                            │                                         │
│               HTTP POST (Prometheus remote write)                    │
│                            │                                         │
│                            ▼                                         │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                vespid-server (Flask, extended)              │  │
│  │                                                                 │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐ │  │
│  │  │ Security │  │ Metrics  │  │  Fleet   │  │    Admin      │ │  │
│  │  │ Blueprint│  │Blueprint │  │ Blueprint│  │   Blueprint   │ │  │
│  │  │ (existing│  │  (NEW)   │  │ (existing│  │  (existing)   │ │  │
│  │  │  15+     │  │          │  │   8+     │  │    8+        │ │  │
│  │  │  pages)  │  │ - ingest │  │  pages)  │  │   pages)     │ │  │
│  │  └──────────┘  │ - query  │  └──────────┘  └───────────────┘ │  │
│  │                 │ - charts │                                    │  │
│  │                 └──────────┘                                    │  │
│  │                                                                 │  │
│  │  ┌──────────────────────────────────────────────────────────┐ │  │
│  │  │  HTMX Dashboard (server-rendered, zero JS build)         │ │  │
│  │  │  - Fleet Overview  - Host Detail  - Metric Charts       │ │  │
│  │  │  - Alert List      - Settings                           │ │  │
│  │  │  Uses chart.js (already vendored in static/)             │ │  │
│  │  └──────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                            │                                         │
│              ┌─────────────┴─────────────┐                          │
│              ▼                           ▼                          │
│  ┌───────────────────────┐   ┌─────────────────────────┐          │
│  │  VictoriaMetrics      │   │  MariaDB (existing)      │          │
│  │  - Time-series metrics│   │  - Agent inventory       │          │
│  │  - PromQL queries     │   │  - Users, API keys       │          │
│  │  - Auto-retention     │   │  - Security events       │          │
│  │  - /api/v1/write      │   │  - Alert rules           │          │
│  │  - /api/v1/query      │   │  - Audit log             │          │
│  └───────────────────────┘   └─────────────────────────┘          │
└──────────────────────────────────────────────────────────────────┘
```

## Component Boundaries

### hivemonitor-agent (Rust, new)
- **Responsibility:** Collect system metrics from Linux hosts
- **Runs as:** systemd service, non-root user with capabilities
- **Communication:** Outbound HTTP POST only (no open ports)
- **Deployment:** Single static binary, /etc/hivemonitor/agent.yaml config

### vespid-server (Flask, extended)
- **Responsibility:** Metrics ingestion, query proxy, dashboard rendering
- **New components:** Metrics blueprint, metric API routes, metric dashboard pages
- **No new process:** Serves alongside existing security blueprints
- **Connection:** Forwards metrics to VictoriaMetrics, queries with PromQL

### VictoriaMetrics (single binary)
- **Responsibility:** Time-series storage and PromQL-based querying
- **Operation:** `./victoria-metrics-prod -retentionPeriod=90d`
- **No schema management, no indexes, no migrations**

### MariaDB (existing)
- **Responsibility:** Agent inventory, configuration, users, alert rules
- **Does NOT store time-series metrics**
- **Extended with:** Agents table for monitored hosts, optional alert rules table

## Data Flow

```
1. Collection:
   Agent reads /proc → pre-aggregates → batches metrics

2. Transport:
   Agent POSTs Prometheus remote write payload → Flask server (JSON/gRPC on wire)

3. Ingestion:
   Flask metric blueprint validates → forwards to VictoriaMetrics /api/v1/write

4. Querying:
   Flask dashboard issues PromQL → VictoriaMetrics /api/v1/query → renders charts

5. Alerting (future):
   Flask evaluator queries VictoriaMetrics periodically → checks thresholds
   → logs alert events to MariaDB → displays in dashboard
```

## Shared Identity with Vespid Security

Both the security agent (vespid-scout) and monitoring agent (hivemonitor-agent)
share the concept of a "node" / "agent." They each:

- Have a unique agent_id (UUID)
- Optionally enroll via the same Vespid server (different API keys)
- Can reference the same host inventory record
- Are displayed in the same fleet dashboard

## Architecture Principles

1. **Extend, don't replace** — The Flask server grows, it isn't discarded
2. **One job per binary** — Agent collects, server stores/serves, VM stores/queries
3. **Standard protocols** — Prometheus remote write, PromQL. No custom formats.
4. **Operational simplicity** — VictoriaMetrics is one flag. Deployment is one binary.
5. **Linux-first** — /proc parsing, systemd integration, capabilities, RPM packaging
6. **Offline resilient** — Agent buffers to disk, replays on reconnect
7. **No build step for UI** — Server-rendered HTML with vendored chart.js
