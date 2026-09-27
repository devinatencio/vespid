# 03 — Server Architecture

## Overview

The HiveMonitor server components extend the existing Vespid Flask application
with metrics ingestion, storage proxy, dashboard pages, and optional alert evaluation.
No new server process — everything integrates into the existing Flask server.

## New Components

### 1. Metrics Blueprint (`app/metrics.py`)

Handles metrics ingestion from agents and query proxying to VictoriaMetrics.

```python
# Routes
POST   /api/v1/metrics/write          # Receive metrics from agents (Prom remote write)
GET    /api/v1/metrics/query          # Proxy PromQL queries to VictoriaMetrics
GET    /api/v1/metrics/query_range    # Proxy range queries to VictoriaMetrics
```

**Authentication:** API key (same mechanism as existing `/api/v1/events` ingest)

**Implementation:**
- `POST /write` endpoint: Accepts snappy-compressed protobuf (Prometheus remote write format), decompresses, validates, forwards to VictoriaMetrics `POST /api/v1/write`
- Query endpoints: Simple reverse proxy to VictoriaMetrics, adding auth if configured

### 2. Agent Inventory

Extend existing MariaDB schema with a `monitored_agents` table (if separate from
existing `nodes` table for security) or reuse with an `agent_type` column.

```sql
-- If separate table:
CREATE TABLE monitored_agents (
    id CHAR(36) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    agent_version VARCHAR(32),
    labels JSON,
    enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TIMESTAMP,
    status ENUM('active', 'stale', 'decommissioned') DEFAULT 'active',
    api_key_hash VARCHAR(255),
    config JSON
);

-- Or add to existing nodes table:
ALTER TABLE nodes ADD COLUMN agent_type ENUM('security', 'monitor', 'both') DEFAULT 'security';
ALTER TABLE nodes ADD COLUMN monitor_last_seen TIMESTAMP NULL;
ALTER TABLE nodes ADD COLUMN monitor_version VARCHAR(32) NULL;
ALTER TABLE nodes ADD COLUMN monitor_config JSON NULL;
```

**Recommendation:** Add columns to existing `nodes` table. One host = one row, with
both security and monitoring state. This gives unified fleet view from day one.

### 3. Dashboard Pages

Add to existing `templates/` directory with Flask routes in a new or existing blueprint.

**New pages:**

| Route | Page | Description |
|-------|------|-------------|
| `/metrics` | Fleet Metrics Overview | All agents, health sparklines, attention list |
| `/metrics/<agent_id>` | Host Detail | Gauges + line charts for one host |
| `/metrics/network` | Network Overview | All hosts' network stats |
| `/metrics/disks` | Disk Space Overview | All hosts' disk usage sorted by risk |

**Chart implementation:** Use chart.js (already vendored at `static/chart.min.js`).
PromQL queries from Flask template rendering or via AJAX/HTMX to the metrics API.

### 4. Optional: Alert Evaluation

A simple threshold evaluator that:
1. Reads alert rules from a MariaDB table
2. Runs PromQL range queries against VictoriaMetrics periodically (every 60s)
3. Compares results against thresholds
4. Logs firing/resolved events
5. Exposes current alerts via API and dashboard

**Deferred to V1.5/V2 if complexity is too high for MVP.** V1 can have "red/yellow/green"
indicators computed client-side from metric values without a formal alerting engine.

## API Design

### Metrics Ingestion (Agent → Server)

```
POST /api/v1/metrics/write
Authorization: Bearer <api_key>
Content-Type: application/x-protobuf
Content-Encoding: snappy

Body: Prometheus remote write protobuf (snappy-compressed)

Response:
  204 No Content  — success
  400 Bad Request — invalid payload
  401 Unauthorized — bad API key
  503 Service Unavailable — VictoriaMetrics unreachable
```

### Metrics Query (Dashboard → Server → VictoriaMetrics)

```
GET /api/v1/metrics/query?query=<promql>&time=<rfc3339>
Authorization: Bearer <api_key>  (or session cookie)

Response: VictoriaMetrics JSON response
{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [...]
  }
}
```

```
GET /api/v1/metrics/query_range?query=<promql>&start=<rfc3339>&end=<rfc3339>&step=<duration>
Authorization: Bearer <api_key>

Response: VictoriaMetrics JSON response (matrix format)
```

### Agent Status (Dashboard)

```
GET /api/v1/agents/monitored
Authorization: Bearer <api_key>

Response:
{
  "agents": [
    {
      "id": "uuid",
      "hostname": "web-01",
      "status": "active",
      "last_seen": "2026-05-28T14:30:00Z",
      "version": "1.0.0",
      "labels": {"environment": "production", "role": "webserver"},
      "metrics_summary": {
        "cpu_percent": 23.5,
        "memory_percent": 67.2,
        "disk_percent_max": 91.0,
        "network_bytes_recv_rate": 1024000
      }
    }
  ]
}
```

The `metrics_summary` is lazily computed by querying VictoriaMetrics for the latest
value of each key metric. This avoids duplicating metric state in MariaDB.

## Integration with Existing Vespid Server

### Files to Create

```
vespid-server/app/
├── metrics.py              # NEW: Metrics blueprint
├── metrics_dashboard.py    # NEW: Dashboard routes + chart helpers
└── templates/
    ├── metrics/            # NEW: Metric dashboard templates
    │   ├── overview.html
    │   ├── host_detail.html
    │   ├── network.html
    │   └── disks.html
    └── fragments/
        └── metric_chart.html   # NEW: Reusable chart partial
```

### Files to Modify

```
vespid-server/app/
├── __init__.py             # Register metrics blueprint
├── models.py               # Add monitored_agents columns
└── templates/
    └── base.html           # Add "Metrics" to nav bar
```

### Connection to VictoriaMetrics

Flask server communicates with VictoriaMetrics via HTTP. Configuration:

```yaml
# vespid-server config.yaml addition:
victoriametrics:
  url: "http://localhost:8428"
  # No auth needed for single-node local deployment
  # For remote: add basic auth or header
```

Flask helper:

```python
import httpx

class VictoriaMetricsClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(timeout=30.0)

    async def write(self, data: bytes):
        resp = await self.client.post(
            f"{self.base_url}/api/v1/write",
            content=data,
            headers={"Content-Encoding": "snappy"}
        )
        resp.raise_for_status()

    async def query(self, promql: str, time: str | None = None) -> dict:
        params = {"query": promql}
        if time:
            params["time"] = time
        resp = await self.client.get(
            f"{self.base_url}/api/v1/query",
            params=params
        )
        return resp.json()

    async def query_range(self, promql: str, start: str, end: str, step: str) -> dict:
        resp = await self.client.get(
            f"{self.base_url}/api/v1/query_range",
            params={"query": promql, "start": start, "end": end, "step": step}
        )
        return resp.json()
```

## Security

- Metrics ingestion endpoint uses same API key auth as existing event ingestion
- VictoriaMetrics runs on localhost only (no external port)
- Admins can create read-only API keys for external PromQL access
- Dashboard queries go through Flask (with session auth), not directly to VM

## Operational Notes

- No new server process. Metrics handling runs in the existing Flask worker pool.
- For high-volume deployments (>500 agents), consider running VictoriaMetrics
  behind the Flask proxy on a separate host
- Metric ingestion is stateless — any Flask worker can handle it
- VictoriaMetrics is a single point of failure for metrics data (acceptable for V1)
- MariaDB remains the source of truth for agent inventory and configuration
