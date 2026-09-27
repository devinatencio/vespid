# Server Integration

Vespid Agent integrates with the Vespid server (Flask + HTMX). The agent ships
metrics via HTTP POST to the server, which forwards them to VictoriaMetrics. The
server renders dashboards with HTMX templates and vendored chart.js.

## Prerequisites

### VictoriaMetrics

Install VictoriaMetrics on the same host as your Vespid server:

**Option A: RPM (recommended)**

```bash
cd vespid-agent/packaging
./build-vm-rpm.sh
dnf install victoria-metrics-1.144.0*.rpm
systemctl enable --now victoria-metrics
```

**Option B: manual**

```bash
curl -L https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v1.144.0/victoria-metrics-linux-amd64-v1.144.0.tar.gz | tar xz
install -m 755 victoria-metrics-prod /usr/bin/victoria-metrics-prod
cp vespid-agent/packaging/victoria-metrics.service /usr/lib/systemd/system/
useradd -r -s /sbin/nologin victoriametrics
mkdir -p /var/lib/victoria-metrics
chown victoriametrics:victoriametrics /var/lib/victoria-metrics
systemctl enable --now victoria-metrics
```

Verify it's running:

```bash
curl http://localhost:8428/api/v1/query?query=up
```

### Vespid server config

Add to `/etc/vespid-server/config.yaml`:

```yaml
METRICS_ENABLED: true
VICTORIAMETRICS_URL: "http://localhost:8428"
```

Restart the server:

```bash
systemctl restart vespid-server
```

## Endpoints

With metrics enabled, the server exposes:

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `POST /api/v1/metrics/write` | Bearer token (agent role) | Agent metric ingestion |
| `POST /api/v1/metrics/checks` | Bearer token (agent role) | Health check results from exec collector |
| `GET /metrics` | Session (viewer+) | Fleet overview dashboard |
| `GET /metrics/<agent_id>` | Session (viewer+) | Per-host metric detail dashboard |
| `GET /metrics/checks` | Session (viewer+) | Health checks status dashboard |
| `GET /metrics/api/summary` | Session (viewer+) | Fleet summary JSON |
| `GET /metrics/api/query?q=<promql>` | Session (viewer+) | Proxy PromQL query to VM |
| `GET /metrics/api/<agent_id>/range?range=1h` | Session (viewer+) | Range query data for charts |

## How it works

```
┌──────────────────┐                    ┌──────────────────┐
│ vespid-       │  POST /api/v1/     │  Vespid       │
│ monitor-agent    │  metrics/write     │  Server (Flask)  │
│                  │──────────────────►│                  │
│  JSON batch      │                    │  1. Validate     │
│  every 60s       │                    │  2. Transform    │
└──────────────────┘                    │  3. Forward      │
                                        │         │        │
                                        │         ▼        │
                                        │  VictoriaMetrics  │
                                        │  /api/v1/import/ │
                                        │  prometheus      │
                                        └──────────────────┘
```

1. Agent POSTs JSON metric batch to server
2. Server validates API key via `@require_role("agent")` decorator
3. Server transforms each metric to Prometheus exposition format
4. Server forwards to VictoriaMetrics `/api/v1/import/prometheus`
5. Dashboard pages query VictoriaMetrics via PromQL and render charts

## API keys

Create an API key with the **agent** role for your monitoring agents:

1. Navigate to **Admin → API Keys** in the Vespid dashboard
2. Click **Create Key**
3. Set **Role** to `agent`
4. Copy the generated key (shown once)
5. Set it in the agent's `server.api_key` config

## Without metrics (security-only)

When `METRICS_ENABLED` is `false` (the default):

- No metric routes are registered
- No VictoriaMetrics connections are attempted
- No "Metrics" nav item appears
- Zero impact on security functionality

The metrics subsystem is completely opt-in.
