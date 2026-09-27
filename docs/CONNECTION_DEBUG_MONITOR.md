# Connection Debug Monitor

## Overview

The Connection Debug Monitor provides real-time visibility into Vespid Server's connection state, gevent worker pool utilization, SSE client counts, and request throughput. It helps diagnose issues where the WebUI becomes unresponsive or requests appear to hang.

The monitor is **disabled by default** in production packages. Enable it when troubleshooting connection or performance issues.

## How It Works

When enabled, the monitor:

1. **Periodic snapshots** — A background thread writes JSON-lines entries to a dedicated log file every 30 seconds (configurable). Each snapshot includes gevent pool stats, SSE client counts, request throughput, and connection pressure calculations.

2. **Request timing middleware** — Tracks response times for all non-SSE requests. Requests exceeding 2 seconds are logged as `SLOW REQUEST` warnings in the error log and stored in a ring buffer for the debug endpoint.

3. **Debug endpoints** — Three localhost-only HTTP endpoints for on-demand inspection:
   - `GET /_debug/connections` — Live connection snapshot
   - `GET /_debug/connections/history?lines=50` — Recent periodic snapshots
   - `GET /_debug/slow` — Slow requests grouped by path

## Enabling the Monitor

Add to `/etc/vespid-server/config.yaml`:

```yaml
# ── Connection Debug Monitor ──────────────────────────────────────────
CONNECTION_DEBUG_ENABLED: true
```

Then restart the service:

```bash
sudo systemctl restart vespid-server
```

## Configuration Options

| Key | Default | Description |
|-----|---------|-------------|
| `CONNECTION_DEBUG_ENABLED` | `false` | Master switch. Set to `true` to enable. |
| `CONNECTION_DEBUG_INTERVAL` | `30` | Seconds between periodic snapshots. |
| `CONNECTION_DEBUG_LOG` | `/var/log/vespid-server/connection_debug.log` | Path to the JSON-lines debug log. |
| `CONNECTION_DEBUG_ALLOW_REMOTE` | `false` | Allow non-localhost access to `/_debug/*` endpoints. |

Environment variable overrides use the `VESPID_` prefix:

```bash
VESPID_CONNECTION_DEBUG_ENABLED=true
VESPID_CONNECTION_DEBUG_INTERVAL=10
```

## Using the Debug Endpoints

All endpoints are restricted to localhost by default (requests from `127.0.0.1` or `::1` only).

### Live Snapshot

```bash
curl -s http://localhost/_debug/connections | python3 -m json.tool
```

Example output:

```json
{
  "timestamp": "2026-05-14T16:34:01.720715+00:00",
  "worker": {
    "pid": 289665,
    "ppid": 289663,
    "worker_connections_configured": 1000
  },
  "gevent": {
    "pool_size": 1000,
    "pool_free": 996,
    "pool_used": 4,
    "pool_utilization_pct": 0.4,
    "total_greenlets": 8
  },
  "sse": {
    "sse_events_clients": 2,
    "sse_fleet_clients": 1,
    "sse_config_clients": 1,
    "sse_config_nodes": ["vespid01-59bca2d3e6f3"],
    "sse_total_clients": 4
  },
  "requests": {
    "requests_last_60s": 12,
    "requests_last_10s": 3,
    "rps_avg_60s": 0.2,
    "rps_avg_10s": 0.3,
    "slow_requests_last_5m": 0,
    "slowest_recent": []
  },
  "pressure": {
    "sse_connections": 4,
    "pool_capacity": 1000,
    "sse_pct_of_pool": 0.4,
    "remaining_for_requests": 996,
    "warning": false
  }
}
```

### Slow Requests

```bash
curl -s http://localhost/_debug/slow | python3 -m json.tool
```

Shows requests that took longer than 2 seconds, grouped by path with counts and durations.

### Snapshot History

```bash
curl -s "http://localhost/_debug/connections/history?lines=20" | python3 -m json.tool
```

Returns the last N entries from the periodic debug log file.

## Interpreting the Output

### Key Fields

- **`gevent.pool_used`** — Active greenlets handling requests. If this approaches `pool_size`, the worker is saturated.
- **`sse.sse_total_clients`** — Total long-lived SSE connections. Each consumes one greenlet for its lifetime.
- **`pressure.warning`** — `true` when SSE connections consume >80% of the gevent pool, leaving little room for HTTP requests.
- **`pressure.remaining_for_requests`** — Greenlet slots available for new HTTP requests after SSE connections are accounted for.
- **`requests.rps_avg_60s`** — Request throughput. If this drops to 0 while the UI is spinning, requests aren't reaching the server (browser-side issue).

### Common Scenarios

| Symptom | Debug Output | Likely Cause |
|---------|-------------|--------------|
| UI spins, no errors | `requests_last_60s: 0`, pool nearly empty | Browser's 6-connection-per-origin limit (HTTP/1.1). SSE streams consuming all browser connection slots. |
| UI spins, pool saturated | `pool_utilization_pct > 90%` | Too many nodes connected via SSE. Increase `GUNICORN_WORKER_CONNECTIONS` or add workers. |
| Intermittent slowness | `slow_requests_last_5m > 0` | Database contention (SQLite WAL lock) or expensive queries. Check `/_debug/slow` for which paths. |
| One worker saturated, other idle | Large difference in `pool_used` between workers | Uneven load balancing. Consider sticky sessions or more workers. |

### Browser Connection Limit (HTTP/1.1)

The most common cause of "UI spinning with an idle server" is the browser's 6-connection-per-origin limit. Each SSE stream holds one connection slot indefinitely. With multiple tabs or pages that open SSE streams, the browser queues new requests internally — they never reach the server.

Signs:
- `requests_last_60s: 0` (nothing reaching the server)
- `pool_utilization_pct < 5%` (server is idle)
- Problem resolves in an incognito window

Solutions:
- Use HTTP/2 (reverse proxy with `http2` enabled) — removes the 6-connection limit
- Reduce SSE connections per browser session (already handled by the BroadcastChannel leader election in `base.html`)
- Close other tabs to the same server

## Log Rotation

The debug log grows continuously while enabled. Add a logrotate rule:

```
/var/log/vespid-server/connection_debug.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    copytruncate
}
```

## Disabling the Monitor

Set `CONNECTION_DEBUG_ENABLED: false` in config (or remove the key entirely — it defaults to disabled) and restart:

```bash
sudo systemctl restart vespid-server
```

The debug endpoints will return 404 when the monitor is disabled.
