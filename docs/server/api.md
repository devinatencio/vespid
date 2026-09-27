# Server API Reference

All API endpoints are served on the configured `HOST:PORT` (default
`0.0.0.0`).  Agent-facing endpoints use `Authorization: Bearer <api-key>`
authentication.  Dashboard endpoints use session cookies from `/login`.

> **Interactive documentation**: Browse and test all documented endpoints at
> `/openapi/` (Swagger UI). The OpenAPI spec is available at
> `/openapi/openapi.json`.

## Rate limiting

Limits are per API key (not per IP), except session-authenticated endpoints
which use per-IP limiting.

| Endpoint | Default | Key |
|----------|---------|-----|
| `POST /api/v1/events` | 60/min | Per API key |
| `POST /api/v1/heartbeat` | 30/min | Per API key |
| `GET/POST /api/v1/nodes/<id>/commands` | 60/min | Per API key |
| `GET /api/v1/events/export` | 10/min | Per session IP |
| SSE streams | Exempt | — |

When exceeded, returns `429 Too Many Requests` with `Retry-After` header.

## Event ingestion

```
POST /api/v1/events
Authorization: Bearer <token>
Content-Type: application/json

{"events": [{
    "event_id": "...",
    "node_id": "...",
    "timestamp": "2026-01-01T00:00:00Z",
    "source_ip": "1.2.3.4",
    "event_type": "SSH_BRUTE",
    "action_taken": "BLOCKED",
    "geo_data": {"country": "RU", "asn": "AS12345"},
    "metadata": {"rule": "ssh_fast_brute", "attempts": 5}
}]}
```

Response: `{"accepted": N, "rejected": [...], "total": N}`

## Heartbeat

```
POST /api/v1/heartbeat
Authorization: Bearer <token>

{
    "node_id": "web01-abc123",
    "timestamp": "2026-01-01T00:00:00Z",
    "host_info": {
        "hostname": "web01",
        "os": "Ubuntu 24.04",
        "active_parsers": ["secure", "apache"]
    },
    "block_list": [{
        "ip": "1.2.3.4",
        "reason": "SSH_BRUTE",
        "ttl_remaining": 86000,
        "strike": 2
    }],
    "allowlist": [{"entry": "10.0.0.0/8", "source": "config"}],
    "feeds": [{
        "name": "firehol_level1",
        "url": "https://...",
        "enabled": true,
        "last_sync_count": 15432
    }],
    "counters": [{
        "set": "shield_feed_firehol_level1",
        "chain": "shield_prerouting",
        "family": "ip",
        "packets": 15955,
        "bytes": 2832851
    }]
}
```

Nodes send this after every successful event batch (default: every 5 minutes).

## Command channel

```
GET /api/v1/nodes/{node_id}/commands
Authorization: Bearer <token>

Response: {"commands": [{"command_id": "...", "command_type": "...", "payload": {...}}]}
```

```
POST /api/v1/nodes/{node_id}/commands/{command_id}/result
Authorization: Bearer <token>

{"status": "completed|failed", "result": "optional message"}
```

## SSE streams

### Dashboard events

```
GET /api/v1/events/stream
Cookie: session=<login-session>
```

SSE stream of incoming security events for the dashboard live feed.  Supports
`Last-Event-ID` reconnection with a 500-event history buffer.

### Fleet blocks

```
GET /api/v1/fleet/blocks/stream
Authorization: Bearer <api-key>
Last-Event-ID: fb-...  (optional)
```

Dedicated SSE channel for fleet block propagation.  Messages use `event:
fleet_block` with `id: <fleet_block_id>`:

```
id: fb-a1b2c3d4-...
event: fleet_block
data: {"action":"block","source_ip":"1.2.3.4","reason":"SSH_BRUTE detected by node-alpha","originating_node_id":"node-alpha","ttl_seconds":3600,"timestamp":"2026-01-01T00:00:00Z","fleet_block_id":"fb-a1b2c3d4-..."}
```

Reconnection buffer: 1000 events.  Keepalive comments every 15s.

## Export

```
GET /api/v1/events/export?format=csv&source_ip=1.2.3.4&event_type=SSH_BRUTE
Cookie: session=<login-session>
```

Supports `format=csv` or `format=json`.

## Enrollment

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/enroll` | None (rate-limited) | Submit enrollment request |
| GET | `/api/v1/enroll/status/<node_id>` | None (rate-limited) | Poll status / retrieve credentials |

Both limited to 10 req/min per source IP.

## Fleet API

All under `/api/v1/fleet/`.  Session endpoints require admin/analyst role.

### Blocks

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/fleet/blocks` | Admin/Analyst | List active blocks (paginated) |
| POST | `/api/v1/fleet/blocks` | Admin | Manually add a block |
| DELETE | `/api/v1/fleet/blocks/<ip>` | Admin | Remove a block + publish unblock |
| GET | `/api/v1/fleet/blocks/<ip>/history` | Admin/Analyst | Reporting history for an IP |
| GET | `/api/v1/fleet/blocks/stream` | Bearer token | Fleet SSE channel |

### Allow-list

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/fleet/allowlist` | Admin | List global allow-list |
| POST | `/api/v1/fleet/allowlist` | Admin | Add entry + remove matching blocks |
| DELETE | `/api/v1/fleet/allowlist/<id>` | Admin | Remove entry |

### Configuration

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/fleet/config` | Admin | Get propagation config |
| PUT | `/api/v1/fleet/config` | Admin | Update config (partial) |

Updatable keys: `corroboration_threshold`, `corroboration_window_seconds`,
`fleet_block_ttl_seconds`, `fleet_recidive_tiers`, `fleet_recidive_decay_seconds`,
`max_fleet_blocks_per_hour`,
`max_reports_per_node_per_hour`, `excluded_event_types`,
`reaper_interval_seconds`, `unlock_webhook_secret`.

### Pause / Resume

```
POST /api/v1/fleet/pause
Authorization: <session>
{"paused": true}   # omit to toggle
```

### Unlock webhook

```
POST /api/v1/unlock-webhook/<secret>/<ip>
# No auth — rate-limited to 10/min
```

Unblock an IP via pre-shared secret if you lock yourself out.

## Detection rules API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/rules` | Admin (session) | List all rules (paginated) |
| POST | `/api/v1/rules/brute-force` | Admin | Create brute force rule |
| POST | `/api/v1/rules/custom` | Admin | Create custom regex rule |
| PUT | `/api/v1/rules/brute-force/<id>` | Admin | Update brute force rule |
| PUT | `/api/v1/rules/custom/<id>` | Admin | Update custom rule |
| DELETE | `/api/v1/rules/brute-force/<id>` | Admin | Disable brute force rule |
| DELETE | `/api/v1/rules/custom/<id>` | Admin | Disable custom rule |
| GET | `/api/v1/rules/distribution` | Bearer token | Get enabled rules for node |

### Distribution endpoint

```
GET /api/v1/rules/distribution
Authorization: Bearer <token>
If-None-Match: "42"
```

Returns 304 if unchanged, 200 with full rule set otherwise.  Response includes
per-node filtering metadata (`active_parsers`, `filtered`, `packs`).

### Pack endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/rules/templates/<pack>` | Admin | List rules in a pack |
| POST | `/api/v1/rules/templates/<pack>/enable-all` | Admin | Enable all rules |
| POST | `/api/v1/rules/templates/<pack>/disable-all` | Admin | Disable all rules |
| POST | `/api/v1/rules/templates/<pack>/<id>/toggle` | Admin | Toggle single rule |

## Intelligence API

Endpoints for IP threat intelligence — sighting/block ingestion and
reputation querying.

### Ingestion

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/intel/sightings` | Bearer | Submit a single sighting event |
| POST | `/api/v1/intel/blocks` | Bearer | Submit a single block event |
| POST | `/api/v1/intel/batch` | Bearer | Submit up to 500 events in one request |

### Querying

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/intel/ips` | Session or Bearer | Search IP records (paginated, filterable) |
| GET | `/api/v1/intel/ips/<ip>` | Session or Bearer | Full threat profile for a single IP |
| GET | `/api/v1/intel/blocklist` | Session or Bearer | Export IP blocklist |

Query parameters for `/api/v1/intel/ips`:

| Parameter | Description |
|-----------|-------------|
| `q` | Search by IP prefix |
| `tag` | Filter by threat tag |
| `min_score` | Minimum threat score (0–100) |
| `repeat_offender` | Filter for repeat offenders only |
| `sort` | Sort field (`threat_score`, `total_times_blocked`, `last_seen_at`) |
| `limit` / `offset` | Pagination |

See the [Intelligence Pipeline](../INTEL_PIPELINE_FEATURES.md) for details
on scoring, multi-vector detection, and block lifecycle tracking.

## Host event ingestion

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/host-events` | Bearer | Submit host-based events (auditd process creation) |

See [Host Threat Detection](../HOST_THREAT_DETECTION.md) for the full
event schema and detection pipeline.

## Host threats API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/admin/host-threats` | Analyst+ | Host threat timeline page |
| GET | `/admin/host-threats/process-tree` | Analyst+ | Process tree visualization |
| GET | `/admin/host-threats/timeline` | Analyst+ | Kill chain timeline JSON (Chart.js) |
| GET | `/admin/host-threats/score-history` | Analyst+ | 24h score timeseries (288 data points) |
| GET | `/admin/host-threats/summary` | Analyst+ | Per-host summary cards JSON |

## Config management API

Centralized agent configuration profile management.

### Profiles

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/config/profiles` | Admin | Create a config profile |
| GET | `/api/v1/config/profiles` | Admin | List all profiles |
| GET | `/api/v1/config/profiles/<id>` | Admin | Get profile details |
| PUT | `/api/v1/config/profiles/<id>` | Admin | Update profile settings |
| DELETE | `/api/v1/config/profiles/<id>` | Admin | Delete profile |

### Assignments

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/config/assignments` | Admin | Assign profile to node or group |
| DELETE | `/api/v1/config/assignments/<id>` | Admin | Remove assignment |

### Groups

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/config/groups` | Admin | Create agent group |
| GET | `/api/v1/config/groups` | Admin | List groups |
| DELETE | `/api/v1/config/groups/<id>` | Admin | Delete group |
| POST | `/api/v1/config/groups/<id>/members` | Admin | Add member to group |
| DELETE | `/api/v1/config/groups/<id>/members` | Admin | Remove member from group |

### Config SSE

```
GET /api/v1/config/stream
Authorization: Bearer <api-key>
Last-Event-ID: <id>  (optional)
```

Dedicated SSE channel for pushing config profile updates to managed agents.
Per-node targeted delivery — each agent only receives updates for its
assigned profile.  Reconnection replay via ring buffer (default 1000 events).
Keepalive comments every 30 seconds.

## Alert manager API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/alerts/rules` | Analyst+ | List alert rules |
| POST | `/api/v1/alerts/rules` | Admin | Create alert rule |
| PUT | `/api/v1/alerts/rules/<id>` | Admin | Update alert rule |
| DELETE | `/api/v1/alerts/rules/<id>` | Admin | Delete alert rule |
| GET | `/api/v1/alerts/events` | Analyst+ | List alert events |
| GET | `/api/v1/alerts/channels` | Admin | List notification channels |
| POST | `/api/v1/alerts/channels` | Admin | Create notification channel |
| PUT | `/api/v1/alerts/channels/<id>` | Admin | Update channel |
| DELETE | `/api/v1/alerts/channels/<id>` | Admin | Delete channel |
| GET | `/api/v1/alerts/silences` | Analyst+ | List active silences |
| POST | `/api/v1/alerts/silences` | Analyst+ | Create silence |
| DELETE | `/api/v1/alerts/silences/<id>` | Analyst+ | Remove silence |
| GET | `/api/v1/alerts/health` | Admin | Eval loop health check |

See the [Alert Manager Guide](../alert-manager.md) for rule types, notification
channels, and silence configuration.

## Metrics API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/metrics/write` | Bearer | Ingest metric batch from agent |

The server proxies metrics to VictoriaMetrics when configured.  See the
[Server Guide](guide.md#metrics-optional) for setup.

## Fleet blocks (agent initial sync)

```
GET /api/v1/fleet/blocks/active
Authorization: Bearer <api-key>
```

Returns all currently active fleet blocks.  Used by agents on startup
to populate their local nftables set before subscribing to the SSE stream.
