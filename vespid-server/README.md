# Vespid Server Dashboard

Centralized security event management server for the Vespid ecosystem. Receives SecurityEvent batches from distributed Vespid daemon instances, persists them in SQLite (or MySQL), and presents them through an HTMX-powered web dashboard with real-time streaming, search, geographic visualization, trend analytics, IP rule management, and threat intelligence feed orchestration.

## Architecture

```
Vespid Daemons ──POST /api/v1/events──▶ Flask API ──▶ SQLite/MySQL
                   ──POST /api/v1/heartbeat──▶            │
                   ──GET  /api/v1/nodes/X/commands──▶      │
                   ──GET  /api/v1/rules/distribution──▶     │
                                                           ├──▶ SSE Manager ──▶ Browser (live event feed)
                                                           ├──▶ Fleet SSE Manager ──▶ Agents (block propagation)
                                                           ├──▶ Config SSE Manager ──▶ Managed agents (config push)
                                                           │
                                                     Dashboard Blueprints
                                                      ├── auth        (login/logout, sessions)
                                                      ├── api         (ingestion, SSE, export, commands)
                                                      ├── dashboard   (overview, events, nodes, geo, trends,
                                                       │                counters, blocked IPs)
                                                       ├── fleet       (blocks, allowlist, config, propagation)
                                                       ├── intel       (IP search, threat metrics, analytics)
                                                       ├── rules       (detection rules CRUD, packs, distribution)
                                                       ├── config      (profiles, assignments, rollouts)
                                                       ├── enrollment  (auto-enrollment lifecycle)
                                                       ├── metrics     (optional — agent ingest, VM proxy, dashboards)
                                                       └── admin       (users, API keys, audit log, test rules)
```

Key design choices:

- **Flask + HTMX + SQLite** — no JavaScript build tooling, no external database required
- **Gevent worker class** — cooperative greenlets for massive I/O concurrency; each worker multiplexes thousands of idle SSE connections with near-zero overhead
- **MySQL/MariaDB support** — optional migration for high-volume deployments (see [MySQL Backend](#mysql-backend))
- **Database abstraction layer** — `app/db_compat.py` transparently handles placeholder translation, row access, and driver differences between SQLite and MySQL
- **Server-rendered HTML** with HTMX partial-page updates and Chart.js for charts
- **SQLite WAL mode** for concurrent reads during writes
- **Blueprint-based** route organization (auth, api, dashboard, fleet, intel, rules, config, enrollment, admin)
- **Role-based access control** — admin, analyst, viewer
- **Command channel** — server queues commands, nodes poll on heartbeat
- **Feed catalog** — centrally managed threat intelligence feeds pushed to nodes
- **Three dedicated SSE channels** — dashboard events, fleet block propagation, and config push each have isolated fan-out managers with reconnection buffers
- **Threat intelligence pipeline** — built-in scoring, sighting tracking, threat tag accumulation, and IP search
- **RPM packaging** with systemd service management

## Prerequisites

- Python 3.11 or later
- SQLite 3 (included with Python) or MySQL 8.0+
- Linux with systemd (for production deployment)
- rpmbuild (only if building the RPM package)

## Metrics Subsystem (optional)

The server can optionally accept system metrics from `vespid-agent`
instances and proxy them to VictoriaMetrics for time-series storage and
dashboarding. When enabled, a "📊 Metrics" section appears in the dashboard nav.

**Prerequisites for metrics:**

- VictoriaMetrics binary ([download](https://github.com/VictoriaMetrics/VictoriaMetrics/releases))
- `vespid-agent` deployed on target hosts

**Quick start:**

```bash
# 1. Start VictoriaMetrics
# Option A: RPM (recommended — systemd service, unprivileged user)
# Build: ./vespid-agent/packaging/build-vm-rpm.sh
# Install: dnf install victoria-metrics-1.148.0*.rpm
#   systemctl enable --now victoria-metrics

# Option B: manual download + systemd (see victoria-metrics.service in vespid-agent/packaging/)
# curl -L https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v1.148.0/victoria-metrics-linux-amd64-v1.148.0.tar.gz | tar xz
# install -m 755 victoria-metrics-prod /usr/bin/victoria-metrics-prod

# 2. Enable in server config (/etc/vespid-server/config.yaml)
METRICS_ENABLED: true
VICTORIAMETRICS_URL: "http://localhost:8428"

# 3. Restart server
sudo systemctl restart vespid-server

# 4. Deploy agents (see vespid-agent docs)
```

**Endpoints:**

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `POST /api/v1/metrics/write` | Bearer token (agent role) | Ingest metric batches from agents |
| `GET /metrics` | Session (viewer+) | System metrics overview dashboard |
| `GET /metrics/<agent_id>` | Session (viewer+) | Per-host metric charts and gauges |

**Configuration:**

| Key | Default | Description |
|-----|---------|-------------|
| `METRICS_ENABLED` | `false` | Enable the metrics subsystem |
| `VICTORIAMETRICS_URL` | `http://localhost:8428` | VictoriaMetrics API URL |

When `METRICS_ENABLED` is `false` (the default), no metric routes are registered,
no VictoriaMetrics connections are attempted, and no nav items appear. The feature
has zero impact on security-only deployments.

## Installation

### Option A: RPM Package (recommended for production)

```bash
# Build the RPM
make rpm

# Install
sudo rpm -ivh rpmbuild/RPMS/noarch/vespid-server-1.0.0-1.*.noarch.rpm

# Create the first admin user
sudo -u vespid /opt/vespid-server/.venv/bin/python \
    /opt/vespid-server/vespid_server.py \
    --config /etc/vespid-server/config.json create-admin

# Start the service
sudo systemctl start vespid-server
sudo systemctl enable vespid-server
```

### Option B: Manual Installation (development or custom setups)

```bash
cd vespid-server/

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Initialize the database
python vespid_server.py init-db

# Create an admin user
python vespid_server.py create-admin

# Start the development server
python vespid_server.py
```

## Quick Start

1. **Install** using either method above. An admin user is created automatically — the password is printed during install.
2. **Log in** at `http://your-server:8000`. For production, place a reverse proxy in front (see [Reverse Proxy](#reverse-proxy)).
3. **Create an API key** in Admin → API Keys (or enable auto-enrollment — see below).
4. **Configure Vespid daemons** with the server URL and API key.
5. Nodes auto-register on first heartbeat. Events flow in, feeds deploy out.

## Reverse Proxy

Vespid Server binds to `127.0.0.1:8000` by default. For production, run a
reverse proxy in front to handle TLS termination, HTTP→HTTPS redirects, and
request buffering.

### nginx

```nginx
server {
    listen 443 ssl;
    server_name vespid.example.com;

    ssl_certificate     /etc/ssl/vespid/fullchain.pem;
    ssl_certificate_key /etc/ssl/vespid/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE endpoints use long-lived connections
        proxy_buffering off;
        proxy_read_timeout 86400s;
    }
}
```

### Caddy

```
vespid.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

After configuring the proxy, set `PROXY_COUNT=1` in `config.yaml` (or
`VESPID_PROXY_COUNT=1`) so Vespid reads the real client IP from the
`X-Forwarded-For` header for rate limiting and audit logs.

## Auto-Enrollment

Auto-enrollment allows Vespid agents to automatically obtain API credentials from the server without requiring administrators to pre-distribute API keys. This eliminates the manual step of creating a key, copying it to the agent's config file, and restarting the daemon.

### How It Works

1. Agent starts with no API key (or the default placeholder `REPLACE_ME_WITH_ENROLLMENT_TOKEN`)
2. Agent sends a `POST /api/v1/enroll` request with its `node_id` and `hostname`
3. Server processes the request based on the active enrollment mode
4. Agent receives credentials (immediately or after admin approval)
5. Agent persists credentials to `/var/lib/vespid/credentials.json` (mode 0600)
6. Agent uses the issued key for all subsequent API calls

If the agent already has a valid API key in its config file, enrollment is skipped entirely.

### Enrollment Modes

| Mode | Behavior | Best For |
|------|----------|----------|
| `open` | Credentials issued immediately, no approval needed | Labs, trusted networks, rapid deployment |
| `manual_approval` | Request queued until an admin approves it | Production environments |
| `restricted` | Requires a pre-shared enrollment token | High-security environments |

### Enabling Enrollment

1. Log in as an admin
2. Go to **Admin → Enrollment**
3. Set enrollment to **Enabled**
4. Choose a mode (defaults to `manual_approval`)
5. Click **Save Settings**

### Manual Approval Workflow

```
Agent starts (no credentials)
    → POST /api/v1/enroll → 202 Pending
    → Agent polls GET /api/v1/enroll/status/<node_id> with exponential backoff

Admin sees pending request in Admin → Enrollment
    → Clicks "Approve"
    → Server generates API key restricted to that node_id

Agent's next poll returns 200 with credentials
    → Agent persists credentials and starts normal operation
```

### Open Mode Workflow

```
Agent starts (no credentials)
    → POST /api/v1/enroll → 200 with api_key
    → Agent persists credentials and starts normal operation immediately
```

### Credential Rotation

Admins can rotate an enrolled agent's credentials without requiring re-enrollment:

1. Go to **Admin → Enrollment**
2. Find the approved agent and click **Rotate**
3. The old key is immediately revoked
4. A new key is generated and made available for the agent
5. On the agent's next 401 error, it checks the status endpoint and picks up the new key

### Credential Revocation

To permanently cut off an agent:

1. Go to **Admin → Enrollment** and click **Revoke** on the agent
2. The API key is deactivated immediately
3. The agent will get 401 on its next request and 403 when checking the status endpoint
4. The agent stops retrying until the daemon is restarted

### Enrollment API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/enroll` | None (rate-limited) | Submit enrollment request |
| GET | `/api/v1/enroll/status/<node_id>` | None (rate-limited) | Poll status / retrieve credentials |

Both endpoints are rate-limited to 10 requests per minute per source IP.

### Agent Configuration

The agent config supports these enrollment-related fields (all optional):

```yaml
# Enrollment settings (vespid.yaml)
enrollment_poll_initial_seconds: 30    # Initial poll interval (doubles each attempt)
enrollment_poll_max_seconds: 300       # Maximum poll interval (5 minutes)
```

If `SERVER_URL` is set and `API_KEY` is left as the default placeholder, the agent will attempt enrollment on startup.

### Audit Trail

All enrollment actions are recorded in the audit log:
- `enrollment_request` — agent submitted a request
- `enrollment_status_change` — record approved/rejected/revoked
- `enrollment_credential_issued` — credentials generated
- `enrollment_credential_rotated` — credentials rotated
- `enrollment_settings_change` — admin changed enrollment settings

## Configuration Reference

Configuration is loaded from a YAML or JSON file with environment variable overrides (`VESPID_` prefix). YAML is the preferred format — it supports comments and doesn't require escaping.

**File resolution order** (when `--config` is not specified):
1. `$VESPID_CONFIG` environment variable
2. `/etc/vespid-server/config.yaml`
3. `/etc/vespid-server/config.yml`
4. `/etc/vespid-server/config.json`

**Priority** (highest to lowest): environment variables → config file → built-in defaults.

| Setting | Default | Description |
|---------|---------|-------------|
| `SECRET_KEY` | `change-me-to-a-random-string` | Flask session signing key. **Must be changed in production.** |
| `DATABASE_PATH` | `/var/lib/vespid-server/vespid.db` | Path to the SQLite database file (used when DATABASE_TYPE is sqlite). |
| `DATABASE_TYPE` | `sqlite` | Database backend: `sqlite`, `mysql`, or `mariadb`. |
| `DATABASE_HOST` | `localhost` | MySQL/MariaDB server hostname. |
| `DATABASE_PORT` | `3306` | MySQL/MariaDB server port (1–65535). |
| `DATABASE_NAME` | `vespid` | MySQL/MariaDB database name. |
| `DATABASE_USER` | `vespid` | MySQL/MariaDB username. |
| `DATABASE_PASSWORD` | *(empty)* | MySQL/MariaDB password. |
| `HOST` | `127.0.0.1` | Address the server binds to (localhost by default — use a reverse proxy). |
| `PORT` | `8000` | Port the server listens on. |
| `DEBUG` | `false` | Enable Flask debug mode. Never use in production. |
| `SESSION_LIFETIME_HOURS` | `24` | How long login sessions remain valid. |
| `EVENTS_PER_PAGE` | `50` | Number of events per page in search results. |
| `SSE_HISTORY_SIZE` | `500` | SSE reconnection replay buffer size (dashboard stream). |
| `FLEET_SSE_HISTORY_SIZE` | `1000` | SSE reconnection replay buffer size (fleet block stream). |
| `CONFIG_SSE_HISTORY_SIZE` | `1000` | SSE reconnection replay buffer size (config push stream). |
| `NODE_HEALTHY_SECONDS` | `300` | Max age (seconds) for "healthy" node status. |
| `NODE_DEGRADED_SECONDS` | `900` | Max age (seconds) before node shows "offline". |
| `FLEET_REAPER_INTERVAL_SECONDS` | `86400` | How often the fleet reaper expires old blocks (24 hours). |
| `COUNTER_RETENTION_DAYS` | `30` | Days to retain counter snapshots before cleanup. |
| `LOG_FILE` | `/var/log/vespid-server/vespid-server.log` | Application log file path. |
| `LOG_LEVEL` | `INFO` | Log level for the application log file. |
| `LOG_MAX_BYTES` | `10485760` | Max size per log file before rotation (10 MB). |
| `LOG_BACKUP_COUNT` | `5` | Number of rotated log files to keep. |
| `CUSTOM_THEME_DIR` | *(none)* | Path to a directory of custom CSS theme files. |
| `RATELIMIT_ENABLED` | `true` | Master switch for API rate limiting. |
| `RATELIMIT_EVENTS_INGEST` | `60 per minute` | Rate limit for event ingestion endpoint (per API key). |
| `RATELIMIT_HEARTBEAT` | `30 per minute` | Rate limit for heartbeat endpoint (per API key). |
| `RATELIMIT_COMMANDS` | `60 per minute` | Rate limit for command poll/result endpoints (per API key). |
| `RATELIMIT_EXPORT` | `10 per minute` | Rate limit for event export endpoint (per session IP). |
| `RATELIMIT_STORAGE_URI` | `memory://` | Backend for rate limit counters. Use `redis://host:6379/0` for multi-process. |

</text>
</invoke>

## Dashboard Pages

The web dashboard uses a streamlined top-level navigation with 5 menu groups:

| Menu | Items |
|------|-------|
| **Dashboard** | Overview (no dropdown) |
| **Analytics** | Events, Counters, Geo, Trends |
| **Intelligence** | Search, Threat Metrics, Admin (authenticated users) |
| **Security** | Blocked, Feeds, Fleet, IP Rules, Nodes, Detection Rules |
| **Admin** | API Keys, Audit Log, Config Management, Enrollment, Test Rules, Users (admin only) |

### Dashboard (`/`)

Overview with stats cards (total events 24h, active nodes, blocked IPs, distinct source IPs), event type breakdown donut chart, 24h sparkline, and the 20 most recent events with SSE live updates. Stats auto-refresh every 30 seconds.

### Analytics → Events (`/events`)

Search and filter events by source IP, node ID, event type, time range, or country. All filters use intersection semantics (AND). Results are paginated. Real-time SSE feed shows new events as toast notifications.

### Security → Blocked IPs (`/blocked`)

Aggregated view of all blocked IPs across nodes. Shows block count (color-coded by severity), first/last blocked timestamps, associated event types, countries, and reporting nodes. Filter by time range, IP, node, event type, or country.

### Security → Rules (`/rules`) — analyst+ role

Side-by-side allowlist and blocklist management panels.

**Allowlist panel:**
- Add IP/CIDR entries with a reason
- Select target nodes (or send to all)
- Adding an IP queues `allowlist_add` commands to nodes
- Allowlisted IPs are automatically unblocked if currently blocked
- Remove entries to queue `allowlist_remove` commands

**Blocklist panel:**
- Manually block IPs across the fleet
- Queues `block` commands to selected nodes
- Remove entries to queue `unblock` commands

**Command queue:**
- Shows the 20 most recent commands with status (pending → acknowledged → completed/failed)
- Auto-refreshes every 15 seconds via HTMX
- Pending commands pulse to indicate they're waiting for pickup

### Security → Feeds (`/feeds`) — analyst+ role

Centralized threat intelligence feed catalog. Feeds are managed here and deployed to nodes via the command channel.

**Feed catalog:**
- 12 pre-seeded feeds across 6 categories (aggregated, hijacked, botnet, attacks, compromised, anonymizers)
- Each feed card shows: name, description, URL, format, refresh interval
- Deployment stats: how many nodes are running each feed, total IPs across active nodes
- "Recommended" badge on high-value, low-false-positive feeds

**Actions:**
- **Deploy** — push a feed to selected nodes (or all). Queues `feed_add` commands.
- **Retract** — remove a feed from all nodes. Queues `feed_remove` commands.
- **Add custom feed** (admin only) — name, URL, format, refresh interval, category
- **Remove from catalog** (admin only) — deletes the feed definition

**Pre-seeded feeds:**

| Category | Feed | Source | Default |
|----------|------|--------|---------|
| Aggregated | firehol_level1 | iplists.firehol.org | ✓ |
| Aggregated | firehol_level2 | iplists.firehol.org | |
| Hijacked | spamhaus_drop | spamhaus.org | ✓ |
| Botnet | abuse_ch_feodo | feodotracker.abuse.ch | ✓ |
| Botnet | abuse_ch_sslbl | sslbl.abuse.ch | |
| Attacks | blocklist_de | lists.blocklist.de | |
| Attacks | ci_army | cinsscore.com | |
| Attacks | dshield_top20 | feeds.dshield.org | |
| Compromised | et_compromised | rules.emergingthreats.net | |
| Anonymizers | tor_exit_nodes | check.torproject.org | |
| Attacks | binarydefense | binarydefense.com | |

### Security → Nodes (`/nodes`)

Lists all registered nodes with health status, last seen time, total events, and location. Click a node ID to open its detail page.

### Security → Node Detail (`/nodes/<node_id>`) — viewer+ role

Per-node management page showing:

- **Stats cards** — health status, active blocks, subscribed IPs (summed from feeds), allowlist entries, total events
- **Detection Packs** — which packs are active on this node, with active parsers shown as pills, assignment mode (auto/explicit), and pack cards showing icon, name, rule count, and assignment type. Shows "Parser information pending" for nodes that haven't heartbeated yet.
- **Subscription feeds** — each feed the node is running, with toggle switches to enable/disable. Shows IP count and refresh interval per feed.
- **Active blocks** — IPs currently in the node's `shield_local` nftables set, with reason, TTL (color-coded: green < 1h, yellow < 24h, red > 24h), and strike count. Unblock button per IP.
- **Allowlist** — config and runtime allowlist entries with source badges. Quick-add form for new entries.
- **Recent commands** — commands sent to this node with status tracking.

### Analytics → Geo (`/geo`)

Country breakdown table showing event counts by source country. Click a country to filter the event list.

### Analytics → Trends (`/trends`)

Time-series charts powered by Chart.js. Select intervals (1h, 6h, 24h, 7d) and group by event type, node ID, or source IP.

### Analytics → Counters (`/counters`)

Fleet-wide nftables packet and byte counters aggregated from all nodes. Displays a horizontal stacked bar chart (one bar per nftables set, stacked by node) and a summary table.

**What it shows:**

- Absolute cumulative packet/byte counts per nftables set as reported in each node's most recent heartbeat
- Sets include threat feed sets (e.g. `shield_feed_firehol_level1`) and local block sets (`shield_local_blocks`)
- Chart bars are stacked by node so you can see each node's contribution
- Summary table lists total packets, total bytes, and how many nodes report each set
- Filter by a single node or view the entire fleet

**Data source and refresh:**

Counter data comes from the `last_counters` field stored on each node record. Nodes collect live nftables counters (via `nft list table`) and include them in every heartbeat payload. The server overwrites the previous snapshot on each heartbeat, so only the latest values are stored — there is no counter history.

**Current limitations:**

| Limitation | Detail |
|------------|--------|
| Snapshot-only | Only the most recent heartbeat's counters are stored. No historical data is retained. |
| No delta / rate calculation | The dashboard displays raw cumulative counters, not packets-per-second or bytes-per-second. There is no server-side delta computation between heartbeats. |
| No counter reset detection | If nftables counters reset to zero (firewall reload, table rebuild, service restart), the displayed values simply drop. The server does not detect or compensate for resets. |
| No trend tracking | Because only the latest snapshot is kept, there are no time-series trends for counter data. |
| Heartbeat cadence | Data freshness depends on the heartbeat interval (default 5 minutes). Counters are not streamed in real time. |

> **Note:** The Vespid CLI (`vespid counters --watch`) does compute local deltas and per-second rates with basic reset handling (`max(0, delta)`), but this is a terminal-only feature and does not feed into the server or web dashboard.

### Admin (`/admin/*`) — admin role only

- **Users** — create operators, assign roles (admin/analyst/viewer)
- **API Keys** — create, revoke, and delete Bearer tokens for node authentication. Active keys can be revoked; revoked keys can be permanently deleted.
- **Enrollment** — manage auto-enrollment settings (enable/disable, mode selection) and agent enrollment lifecycle (approve, reject, revoke, rotate credentials)
- **Audit Log** — all administrative actions with actor, IP, timestamp, and details
- **Config Management** — centralized configuration profiles for server-managed nodes
- **Test Rules** — dry-run simulation engine for testing detection rules against log samples

### Security → Detection Rules (`/admin/rules`) — admin role only

Centralized detection rule management (brute force and custom regex rules). Create, edit, enable/disable rules that are distributed to all enrolled nodes. Includes collapsible detection rule packs (Apache, NGINX, OpenSSH, Postfix) that can be enabled with one click. Each pack shows a node count badge indicating how many nodes receive it based on per-node filtering.

## Command Channel

The server queues commands for nodes. Nodes poll for commands after each successful heartbeat (default every 5 minutes).

### Flow

```
Dashboard action → pending_commands table → node heartbeat →
  GET /api/v1/nodes/{id}/commands → node executes via control socket →
  POST /api/v1/nodes/{id}/commands/{cmd_id}/result → status updated
```

### Command Types

| Command | Payload | Description |
|---------|---------|-------------|
| `allowlist_add` | `{"entry": "10.0.0.0/8"}` | Add IP/CIDR to node's runtime allowlist |
| `allowlist_remove` | `{"entry": "10.0.0.0/8"}` | Remove from runtime allowlist |
| `block` | `{"ip": "1.2.3.4", "reason": "..."}` | Block an IP in shield_local |
| `unblock` | `{"ip": "1.2.3.4", "reason": "..."}` | Unblock from shield_local |
| `feed_enable` | `{"name": "firehol_level1"}` | Enable a subscription feed |
| `feed_disable` | `{"name": "firehol_level1"}` | Disable a subscription feed |
| `feed_add` | `{"name": "...", "url": "...", "format": "...", "refresh_seconds": N}` | Add a new subscription feed |
| `feed_remove` | `{"name": "firehol_level1"}` | Remove a subscription feed |

### Command Statuses

| Status | Meaning |
|--------|---------|
| `pending` | Queued, waiting for node to poll |
| `acknowledged` | Node picked up the command |
| `completed` | Node executed successfully |
| `failed` | Node execution failed (see result message) |
| `expired` | Command was not picked up in time |

## Node Heartbeat Data

Each heartbeat includes the node's current state, stored on the server for the node detail page:

```json
{
    "node_id": "web01-abc123",
    "timestamp": "2026-05-03T04:00:00Z",
    "host_info": {
        "hostname": "web01",
        "os": "Ubuntu 24.04",
        "active_parsers": ["secure", "apache"]
    },
    "block_list": [{"ip": "1.2.3.4", "reason": "SSH_BRUTE", "ttl_remaining": 86000, "strike": 2}],
    "allowlist": [{"entry": "10.0.0.0/8", "source": "config"}],
    "feeds": [{"name": "firehol_level1", "url": "...", "enabled": true, "last_sync_count": 15432}],
    "counters": [{"set": "shield_feed_firehol_level1", "chain": "shield_prerouting", "family": "ip", "packets": 15955, "bytes": 2832851}]
}
```

The `active_parsers` field is derived from the node's configured `log_sources` and is used by the server for per-node detection pack filtering. It lists the unique parser names the node is monitoring (e.g., `["secure", "apache", "postfix"]`).

## Rate Limiting

All API endpoints are rate-limited to prevent abuse from compromised or misbehaving nodes. Limits are enforced per API key (not per IP), so nodes behind NAT or a load balancer get independent quotas.

### How it works

- Each API key has its own rate limit counter
- When a limit is exceeded, the server returns `429 Too Many Requests` with a JSON body:
  ```json
  {"error": "rate_limit_exceeded", "message": "Rate limit exceeded: 60 per 1 minute"}
  ```
- The `Retry-After` header indicates how many seconds to wait before retrying
- The SSE stream endpoint is exempt (it's a long-lived connection)
- Session-authenticated endpoints (export) fall back to per-IP limiting

### Default limits

| Endpoint | Default | Key |
|----------|---------|-----|
| `POST /api/v1/events` | 60/min | Per API key |
| `POST /api/v1/heartbeat` | 30/min | Per API key |
| `GET /api/v1/nodes/<id>/commands` | 60/min | Per API key |
| `POST /api/v1/nodes/<id>/commands/<id>/result` | 60/min | Per API key |
| `GET /api/v1/events/export` | 10/min | Per session IP |
| `GET /api/v1/events/stream` | Exempt | — |

### Multi-process deployments

The default `memory://` storage backend works for single-process or single-worker setups. For gunicorn with multiple workers, use Redis so counters are shared across processes:

```yaml
RATELIMIT_STORAGE_URI: "redis://localhost:6379/0"
```

### Disabling rate limiting

Set `RATELIMIT_ENABLED: false` in your config file or `VESPID_RATELIMIT_ENABLED=false` as an environment variable. This is useful for development or load testing.

## API Reference

### Event Ingestion

```
POST /api/v1/events
Authorization: Bearer <token>
Content-Type: application/json

{"events": [{...SecurityEvent...}]}
```

Response: `{"accepted": N, "rejected": [...], "total": N}`

### Heartbeat

```
POST /api/v1/heartbeat
Authorization: Bearer <token>

{"node_id": "...", "timestamp": "...", "block_list": [...], "allowlist": [...], "feeds": [...], "counters": [...]}
```

### Command Channel

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

### SSE Stream

```
GET /api/v1/events/stream
Cookie: session=<login-session>
```

### Export

```
GET /api/v1/events/export?format=csv&source_ip=...&event_type=...
Cookie: session=<login-session>
```

## User Roles

Pages are grouped under the new navigation menus: **Analytics** (Events, Counters, Geo, Trends), **Intelligence** (Search, Threat Metrics), **Security** (Blocked, Feeds, Fleet, IP Rules, Nodes, Detection Rules), and **Admin**.

| Role | Dashboard | Analytics | Intelligence | Security | Export | Admin |
|------|-----------|-----------|--------------|----------|--------|-------|
| viewer | ✓ | Events, Counters, Geo, Trends | | Blocked, Nodes (read) | | |
| analyst | ✓ | All | Search, Threat Metrics | All (actions) | ✓ | |
| admin | ✓ | All | All (+ Intel Admin) | All (+ Detection Rules) | ✓ | ✓ |

## Database Schema

The server uses 29 tables (identical schema on both SQLite and MySQL/MariaDB):

| Table | Purpose |
|-------|---------|
| `events` | All ingested SecurityEvents with flattened geo columns |
| `event_log_context` | Contextual log lines surrounding detected events |
| `users` | Dashboard operators with hashed passwords and roles |
| `api_keys` | Bearer tokens for node authentication (SHA-256 hashed) |
| `nodes` | Auto-registered node registry with health and state snapshots |
| `audit_log` | Administrative action audit trail |
| `pending_commands` | Command queue for server-to-node communication |
| `ip_rules` | Allowlist/blocklist entries managed from the dashboard |
| `feed_catalog` | Centrally managed threat intelligence feed definitions |
| `counter_snapshots` | Periodic nftables counter snapshots for fleet analytics |
| `enrollment_requests` | Agent enrollment lifecycle tracking (pending/approved/rejected/revoked) |
| `enrollment_settings` | Server-wide enrollment configuration (enabled, mode) |
| `fleet_blocks` | Active and historical fleet blocklist entries |
| `fleet_block_reports` | Individual node reports for corroboration tracking |
| `fleet_allowlist` | Global allow-list of IPs/CIDRs exempt from propagation |
| `fleet_config` | Propagation policy configuration (key-value store) |
| `detection_rules_brute_force` | Centrally managed brute force detection rules |
| `detection_rules_custom` | Centrally managed custom regex detection rules |
| `detection_rules_correlation` | Centrally managed multi-signal correlation rules |
| `detection_rules_revision` | Monotonic revision counter for rule change detection |
| `config_profiles` | Centralized agent configuration profiles |
| `config_version_history` | Version history for configuration profiles |
| `config_assignments` | Profile-to-node and profile-to-group assignments |
| `agent_groups` | Named groups of agents for bulk config assignment |
| `agent_group_members` | Node membership in agent groups |
| `config_rollouts` | Canary and staged rollout tracking for profile changes |
| `config_agent_status` | Per-node config synchronization status and health |
| `ip_intel` | Threat intelligence records for known malicious IPs |
| `ip_intel_events` | Individual intel events (sightings, threat tags) per IP |

## MySQL Backend

For high-volume deployments where SQLite's write concurrency becomes a bottleneck, you can switch to MySQL/MariaDB. The server includes a database abstraction layer that handles driver differences transparently — all existing queries, migrations, and application logic work with either backend.

### When to use MySQL

| Factor | SQLite | MySQL/MariaDB |
|--------|--------|---------------|
| Setup | Zero — included with Python | Requires MySQL/MariaDB server |
| Write concurrency | Single writer (WAL helps reads) | Full concurrent writes |
| Recommended for | < 50 nodes, < 100k events/day | 50+ nodes, high volume |
| Backup | Copy the .db file | mysqldump or replication |
| Operational overhead | None | Server maintenance required |

### 1. Install the MySQL Python driver

The driver is already listed in `requirements.txt`. If you installed from the RPM or ran `pip install -r requirements.txt`, it's already available:

```bash
# Verify it's installed
python -c "import mysql.connector; print(mysql.connector.__version__)"
```

### 2. Create the MySQL database and user

```sql
CREATE DATABASE vespid CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'vespid'@'localhost' IDENTIFIED BY 'your-secure-password';
GRANT ALL PRIVILEGES ON vespid.* TO 'vespid'@'localhost';
FLUSH PRIVILEGES;
```

### 3. Configure the server

Update your config file (`/etc/vespid-server/config.yaml`):

```yaml
DATABASE_TYPE: mysql
DATABASE_HOST: localhost
DATABASE_PORT: 3306
DATABASE_NAME: vespid
DATABASE_USER: vespid
DATABASE_PASSWORD: your-secure-password
```

Or use environment variables:

```bash
export VESPID_DATABASE_TYPE=mysql
export VESPID_DATABASE_HOST=localhost
export VESPID_DATABASE_PORT=3306
export VESPID_DATABASE_NAME=vespid
export VESPID_DATABASE_USER=vespid
export VESPID_DATABASE_PASSWORD=your-secure-password
```

### 4. Initialize the schema

The server automatically creates all tables on first startup. You can also initialize manually:

```bash
python vespid_server.py --config /etc/vespid-server/config.yaml init-db
```

This reads `schema_mysql.sql` and creates all 29 tables, indexes, and seed data. The operation is idempotent — safe to run multiple times.

### 5. Migrate existing data from SQLite (optional)

If you have an existing SQLite database with data you want to keep:

```bash
# Preview what would be migrated (no writes)
python migrate_sqlite_to_mysql.py \
    --sqlite /var/lib/vespid-server/vespid.db \
    --dry-run

# Run the migration
python migrate_sqlite_to_mysql.py \
    --sqlite /var/lib/vespid-server/vespid.db \
    --host localhost \
    --port 3306 \
    --database vespid \
    --user vespid \
    --password 'your-secure-password'
```

The migration script:
- Copies all rows from each table in foreign-key dependency order
- Uses `INSERT IGNORE` so duplicates are skipped (safe to run multiple times)
- Preserves original IDs and resets AUTO_INCREMENT counters
- Supports `--dry-run` to preview without writing
- Accepts credentials via CLI args or environment variables (`MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`)

### 6. Start the server

```bash
sudo systemctl restart vespid-server
```

On startup you'll see in the logs:

```
Database backend: mysql (localhost:3306/vespid)
```

### How it works

The abstraction layer (`app/db_compat.py`) provides:

- **Placeholder translation** — application code uses `?` placeholders everywhere; the layer converts to `%s` for MySQL automatically
- **Row wrapper** — query results support both `row["column_name"]` and `row[0]` access on both backends
- **Lazy driver import** — `mysql-connector-python` is only imported when `DATABASE_TYPE` is set to `mysql` or `mariadb`; SQLite-only deployments don't need it installed
- **Connection wrapping** — MySQL connections are wrapped to provide a sqlite3-compatible interface

### MariaDB compatibility

Set `DATABASE_TYPE: mariadb` — the server treats it identically to `mysql`. Both MySQL 8.0+ and MariaDB 10.5+ are supported.

## Centralized Detection Rule Management

Centralized rule management allows admins to create, edit, and distribute detection rules from the server dashboard. Nodes automatically poll for rule updates and hot-reload their detectors without restarting.

### How It Works

1. Admin creates/edits rules in **Security → Detection Rules** (or via the API)
2. Each mutation increments a revision counter
3. Nodes poll `GET /api/v1/rules/distribution` every 5 minutes with `If-None-Match: <revision>`
4. Server returns 304 (no change) or 200 with the full enabled rule set
5. Node merges server rules with local config and hot-reloads the detector

### Admin UI

Navigate to **Security → Detection Rules** to manage detection rules. The page shows all rules (both brute force and custom regex) with controls to:

- **Add** brute force or custom regex rules
- **Edit** any rule's parameters (thresholds, windows, parsers, regex)
- **Enable/Disable** rules (soft-delete)
- **Template rules** — pre-built patterns for common attacks (disabled by default, enable when ready)

### Detection Rule Packs

Rule packs are curated sets of detection rules stored as YAML files in the `packs/` directory. Each pack targets a specific service or attack category. Packs are loaded on server startup and seeded into the database (disabled by default). Admins enable them from the WebUI with one click.

**Included packs:**

| Pack | File | Rules | What It Detects |
|------|------|-------|-----------------|
| Apache Attack Detection | `apache-attacks.yaml` | 14 | RCE, path traversal, credential scanning, IoT exploits, PHP attacks |
| NGINX Attack Detection | `nginx-attacks.yaml` | 10 | Auth brute force, SQLi, XSS, shellshock, scanner UAs, request smuggling |
| OpenSSH Attack Detection | `openssh-attacks.yaml` | 9 | Root brute force, user enumeration, pubkey probing, PAM failures |
| Postfix Mail Server | `postfix-attacks.yaml` | 9 | SASL brute force, relay abuse, VRFY probing, command pipelining |

**Enabling packs:**

1. Go to **Security → Detection Rules**
2. Each pack appears as a collapsible card with a status badge (green/yellow/red)
3. Click **Enable All** to activate the entire pack, or toggle individual rules
4. Enabled rules are distributed to nodes on the next poll cycle

**Creating a custom pack:**

Create a YAML file in the `packs/` directory and restart the server:

```yaml
# packs/my-custom-pack.yaml
pack_name: my-custom-pack
display_name: My Custom Detection Pack
icon: "🔥"
description: Detects custom attack patterns for my environment.
prerequisite: Requires my-service logs configured with parser "messages".

rules:
  - name: my_custom_rule
    event_type: MY_CUSTOM_EVENT
    regex: 'my-service.*?failed auth from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    log_sources: ["messages"]
    max_attempts: 5
    window_seconds: 300
```

Pack YAML schema:

| Field | Required | Description |
|-------|----------|-------------|
| `pack_name` | Yes | Unique identifier (used in API URLs and DB) |
| `display_name` | Yes | Human-readable name shown in the UI |
| `icon` | No | Emoji icon for the UI (default: 📦) |
| `description` | No | Brief description shown in the pack card |
| `prerequisite` | No | Setup instructions shown below the rule grid |
| `rules` | Yes | Array of rule definitions |

Rule fields within a pack:

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `name` | Yes | — | Unique rule name (max 64 chars) |
| `event_type` | Yes | — | Event type emitted on detection |
| `regex` | Yes | — | Python regex with `(?P<ip>...)` named group |
| `log_sources` | No | `["*"]` | Which parsers to evaluate against |
| `max_attempts` | No | 3 | Threshold before detection fires |
| `window_seconds` | No | 3600 | Sliding window duration |

### Pack API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/rules/templates/<pack_name>` | Admin (session) | List rules in a pack |
| POST | `/api/v1/rules/templates/<pack_name>/enable-all` | Admin (session) | Enable all rules in a pack |
| POST | `/api/v1/rules/templates/<pack_name>/disable-all` | Admin (session) | Disable all rules in a pack |
| POST | `/api/v1/rules/templates/<pack_name>/<id>/toggle` | Admin (session) | Toggle a single rule |

### Rules API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/rules` | Admin (session) | List all rules (paginated) |
| POST | `/api/v1/rules/brute-force` | Admin (session) | Create brute force rule |
| POST | `/api/v1/rules/custom` | Admin (session) | Create custom regex rule |
| PUT | `/api/v1/rules/brute-force/<id>` | Admin (session) | Update brute force rule |
| PUT | `/api/v1/rules/custom/<id>` | Admin (session) | Update custom regex rule |
| DELETE | `/api/v1/rules/brute-force/<id>` | Admin (session) | Disable brute force rule |
| DELETE | `/api/v1/rules/custom/<id>` | Admin (session) | Disable custom rule |
| GET | `/api/v1/rules/distribution` | Bearer token | Get enabled rules for nodes |

### Distribution Endpoint

The distribution endpoint supports conditional fetching for efficiency:

```
GET /api/v1/rules/distribution
Authorization: Bearer <token>
If-None-Match: "42"

→ 304 (no changes since revision 42)
→ 200 with ETag: "43" and full rule set JSON
```

Response format:
```json
{
  "revision": 43,
  "brute_force_rules": [
    {"name": "ssh_fast_brute", "event_type": "SSH_BRUTE", "max_attempts": 5, "window_seconds": 60, "parser": "secure"}
  ],
  "custom_rules": [
    {"name": "tls_on_http_probe", "event_type": "TLS_ON_HTTP_PROBE", "regex": "...", "log_sources": ["apache"], "max_attempts": 3, "window_seconds": 3600, "enabled": true, "pack_name": "apache-attacks"}
  ],
  "packs": ["apache-attacks", "openssh-attacks"],
  "filtered": true,
  "active_parsers": ["secure", "apache"]
}
```

The additional metadata fields:
- `packs` — list of pack names that have rules in this response
- `filtered` — `true` if per-node filtering was applied, `false` if all rules were returned
- `active_parsers` — the parsers the server used for filtering (useful for debugging), or `null` if no filtering

### Per-Node Detection Pack Filtering

By default, the distribution endpoint returns **all** enabled rules to every node. Per-node pack filtering changes this so nodes only receive rules relevant to the services they actually monitor. A node running only Postfix won't receive Apache attack rules it can never match.

#### Two Gates: Enable + Filter

A rule must pass **two gates** to reach a node:

1. **Globally enabled** (Security → Detection Rules page) — the rule's toggle must be ON. If a pack shows "0/10 ACTIVE", those rules won't be sent to anyone.
2. **Relevant to the node** (per-node filtering) — the rule's `log_sources` or `parser` must match what the node monitors.

Think of it as: **Security → Detection Rules is the global on/off switch**, and **per-node filtering is the delivery filter**. Both must pass.

```
Rule enabled?  ──NO──▶  Not distributed to anyone
     │
    YES
     │
     ▼
Node matches?  ──NO──▶  Not distributed to THIS node
     │
    YES
     │
     ▼
Rule delivered to node
```

#### How Nodes Report What They Monitor

Each node includes an `active_parsers` field in its heartbeat:

```json
{
  "host_info": {
    "hostname": "web01",
    "active_parsers": ["secure", "apache"]
  }
}
```

This is derived automatically from the node's configured `log_sources`. If a node monitors `/var/log/secure` (parser: `secure`) and `/var/log/apache2/access.log` (parser: `apache`), its `active_parsers` will be `["secure", "apache"]`.

For **managed nodes** (server-managed mode), the active parsers come from the config profile's `log_sources` setting. For **standalone nodes**, they come from the local YAML config.

#### Filtering Modes

| Mode | How It Works | When It Applies |
|------|-------------|-----------------|
| **Auto** (default) | Packs are matched by comparing the node's active parsers against each rule's `log_sources` field. If there's overlap, the rule is included. | Any node that reports `active_parsers` |
| **Explicit** | Only rules from admin-specified packs are distributed. No automatic matching. | Managed nodes with `detection_pack_mode: "explicit"` in their profile |
| **All (no filtering)** | All enabled rules are sent. Backward-compatible behavior. | Legacy nodes that haven't reported `active_parsers` yet |

#### Auto Mode (Default Behavior)

In auto mode, the server checks each rule:

- **Brute force rules**: included if the rule's `parser` field is in the node's `active_parsers`
- **Custom rules**: included if the rule's `log_sources` list overlaps with `active_parsers`, or if the rule has `log_sources: ["*"]` (wildcard — always included)

**Example:** Node reports `active_parsers: ["secure", "apache"]`
- ✅ `ssh_fast_brute` (parser: `secure`) — included
- ✅ `http_auth_brute` (parser: `apache`) — included
- ❌ `postfix_relay_brute` (parser: `postfix`) — excluded
- ✅ Apache Attack Detection Pack rules (log_sources: `["apache"]`) — included
- ✅ OpenSSH Attack Detection Pack rules (log_sources: `["secure"]`) — included
- ❌ Postfix Attack Detection Pack rules (log_sources: `["postfix"]`) — excluded
- ✅ Any rule with `log_sources: ["*"]` — always included

#### Explicit Mode (Admin Override)

For managed nodes, admins can override auto-detection by setting `detection_pack_mode: "explicit"` in the config profile. In this mode, only the packs listed in `detection_packs` are distributed, regardless of what the node monitors.

This is useful when you want precise control — for example, a node monitors both Apache and SSH but you only want it to receive the Apache pack.

See [Centralized Config Management](../docs/CENTRALIZED_CONFIG_MANAGEMENT.md#detection-pack-filtering) for profile configuration details.

#### Resolution Priority

When the server determines what to send a node, it follows this priority chain:

1. **Explicit profile** — `detection_pack_mode: "explicit"` → only listed packs
2. **Auto from profile log_sources** — managed node with `detection_pack_mode: "auto"` → derive parsers from profile's `log_sources`
3. **Auto from heartbeat** — standalone node → use heartbeat-reported `active_parsers`
4. **No filtering** — no data available → send everything (backward compat)

#### Node Detail Page — Detection Packs Section

The node detail page (`/nodes/<node_id>`) shows a "Detection Packs" section displaying:

- **Active parsers** — shown as colored pills (e.g., `APACHE`, `SECURE`, `MESSAGES`)
- **Assignment mode** — "auto" or "explicit"
- **Pack cards** — each relevant pack with its icon, name, rule count, and assignment type

If a pack shows "0 RULES" on the node detail page, it means the pack is relevant to the node (parser match) but has no rules enabled globally. Go to Security → Detection Rules and enable the pack's rules.

If no parsers have been reported yet (new node, never heartbeated), the section shows a "Parser information pending" message and all packs are distributed until the first heartbeat arrives.

#### Detection Rules Page — Node Count Badge

On the Security → Detection Rules page, each pack card shows a "🖥 N nodes" badge indicating how many nodes currently receive that pack. Click the expand arrow to see the list of node IDs.

This helps admins understand the reach of each pack before enabling/disabling rules.

#### Backward Compatibility

- Nodes running older agent versions that don't send `active_parsers` continue to receive all rules (no disruption)
- The `active_parsers` field is optional in the heartbeat — omitting it triggers "all rules" behavior
- When a node upgrades and starts reporting `active_parsers`, filtering takes effect on the next rule poll (within 5 minutes)
- No server-side configuration changes are needed for filtering to activate

### Validation

All rule mutations are validated server-side:

- **Name**: 1–64 characters, unique per rule type
- **max_attempts**: integer 1–10,000
- **window_seconds**: integer 1–604,800 (up to 7 days)
- **parser** (brute force): 1–64 characters
- **regex** (custom): 1–1,024 characters, must compile, must contain `(?P<ip>...)` named group
- **log_sources** (custom): array of 1–20 strings

Invalid submissions return HTTP 422 with all errors listed.

## Development

```bash
make venv    # Set up virtual environment
make test    # Run tests
make dev     # Start development server
```

### Project Structure

```
vespid-server/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── config.py            # Configuration loading
│   ├── models.py            # Database schema, migrations, query helpers
│   ├── db_compat.py         # Database abstraction layer (MySQL wrapper, placeholder translation)
│   ├── pack_loader.py       # Rule pack YAML loader (reads packs/ directory)
│   ├── enrollment_models.py # Enrollment-specific DB queries
│   ├── enrollment.py        # Enrollment API blueprint (POST/GET /api/v1/enroll)
│   ├── auth.py              # Authentication blueprint
│   ├── api.py               # API blueprint (ingestion, SSE, export, commands)
│   ├── fleet.py             # Fleet API blueprint (blocks, allowlist, config, SSE)
│   ├── fleet_sse.py         # Fleet SSE manager (dedicated fan-out, reconnection)
│   ├── propagation_engine.py # Propagation Engine (corroboration, rate limits, policies)
│   ├── rules.py             # Rules API blueprint (CRUD, distribution, pack endpoints)
│   ├── dashboard.py         # Dashboard blueprint (overview, events, nodes,
│   │                        #   rules, feeds, geo, trends)
│   ├── admin.py             # Admin blueprint (users, keys, audit, enrollment, rules)
│   ├── export.py            # CSV/JSON export helpers
│   ├── sse.py               # SSE manager (fan-out, reconnection)
│   ├── rate_limit.py        # API rate limiting (per-key, Flask-Limiter)
│   ├── validators.py        # SecurityEvent schema validation
│   ├── decorators.py        # @require_auth, @require_role
│   ├── templates/           # Jinja2 templates
│   │   ├── base.html        # Layout with nav, theme toggle, SSE, toasts
│   │   ├── dashboard.html   # Overview page
│   │   ├── events.html      # Event search page
│   │   ├── blocked.html     # Blocked IPs page
│   │   ├── rules.html       # Allowlist/blocklist management
│   │   ├── feeds.html       # Feed catalog management
│   │   ├── nodes.html       # Node list page
│   │   ├── node_detail.html # Per-node detail page
│   │   ├── geo.html         # Geographic breakdown
│   │   ├── trends.html      # Trend charts
│   │   ├── login.html       # Login form
│   │   ├── admin/           # Admin templates (users, keys, audit, enrollment, rules)
│   │   └── fragments/       # HTMX partial templates
│   └── static/              # Vendored JS/CSS (htmx, chart.js, sse.js)
├── packs/                   # Detection rule packs (YAML files)
│   ├── apache-attacks.yaml  # Apache/HTTP attack detection (14 rules)
│   ├── nginx-attacks.yaml   # NGINX web attack detection (10 rules)
│   ├── openssh-attacks.yaml # OpenSSH targeted attack detection (9 rules)
│   └── postfix-attacks.yaml # Postfix mail server attack detection (9 rules)
├── tests/                   # pytest test suite
├── schema_mysql.sql         # MySQL/MariaDB-compatible schema with seed data
├── migrate_sqlite_to_mysql.py # Data migration script (SQLite → MySQL/MariaDB)
├── vespid_server.py     # Entry point and CLI
├── gunicorn.conf.py         # Gunicorn production config
├── config.example.yaml      # Example configuration (YAML, with MySQL options)
├── config.example.json      # Example configuration (JSON, legacy)
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

## Fleet-Wide Blocklist Sharing

Fleet-wide blocklist sharing adds a collaborative threat intelligence layer to Vespid. When any enrolled node detects and blocks a malicious IP, it reports the block to the server. The server's Propagation Engine evaluates reports against configurable policies (corroboration threshold, rate limits, allow-lists) and distributes approved blocks to all subscribed nodes via a dedicated SSE channel. Nodes apply fleet blocks to their local nftables sets with configurable TTLs.

### Architecture

```
Node blocks IP → Block_Report via POST /api/v1/events →
  Propagation Engine evaluates (allowlist, corroboration, rate limits) →
  Approved → fleet_blocks table + Fleet SSE Channel →
  Subscribed nodes receive SSE → apply block to local nftables

Reaper task (every 24h) → expires stale blocks → publishes unblock directives
```

Key design points:

- **Dedicated SSE channel** — fleet block traffic is isolated from the dashboard SSE stream
- **Propagation Engine** — stateless service class encapsulating all policy logic
- **Reaper task** — background thread that expires blocks past their TTL
- **Block reports flow through existing event ingestion** — no separate endpoint needed

### Fleet API Endpoints

All fleet endpoints are registered under `/api/v1/fleet/`. Session-authenticated endpoints require the user to have the specified role. The SSE stream uses Bearer token auth.

#### Fleet Blocks

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/fleet/blocks` | Admin/Analyst | List active fleet blocks (paginated, filterable) |
| POST | `/api/v1/fleet/blocks` | Admin | Manually add a fleet block |
| DELETE | `/api/v1/fleet/blocks/<ip>` | Admin | Remove a fleet block + publish unblock |
| GET | `/api/v1/fleet/blocks/<ip>/history` | Admin/Analyst | Reporting history for an IP |
| GET | `/api/v1/fleet/blocks/stream` | Bearer token | Fleet SSE channel |

**GET /api/v1/fleet/blocks**

Query parameters:
- `page` (int, default: 1) — page number
- `per_page` (int, default: 50, max: 200) — items per page
- `source_ip` (str) — filter by source IP
- `node_id` (str) — filter by originating node ID
- `event_type` (str) — filter by event type
- `status` (str) — filter by status (`active`, `expired`, `removed`)

Response:
```json
{
  "items": [...],
  "total": 42,
  "page": 1,
  "per_page": 50,
  "pages": 1
}
```

**POST /api/v1/fleet/blocks**

Request body:
```json
{
  "source_ip": "192.168.1.100",
  "reason": "Manual block for suspicious activity"
}
```

Response (201):
```json
{
  "status": "created",
  "fleet_block_id": "fb-...",
  "source_ip": "192.168.1.100"
}
```

Returns 409 if the IP is already blocked or is on the allow-list.

**DELETE /api/v1/fleet/blocks/\<ip\>**

Response (200):
```json
{
  "status": "removed",
  "source_ip": "192.168.1.100"
}
```

Returns 404 if no active block exists for the IP.

**GET /api/v1/fleet/blocks/\<ip\>/history**

Response:
```json
{
  "source_ip": "192.168.1.100",
  "reports": [{"node_id": "...", "event_type": "...", "reported_at": "..."}],
  "blocks": [{"fleet_block_id": "...", "status": "active", "expires_at": "..."}]
}
```

#### Allow-List

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/fleet/allowlist` | Admin | List global allow-list entries |
| POST | `/api/v1/fleet/allowlist` | Admin | Add allow-list entry |
| DELETE | `/api/v1/fleet/allowlist/<id>` | Admin | Remove allow-list entry |

**POST /api/v1/fleet/allowlist**

Request body:
```json
{
  "entry": "192.168.1.0/24"
}
```

Adding an allow-list entry automatically removes any matching active fleet blocks and publishes unblock directives.

**DELETE /api/v1/fleet/allowlist/\<id\>**

Returns 404 if the entry does not exist.

#### Configuration

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/fleet/config` | Admin | Get propagation config |
| PUT | `/api/v1/fleet/config` | Admin | Update propagation config |

**PUT /api/v1/fleet/config**

Request body (partial updates supported):
```json
{
  "corroboration_threshold": 2,
  "fleet_block_ttl_seconds": 7200,
  "max_fleet_blocks_per_hour": 200
}
```

Updatable keys: `corroboration_threshold`, `corroboration_window_seconds`, `fleet_block_ttl_seconds`, `max_fleet_blocks_per_hour`, `max_reports_per_node_per_hour`, `excluded_event_types`, `reaper_interval_seconds`, `unlock_webhook_secret`.

#### Unlock Webhook

A simple no-auth endpoint to unblock yourself if you get locked out from another IP.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/unlock-webhook/<secret>/<ip>` | None (rate-limited) | Unblock an IP via pre-shared secret |

The secret is set via the Fleet Configuration page (`unlock_webhook_secret`) or the API (`PUT /api/v1/fleet/config`). When the secret matches, the fleet block is removed and an unblock directive is published to all connected agents — same as the admin DELETE endpoint.

Example:
```bash
curl -X POST https://server.example.com/api/v1/unlock-webhook/my-secret/1.2.3.4
```

Returns 200 on success, 403 for bad secret, 404 if IP is not blocked, 501 if no secret is configured.

**Important:** The secret is sent in the URL — use HTTPS. Rate-limited to 10 requests/minute.

#### Pause/Resume

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/fleet/pause` | Admin | Toggle propagation pause (kill switch) |

**POST /api/v1/fleet/pause**

Request body (optional — omit to toggle):
```json
{
  "paused": true
}
```

Response:
```json
{
  "status": "updated",
  "propagation_paused": true
}
```

While paused, block reports are still accepted and stored but no SSE messages are published.

### Fleet SSE Stream

**Endpoint:** `GET /api/v1/fleet/blocks/stream`

**Authentication:** Bearer token (same API key used for event ingestion).

```
GET /api/v1/fleet/blocks/stream HTTP/1.1
Authorization: Bearer <api-key>
Last-Event-ID: fb-a1b2c3d4-...   (optional, for reconnection)
```

**Response headers:**
```
Content-Type: text/event-stream
Cache-Control: no-cache
X-Accel-Buffering: no
Connection: keep-alive
```

#### SSE Message Format

Each message uses the `fleet_block` event type with the `fleet_block_id` as the SSE `id` field:

```
id: fb-a1b2c3d4-e5f6-7890-abcd-ef1234567890
event: fleet_block
data: {"action":"block","source_ip":"192.168.1.100","reason":"SSH_BRUTE detected by node-alpha","originating_node_id":"node-alpha-abc123","ttl_seconds":3600,"timestamp":"2025-01-15T10:30:00Z","fleet_block_id":"fb-a1b2c3d4-e5f6-7890-abcd-ef1234567890"}

```

**Block message JSON schema:**

```json
{
  "action": "block",
  "source_ip": "192.168.1.100",
  "reason": "SSH_BRUTE detected by node-alpha",
  "originating_node_id": "node-alpha-abc123",
  "ttl_seconds": 3600,
  "timestamp": "2025-01-15T10:30:00Z",
  "fleet_block_id": "fb-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**Unblock message JSON schema:**

```json
{
  "action": "unblock",
  "source_ip": "192.168.1.100",
  "reason": "TTL expired",
  "originating_node_id": "",
  "ttl_seconds": 0,
  "timestamp": "2025-01-15T11:30:00Z",
  "fleet_block_id": "fb-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | `"block"` or `"unblock"` |
| `source_ip` | string | IPv4 or IPv6 address |
| `reason` | string | Human-readable reason for the action |
| `originating_node_id` | string | Node that first reported the block (empty for system actions) |
| `ttl_seconds` | int | TTL for the block (0 for unblock) |
| `timestamp` | string | ISO-8601 UTC timestamp |
| `fleet_block_id` | string | Unique identifier for the fleet block |

#### Reconnection Protocol

The stream supports the standard SSE reconnection mechanism:

1. Client connects with `Last-Event-ID` header set to the last received `id`
2. Server replays all events after that ID from its history buffer (default: 1000 events)
3. If the ID is not found in the buffer (too old), the client starts receiving live events only
4. Keepalive comments (`: keepalive\n\n`) are sent every 15 seconds to prevent proxy timeouts

### Fleet Configuration Defaults

The `fleet_config` table stores propagation policy as key-value pairs. These are the seeded defaults:

| Key | Default | Description |
|-----|---------|-------------|
| `corroboration_threshold` | `1` | Min distinct nodes required before propagation |
| `corroboration_window_seconds` | `3600` | Time window for corroborating reports (1 hour) |
| `fleet_block_ttl_seconds` | `3600` | TTL applied to propagated blocks (1 hour) |
| `max_fleet_blocks_per_hour` | `100` | Fleet-wide rate limit for new blocks |
| `max_reports_per_node_per_hour` | `50` | Per-node rate limit for block reports |
| `propagation_paused` | `false` | Emergency kill switch |
| `excluded_event_types` | `[]` | JSON array of event types to never propagate |
| `reaper_interval_seconds` | `86400` | How often the reaper checks for expired blocks (24 hours) |
| `expired_block_retention_seconds` | `86400` | How long expired blocks are retained before purge (1 day) |
| `unlock_webhook_secret` | `""` | Pre-shared secret for the unlock webhook endpoint |

### Fleet Audit Log Action Types

All fleet propagation activity is recorded in the `audit_log` table with these action types:

| Action Type | Trigger |
|-------------|---------|
| `fleet_block_reported` | A node submits a block report |
| `fleet_block_propagated` | A block is approved and published to the SSE channel |
| `fleet_block_rejected` | A block report is rejected (allow-listed IP or rate-limited) |
| `fleet_block_expired` | The reaper expires a block past its TTL |
| `fleet_allowlist_modified` | An admin adds or removes an allow-list entry |
| `fleet_propagation_toggled` | An admin pauses/resumes propagation or updates config |

### Fleet Database Tables

Four new tables support the feature:

| Table | Purpose |
|-------|---------|
| `fleet_blocks` | Active and historical fleet blocklist entries |
| `fleet_block_reports` | Individual node reports for corroboration tracking |
| `fleet_allowlist` | Global allow-list of IPs/CIDRs exempt from propagation |
| `fleet_config` | Propagation policy configuration (key-value store) |

## Troubleshooting

### Node not picking up commands

Commands are polled after each successful heartbeat (default 5 min interval). Check:
1. Node logs for `Command poll` messages
2. The command queue on the Rules page or node detail page
3. That the node's API key is valid and not restricted to a different node_id

### Feed deploy not taking effect

After deploying a feed from the Feeds page:
1. The command enters `pending` status
2. On next heartbeat, the node picks it up → `acknowledged`
3. The node adds the feed and syncs → `completed`
4. On the following heartbeat, the feed appears in the node detail page

If stuck at `pending`, the node may be offline. If `failed`, check the result message.

### Database permission errors

```bash
sudo chown -R vespid:vespid /var/lib/vespid-server
sudo chmod 750 /var/lib/vespid-server
```

### Service won't start

```bash
journalctl -u vespid-server -n 50 --no-pager
```

## Performance Tuning

The server uses Gunicorn as its WSGI server. After RPM installation, the environment file at `/etc/vespid-server/environment` controls worker configuration. The defaults in `gunicorn.conf.py` are sensible starting points, but you should tune them for your hardware and database backend.

### Worker Types

| Worker Class | Best For | How It Works |
|--------------|----------|--------------|
| `gevent` (default) | Most deployments | Cooperative greenlets — one worker handles thousands of concurrent connections with minimal memory |
| `gthread` | Environments where gevent causes issues | OS threads — each connection holds one thread |

Gevent is the default because Vespid Server is I/O-bound (waiting on DB queries, SSE streams sitting idle, keepalive connections from nodes). A single gevent worker can multiplex hundreds of connections that would each require a dedicated thread with gthread.

### Sizing by Backend

#### SQLite

SQLite serializes all writes through a single lock. More workers means more lock contention, not more throughput. Keep workers minimal and let gevent handle concurrency within each worker.

```
# /etc/vespid-server/environment
GUNICORN_WORKERS=1
GUNICORN_WORKER_CLASS=gevent
GUNICORN_WORKER_CONNECTIONS=1000
```

#### MySQL / MariaDB

MySQL handles concurrent writes natively. Scale workers with CPU cores — one worker per core is the sweet spot with gevent since each worker already multiplexes many connections internally.

```
# /etc/vespid-server/environment — 2-core example
GUNICORN_WORKERS=2
GUNICORN_WORKER_CLASS=gevent
GUNICORN_WORKER_CONNECTIONS=1000
```

For a 4-core box, use `GUNICORN_WORKERS=4`.

### Recommended Environment File

After RPM/DEB installation, edit `/etc/vespid-server/environment`:

```bash
# Bind — localhost only by default. Bind to 0.0.0.0 if serving directly
# without a reverse proxy (not recommended for production).
GUNICORN_BIND=127.0.0.1:8000
GUNICORN_WORKER_CLASS=gevent
GUNICORN_TIMEOUT=120

# Workers — set to your CPU core count (MySQL) or 1 (SQLite)
GUNICORN_WORKERS=2

# Max concurrent connections per worker (gevent only)
GUNICORN_WORKER_CONNECTIONS=1000

# Keep-alive — set above heartbeat interval so nodes reuse connections
GUNICORN_KEEPALIVE=65

# Worker recycling — prevents memory leaks over long uptimes
GUNICORN_MAX_REQUESTS=8000
GUNICORN_MAX_REQUESTS_JITTER=800
```

### Common Mistakes

| Mistake | Symptom | Fix |
|---------|---------|-----|
| Too many workers on few cores | High CPU from context switching, slow responses | Set workers = core count |
| Too many workers with SQLite | Write timeouts, "database is locked" errors | Use 1 worker |
| Low keepalive with many nodes | Constant TCP reconnections, high TIME_WAIT count | Set `GUNICORN_KEEPALIVE=65` |
| No worker recycling | Memory usage grows over days/weeks | Set `GUNICORN_MAX_REQUESTS` |
| Using `sync` worker class | SSE streams block workers, timeout kills them | Use `gevent` |

### Verifying Your Configuration

After restarting, check the process list:

```bash
ps aux | grep gunicorn | grep -v grep
```

You should see 1 master process + N worker processes (where N = `GUNICORN_WORKERS`). If you see more workers than expected, check that the environment file doesn't have a stale `GUNICORN_WORKERS` override.

Check logs for startup confirmation:

```bash
journalctl -u vespid-server | grep "Booting worker"
```

### Applying Changes

```bash
# Edit the environment file
sudo vim /etc/vespid-server/environment

# Restart to apply
sudo systemctl restart vespid-server
```

Note: with `preload_app = True` (the default), graceful reload (`systemctl reload`) is not supported. Always use `restart`.
