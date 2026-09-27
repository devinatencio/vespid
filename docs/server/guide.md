# Vespid Server

Centralized security event management server for the Vespid ecosystem.
Receives events from distributed agents, persists them in SQLite or MySQL,
and presents them through an HTMX-powered web dashboard with real-time SSE
streaming.

## Requirements

- Python 3.10+
- SQLite 3 (included) or MySQL/MariaDB 8.0+
- Linux with systemd (for production)
- `rpmbuild` (only if building the RPM)

## Installation

=== "RPM (production)"

    ```bash
    make rpm
    sudo rpm -ivh rpmbuild/RPMS/noarch/vespid-server-1.0.0-1.*.noarch.rpm
    sudo systemctl start vespid-server
    sudo systemctl enable vespid-server
    ```

=== "Manual (development)"

    ```bash
    cd vespid-server/
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    pip install -r requirements-dev.txt   # for running tests
    python vespid_server.py init-db
    python vespid_server.py create-admin --non-interactive
    python vespid_server.py
    ```

    The server starts on `http://127.0.0.1:8000` by default.
    For production TLS, place a reverse proxy (nginx/Caddy) in front.

## Quick start

1. Install and create an admin user.
2. Log in at `http://your-server`.
3. Create an API key in **Admin → API Keys** (or enable auto-enrollment).
4. Configure agents with the server URL and API key.
5. Nodes auto-register on first heartbeat.

## Configuration

Config file at `/etc/vespid-server/config.yaml` (or `.json`).  
Environment variables with `VESPID_` prefix override file values.

Generate a random secret key:

```bash
openssl rand -base64 32
```

```yaml
SECRET_KEY: "change-me-to-a-random-string"  # Must change in production!
DATABASE_TYPE: sqlite
DATABASE_PATH: /var/lib/vespid-server/vespid.db
HOST: "127.0.0.1"
PORT: 8000
SESSION_LIFETIME_HOURS: 24
```

### Configuration reference

| Setting | Default | Description |
|---------|---------|-------------|
| `SECRET_KEY` | *(placeholder)* | Flask session key. **Change in production.** |
| `DATABASE_TYPE` | `sqlite` | `sqlite`, `mysql`, or `mariadb` |
| `DATABASE_PATH` | `/var/lib/vespid-server/vespid.db` | SQLite path |
| `HOST` / `PORT` | `127.0.0.1` / `8000` | Bind address (localhost by default — use a reverse proxy) |
| `DEBUG` | `false` | Never enable in production |
| `SESSION_LIFETIME_HOURS` | `24` | Session expiry |
| `EVENTS_PER_PAGE` | `50` | Pagination size |
| `SSE_HISTORY_SIZE` | `500` | Dashboard SSE replay buffer |
| `FLEET_SSE_HISTORY_SIZE` | `1000` | Fleet SSE replay buffer |
| `FLEET_REAPER_INTERVAL_SECONDS` | `86400` | Fleet block reaper interval (24h) |
| `NODE_HEALTHY_SECONDS` | `300` | Max age for "healthy" status |
| `NODE_DEGRADED_SECONDS` | `900` | Max age before "offline" |
| `RATELIMIT_ENABLED` | `true` | API rate limiting master switch |
| `RATELIMIT_STORAGE_URI` | `memory://` | Use `redis://host:6379/0` for multi-worker |
| `LOG_FILE` | `/var/log/vespid-server/vespid-server.log` | App log path |
| `LOG_LEVEL` | `INFO` | App log level |
| `LOG_FORMAT` | `text` | `text` (human-readable) or `json` (SIEM integration) |

## Redis / Valkey

Redis (or its open-source fork Valkey) is **optional** but recommended for
multi-worker production deployments. It enables two critical features
that in-memory storage cannot support across processes:

| Feature | Config Key | What it does |
|---------|-----------|--------------|
| **Rate limiting** | `RATELIMIT_STORAGE_URI` | Shares API rate-limit counters across all workers so a single client cannot exhaust limits by switching workers |
| **SSE bridge** | `SSE_REDIS_URL` | Coordinates real-time Server-Sent Events across workers — command delivery, config profile pushes, fleet block propagation, and dashboard live updates all reach the correct worker |

Without Redis, rate limiting and SSE work only within a single worker
(the default `memory://` backend). If you run multiple gunicorn workers
or behind a load balancer, you **must** configure Redis.

### Setup

Install Redis or Valkey on the server host:

```bash
# Debian / Ubuntu
apt install redis-server

# AlmaLinux / RHEL
dnf install redis

# openSUSE
zypper install redis
```

The Python `redis` module is already included in the server's
`requirements.txt` and installed into the venv automatically
during package install. If it is missing, install it manually:

```bash
/opt/vespid-server/.venv/bin/pip install redis
```

> Valkey users: the `redis` Python package also works with Valkey servers.
> Alternatively, use `valkey://` scheme if using the `valkey` Python client.

### Configuration

Add to your config file:

```yaml
RATELIMIT_STORAGE_URI: "redis://localhost:6379/0"
SSE_REDIS_URL: "redis://localhost:6379/0"
```

Both keys can point to the same Redis instance. For separate instances,
use different database numbers or hosts:

```yaml
RATELIMIT_STORAGE_URI: "redis://redis-ratelimit:6379/0"
SSE_REDIS_URL: "redis://redis-sse:6379/0"
```

### How SSE bridging works

When `SSE_REDIS_URL` is set, each worker subscribes to Redis pub/sub
channels (`vespid:sse:events`, `vespid:sse:fleet`, `vespid:sse:config`).
Any worker that publishes an event (e.g., a command queued for a node)
broadcasts it via Redis, and the worker that owns the relevant SSE
connection delivers it to the agent or browser. This allows the
command queue, fleet blocks, and config profile pushes to work
correctly regardless of which worker handles the request.

## Structured logging

Every request is assigned a unique **request ID** (e.g. `8c9f1c2a-e0c`) that
appears in all log files, enabling you to trace a single request end-to-end
across the main app log, reaper log, alert log, and access log.

### Default: human-readable text format

```
2026-06-19T04:58:34+0000 INFO     app.api  [8c9f1c2a-e0c] POST /api/v1/events - Event batch received
```

Access log includes the same request ID:

```
127.0.0.1 - - [19/Jun/2026:04:58:34 +0000] "GET /healthz HTTP/1.1" 200 16 "-" "curl/8.12.1" rid=8c9f1c2a-e0c D=1873
```

Background tasks (reapers, alert evaluator, backup scheduler) show `[]`
since they run outside request context — this is expected.

### Tracing a request

```bash
# Find all log entries for a specific request across all log files
grep "8c9f1c2a-e0c" /var/log/vespid-server/*.log
```

### JSON format for SIEM integration

Set `LOG_FORMAT: json` in your config to switch all log files to JSON:

```yaml
LOG_FORMAT: json
```

Each log line becomes a JSON object:

```json
{"timestamp":"2026-06-19T04:58:34+0000","level":"INFO","logger":"app.api","message":"Event batch received","request_id":"8c9f1c2a-e0c","method":"POST","path":"/api/v1/events","remote_addr":"10.0.0.1"}
```

For the gunicorn access log, also set:

```bash
export GUNICORN_ACCESS_LOG_FORMAT=json
```

This produces JSON access logs with the same `request_id` field for
correlation with app logs. Ship all `.log` files to your SIEM
(ELK, Splunk, Datadog, etc.) for centralized analysis.

## Swagger UI / OpenAPI

The server includes an interactive **Swagger UI** at `/openapi/` that
documents the REST API. The OpenAPI specification is available at
`/openapi/openapi.json`.

### Accessing the UI

Navigate to `https://your-server/openapi/` in your browser. The UI shows:

- All documented endpoints grouped by tag (Events, Fleet, Intelligence, Enrollment, Health)
- Request/response schemas with example payloads
- "Try it out" button for testing endpoints directly from the browser
- Authentication support (Bearer token for agent APIs, session cookie for dashboard APIs)

### Documented endpoints

| Method | Path | Tag | Description |
|--------|------|-----|-------------|
| `POST` | `/api/v1/events` | Events | Ingest event batch |
| `GET` | `/api/v1/verify` | Nodes | Verify API key |
| `GET` | `/api/v1/fleet/blocks` | Fleet | List fleet blocks |
| `POST` | `/api/v1/fleet/blocks` | Fleet | Add fleet block |
| `GET` | `/api/v1/intel/ips` | Intelligence | Query IP records |
| `POST` | `/api/v1/enroll` | Enrollment | Submit enrollment request |
| `GET` | `/api/v1/enroll/status/{node_id}` | Enrollment | Check enrollment status |
| `GET` | `/healthz` | Health | Liveness probe |
| `GET` | `/readyz` | Health | Readiness probe |

### Adding documentation to new endpoints

Use `APIBlueprint` instead of `Blueprint` and pass OpenAPI metadata
to the route decorator:

```python
from flask_openapi3 import APIBlueprint
from flask_openapi3.models import Tag

my_bp = APIBlueprint("myapi", __name__, url_prefix="/api/v1/myapi")

@my_bp.post(
    "/do-something",
    summary="Do something",
    description="Detailed description of what this endpoint does.",
    tags=[Tag(name="MyAPI", description="My API endpoints")],
    security=[{"BearerAuth": []}],
    responses={
        200: MyResponseModel,
        400: {"description": "Bad request"},
    },
)
def do_something():
    ...
```

Register with `app.register_api(my_bp)` instead of `app.register_blueprint()`.

## Dashboard pages

| Menu | Pages | Access |
|------|-------|--------|
| **Dashboard** | Overview (stats, charts, live feed) | All roles |
| **Analytics** | Events, Counters, Geo, Trends | All roles |
| **Intelligence** | IP Search, Threat Metrics | Analyst+ |
| **Security** | Blocked IPs, Feeds, Fleet, IP Rules, Nodes, Detection Rules | Viewer (read) / Analyst+ (actions) |
| **Admin** | Users, API Keys, Audit Log, Enrollment, Config Management, Test Rules | Admin only |

### Key pages

**Dashboard (`/`)** — stats cards (events 24h, active nodes, blocked IPs),
event type donut chart, 24h sparkline, 20 most recent events with live SSE.
Auto-refreshes every 30s.

**Events (`/events`)** — search and filter by IP, node, event type, time
range, country.  All filters use AND semantics.  Real-time SSE toast
notifications.

**Blocked IPs (`/blocked`)** — aggregated view of blocked IPs across all
nodes with color-coded severity, filters, and drill-down.

**Nodes (`/nodes`)** — registered node list with health status.  Click a
node for its detail page showing: stats, detection packs, subscription feeds,
active blocks, allowlist, recent commands.

**Detection Rules (`/admin/rules`)** — centralized rule management with
collapsible rule packs (Apache, NGINX, OpenSSH, Postfix).  Enable/disable
at pack or individual rule level.  Per-node filtering ensures nodes only
receive rules relevant to the parsers they monitor.

## Fleet block recidive

The server automatically escalates the TTL of fleet blocks for repeat offenders.
When a block report arrives, the Propagation Engine queries the Intelligence
database (`ip_intel.total_times_blocked`) to determine how many times the IP
has been blocked across the fleet, and maps that count to an escalated TTL using
configurable tiers:

| Prior blocks | Fleet block TTL |
|-------------|-----------------|
| 0 (first offense) | 1 day |
| 1 | 3 days |
| 2 | 7 days |
| 3+ | 30 days |

For example: an IP blocks a node, gets a 1-day fleet block, expires, then
attacks again → the new fleet block escalates to 3 days. Each repeat drives
the next tier; after 4+ offenses the block caps at 30 days.

This works alongside the node-level recidive (`recidive_tiers` in agent config)
which escalates the **local** block duration. Fleet recidive operates
independently using fleet-wide data from the Intelligence database.

Configuration keys (managed via **Fleet → Configuration** in the dashboard):

| Key | Default | Description |
|-----|---------|-------------|
| `fleet_recidive_tiers` | `[86400, 259200, 604800, 2592000]` | TTL per offense count (seconds) |
| `fleet_recidive_decay_seconds` | `2592000` (30d) | Clean period before offense counter resets |

## Auto-enrollment

Three enrollment modes control how agents obtain API credentials:

| Mode | Behavior |
|------|----------|
| `open` | Credentials issued immediately |
| `manual_approval` | Queued until admin approves (default) |
| `restricted` | Requires a pre-shared enrollment token |

Enable via **Admin → Enrollment**.  Agents attempt enrollment if `SERVER_URL`
is set and `API_KEY` is empty (`""`).

## Command channel

The server queues commands that nodes poll on heartbeat:

| Command | Payload | Description |
|---------|---------|-------------|
| `allowlist_add` / `allowlist_remove` | `{"entry": "10.0.0.0/8"}` | Manage node runtime allowlist |
| `block` / `unblock` | `{"ip": "1.2.3.4", "reason": "..."}` | Manual block/unblock |
| `feed_enable` / `feed_disable` | `{"name": "firehol_level1"}` | Toggle subscription feeds |
| `feed_add` / `feed_remove` | `{"name": "...", "url": "...", ...}` | Add/remove feeds |

Statuses: `pending` → `acknowledged` → `completed` / `failed` / `expired`.

## User roles

| Role | Dashboard | Analytics | Intelligence | Security | Export | Admin |
|------|-----------|-----------|--------------|----------|--------|-------|
| **viewer** | ✓ | Events, Counters, Geo, Trends | — | Blocked, Nodes (read) | — | — |
| **analyst** | ✓ | All | Search, Threat Metrics | All (actions) | ✓ | — |
| **admin** | ✓ | All | All (+ Intel Admin) | All (+ Detection Rules) | ✓ | ✓ |

## Metrics (optional)

The server can serve system monitoring dashboards when the optional
VictoriaMetrics backend is configured.

```bash
# Install VictoriaMetrics (single binary, no config files)
curl -L https://github.com/VictoriaMetrics/VictoriaMetrics/releases/latest/download/victoria-metrics-linux-amd64.tar.gz | tar xz

# Start it (90-day retention, listen on localhost)
./victoria-metrics-prod -retentionPeriod=90d -httpListenAddr=:8428 &

# Enable in server config
echo "METRICS_ENABLED: true" >> /etc/vespid-server/config.yaml
echo "VICTORIAMETRICS_URL: http://localhost:8428" >> /etc/vespid-server/config.yaml

# Restart the server
systemctl restart vespid-server
```

Deploy the Vespid agent on target hosts. Agents ship CPU, memory, disk,
network, and systemd metrics. The dashboard shows a fleet overview with color-coded
health indicators and per-host line charts. See the
[Agent Guide](../agent/guide.md) for agent installation and configuration.

### Synthetic monitoring

The server includes built-in synthetic monitoring — ICMP, HTTP, TCP, DNS, and SSL
health checks run from distributed worker nodes. Checks are managed via
**Admin → Checks** in the dashboard. Workers poll for assigned checks and
report results back to the server for alerting and trend analysis.
