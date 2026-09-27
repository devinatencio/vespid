# Vespid

A lightweight, high-performance security daemon for Linux systems running
`nftables`.  Supports **AlmaLinux / RHEL / Rocky**, **Debian / Ubuntu**, and
**SUSE / openSUSE** — all with automatic distro detection and correct default
log paths.

Vespid is the **Node Client** of the Vespid client/server platform.  The
daemon can operate fully standalone (local detection, blocking, and feed
syncing) or connect to a **Vespid Server** for fleet-wide blocklist sharing,
centralized rule management, auto-enrollment, and configuration management.

---

## Features

- **Multi-distro support** — automatically detects Debian, RedHat, and SUSE
  families at startup, using the correct default log paths for each
  (`/var/log/auth.log` vs `/var/log/secure`, etc.).
- **Event Telemetry Bus** — thread-safe `DataBus` with a background worker that
  batches events and ships them to `SERVER_URL` (when enabled) or spools them
  as JSONL for later replay.
- **Canonical event schema** — every event carries `node_id`, `timestamp`,
  `source_ip`, `event_type`, `action_taken`, and `geo_data`.
- **Async log processor** — tails SSH auth logs, syslog, Apache/Nginx access
  logs, and HAProxy logs (HTTP and TCP mode) with automatic log-rotation
  handling.
- **Sliding-window brute-force detection** — both classic fast brute force and
  *slow* brute force (e.g. 5 attempts spread over 6 hours).
- **Multi-signal correlation detection** — catches "low and slow" reconnaissance
  by correlating distinct categories of suspicious activity (e.g. scanner UA +
  bad request + TLS probe) that individually stay below any single rule's
  threshold.
- **Custom detection rules** — deploy your own regex-based rules via the YAML
  config file. No code changes, no recompile — just edit and restart.
- **Dual `nftables` sets**:
  - `shield_local` — dynamic, populated by detections, per-element TTL.
  - `shield_subscribed` — static/feed-driven, replaced atomically on refresh.
- **Firewalld coexistence** — the `shield` table uses an independent priority
  and auto-rebuilds on health-check failures so it survives `firewalld --reload`
  and reboots.
- **Repeat-offender escalation** — IPs that get blocked repeatedly receive
  progressively longer bans (24 h → 3 d → 7 d → 30 d by default). Strike
  counts decay after a configurable clean period.
- **Automatic expiry reaper** — expired entries are pruned from the in-memory
  block list every 60 seconds so `vespid-cli list-local` never shows stale
  "expired" rows.
- **Subscription manager** — downloads external IP blocklists, deduplicates
  them against the local allowlist and the live `shield_local` set, and syncs
  the result into `shield_subscribed`.
- **Fleet-wide blocklist sharing** — nodes in a fleet report locally detected
  blocks to the server, which corroborates reports and distributes approved
  blocks to all subscribed nodes. Supports offline queuing with exponential
  backoff retry.
- **Auto-enrollment** — agents can automatically obtain API credentials from the
  server with support for open, manual-approval, and restricted modes. Includes
  credential rotation and revocation.
- **Centralized config management** — in server-managed mode, the agent
  receives configuration profiles, detection rules, and feed definitions from
  the server with atomic apply/rollback.
- **Server-side rule management** — pull detection rules from the server at
  configurable intervals with hot-reload (zero downtime). Supports `layer` and
  `replace` merge strategies.
- **SSL/TLS configuration** — configurable certificate verification (system CA,
  custom CA bundle, or disable), plus mutual TLS with client certificates.
- **Local CLI** — `vespid-cli` talks to the daemon over a 0600 UNIX socket to
  show status, list blocks, check whether an IP is blocked, manage allowlist
  entries, view recidive history, force feed syncs, and tail logs live.
- **Two-tier logging** — human-readable rotating log plus a structured JSONL
  audit trail of every decision the node makes.

---

## Repository layout

```
vespid/
  __init__.py
  config.py                # ShieldConfig: paths, rules, feeds, SERVER_URL/API_KEY
  config_conflict.py       # Config conflict resolution
  config_subscriber.py     # Server-pushed config subscription (server-managed mode)
  country_codes.py         # Country code mapping utilities
  geo.py                   # GeoIP lookup (graceful fallback)
  databus.py               # Producer/Consumer event bus + JSON schema + fleet queue
  detectors.py             # SlidingWindowDetector + CorrelationDetector
  log_processor.py         # asyncio tailers + parsers (SSH, Apache, HAProxy, syslog)
  nftables_manager.py      # Dual-set nftables manager + recidive tracker + expiry reaper
  subscription_manager.py  # External feed sync
  rule_subscriber.py       # Server-side rule polling + merge + hot-reload
  fleet_queue.py           # Fleet block report offline queue
  fleet_subscriber.py      # Fleet SSE subscriber
  enrollment_client.py     # Auto-enrollment with credential rotation support
  server_client.py         # HTTP client for server REST API
  http_client.py           # Low-level HTTP client utilities
  control_socket.py        # UNIX-socket JSON-line control plane
  logging_setup.py         # Rotating human log + JSONL audit log
  host_info.py             # Host information collection
  file_watcher.py          # File watching utilities (log rotation detection)
  cli.py                   # vespid-cli shim (imports from cli/ subpackage)
  cli/                     # Modular CLI subpackage
    app.py                 # Main Typer app, local daemon commands, log tailing
    fleet.py               # Fleet-wide blocklist management (server)
    intel.py               # IP intelligence queries (server)
    nodes.py               # Node management and visibility (server)
    config.py              # Centralized config management (server)
    admin.py               # User/key/enrollment administration (server)
    server.py              # Server connection management (login/logout/status)
    events.py              # Event search and export (server)
  daemon.py                # vespid entry point (main orchestrator)
pyproject.toml
vespid-server/             # Flask dashboard + management server (standalone project)
vespid-agent/              # Rust monitoring agent (Cargo workspace)
tests/                     # Agent test suite
docs/                      # MkDocs documentation source
config/                    # Example/sample configuration files
data/                      # Shared country-code data
packaging/                 # Packaging assets
```

**Runtime state** (under `/var/lib/vespid/` by default):

| File                  | Purpose                                                    |
|-----------------------|------------------------------------------------------------|
| `local_blocks.json`   | Persisted local block list (survives restarts).            |
| `recidive.json`       | Repeat-offender strike counts per IP.                      |
| `allowlist.json`      | Runtime allowlist additions (added via CLI).               |
| `spool.jsonl`         | Spooled telemetry events (auto-drained on reconnect).      |
| `node_id`             | Auto-generated node identity.                              |
| `tailer_offsets.json` | Log tailer seek offsets for catchup on restart.            |
| `rules_cache.json`    | Cached server-pushed detection rules (offline resilience). |
| `runtime_feeds.json`  | Persisted dynamically-added subscription feeds.            |
| `activity.json`       | Rolling 24h activity tracker state (survives restarts).    |
| `credentials.json`    | Enrolled API credentials (auto-enrollment).                |

---

## Requirements

- Linux with `nftables` — works on AlmaLinux, RHEL, Rocky, Debian, Ubuntu, SUSE,
  openSUSE, and any other distribution with `nftables` kernel support.
- Python **3.10+** (AlmaLinux 10 ships 3.12 by default).
- `nftables` (`/usr/sbin/nft`) installed and the kernel module loaded.
- Root privileges (the daemon must be able to manage `nftables` and read
  `/var/log/secure`).
- *(Optional)* `maxminddb` Python package + a MaxMind `GeoLite2-Country.mmdb`
  or db-ip `dbip-country-lite.mmdb` database for the `geo_data` field. Without
  it, `geo_data` is still emitted but country/ASN are `null`.

---

## Installation

### 1. Install system packages

```bash
sudo dnf install -y python3 python3-pip nftables
sudo systemctl enable --now nftables
```

### 2. Install Vespid

From the repository root:

```bash
sudo python3 -m pip install .
```

This installs two console scripts:

- `vespid`  - the daemon
- `vespid-cli`  - the local management CLI

### 3. Create the runtime directories

```bash
sudo install -d -m 0750 /etc/vespid
sudo install -d -m 0750 /var/lib/vespid
sudo install -d -m 0750 /var/log/vespid
```

### 4. *(Optional)* enable GeoIP enrichment

```bash
sudo dnf install -y python3-maxminddb
# Place a GeoIP database under /var/lib/GeoIP/.
# Supported file names (tried in order, first wins):
#   Country: GeoLite2-Country.mmdb → dbip-country-lite.mmdb → dbip-country.mmdb
#   City:    GeoLite2-City.mmdb    → dbip-city-lite.mmdb    → dbip-city.mmdb
#   ASN:     GeoLite2-ASN.mmdb     → dbip-asn-lite.mmdb     → dbip-asn.mmdb
# Env vars (VESPID_GEOIP_DB, VESPID_GEOIP_CITY_DB, VESPID_GEOIP_ASN_DB)
# can override the path for any DB type.
```

---

## Configuration

Vespid reads its configuration from `/etc/vespid/` in either **YAML**
or **JSON** format. YAML is recommended because regex patterns are much easier
to write (no double-escaping backslashes).

The loader checks for files in this order and uses the first one found:

1. `$VESPID_CONFIG` (env var override — any path, any format)
2. `/etc/vespid/vespid.yaml`
3. `/etc/vespid/vespid.yml`
4. `/etc/vespid/vespid.conf` (JSON, for backward compatibility)

All keys are optional. Anything you omit falls back to the defaults defined in
`vespid/config.py`.

### YAML example (recommended)

`/etc/vespid/vespid.yaml`:

```yaml
SERVER_URL: "https://server.example.com/api/v1/events"
API_KEY: "REPLACE_ME_WITH_ENROLLMENT_TOKEN"
upload_enabled: false

log_level: INFO

log_sources:
  - path: /var/log/secure
    parser: secure
  - path: /var/log/auth.log
    parser: secure
  - path: /var/log/messages
    parser: messages
  - path: /var/log/httpd/access_log
    parser: apache
  - path: /var/log/httpd/error_log
    parser: apache
  # HAProxy — see docs/HAPROXY_LOGGING.md for detailed setup
  - path: /var/log/haproxy/access.log
    parser: haproxy
    haproxy_mode: http  # skips TCP fallback for performance

brute_force_rules:
  - name: ssh_fast_brute
    event_type: SSH_BRUTE
    max_attempts: 5
    window_seconds: 60
    parser: secure
  - name: ssh_slow_brute
    event_type: SSH_SLOW_BRUTE
    max_attempts: 5
    window_seconds: 21600
    parser: secure
  - name: http_auth_brute
    event_type: HTTP_AUTH_BRUTE
    max_attempts: 20
    window_seconds: 600
    parser: apache

allowlist:
  - "127.0.0.1/32"
  - "::1/128"
  - "10.0.0.0/8"

subscriptions:
  - name: firehol_level1
    url: "https://iplists.firehol.org/files/firehol_level1.netset"
    format: cidr
    refresh_seconds: 21600

nft_local_block_ttl: 86400

# Repeat-offender escalation: each entry is a TTL in seconds.
# 1st offense = 24h, 2nd = 3 days, 3rd = 7 days, 4th+ = 30 days.
recidive_tiers:
  - 86400
  - 259200
  - 604800
  - 2592000

# After this many seconds without a new offense, the strike count
# resets to zero.  Default: 30 days.
recidive_decay_seconds: 2592000

# How often (seconds) the daemon reaps expired entries from the
# in-memory local block list.  Default: 60 seconds.
expiry_reap_interval: 60

# See "Custom detection rules" section below
custom_rules: []
```

### JSON example (backward compatible)

`/etc/vespid/vespid.conf`:

```json
{
  "SERVER_URL": "https://server.example.com/api/v1/events",
  "API_KEY": "REPLACE_ME_WITH_ENROLLMENT_TOKEN",
  "upload_enabled": false,
  "log_level": "INFO",
  "log_sources": [
    {"path": "/var/log/secure",            "parser": "secure"},
    {"path": "/var/log/messages",          "parser": "messages"},
    {"path": "/var/log/httpd/access_log",  "parser": "apache"},
    {"path": "/var/log/httpd/error_log",   "parser": "apache"},
    {"path": "/var/log/haproxy/access.log", "parser": "haproxy",
     "haproxy_mode": "http"}
  ],
  "brute_force_rules": [
    {"name": "ssh_fast_brute", "event_type": "SSH_BRUTE",
     "max_attempts": 5,  "window_seconds": 60,    "parser": "secure"},
    {"name": "ssh_slow_brute", "event_type": "SSH_SLOW_BRUTE",
     "max_attempts": 5, "window_seconds": 21600, "parser": "secure"},
    {"name": "http_auth_brute","event_type": "HTTP_AUTH_BRUTE",
     "max_attempts": 20, "window_seconds": 600,   "parser": "apache"}
  ],
  "allowlist": ["127.0.0.1/32", "::1/128", "10.0.0.0/8"],
  "subscriptions": [
    {
      "name": "firehol_level1",
      "url":  "https://iplists.firehol.org/files/firehol_level1.netset",
      "format": "cidr",
      "refresh_seconds": 21600
    }
  ],
  "nft_local_block_ttl": 86400,
  "recidive_tiers": [86400, 259200, 604800, 2592000],
  "recidive_decay_seconds": 2592000,
  "expiry_reap_interval": 60,
  "custom_rules": []
}
```

### Notable settings

| Key                        | Purpose                                                  |
|----------------------------|----------------------------------------------------------|
| `SERVER_URL`               | Central server endpoint for telemetry, heartbeat, and fleet communication. |
| `API_KEY`                  | Bearer token for server authentication (set via config or auto-enrollment). |
| `upload_enabled`           | When `true`, ships telemetry batches to `SERVER_URL` instead of only spooling to disk. |
| `ssl_verify`               | Certificate verification mode: `true` (system CA), `false` (insecure), or a path to a custom CA bundle. |
| `ssl_cert` / `ssl_key`     | Paths to client certificate and key for mutual TLS.       |
| `management_mode`          | `"standalone"` (default) or `"server-managed"` for centralized config profiles. |
| `log_level`                | `DEBUG`, `INFO`, `WARNING`, or `ERROR` (default: `INFO`). |
| `log_sources`              | List of log files to tail. Auto-detected by distro family (Debian/RedHat/SUSE) if not set. |
| `brute_force_rules`        | Sliding-window detection rules (replaces built-in defaults if set). |
| `correlation_rules`        | Multi-signal correlation rules (see *Correlation detection* below). |
| `custom_rules`             | User-defined regex detection rules (see below).          |
| `nft_local_block_ttl`      | Default auto-expiry for dynamic blocks (seconds). Used as the first tier when `recidive_tiers` is not set. |
| `recidive_tiers`           | List of escalating TTLs (seconds) for repeat offenders. Index 0 = 1st offense, last entry = all subsequent. |
| `recidive_decay_seconds`   | Seconds without a new offense before the strike count resets (default 30 days). |
| `expiry_reap_interval`     | How often (seconds) the daemon prunes expired entries from memory (default 60). |
| `allowlist`                | Never blocked; also filtered out of subscription feeds.  |
| `blocklist`                | Server-managed persistent blocks (not expired locally).   |
| `subscriptions`            | List of external IP blocklists to sync.                  |
| `excluded_http_paths`      | Request paths excluded from detection (e.g. `["/favicon.ico"]`). |

---

## Fleet blocklist sharing (agent configuration)

When enrolled in a Vespid server fleet, the agent can participate in
fleet-wide blocklist sharing — automatically reporting locally detected blocks
to the server and receiving blocks detected by other nodes. Add a
`fleet_blocklist` section to your config file to control this behavior.

### YAML example

```yaml
fleet_blocklist:
  report_enabled: true           # Send local block reports to the server (default: true)
  subscribe_enabled: true        # Receive and apply fleet-wide blocks from the server (default: true)
  fleet_block_ttl_seconds: 3600  # TTL applied to fleet-propagated blocks locally (default: 3600)
  local_allow_list:              # IPs/CIDRs that are never blocked via fleet propagation
    - "10.0.0.0/8"
    - "192.168.1.1"
  fleet_queue_dir: "/var/lib/vespid/fleet_queue"  # On-disk queue directory (default)
  fleet_queue_max_size: 1000     # Max queued reports before oldest is evicted (default: 1000)
```

### Settings reference

| Key                        | Type      | Default                              | Description                                                                 |
|----------------------------|-----------|--------------------------------------|-----------------------------------------------------------------------------|
| `report_enabled`           | bool      | `true`                               | When true, the agent sends block reports to the server for fleet sharing.   |
| `subscribe_enabled`        | bool      | `true`                               | When true, the agent connects to the fleet SSE stream and applies received blocks. |
| `fleet_block_ttl_seconds`  | int       | `3600`                               | TTL (seconds) applied to fleet-propagated blocks in the local `shield_local` set. Overrides the server-suggested TTL. |
| `local_allow_list`         | list[str] | `[]`                                 | IPs or CIDRs that the agent will never block via fleet propagation, even if the server distributes them. |
| `fleet_queue_dir`          | str       | `/var/lib/vespid/fleet_queue/`   | Directory where block reports are queued to disk when the server is unreachable. |
| `fleet_queue_max_size`     | int       | `1000`                               | Maximum number of reports held in the offline queue. When full, the oldest report is evicted. |

### Offline queuing behavior

When the server is unreachable (connection refused, timeout, or HTTP 5xx), the
agent persists pending block reports as individual JSON files in
`fleet_queue_dir`. Reports are stored in FIFO order and survive agent restarts.

Once the server becomes reachable again, the agent drains the queue
automatically — sending queued reports one by one in the order they were
recorded. Delivery is retried with exponential backoff (initial interval 30 s,
maximum 300 s, factor 2). Successfully delivered reports are removed from disk
immediately.

If the queue reaches `fleet_queue_max_size`, the oldest report is discarded and
a warning is logged. Under normal connectivity this queue stays empty; it only
fills during extended outages.

---

## Server-side rule management (agent configuration)

When enrolled in a Vespid server fleet, the agent can automatically pull
detection rules from the server. This allows fleet-wide rule changes from a
single admin interface — no need to SSH into each node to update detection
logic.

### How it works

1. Admin creates/edits rules on the server (Admin → Rules or via API)
2. Agent polls `GET /api/v1/rules/distribution` at a configurable interval
3. Server returns the full enabled rule set (or 304 if unchanged)
4. Agent merges server rules with local config rules
5. Agent hot-reloads the detector — zero downtime, no restart needed

### YAML example

```yaml
# Server-side rule sync settings
rule_subscribe_enabled: true       # Pull rules from the server (default: true)
rule_poll_interval_seconds: 300    # How often to check for updates (default: 5 min)
rule_merge_strategy: "layer"       # "layer" or "replace" (default: "layer")
```

### Settings reference

| Key                        | Type   | Default  | Description                                                                 |
|----------------------------|--------|----------|-----------------------------------------------------------------------------|
| `rule_subscribe_enabled`   | bool   | `true`   | When true, the agent polls the server for detection rule updates.           |
| `rule_poll_interval_seconds` | int  | `300`    | Polling interval in seconds (min: 60, max: 86400).                          |
| `rule_merge_strategy`      | string | `"layer"` | How server rules combine with local config rules.                          |

### Merge strategies

| Strategy | Behavior |
|----------|----------|
| `layer`  | Server rules + local rules. If a rule name exists in both, the server version wins (local rule is shadowed). |
| `replace` | Only server rules are used. Local config rules are ignored entirely. |

The `layer` strategy is the default and recommended for most deployments. It
lets you maintain node-specific rules in the local config while still receiving
fleet-wide policy from the server.

### Offline resilience

The agent caches the last-received rule set to
`/var/lib/vespid/rules_cache.json`. If the server is unreachable on
startup, the agent uses the cached rules. If no cache exists, it falls back to
the locally configured rules.

### Hot-reload behavior

When new rules arrive from the server, the agent:

1. Validates all rules (regex compilation, field constraints)
2. Constructs a new detector with the merged rule set
3. Atomically swaps the old detector for the new one
4. Logs which rules were added or removed

Log lines are never dropped during the swap. If validation fails (e.g. a
server-pushed regex doesn't compile), the reload is rejected and the previous
detector continues operating.

---

## Management modes (standalone vs server-managed)

The `management_mode` setting controls *how* the agent receives its
configuration:

| Mode             | Value             | Behavior |
|------------------|-------------------|----------|
| **Standalone**   | `"standalone"`    | All configuration is read from the local config file (`/etc/vespid/vespid.yaml`).  You control rules, feeds, allowlist, and all settings manually.  Fleet blocklist sharing and server-side rule polling still work (if a `SERVER_URL` is configured), but the server never *pushes* configuration to the agent. |
| **Server-managed** | `"server-managed"` | The agent subscribes to a Config SSE channel from the server.  Configuration profiles (log sources, detection rules, subscription feeds, allowlist, fleet settings, telemetry settings) are pushed down and applied atomically with rollback on failure.  Local config file settings are treated as defaults — the server always wins by default. |

When switching to `"server-managed"`, the agent also begins reporting health
metrics (uptime, active rules, blocked IP count) on each config check-in.

### Conflict resolution

The `config_conflict_strategy` setting controls what happens when both the
local config file and the server profile define the same key:

| Strategy        | Behavior |
|-----------------|----------|
| `"server-wins"` | Server values override local config (default). |
| `"local-wins"`  | Local config values take precedence. |
| `"merge"`       | Lists (e.g. allowlist, feeds) are merged; scalar values follow server-wins. |

### Managed config categories

In server-managed mode, the following configuration categories are pushed from
the server profile:  log sources, brute force rules, custom rules, correlation
rules, subscription feeds, allowlist, fleet blocklist settings, and telemetry
settings.  See `docs/CENTRALIZED_CONFIG_MANAGEMENT.md` for full details on
profile creation, versioning, rollouts, and canary deployments.

---

## Built-in detection rules

Vespid ships with the following detection rules enabled by default. No
configuration is needed — they are active out of the box. If you override
`brute_force_rules` in your config file, the entire default list is replaced,
so include any built-in rules you still want active.

### Log parsers (what patterns are recognized)

| Parser name              | Log source       | What it matches                                                                                              |
|--------------------------|------------------|--------------------------------------------------------------------------------------------------------------|
| `secure`                 | `/var/log/secure`, `/var/log/auth.log` | Failed password, invalid user, PAM authentication failure.                                |
| `secure_recon_strong`    | same             | Pre-auth disconnects (`[preauth]`), SSH auth timeouts (LoginGraceTime expired).                              |
| `secure_negotiate_fail`  | same             | "Unable to negotiate" — client offers only deprecated algorithms (ssh-rsa, ssh-dss, weak DH groups).         |
| `secure_recon_weak`      | same             | Generic connection reset/close by remote host (can be legitimate — flaky Wi-Fi, NAT timeout).                |
| `messages`               | `/var/log/messages` | Kernel DROP/REJECT with a source IP (firewall log).                                                       |
| `apache`                 | Apache/NGINX access logs | HTTP 401/403 responses (auth failures).                                                                    |
| `haproxy`                | HAProxy logs     | HTTP 401/403 responses (auth failures) in `option httplog` or `option tcplog` mode.                         |
| `haproxy_bad_request`    | same             | HTTP 400 responses (malformed requests, automated scanning).                                                |
| `haproxy_not_found`      | same             | HTTP 404 responses (directory brute force, path probing).                                                   |
| `haproxy_scanner_ua`     | same             | Known scanner/bot user-agent signatures (sqlmap, nikto, nuclei, etc.).                                       |
| `haproxy_other`          | same             | All other HTTP status codes (2xx, 3xx, 5xx) — catch-all for custom rules.                                   |

### Sliding-window rules (when a block is triggered)

| Rule name            | Event type           | Parser                  | Threshold        | Window   | Description                                                                 |
|----------------------|----------------------|-------------------------|------------------|----------|-----------------------------------------------------------------------------|
| `ssh_fast_brute`     | `SSH_BRUTE`          | `secure`                | 5 attempts       | 1 min    | Classic rapid-fire brute force.                                             |
| `ssh_medium_brute`   | `SSH_MEDIUM_BRUTE`   | `secure`                | 4 attempts       | 10 min   | Medium-speed brute force (~2 min interval pattern).                         |
| `ssh_slow_brute`     | `SSH_SLOW_BRUTE`     | `secure`                | 5 attempts       | 6 hours  | Low-and-slow brute force spread over hours.                                 |
| `ssh_negotiate_fail` | `SSH_NEGOTIATE_FAIL` | `secure_negotiate_fail` | 3 attempts       | 24 hours | Clients offering only deprecated/weak algorithms (scanners, exploit tools). |
| `ssh_recon_strong`   | `SSH_BANNER_GRAB`    | `secure_recon_strong`   | 3 attempts       | 24 hours | Pre-auth disconnects and auth timeouts (banner grabbing / port scanning).   |
| `ssh_recon_weak`     | `SSH_RECON_WEAK`     | `secure_recon_weak`     | 8 attempts       | 24 hours | Generic connection resets (high threshold to avoid false positives).        |
| `http_auth_brute`    | `HTTP_AUTH_BRUTE`    | `apache`                | 20 attempts      | 10 min   | HTTP authentication brute force (401/403 responses).                        |
| `haproxy_auth_brute` | `HAPROXY_AUTH_BRUTE` | `haproxy`               | 10 attempts      | 5 min    | HAProxy HTTP auth brute force (401/403 responses from httplog/tcplog).      |
| `haproxy_bad_request`| `HAPROXY_BAD_REQUEST`| `haproxy_bad_request`   | 10 attempts      | 1 min    | HAProxy HTTP 400 responses (malformed requests, automated scanning).        |
| `haproxy_path_probe` | `HAPROXY_PATH_PROBE` | `haproxy_not_found`     | 5 attempts       | 2 min    | HAProxy HTTP 404 responses (directory brute force, path probing).           |

### What each SSH check catches

**Failed auth (`secure`)** — the bread and butter. Matches:
```
Failed password for root from 1.2.3.4 port 22 ssh2
Invalid user admin from 1.2.3.4 port 22
authentication failure; ... rhost=1.2.3.4
```

**Negotiation failures (`secure_negotiate_fail`)** — scanners probing for weak
SSH configurations. Matches:
```
Unable to negotiate with 1.2.3.4 port 60768: no matching host key type found. Their offer: ssh-rsa,ssh-dss [preauth]
Unable to negotiate with 1.2.3.4 port 36754: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1 [preauth]
```

**Pre-auth disconnect (`secure_recon_strong`)** — banner grabbers and port
scanners that connect, grab the SSH banner, then disconnect without
authenticating. Matches:
```
Received disconnect from 1.2.3.4 port 12345: ... [preauth]
Disconnected from 1.2.3.4 port 12345 [preauth]
```

**Auth timeout (`secure_recon_strong`)** — connections that sit idle until
LoginGraceTime expires. No legitimate client does this. Matches:
```
Timeout before authentication from 1.2.3.4
```

**Connection reset (`secure_recon_weak`)** — generic TCP resets. These happen
legitimately (laptop lid close, flaky Wi-Fi), so the threshold is high (8 in
24h). Matches:
```
Read error from remote host 1.2.3.4 port 22: Connection reset by peer
Connection closed by 1.2.3.4 port 22: Connection timed out
```

---

## Multi-signal correlation detection

The **CorrelationDetector** complements the sliding-window rules by tracking
*distinct signal categories* per IP instead of counting repeated hits on a
single rule.  This catches "low and slow" reconnaissance where an attacker
probes multiple services/vectors — staying below every individual rule's
threshold — but the combination of signals is a clear indicator of malicious
activity.

### How it works

Each incoming log line is assigned to a **signal category** based on its
parser.  The category mapping is intentionally coarse — counting *types* of
misbehaviour, not individual events:

| Parser                 | Category           |
|------------------------|--------------------|
| `secure`               | `ssh_auth_fail`    |
| `secure_recon_strong`  | `ssh_recon`        |
| `secure_negotiate_fail`| `ssh_negotiate`    |
| `secure_recon_weak`    | `ssh_recon_weak`   |
| `apache`               | `http_auth_fail`   |
| `apache_bad_request`   | `http_bad_request` |
| `apache_not_found`     | `http_probe`       |
| `messages`             | `firewall_deny`    |
| `haproxy`              | `http_auth_fail`   |
| `haproxy_scanner_ua`   | `http_scanner_ua`  |
| `custom:<name>`        | `custom:<name>`    |

The detector counts how many **distinct** categories an IP triggers within a
time window.  If the count reaches `min_categories`, the detection fires —
even if no individual rule threshold was crossed.

**Example:** An IP that triggers a 400 Bad Request (category: `http_bad_request`),
a scanner user-agent (category: `http_scanner_ua`), and a TLS-on-HTTP probe
(category: `http_probe`) within 10 minutes will fire if `min_categories` is 3 —
even if each happens only once.

### Configuration

Correlation rules live in the `correlation_rules` list.  A default rule ships
enabled out of the box:

```yaml
correlation_rules:
  - name: recon_correlation
    event_type: RECON_CORRELATION
    min_categories: 3    # number of distinct signal types required
    window_seconds: 600   # 10-minute observation window
    enabled: true
```

### Rule schema

| Field            | Type    | Default | Description                                              |
|------------------|---------|---------|----------------------------------------------------------|
| `name`           | string  | —       | Unique rule identifier.                                   |
| `event_type`     | string  | —       | Event type emitted when the rule trips (e.g. `RECON_CORRELATION`). |
| `min_categories` | integer | `3`     | Number of distinct signal categories required to fire.   |
| `window_seconds` | integer | `600`   | Observation window in seconds (10 min default).          |
| `enabled`        | boolean | `true`  | Set to `false` to disable without deleting.              |

### Cooldown and pruning

After a correlation detection fires, the IP enters a 5-minute cooldown
(per-rule) to avoid duplicate fires.  The daemon's background GC loop prunes
observation data for IPs that have been inactive beyond the longest window +
cooldown, keeping memory bounded on long-running nodes.

---

## Custom detection rules

Custom rules let you add new detection patterns without touching source code.
Define them in the `custom_rules` list in your config file, restart the daemon,
and they're live.

Each custom rule is a regex that runs against log lines from the specified log
sources. When the regex matches, the extracted IP is fed into the same
sliding-window detector used by the built-in rules. If the IP hits the
threshold (`max_attempts` within `window_seconds`), Vespid fires a
detection event and blocks the IP — exactly like a built-in rule.

### Rule schema

| Field            | Type       | Required | Default | Description                                                                                                  |
|------------------|------------|----------|---------|--------------------------------------------------------------------------------------------------------------|
| `name`           | string     | yes      |         | Unique rule identifier. Used in logs, events, and the `reason` field on blocks.                              |
| `event_type`     | string     | yes      |         | Event type emitted when the rule trips (e.g. `SSH_AUTH_TIMEOUT`). Shows up in telemetry and the dashboard.   |
| `regex`          | string     | yes      |         | Python regex applied to each log line. **Must** contain a `(?P<ip>...)` named group to capture the source IP.|
| `log_sources`    | list       | yes      |         | Which log parsers to evaluate against: `["secure"]`, `["messages"]`, `["apache"]`, or `["*"]` for all.       |
| `max_attempts`   | integer    | no       | `3`     | Number of matches within the window before the rule fires.                                                   |
| `window_seconds` | integer    | no       | `3600`  | Sliding window duration in seconds.                                                                          |
| `enabled`        | boolean    | no       | `true`  | Set to `false` to disable a rule without deleting it.                                                        |

### Writing the regex

The only hard requirement is a named capture group called `ip`:

```
(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)
```

This captures both IPv4 and IPv6 addresses. You can use a simpler pattern if
you only care about IPv4:

```
(?P<ip>\d{1,3}(?:\.\d{1,3}){3})
```

Build the rest of the regex to match the specific log message you're targeting.
Anchor on the daemon name and key phrases to avoid false positives.

### YAML example with custom rules

```yaml
custom_rules:
  # SSH auth timeout — attacker connects but never authenticates
  - name: ssh_auth_timeout
    event_type: SSH_AUTH_TIMEOUT
    regex: 'sshd.*?Timeout before authentication.*?from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)'
    log_sources: [secure]
    max_attempts: 3
    window_seconds: 3600

  # SSH bad protocol version — scanner sending garbage
  - name: ssh_bad_protocol
    event_type: SSH_BAD_PROTOCOL
    regex: 'sshd.*?Bad protocol version.*?from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)'
    log_sources: [secure]
    max_attempts: 2
    window_seconds: 3600

  # Postfix SMTP auth brute force
  - name: postfix_auth_fail
    event_type: SMTP_AUTH_BRUTE
    regex: 'postfix.*authentication failed.*\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]'
    log_sources: ["*"]
    max_attempts: 5
    window_seconds: 600

  # Dovecot IMAP auth failure
  - name: dovecot_auth_fail
    event_type: IMAP_AUTH_BRUTE
    regex: 'dovecot.*auth failed.*rip=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    log_sources: ["*"]
    max_attempts: 10
    window_seconds: 600

  # WordPress xmlrpc.php brute force (Apache access log)
  - name: wp_xmlrpc_brute
    event_type: WP_XMLRPC_BRUTE
    regex: '^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*POST.*/xmlrpc\.php.*" (?:200|403)'
    log_sources: [apache]
    max_attempts: 15
    window_seconds: 300

  # Disabled rule — kept for reference, not evaluated
  - name: experimental_rule
    event_type: EXPERIMENTAL
    regex: 'something.*(?P<ip>\d+\.\d+\.\d+\.\d+)'
    log_sources: [secure]
    enabled: false
```

Note how YAML makes regex strings clean — single quotes mean no
double-escaping. Compare the YAML `'sshd.*?Timeout before authentication.*?from\s+(?P<ip>...)'`
with the JSON equivalent `"sshd.*?Timeout before authentication.*?from\\s+(?P<ip>...)"`.

### JSON equivalent

If you prefer JSON, the same rules look like this (note the `\\` escaping):

```json
{
  "custom_rules": [
    {
      "name": "ssh_auth_timeout",
      "event_type": "SSH_AUTH_TIMEOUT",
      "regex": "sshd.*?Timeout before authentication.*?from\\s+(?P<ip>\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9a-fA-F:]+)",
      "log_sources": ["secure"],
      "max_attempts": 3,
      "window_seconds": 3600,
      "enabled": true
    }
  ]
}
```

### Validation

Vespid validates every custom rule at startup:

- **Invalid regex** — logged as an error, rule is skipped. The daemon still starts.
- **Missing `(?P<ip>...)` group** — logged as an error, rule is skipped.
- **Disabled rules** — logged at INFO level, not compiled.

Use `--check-config` to verify your rules parse correctly without starting the
daemon:

```bash
sudo vespid --check-config
```

At `log_level: DEBUG`, every custom rule match is logged:

```
CUSTOM_MATCH rule=custom:ssh_auth_timeout ip=39.164.126.118
```

### How custom rules flow through the system

```
Log line arrives
    │
    ├─► Built-in parser (secure/messages/apache)
    │       │
    │       └─► ParsedLine ──► SlidingWindowDetector (built-in rules)
    │                │
    │                └─► CustomRuleEngine.evaluate()
    │                        │
    │                        └─► ParsedLine(s) ──► SlidingWindowDetector (custom rules)
    │
    └─► On threshold breach: DETECT event ──► NFTablesManager.block_local()
```

Custom rules generate `BruteForceRule` entries with parser names prefixed
`custom:` (e.g. `custom:ssh_auth_timeout`), so they never collide with
built-in parsers. They share the same sliding-window detector, cooldown logic,
event publishing, and blocking pipeline as built-in rules.

### Tips for writing rules

1. **Test your regex first.** Use `grep -P` or Python to verify it matches
   real log lines before deploying:
   ```bash
   grep -P 'sshd.*?Timeout before authentication.*?from\s+(\d{1,3}(\.\d{1,3}){3})' /var/log/secure
   ```

2. **Be specific.** Anchor on the daemon name (`sshd`, `postfix`, `dovecot`)
   and key phrases to avoid false positives across different log sources.

3. **Start with high thresholds.** Set `max_attempts` conservatively, watch
   the logs for a day, then tighten. A rule that fires too aggressively can
   lock out legitimate users.

4. **Use `log_sources` to scope.** If your regex only makes sense for
   `/var/log/secure`, set `log_sources: [secure]` rather than `["*"]`.

5. **Use `enabled: false` to stage.** Add a rule disabled, deploy, then flip
   it on once you're confident.

---

## Repeat-offender escalation (recidive)

Vespid tracks how many times each IP has been blocked. When an IP is
blocked again, it receives a progressively longer ban instead of the same flat
TTL every time.

### Default escalation tiers

| Offense | Ban duration |
|---------|-------------|
| 1st     | 24 hours    |
| 2nd     | 3 days      |
| 3rd     | 7 days      |
| 4th+    | 30 days     |

The last tier is a ceiling — all subsequent offenses use the same duration.

### Decay

If an IP stays clean (no new blocks) for `recidive_decay_seconds` (default
30 days), its strike count resets to zero. The next offense is treated as a
fresh first offense.

### Configuration

Override the tiers and decay in your config file:

```yaml
# Aggressive escalation: 1h → 24h → 7d → permanent (365d)
recidive_tiers:
  - 3600
  - 86400
  - 604800
  - 31536000

# Reset after 60 days clean
recidive_decay_seconds: 5184000
```

Or in JSON:

```json
{
  "recidive_tiers": [3600, 86400, 604800, 31536000],
  "recidive_decay_seconds": 5184000
}
```

To disable escalation entirely and use a flat TTL for every block, set a
single-element tier list:

```yaml
recidive_tiers:
  - 86400
```

### State persistence

Strike counts are persisted to `/var/lib/vespid/recidive.json` and survive
daemon restarts. Decayed entries are pruned on load.

### CLI inspection

Check any IP's offense history:

```bash
sudo vespid-cli recidive 203.0.113.5
```

The `list-local` command also shows the current strike count for each blocked
IP in the **Strike** column.

---

## Expiry reaper

The daemon runs a background task every `expiry_reap_interval` seconds
(default 60) that removes expired entries from the in-memory block list. This
keeps `vespid-cli list-local` clean — you'll never see stale "expired" rows.

The nftables kernel set already stops blocking traffic when an element's TTL
expires, so the reaper is purely cosmetic: it synchronizes the shadow state
with what the kernel is actually enforcing.

The reap interval is configurable:

```yaml
expiry_reap_interval: 30   # check every 30 seconds instead of 60
```

---

## Firewalld coexistence

On systems running `firewalld` with the nftables backend, firewalld owns the
main ruleset and may flush/rebuild its tables on reload.  Vespid's `shield`
table uses **priority -150** — well before firewalld's default priority 10 — so
they never conflict.

To survive firewalld reloads **and** reboots, the agent:

1. **Persists** the table structure to `/etc/nftables/shield.rules` after every
   successful `ensure_infrastructure()` call.
2. **Injects** an include line into `/etc/sysconfig/nftables.conf` so the
   system nftables service loads the shield table at boot — before firewalld
   starts.
3. **Health checks** every 30 seconds — if the table is missing (e.g.
   `firewalld --reload` flushed it), the daemon rebuilds it automatically and
   re-injects all active blocks from the in-memory and on-disk state.

This means Vespid works alongside firewalld without any manual intervention
or special firewall rules.

---

## Running the daemon

### Manual run (debugging)

```bash
sudo vespid
```

You can validate the resolved configuration without starting the daemon:

```bash
sudo vespid --check-config
```

### As a `systemd` service

Create `/etc/systemd/system/vespid.service`:

```ini
[Unit]
Description=Vespid security daemon
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/vespid
Restart=on-failure
RestartSec=5
# nftables + reading /var/log/secure require privileges:
User=root
Group=root
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vespid
sudo journalctl -u vespid -f
```

On startup Vespid will:

1. Ensure the `inet shield` table exists with both sets and an input chain
   that drops traffic from `@shield_subscribed` and `@shield_local`.
2. Start the DataBus worker.
3. Begin tailing the configured logs.
4. Run an immediate subscription sync, then refresh on each feed's schedule.
5. Open the control socket at `/run/vespid.sock` (mode 0600).

---

## Using the CLI

`vespid-cli` talks to the running daemon over its UNIX socket. All commands
must be run as `root` (or any user with read/write access to the socket).

### Show status

```bash
sudo vespid-cli status
```

```json
{
  "ok": true,
  "node_id": "host01-3a0c1f...",
  "version": "1.0.0",
  "nft": {
    "nft_available": true,
    "table": "inet shield",
    "local_count": 7,
    "subscribed_count": 38421,
    "local_sample": ["1.2.3.4", "5.6.7.8"],
    "allowlist": ["127.0.0.1/32", "::1/128"]
  },
  "subs": {
    "feeds": {
      "firehol_level1": {"ts": 1730000000.0, "count": 38421}
    }
  },
  "bus": {"published": 142, "shipped": 0, "spooled": 142, "queued": 0},
  "upload_enabled": false,
  "server_url": "https://server.example.com/api/v1/events"
}
```

### See what the node is currently blocking

```bash
sudo vespid-cli list-local
```

```
IP                    TTL        STRIKE   BLOCKED AT             REASON
------------------------------------------------------------------------------------------
203.0.113.5           23h57m     2        2026-04-28 09:12:33Z   ssh_slow_brute
198.51.100.42         12h03m     1        2026-04-28 09:00:11Z   http_auth_brute
192.0.2.10             4h42m     3        2026-04-28 04:30:00Z   cli

3 entries
```

The **Strike** column shows how many times the IP has been blocked. Higher
strikes mean longer ban durations (see *Repeat-offender escalation* below).

### See what came from external feeds

```bash
sudo vespid-cli list-subscribed              # first 50 entries by default
sudo vespid-cli list-subscribed --limit 0    # show everything
sudo vespid-cli list-subscribed --limit 5
```

```
1.10.16.0/20
1.116.0.0/16
1.119.16.0/20
1.119.96.0/20
1.119.128.0/22

showing 5 of 38421 entries
```

### Check why a specific IP is (or isn't) blocked

```bash
sudo vespid-cli check 1.10.16.42
```

```
ip             : 1.10.16.42
allowlisted    : False
in shield_local: False
in shield_subscr: True
  matched CIDR : 1.10.16.0/20
```

```bash
sudo vespid-cli check 203.0.113.5
```

```
ip             : 203.0.113.5
allowlisted    : False
in shield_local: True
  reason       : ssh_slow_brute
  blocked_at   : 2026-04-28 09:12:33Z
  expires_at   : 2026-04-29 09:12:33Z
in shield_subscr: False
```

### Check repeat-offender history for an IP

```bash
sudo vespid-cli recidive 203.0.113.5
```

```
ip             : 203.0.113.5
offenses       : 3
first_seen     : 2026-04-26 02:14:11Z
last_seen      : 2026-04-28 09:12:33Z
next_ban_ttl   : 30d0h
```

This shows the IP has been blocked 3 times. Its next offense would receive a
30-day ban (the 4th tier). If the IP stays clean for 30 days (configurable via
`recidive_decay_seconds`), the strike count resets to zero.

### See recent block / unblock decisions

```bash
sudo vespid-cli recent --limit 10
```

```
TIME                   ACTION   IP                                       REASON
------------------------------------------------------------------------------------------
2026-04-28 09:12:33Z   BLOCK    203.0.113.5                              ssh_slow_brute
2026-04-28 09:10:18Z   UNBLOCK  192.0.2.99                               cli
2026-04-28 09:09:51Z   BLOCK    198.51.100.42                            http_auth_brute
```

### Block / unblock an IP manually

```bash
sudo vespid-cli block   1.2.3.4 --reason "ops_request"
sudo vespid-cli unblock 1.2.3.4 --reason "false_positive"
```

Allowlisted addresses are silently refused.

### Force a subscription feed sync

```bash
sudo vespid-cli sync-feeds
```

### Manage the runtime allowlist

```bash
sudo vespid-cli allowlist-add 10.0.0.0/8
sudo vespid-cli allowlist-remove 10.0.0.0/8
sudo vespid-cli allowlist-list
```

Runtime allowlist entries are additive — they supplement the config file
allowlist.  Entries added this way persist across restarts.

### Telemetry bus statistics

```bash
sudo vespid-cli stats
```

### View live nftables counters

```bash
sudo vespid-cli counters
```

Shows per-set packet and byte counters from the nftables kernel tables, with
live per-second delta rates.  Useful for monitoring how much traffic each
shield set is dropping in real time.

### Tail the daemon log live

```bash
sudo vespid-cli tail-log -f               # human-readable activity log
sudo vespid-cli tail-log -f --decisions   # JSON audit trail of every decision
```

### Raw JSON output

Every command supports `--json` if you'd rather pipe to `jq`:

```bash
sudo vespid-cli --json list-local | jq '.entries[] | select(.reason=="ssh_slow_brute")'
```

---

## Logging

Vespid writes to three sinks simultaneously:

| Sink                                         | Purpose                                                |
|----------------------------------------------|--------------------------------------------------------|
| **stdout**                                   | Picked up by `journalctl -u vespid -f`.            |
| `/var/log/vespid/vespid.log`         | Human-readable rotating log (10 MB x 5).               |
| `/var/log/vespid/decisions.jsonl`        | One JSON object per decision (block / unblock / detect / sync). Easy to ship to a SIEM. |

### Human log (`vespid.log`)

```
2026-04-28T09:00:00+0000 INFO    vespid             Starting Vespid (node_id=host01-3a0c1f..., version=1.0.0)
2026-04-28T09:00:00+0000 INFO    vespid             Log sources: /var/log/secure, /var/log/messages, /var/log/httpd/access_log
2026-04-28T09:00:00+0000 INFO    vespid             Detection rules: ssh_fast_brute(5/60s), ssh_slow_brute(5/21600s), http_auth_brute(20/600s)
2026-04-28T09:00:00+0000 INFO    vespid             Subscription feeds: firehol_level1
2026-04-28T09:00:00+0000 INFO    vespid             Telemetry upload: DISABLED (spool only) -> https://server.example.com/api/v1/events
2026-04-28T09:00:01+0000 INFO    vespid.logproc     Tailing /var/log/secure (secure)
2026-04-28T09:00:01+0000 INFO    vespid.subs        FEED firehol_level1 url=https://iplists.firehol.org/... entries=38421
2026-04-28T09:00:01+0000 INFO    vespid.nft         SYNC shield_subscribed -> 38421 entries committed
2026-04-28T09:12:30+0000 WARNING vespid.logproc     DETECT SSH_SLOW_BRUTE ip=203.0.113.5 attempts=5 window=21600s (rule=ssh_slow_brute)
2026-04-28T09:12:30+0000 INFO    vespid.nft         BLOCK 203.0.113.5 -> shield_local (reason=ssh_slow_brute, strike=2, ttl=259200s)
```

Set `"log_level": "DEBUG"` in the config to also see every individual log
match (`MATCH SECURE parser=secure ip=...`).

### Decisions log (`decisions.jsonl`)

One JSON object per line, perfect for `jq`, `grep`, or shipping to a SIEM:

```json
{"ts":"2026-04-28T09:12:30Z","level":"INFO","event":"detect","rule":"ssh_slow_brute","event_type":"SSH_SLOW_BRUTE","ip":"203.0.113.5","attempts":5,"window_seconds":21600}
{"ts":"2026-04-28T09:12:30Z","level":"INFO","event":"block","ip":"203.0.113.5","set":"shield_local","reason":"ssh_slow_brute","ttl":259200,"strike":2}
{"ts":"2026-04-28T09:30:00Z","level":"INFO","event":"subscription_sync","set":"shield_subscribed","count":38421}
{"ts":"2026-04-28T10:05:11Z","level":"INFO","event":"unblock","ip":"203.0.113.5","set":"shield_local","reason":"cli","was_present":true}
```

Useful one-liners:

```bash
# Everything blocked in the last hour:
sudo grep '"event":"block"' /var/log/vespid/decisions.jsonl | tail -n 50 | jq

# Top reasons for blocks:
sudo jq -r 'select(.event=="block") | .reason' \
    /var/log/vespid/decisions.jsonl | sort | uniq -c | sort -rn

# Watch detections live:
sudo vespid-cli tail-log -f --decisions | jq 'select(.event=="detect")'
```

The log directory can be overridden with `VESPID_LOG_DIR=/some/where`.

---

## Telemetry / event schema

Every event the node emits looks like this:

```json
{
  "event_id":     "1f3a...hex...",
  "node_id":      "host01-3a0c1f...",
  "timestamp":    "2026-04-28T09:12:33Z",
  "source_ip":    "203.0.113.5",
  "event_type":   "SSH_SLOW_BRUTE",
  "action_taken": "BLOCKED",
  "geo_data":     {"country": "RU", "asn": "AS12345", "org": "Example ISP"},
  "metadata":     {"rule": "ssh_slow_brute", "attempts": 5, "window_seconds": 21600}
}
```

Common `event_type` values:

| Event type            | Producer            | Notes                                |
|-----------------------|---------------------|--------------------------------------|
| `LOG_MATCH`           | log processor       | Every parsed failure (low-level).    |
| `SSH_BRUTE`           | detector            | Fast SSH brute force.                |
| `SSH_MEDIUM_BRUTE`    | detector            | Medium-speed SSH brute force.        |
| `SSH_SLOW_BRUTE`      | detector            | Slow SSH brute force.                |
| `SSH_NEGOTIATE_FAIL`  | detector            | SSH negotiation failure (client offers only deprecated algorithms). |
| `SSH_BANNER_GRAB`     | detector            | SSH recon strong signal (pre-auth disconnect / auth timeout). |
| `SSH_RECON_WEAK`      | detector            | SSH recon weak signal (generic connection reset / close).     |
| `HTTP_AUTH_BRUTE`     | detector            | Apache 401/403 brute force.          |
| `HAPROXY_AUTH_BRUTE`  | detector            | HAProxy 401/403 brute force.         |
| `HAPROXY_BAD_REQUEST` | detector            | HAProxy 400 responses (malformed requests). |
| `HAPROXY_PATH_PROBE`  | detector            | HAProxy 404 responses (directory brute force). |
| `RECON_CORRELATION`   | correlation detector| Multi-signal recon detected across distinct categories. |
| `NFT_ACTION`          | nftables manager    | `BLOCKED` / `UNBLOCKED`.             |
| `SUBSCRIPTION_SYNC`   | subscription mgr    | `REPLACED` after a feed sync.        |
| `SUBSCRIPTION_FETCH`  | subscription mgr    | `FAILED` when a feed download fails. |
| *(custom)*            | custom rule engine  | Any `event_type` you define in `custom_rules`. |

While `upload_enabled` is `false`, every batch is appended to
`/var/lib/vespid/spool.jsonl` so nothing is lost. Once the central server
is available, set `upload_enabled: true` and `SERVER_URL` / `API_KEY`; the
worker will POST batches as `{"events": [...]}` with `Authorization: Bearer ...`
and `X-Node-Id: ...` headers.

### Telemetry resilience (heartbeat retry & spool drain)

When `upload_enabled` is `true` but the server is unreachable (connection
refused, timeout, or HTTP 5xx), the agent handles it gracefully:

1. **Heartbeat retry** — each heartbeat cycle retries up to 3 times with 15
   seconds between attempts before giving up until the next cycle.

2. **Event spooling** — failed telemetry batches are appended to
   `spool.jsonl` on disk. No events are lost during an outage.

3. **Automatic spool drain** — after every successful heartbeat, the agent
   checks for spooled events and re-sends them in batches. If a batch fails
   during drain, it stops immediately and retries on the next heartbeat. Once
   all spooled events are delivered, the spool file is removed.

This means the agent is fully autonomous during server outages — it continues
detecting and blocking threats locally, queues all telemetry to disk, and
automatically catches the server up once connectivity is restored.

---

## How it fits together

```
+-------------------+     +------------------+     +---------------------+
| /var/log/secure   |---->| LogProcessor     |---->| SlidingWindowDetect |
| /var/log/messages |     | (asyncio tailer) |     | + CorrelationDetect |
| Apache/Nginx/HA   |     +--------+---------+     +----------+----------+
+-------------------+              |                          |
                                   |                          v
                                   |                  +-------+--------+
                                   |                  | NFTablesManager|
                                   |                  | shield_local   |
                                   |                  +-------+--------+
                                   v                          ^
                       +-----------+---+                      |
                       |   DataBus     |<---------+-----------+
                       | (Producer/    |          |
                       |  Consumer)    |   +------+----------+
                       +------+--------+   | SubscriptionMgr |
                              |            | shield_subscribed
                              v            +-----------------+
                     spool.jsonl  OR  POST {SERVER_URL}

                       +---------------------+
                       | EnrollmentClient    |──► POST /api/v1/enroll
                       +---------------------+

                       +---------------------+
                       | FleetBlockSubscriber|──► GET /api/v1/fleet/blocks/stream
                       +---------------------+

                       +---------------------+
                       | RuleSubscriber      |──► GET /api/v1/rules/distribution
                       +---------------------+

                       +---------------------+
                       | ConfigSubscriber    |──► Config SSE (server-managed)
                       +---------------------+
```

---

## Uninstall

```bash
sudo systemctl disable --now vespid
sudo python3 -m pip uninstall vespid
sudo rm -rf /etc/vespid /var/lib/vespid /var/log/vespid /run/vespid.sock
sudo nft delete table inet shield 2>/dev/null || true
```

---

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
