# Vespid Agent

A lightweight daemon that runs on each Linux node.  It tails local logs,
detects attacks, manages `nftables` blocklists, syncs external threat feeds,
and optionally connects to a Vespid Server for fleet-wide sharing and
centralized management.

## Requirements

- Linux with `nftables` — AlmaLinux / RHEL / Rocky / Debian / Ubuntu / SUSE
- Python 3.10+
- Root privileges (for `nftables` management and reading `/var/log/secure`)
- *(Optional)* `maxminddb` + a MaxMind `GeoLite2-Country.mmdb` or db-ip `dbip-country-lite.mmdb` for GeoIP enrichment

## Installation

```bash
sudo dnf install -y python3 python3-pip nftables
sudo systemctl enable --now nftables

sudo python3 -m pip install .

sudo install -d -m 0750 /etc/vespid
sudo install -d -m 0750 /var/lib/vespid
sudo install -d -m 0750 /var/log/vespid
```

This installs two binaries: `vespid` (daemon) and `vespid-cli` (CLI).

## Quick start

```bash
# Validate config
sudo vespid --check-config

# Run the daemon
sudo vespid

# Use the CLI
sudo vespid-cli status
sudo vespid-cli list-local
```

## Configuration

The daemon reads from `/etc/vespid/vespid.yaml` (YAML preferred) or
`/etc/vespid/vespid.conf` (JSON).  All keys are optional — defaults
are sensible.

```yaml
SERVER_URL: "https://server.example.com/api/v1/events"
API_KEY: "your-api-key"
upload_enabled: true
log_level: INFO

log_sources:
  - path: /var/log/secure
    parser: secure
  - path: /var/log/messages
    parser: messages
  - path: /var/log/httpd/access_log
    parser: apache
  - path: /var/log/haproxy/access.log
    parser: haproxy

brute_force_rules:
  - name: ssh_fast_brute
    event_type: SSH_BRUTE
    max_attempts: 5
    window_seconds: 60
    parser: secure

allowlist:
  - "127.0.0.1/32"
  - "::1/128"

subscriptions:
  - name: firehol_level1
    url: "https://iplists.firehol.org/files/firehol_level1.netset"
    format: cidr
    refresh_seconds: 21600
```

### Log sources (auto-detected)

If `log_sources` is omitted, the daemon auto-detects the distro and sets the
correct default paths:

| Distro | SSH auth | Syslog | Apache |
|--------|----------|--------|--------|
| RedHat | `/var/log/secure` | `/var/log/messages` | `/var/log/httpd/access_log` |
| Debian | `/var/log/auth.log` | `/var/log/syslog` | `/var/log/apache2/access.log` |
| SUSE | `/var/log/messages` | `/var/log/messages` | `/var/log/apache2/access_log` |

HAProxy logs (`/var/log/haproxy/access.log`) are included in all defaults.

### Complete settings reference

| Key | Default | Description |
|-----|---------|-------------|
| `SERVER_URL` | `https://server.example.com/api/v1/events` | Central server endpoint |
| `API_KEY` | `""` (empty) | Bearer token; set via config or auto-enrollment. Leave empty to trigger auto-enrollment. |
| `upload_enabled` | `false` | Ship telemetry to SERVER_URL (vs spool-only) |
| `ssl_verify` | `true` | `true` (system CA), `false` (insecure), or path to custom CA |
| `ssl_cert` / `ssl_key` | `""` | Client certificate paths for mutual TLS |
| `management_mode` | `"standalone"` | `"standalone"` or `"server-managed"` |
| `log_level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `log_sources` | *(auto-detected)* | List of log files to tail |
| `brute_force_rules` | *(built-in defaults)* | Sliding-window detection rules |
| `correlation_rules` | *(1 default rule)* | Multi-signal correlation rules |
| `custom_rules` | `[]` | User-defined regex detection rules |
| `allowlist` | `["127.0.0.1/32", "::1/128"]` | Never-blocked IPs |
| `blocklist` | `[]` | Server-managed persistent blocks |
| `subscriptions` | *(firehol_level1)* | External IP blocklists |
| `excluded_http_paths` | `["/favicon.ico"]` | Paths excluded from detection |
| `nft_local_block_ttl` | `86400` | Default block TTL (24h) |
| `recidive_tiers` | `[86400, 259200, 604800, 2592000]` | Escalating ban durations |
| `recidive_decay_seconds` | `2592000` | Clean period before strike reset (30d) |
| `expiry_reap_interval` | `60` | How often expired entries are pruned from memory |

## Detection system

### Built-in rules (default)

These ship enabled and active with no configuration:

| Rule | Event Type | Parser | Threshold | Window |
|------|-----------|--------|-----------|--------|
| `ssh_fast_brute` | `SSH_BRUTE` | `secure` | 5 | 1 min |
| `ssh_medium_brute` | `SSH_MEDIUM_BRUTE` | `secure` | 4 | 10 min |
| `ssh_slow_brute` | `SSH_SLOW_BRUTE` | `secure` | 5 | 6 hours |
| `ssh_negotiate_fail` | `SSH_NEGOTIATE_FAIL` | `secure_negotiate_fail` | 3 | 24 hours |
| `ssh_recon_strong` | `SSH_BANNER_GRAB` | `secure_recon_strong` | 3 | 24 hours |
| `ssh_recon_weak` | `SSH_RECON_WEAK` | `secure_recon_weak` | 8 | 24 hours |
| `http_auth_brute` | `HTTP_AUTH_BRUTE` | `apache` | 20 | 10 min |
| `haproxy_auth_brute` | `HAPROXY_AUTH_BRUTE` | `haproxy` | 10 | 5 min |
| `haproxy_bad_request` | `HAPROXY_BAD_REQUEST` | `haproxy_bad_request` | 10 | 1 min |
| `haproxy_path_probe` | `HAPROXY_PATH_PROBE` | `haproxy_not_found` | 5 | 2 min |

### Log parsers

| Parser | What it matches |
|--------|----------------|
| `secure` | Failed password, invalid user, PAM failure |
| `secure_recon_strong` | Pre-auth disconnects, auth timeouts |
| `secure_negotiate_fail` | Weak algorithm offers (ssh-rsa, ssh-dss) |
| `secure_recon_weak` | Generic connection resets |
| `messages` | Kernel DROP/REJECT with source IP |
| `apache` | HTTP 401/403 responses |
| `haproxy` | HAProxy HTTP 401/403 auth failures |
| `haproxy_bad_request` | HAProxy HTTP 400 (malformed requests) |
| `haproxy_not_found` | HAProxy HTTP 404 (path probing) |
| `haproxy_scanner_ua` | Known scanner user-agent signatures |
| `haproxy_other` | All other HAProxy status codes |

### Correlation detection

The CorrelationDetector catches "low and slow" reconnaissance by tracking
distinct signal categories per IP.  If an IP triggers observations across
enough different categories within a time window, it's flagged even if no
single rule's threshold was crossed.

```yaml
correlation_rules:
  - name: recon_correlation
    event_type: RECON_CORRELATION
    min_categories: 3    # distinct signal types required
    window_seconds: 600   # 10-minute observation window
    enabled: true
```

### Custom rules

Define regex-based detection rules without changing source code:

```yaml
custom_rules:
  - name: postfix_auth_fail
    event_type: SMTP_AUTH_BRUTE
    regex: 'postfix.*authentication failed.*\[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\]'
    log_sources: ["*"]
    max_attempts: 5
    window_seconds: 600
```

The `(?P<ip>...)` named group is required — it captures the source IP.

## Fleet blocklist sharing

When connected to a server, the agent participates in fleet-wide blocklist
sharing:

```yaml
fleet_blocklist:
  report_enabled: true           # Send local block reports to the server
  subscribe_enabled: true        # Receive fleet-wide blocks via SSE
  fleet_block_ttl_seconds: 3600  # TTL for fleet-propagated blocks
  local_allow_list:              # IPs never blocked via fleet propagation
    - "10.0.0.0/8"
```

### Offline queuing

When the server is unreachable, block reports are persisted to disk
(`/var/lib/vespid/fleet_queue/`) and drained automatically on reconnect
with exponential backoff (30s → 300s).

## Server-side rule management

```yaml
rule_subscribe_enabled: true       # Pull rules from server
rule_poll_interval_seconds: 300    # Check every 5 minutes
rule_merge_strategy: "layer"       # "layer" (server wins) or "replace"
```

Rules are hot-reloaded — zero downtime, no daemon restart.

## Management modes

| Mode | Behavior |
|------|----------|
| `"standalone"` (default) | All config from local file. Fleet and rule polling still work if SERVER_URL is set. |
| `"server-managed"` | Config profiles pushed from server via SSE. Atomic apply with rollback on failure. |

```yaml
management_mode: "server-managed"
config_conflict_strategy: "server-wins"  # or "local-wins" or "merge"
```

## Repeat-offender escalation

IPs blocked repeatedly get progressively longer bans:

| Offense | Duration |
|---------|----------|
| 1st | 24 hours |
| 2nd | 3 days |
| 3rd | 7 days |
| 4th+ | 30 days |

Strike counts decay after 30 days clean.  Configurable via `recidive_tiers`.

The server also applies fleet-wide recidive escalation independently — see the
[Server Guide](../server/guide.md#fleet-block-recidive) for details on how fleet
block TTL escalates for repeat offenders across the entire fleet.

## Firewalld coexistence

The `shield` nftables table uses **priority -150** (before firewalld's
priority 10).  The agent persists the table to `/etc/nftables/shield.rules`
and injects an include line into the system nftables config.  A health check
runs every 30 seconds — if the table is missing, it's rebuilt automatically.

## systemd service

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
User=root
Group=root
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

## Uninstall

```bash
sudo systemctl disable --now vespid
sudo python3 -m pip uninstall vespid
sudo rm -rf /etc/vespid /var/lib/vespid /var/log/vespid /run/vespid.sock
sudo nft delete table inet shield 2>/dev/null || true
```
