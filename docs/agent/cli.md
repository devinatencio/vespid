# Agent CLI Reference

`vespid-cli` communicates with the running daemon over a UNIX socket at
`/run/vespid.sock` (mode 0600).  All commands require root or read/write
access to the socket.

Every command supports `--json` for machine-readable output.

## Local daemon commands

### `status`

Show daemon overview: node ID, version, nftables table state, subscription
feeds, telemetry bus statistics, fleet connection status, 24h activity snapshot.

```bash
sudo vespid-cli status
```

### `list-local`

Show all currently blocked IPs with TTL, strike count, block time, and reason.

```bash
sudo vespid-cli list-local
```

### `list-subscribed`

Show entries in the `shield_subscribed` set (external feed IPs).

```bash
sudo vespid-cli list-subscribed              # first 50 entries
sudo vespid-cli list-subscribed --limit 0    # show everything
sudo vespid-cli list-subscribed --limit 5
```

### `check`

Check why a specific IP is or isn't blocked — shows allowlist status and
which nftables set (if any) contains it.

```bash
sudo vespid-cli check 1.2.3.4
```

### `block` / `unblock`

Manually add or remove a block from `shield_local`.

```bash
sudo vespid-cli block 1.2.3.4 --reason "ops_request"
sudo vespid-cli unblock 1.2.3.4 --reason "false_positive"
```

Allowlisted addresses are silently refused for `block`.

### `recent`

Show recent block and unblock decisions.

```bash
sudo vespid-cli recent --limit 10
```

### `recidive`

Check an IP's repeat-offender history: number of offenses, first/last seen,
and next ban TTL.

```bash
sudo vespid-cli recidive 203.0.113.5
```

### `sync-feeds`

Force an immediate sync of all subscription feeds.

```bash
sudo vespid-cli sync-feeds
```

### `allowlist-add` / `allowlist-remove` / `allowlist-list`

Manage the runtime allowlist (additive to the config file allowlist).

```bash
sudo vespid-cli allowlist-add 10.0.0.0/8
sudo vespid-cli allowlist-remove 10.0.0.0/8
sudo vespid-cli allowlist-list
```

### `counters`

Show live nftables packet and byte counters per set with per-second delta
rates.  Use `--watch` for continuous updates.

```bash
sudo vespid-cli counters
sudo vespid-cli counters --watch 5   # refresh every 5 seconds
```

### `stats`

Alias for `status` — kept for backward compatibility.

### `tail-log`

Tail the daemon logs live.

```bash
sudo vespid-cli tail-log -f               # human-readable activity log
sudo vespid-cli tail-log -f --decisions   # JSON audit trail of every decision
```

### `spool`

View or manage the spooled telemetry queue.

```bash
sudo vespid-cli spool             # show spool stats
sudo vespid-cli spool --tail 10   # show last 10 entries
sudo vespid-cli spool --purge     # clear the spool
```

## Server commands

When the server is configured, `vespid-cli` can interact with the
Vespid Server for fleet management, intelligence queries, and event
search.

### Connecting to the server

```bash
vespid-cli server login --url https://vespid.example.com --key hg_your_api_key
vespid-cli server status
vespid-cli server logout
```

Credentials are stored in `~/.config/vespid/cli.yaml` (mode 0600).
Environment variables also work:

```bash
export VESPID_SERVER_URL=https://vespid.example.com
export VESPID_API_KEY=hg_your_api_key
```

#### Credential resolution order

1. **Environment variables**: `VESPID_SERVER_URL`, `VESPID_API_KEY`
2. **CLI config file**: `~/.config/vespid/cli.yaml`
3. **Agent config**: `/etc/vespid/vespid.yaml` (`SERVER_URL` + `API_KEY`)

Use `vespid-cli server status` to see which source is active.

### Fleet management

Manage the fleet-wide blocklist and propagation settings.

```bash
vespid-cli fleet blocks                          # list fleet blocks
vespid-cli fleet blocks --ip 1.2.3.4             # filter by IP
vespid-cli fleet blocks --status active           # filter by status
vespid-cli fleet block 1.2.3.4 --reason botnet   # add fleet block
vespid-cli fleet block 1.2.3.4 --ttl 7200        # with custom TTL
vespid-cli fleet unblock 1.2.3.4                 # remove fleet block
vespid-cli fleet history 1.2.3.4                 # reporting history
vespid-cli fleet allowlist                       # show allow-list
vespid-cli fleet allow 10.0.0.0/8 --reason infra # add to allow-list
vespid-cli fleet deny 42                         # remove allow-list entry by ID
vespid-cli fleet config                          # show propagation config
vespid-cli fleet config-set corroboration_threshold 3
vespid-cli fleet pause                           # toggle propagation pause
```

### Intelligence

Query the IP intelligence database.

```bash
vespid-cli intel search 192.168.0                # search by prefix
vespid-cli intel search --tag scanner            # filter by threat tag
vespid-cli intel search --min-score 70           # high-threat only
vespid-cli intel ip 1.2.3.4                     # full threat profile
```

The `intel ip` command shows threat score, block/sighting counts, geo,
ASN, event type breakdown, and timeline.

### Nodes

View and manage enrolled nodes across the fleet.

```bash
vespid-cli nodes list                            # all nodes with health status
vespid-cli nodes show web-prod-01-abc123         # detailed node view
vespid-cli nodes command web-prod-01 sync_feeds  # send remote command
vespid-cli nodes command web-prod-01 unblock \
    --payload '{"ip": "1.2.3.4"}'                   # remote unblock
vespid-cli nodes assign-profile web-prod-01 3    # assign config profile
```

### Config management

Manage centralized configuration profiles, groups, and assignments.

```bash
# Profiles
vespid-cli config profiles list
vespid-cli config profiles show 3
vespid-cli config profiles create "production" --settings prod.yaml -d "Prod servers"
vespid-cli config profiles update 3 --settings updated.yaml
vespid-cli config profiles delete 3

# Groups
vespid-cli config groups list
vespid-cli config groups create "web-tier" -d "Web frontend servers"
vespid-cli config groups add-member 1 web-prod-01
vespid-cli config groups remove-member 1 web-prod-01
vespid-cli config groups delete 1

# Assignments
vespid-cli config assign create 3 --node web-prod-01
vespid-cli config assign create 3 --group 1
vespid-cli config assign delete 7
```

### Admin

User management, API keys, audit log, and enrollment.

```bash
# Users
vespid-cli admin users list
vespid-cli admin users create operator1 --role analyst

# API Keys
vespid-cli admin keys list
vespid-cli admin keys create "ci-pipeline" --role agent
vespid-cli admin keys revoke 5

# Audit Log
vespid-cli admin audit
vespid-cli admin audit --actor admin --action config_updated

# Enrollment
vespid-cli admin enrollment list
vespid-cli admin enrollment approve 12
vespid-cli admin enrollment reject 13
vespid-cli admin enrollment revoke 12
```

### Events

Search and export events from the central server.

```bash
vespid-cli events search --ip 1.2.3.4
vespid-cli events search --type SSH_BRUTE --action BLOCKED
vespid-cli events search --node web-prod-01
vespid-cli events export --format json --output events.json
vespid-cli events export --format csv --output report.csv --type SSH_BRUTE
```

## JSON output

Every command supports `--json` for machine-readable output:

```bash
vespid-cli status --json
vespid-cli fleet blocks --json | jq '.blocks[].source_ip'
vespid-cli intel ip 1.2.3.4 --json | jq '.record.threat_score'
vespid-cli nodes list --json | jq '.[] | select(.health == "offline")'
```

## Shell completion

Typer provides built-in shell completion:

```bash
# Bash
vespid-cli --install-completion bash

# Zsh
vespid-cli --install-completion zsh

# Fish
vespid-cli --install-completion fish
```

## Examples

### Incident response workflow

```bash
# 1. Check if an IP is already known
vespid-cli check 203.0.113.50
vespid-cli intel ip 203.0.113.50

# 2. Block it locally (immediate)
vespid-cli block 203.0.113.50 --reason "active attack"

# 3. Escalate to fleet-wide block
vespid-cli fleet block 203.0.113.50 --reason "coordinated attack" --ttl 86400

# 4. Verify propagation
vespid-cli fleet history 203.0.113.50
```

### Fleet health check

```bash
# Quick overview of all nodes
vespid-cli nodes list

# Check which nodes are offline
vespid-cli nodes list --json | jq '.[] | select(.health != "healthy") | .node_id'

# Inspect a specific node
vespid-cli nodes show web-prod-01-abc123
```

### Scripting / CI integration

```bash
#!/bin/bash
# Block a list of IPs fleet-wide
while read -r ip; do
    vespid-cli fleet block "$ip" --reason "threat-feed-import" --json
done < bad_ips.txt

# Export today's blocks for reporting
vespid-cli events search --action BLOCKED --json | jq '.events' > daily_blocks.json
```
