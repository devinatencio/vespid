# vespid-cli

Command-line interface for Vespid — manage your local agent, query the central server, and operate your entire fleet from the terminal.

## Installation

The CLI is included in the `vespid` package. After installing via `.deb` or pip:

```bash
vespid-cli --help
```

### Dependencies

- **Local commands**: No extra dependencies (uses UNIX socket to the local daemon)
- **Server commands**: Requires `httpx` (`pip install httpx`)

## Quick Start

### Local Agent Management

These commands talk directly to the local Vespid daemon. No server connection needed.

```bash
# Check daemon status
vespid-cli status

# Block/unblock an IP locally
vespid-cli block 1.2.3.4 --reason "manual investigation"
vespid-cli unblock 1.2.3.4

# Check if an IP is blocked and why
vespid-cli check 1.2.3.4

# View local blocklist
vespid-cli list-local

# Watch live traffic counters
vespid-cli counters --watch 5

# Tail logs in real time
vespid-cli tail-log -f
vespid-cli tail-log --decisions -f
```

### Connecting to the Server

To use fleet, intel, nodes, config, and admin commands, connect to your Vespid server:

```bash
vespid-cli server login --url https://vespid.example.com --key hg_your_api_key
vespid-cli server status
```

Credentials are stored in `~/.config/vespid/cli.yaml` (mode 0600).

You can also use environment variables:

```bash
export VESPID_SERVER_URL=https://vespid.example.com
export VESPID_API_KEY=hg_your_api_key
```

## Command Reference

### Local Commands

| Command | Description |
|---------|-------------|
| `status` | Daemon overview — node ID, nft state, feeds, fleet, 24h activity |
| `counters` | nftables packet/byte counters per set (supports `--watch`) |
| `block <ip>` | Block an IP in shield_local |
| `unblock <ip>` | Remove an IP from shield_local |
| `check <ip>` | Look up whether an IP is blocked and why |
| `recidive <ip>` | Show repeat-offender history and next TTL |
| `recent` | Recent block/unblock decisions |
| `list-local` | All entries in shield_local with TTL and strike count |
| `list-subscribed` | Entries in shield_subscribed (feed-sourced) |
| `sync-feeds` | Force an immediate feed sync |
| `allowlist-add <ip>` | Add to runtime allowlist (auto-unblocks if blocked) |
| `allowlist-remove <ip>` | Remove from runtime allowlist |
| `allowlist-list` | Show all allowlisted entries with source |
| `tail-log` | Tail the human-readable log (`-f` to follow, `--decisions` for audit) |
| `spool` | Inspect the event spool (`--tail N`, `--purge`) |

### Server: Fleet Management

Manage the fleet-wide blocklist and propagation settings.

```bash
vespid-cli fleet blocks                          # List fleet blocks
vespid-cli fleet blocks --ip 1.2.3.4             # Filter by IP
vespid-cli fleet blocks --status active           # Filter by status
vespid-cli fleet block 1.2.3.4 --reason botnet   # Add fleet block
vespid-cli fleet block 1.2.3.4 --ttl 7200        # With custom TTL
vespid-cli fleet unblock 1.2.3.4                 # Remove fleet block
vespid-cli fleet history 1.2.3.4                 # Reporting history
vespid-cli fleet allowlist                       # Show allow-list
vespid-cli fleet allow 10.0.0.0/8 --reason infra # Add to allow-list
vespid-cli fleet deny 42                         # Remove allow-list entry by ID
vespid-cli fleet config                          # Show propagation config
vespid-cli fleet config-set corroboration_threshold 3
vespid-cli fleet pause                           # Toggle propagation pause
```

### Server: Intelligence

Query the IP intelligence database.

```bash
vespid-cli intel search 192.168.0                # Search by prefix
vespid-cli intel search --tag scanner            # Filter by threat tag
vespid-cli intel search --min-score 70           # High-threat only
vespid-cli intel ip 1.2.3.4                     # Full threat profile
```

The `intel ip` command shows threat score, block/sighting counts, geo, ASN, event type breakdown, and timeline.

### Server: Nodes

View and manage enrolled nodes across your fleet.

```bash
vespid-cli nodes list                            # All nodes with health status
vespid-cli nodes show web-prod-01-abc123         # Detailed node view
vespid-cli nodes command web-prod-01 sync_feeds  # Send remote command
vespid-cli nodes command web-prod-01 unblock \
    --payload '{"ip": "1.2.3.4"}'                   # Remote unblock
vespid-cli nodes assign-profile web-prod-01 3    # Assign config profile
```

### Server: Config Management

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

### Server: Admin

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

### Server: Events

Search and export events from the central server.

```bash
vespid-cli events search --ip 1.2.3.4
vespid-cli events search --type SSH_BRUTE --action BLOCKED
vespid-cli events search --node web-prod-01
vespid-cli events export --format json --output events.json
vespid-cli events export --format csv --output report.csv --type SSH_BRUTE
```

## JSON Output

Every command supports `--json` for machine-readable output:

```bash
vespid-cli status --json
vespid-cli fleet blocks --json | jq '.blocks[].source_ip'
vespid-cli intel ip 1.2.3.4 --json | jq '.record.threat_score'
vespid-cli nodes list --json | jq '.[] | select(.health == "offline")'
```

## Credential Resolution

The CLI resolves server credentials in this order (first match wins):

1. **Environment variables**: `VESPID_SERVER_URL`, `VESPID_API_KEY`
2. **CLI config file**: `~/.config/vespid/cli.yaml`
3. **Agent config**: `/etc/vespid/vespid.yaml` (`SERVER_URL` + `API_KEY`)

Use `vespid-cli server status` to see which source is active.

## Shell Completion

Typer provides built-in shell completion:

```bash
# Bash
vespid-cli --install-completion bash

# Zsh
vespid-cli --install-completion zsh

# Fish
vespid-cli --install-completion fish
```

## Project Structure

```
vespid/cli/
├── __init__.py     # Package init, exports app and main
├── app.py          # Main Typer app + local daemon commands
├── fleet.py        # vespid-cli fleet ...
├── intel.py        # vespid-cli intel ...
├── nodes.py        # vespid-cli nodes ...
├── config.py       # vespid-cli config ...
├── admin.py        # vespid-cli admin ...
├── server.py       # vespid-cli server ... (login/logout/status)
└── events.py       # vespid-cli events ...

vespid/
├── cli.py              # Backward-compat shim (re-exports from cli/)
└── server_client.py    # HTTP client for the server REST API
```

## Examples

### Incident Response Workflow

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

### Fleet Health Check

```bash
# Quick overview of all nodes
vespid-cli nodes list

# Check which nodes are offline
vespid-cli nodes list --json | jq '.[] | select(.health != "healthy") | .node_id'

# Inspect a specific node
vespid-cli nodes show web-prod-01-abc123
```

### Scripting / CI Integration

```bash
#!/bin/bash
# Block a list of IPs fleet-wide
while read -r ip; do
    vespid-cli fleet block "$ip" --reason "threat-feed-import" --json
done < bad_ips.txt

# Export today's blocks for reporting
vespid-cli events search --action BLOCKED --json | jq '.events' > daily_blocks.json
```
