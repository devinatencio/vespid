# Allowlist Convergence Model

## Overview

Vespid has multiple allowlists that serve different purposes at different layers. When an IP is allowlisted via the **IP Rules Management** page on the server dashboard, the system uses three convergence paths to ensure all nodes stop blocking that IP — even if one path fails.

## Allowlists and What They Gate

| Allowlist | Location | What It Prevents |
|-----------|----------|-----------------|
| **Node allowlist** (`config.allowlist`) | Agent config + runtime additions | Local detection from blocking the IP (`block_local()` refuses) |
| **Fleet local allow-list** (`config.fleet_local_allow_list`) | Agent config | Fleet subscriber from applying fleet block directives for the IP |
| **Fleet allowlist** (`fleet_allowlist` table) | Server database | Server from propagating new fleet blocks for the IP to other nodes |

The **node allowlist** is the authoritative local gate. If an IP is in the node allowlist, it cannot be blocked locally regardless of source (local detection, fleet directive, blocklist, or manual command).

## Convergence Paths

When you add an IP to the allowlist via IP Rules Management, three independent paths work to deliver that change to nodes:

```
IP Rules Management (allowlist add)
│
├─ Path 1: Command Queue (instant, best-effort)
│   └─ "allowlist_add" command queued for target node(s)
│   └─ Node polls on next heartbeat → executes allowlist_add
│   └─ NFTablesManager adds to runtime allowlist + auto-unblocks
│
├─ Path 2: Config Profile Sync (durable, seconds to minutes)
│   └─ Entry added to all active config profiles
│   └─ SSE push sent to connected nodes immediately
│   └─ Config subscriber applies allowlist diff
│   └─ _reconcile_allowlist_blocks() unblocks matching IPs
│
└─ Path 3: Fleet Allowlist (prevents future propagation)
    └─ Entry added to server-side fleet_allowlist table
    └─ Future block reports for this IP are rejected
    └─ Does NOT send unblock to nodes (only prevents new blocks)
```

### Path 1: Command Queue (Fast Path)

- **Delivery:** Node polls for commands after each heartbeat (default 60s interval)
- **Durability:** Commands persist in the database until delivered, but if the node is deleted or re-registers with a new ID, queued commands are orphaned
- **Effect:** Immediate `allowlist_add` on the node — adds to runtime allowlist, auto-unblocks any matching blocked IPs
- **Failure mode:** Node offline, node deleted before delivery, node re-enrolled with different ID

### Path 2: Config Profile Sync (Durable Path)

- **Delivery:** SSE push to connected nodes (sub-second), or check-in on reconnect (5-minute fallback interval)
- **Durability:** Profile is the persistent record — survives node restarts, re-enrollments, and server restarts
- **Effect:** Config subscriber diffs the allowlist, updates `nft_manager._allowlist`, then calls `_reconcile_allowlist_blocks()` to unblock any currently-blocked IPs that now match
- **Failure mode:** Node in standalone mode (no config sync), SSE connection down AND heartbeat failing

### Path 3: Fleet Allowlist (Defensive)

- **Delivery:** Immediate (server-side only)
- **Durability:** Database record
- **Effect:** Prevents the server from propagating future fleet blocks for this IP. Does NOT retroactively unblock on nodes.
- **Failure mode:** None for its intended purpose. But it does not help nodes that already have the IP blocked locally.

## Fleet Subscriber Behavior

The fleet subscriber checks two things before applying a fleet block directive:

1. **`nft.is_allowlisted(ip)`** — checks the node's main runtime allowlist (includes config file entries, runtime additions from CLI/commands, and config profile sync)
2. **`config.fleet_local_allow_list`** — a separate fleet-specific allow list (refreshed dynamically when config profile updates change it)

If either check returns true, the fleet block is rejected locally with a log message.

This means:
- Once a `allowlist_add` command lands (path 1), the fleet subscriber immediately respects it
- Once a config profile update arrives (path 2), the fleet subscriber immediately respects it
- No daemon restart is required for either path

## Timeline Expectations

| Scenario | Expected convergence time |
|----------|--------------------------|
| Node online, SSE connected | < 5 seconds (SSE push + command poll) |
| Node online, SSE disconnected | < 60 seconds (next heartbeat polls commands) |
| Node offline, comes back | < 5 minutes (config check-in on reconnect) |
| Node deleted and re-enrolled | Next config profile assignment (manual) |

## Troubleshooting: "Why Is This IP Still Blocked?"

1. **Check the node's allowlist:** `vespid-cli allowlist list` — is the IP present?
2. **Check pending commands:** Server dashboard → node detail → recent commands. Was `allowlist_add` delivered?
3. **Check config profile:** Does the node's assigned profile include the IP in its `allowlist` setting?
4. **Check management mode:** Is the node in `server-managed` mode? Standalone nodes don't receive config profile updates.
5. **Check fleet subscriber logs:** Look for "rejected by local allow-list" messages. If absent, the fleet subscriber is still applying blocks for this IP.

If the IP is in the server's IP Rules but not on the node:
- The command was likely never delivered (node was offline/deleted)
- The config profile sync hasn't reached the node yet
- Fix: manually run `vespid-cli allowlist add <IP>` on the node, or ensure the node has a config profile assigned and is in `server-managed` mode

## CLI reference

```bash
# Local allowlist management (immediate, no server needed)
sudo vespid-cli allowlist-add 10.0.0.0/8
sudo vespid-cli allowlist-remove 10.0.0.0/8
sudo vespid-cli allowlist-list

# Fleet allowlist management (requires server connection)
vespid-cli fleet allowlist
vespid-cli fleet allow 10.0.0.0/8 --reason "internal network"
vespid-cli fleet deny 42   # remove by entry ID
```

## Interaction with other features

### Detection rules

When an IP is allowlisted, the agent's `block_local()` method refuses
to create a block, regardless of how many detection rules fire.  The
detection event is still logged and shipped to the server for visibility,
but no nftables rule is created.

### Subscription feeds

IPs from external subscription feeds are checked against the allowlist
before being added to `shield_subscribed`.  Allowlisted IPs are silently
skipped during feed sync.

### Fleet blocks

Fleet block directives are checked against both the node allowlist and
the `fleet_local_allow_list` before application.  See the
[Fleet Blocklist](server/fleet.md) documentation for details.

## Design rationale

The three-path convergence model ensures reliability through redundancy:

- **Path 1** (command queue) is fast but best-effort
- **Path 2** (config profile) is durable but requires server-managed mode
- **Path 3** (fleet allowlist) is server-side only but prevents future damage

No single failure can prevent allowlist convergence as long as at least
one path succeeds.
