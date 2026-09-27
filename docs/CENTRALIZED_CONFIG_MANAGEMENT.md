# Centralized Configuration Management

## Overview

Vespid supports centralized configuration management where the server acts as the authoritative source for agent settings. This document explains how the system works, how settings are merged between server profiles and local agent state, and how existing features (Feeds, Detection Rules) interact with server-managed profiles.

## Key Concepts

### Management Modes

Each agent operates in one of two modes:

| Mode | Behavior |
|------|----------|
| `standalone` (default) | Agent loads all config from its local YAML file. No server communication for config. |
| `server-managed` | Agent connects to the server, receives a configuration profile, and merges it with local state. |

Set the mode in the agent's config file:

```yaml
management_mode: "server-managed"
config_conflict_strategy: "server-wins"  # or "local-wins" or "merge"
```

### Configuration Profiles

A profile is a named, versioned collection of settings stored on the server. Profiles only manage the keys they contain — everything else stays under local agent control.

**Example:** A profile with only `{"flush_interval_seconds": 30}` manages just that one setting. Detection rules, feeds, allowlist, and everything else remain local.

### Layered List Merging

For list-type settings that represent collections of named items (feeds, detection rules), the system uses **layered merging** rather than replacement:

- **Profile provides the baseline** (the "floor")
- **Local additions layer on top** (feeds/rules added via the dashboard or command queue)
- **Deduplication by name** — if both profile and local have an item with the same name, the profile version wins

This means the Security → Feeds page and Security → Detection Rules page continue to work normally for server-managed nodes. Items added through those pages persist as local additions that survive profile syncs.

---

## How Settings Are Merged

### Conflict Resolution Strategies

The `config_conflict_strategy` field determines how overlapping settings are resolved:

#### `server-wins` (default, recommended)

| Setting Type | Behavior |
|-------------|----------|
| Scalar values (integers, booleans) | Server value replaces local |
| `subscriptions` (feeds) | **Layered merge** — profile feeds + local-only feeds |
| `brute_force_rules` | **Layered merge** — profile rules + local-only rules |
| `custom_rules` | **Layered merge** — profile rules + local-only rules |
| `allowlist` | **Layered merge** — profile IPs + local-only IPs |
| `fleet_local_allow_list` | **Layered merge** — profile IPs + local-only IPs |
| `log_sources` | Server list replaces local entirely |

#### `local-wins`

Same as server-wins but for scalar values: if the local config has a non-default value, it takes precedence over the server. Layered list merging still applies for feeds and rules.

#### `merge`

Same layered behavior for feeds/rules. For scalars, server wins. For non-layered lists (allowlist, log_sources), server replaces local.

---

## Examples

### Example 1: Profile manages telemetry, admin adds a feed via dashboard

**Setup:**
- Profile "production-standard" contains:
  ```json
  {
    "flush_interval_seconds": 30,
    "heartbeat_interval_seconds": 120,
    "subscriptions": [
      {"name": "firehol_level1", "url": "https://iplists.firehol.org/files/firehol_level1.netset", "format": "cidr", "refresh_seconds": 21600, "enabled": true}
    ]
  }
  ```
- Admin goes to Security → Feeds and deploys "abuse_ch_feodo" to the node

**Result after next sync:**
```
Effective subscriptions = [
  firehol_level1  (from profile — baseline)
  abuse_ch_feodo  (from local — dashboard addition, survives sync)
]
flush_interval_seconds = 30  (from profile)
heartbeat_interval_seconds = 120  (from profile)
```

The locally-added feed persists because it has a unique name not present in the profile.

---

### Example 2: Profile and local both define the same rule (name conflict)

**Setup:**
- Profile contains:
  ```json
  {
    "brute_force_rules": [
      {"name": "ssh_fast_brute", "event_type": "SSH_BRUTE", "max_attempts": 5, "window_seconds": 60, "parser": "secure"}
    ]
  }
  ```
- Agent's local config (or runtime state from Detection Rules page) has:
  ```json
  {
    "brute_force_rules": [
      {"name": "ssh_fast_brute", "event_type": "SSH_BRUTE", "max_attempts": 10, "window_seconds": 60, "parser": "secure"},
      {"name": "my_custom_ssh", "event_type": "SSH_CUSTOM", "max_attempts": 3, "window_seconds": 300, "parser": "secure"}
    ]
  }
  ```

**Result after merge (server-wins):**
```
Effective brute_force_rules = [
  ssh_fast_brute   → max_attempts: 5  (PROFILE WINS — same name, profile takes precedence)
  my_custom_ssh    → max_attempts: 3  (LOCAL SURVIVES — unique name, not in profile)
]
```

---

### Example 3: Admin removes a feed from the profile

**Setup:**
- Profile previously had `[firehol_level1, spamhaus_drop]`
- Node also has locally-added `abuse_ch_feodo`
- Admin updates profile to only `[firehol_level1]` (removes spamhaus_drop)

**Result after sync:**
```
Effective subscriptions = [
  firehol_level1  (still in profile)
  abuse_ch_feodo  (local addition — survives)
]
spamhaus_drop is GONE — it was only in the profile, not locally added
```

---

### Example 4: Standalone node with no profile

**Setup:**
- Agent config has `management_mode: "standalone"` (or field is absent)
- No server communication for config

**Result:**
- All settings come from the local YAML config file
- Security → Feeds and Detection Rules work exactly as before
- No profile sync, no merging, no SSE connection for config

---

### Example 5: Server-managed node with partial profile (only fleet settings)

**Setup:**
- Profile "fleet-only" contains:
  ```json
  {
    "fleet_blocklist_report_enabled": true,
    "fleet_blocklist_subscribe_enabled": true,
    "fleet_block_ttl_seconds": 7200
  }
  ```
- Agent's local config has detection rules, feeds, allowlist, etc.

**Result:**
- Only the three fleet settings are managed by the server
- Detection rules, feeds, allowlist, telemetry, log_sources — all remain 100% local
- Security → Feeds and Detection Rules work normally with no interference

---

## How Existing Features Interact

### Security → Feeds (Subscription Management)

| Scenario | Behavior |
|----------|----------|
| Standalone node | Works exactly as before. No profile involvement. |
| Server-managed, profile has NO `subscriptions` key | Works exactly as before. Feeds are fully local. |
| Server-managed, profile HAS `subscriptions` | Feeds from profile are the baseline. Feeds added via dashboard layer on top. Both coexist. |
| Feed name conflict (same name in profile and local) | Profile version wins. Local version is ignored for that name. |
| Admin removes a feed via dashboard | Feed is removed from local runtime state. If it's also in the profile, it will reappear on next sync (profile is authoritative for its entries). |

> **Key point:** If you include feeds in a config profile, you do NOT need to also deploy them from the Feeds page. The profile delivers them to all assigned nodes automatically via the config sync channel. The Feeds page "Deploy" action is for ad-hoc pushes to nodes that aren't under profile management (or for adding extra feeds on top of what the profile provides).

**To permanently remove a profile-managed feed:** Edit the profile to remove it, not the node's local state.

### Security → Detection Rules

| Scenario | Behavior |
|----------|----------|
| Standalone node | Works exactly as before. |
| Server-managed, profile has NO rule keys | Works exactly as before. Rules are fully local. |
| Server-managed, profile HAS `brute_force_rules` or `custom_rules` | Profile rules are the baseline. Rules added via the Rules page layer on top. |
| Rule name conflict | Profile version wins (thresholds, parser, etc. from profile take precedence). |
| Admin modifies a rule via Rules page that exists in profile | Local modification is overwritten on next sync (profile is authoritative for its named rules). |

**To modify a profile-managed rule's thresholds:** Edit the profile, not the node's local rules.

### Allowlist and Log Sources

**Allowlist and fleet_local_allow_list** are now **layered** (same as feeds/rules):

| Key | Merge behavior |
|-----|---------------|
| `allowlist` | **Layered merge** — profile entries + local entries = union (deduplicated) |
| `fleet_local_allow_list` | **Layered merge** — profile entries + local entries = union (deduplicated) |
| `log_sources` | Server list replaces local entirely |

**Rationale:** Allowlist entries added via the Node screen (or local config) are additive — they represent IPs that the local admin knows are safe. The profile provides the baseline allowlist, and local additions layer on top. This means the Node allowlist screen works correctly even for server-managed nodes.

Only `log_sources` still replaces entirely, because log file paths are tightly coupled to the host's filesystem layout and partial merging could cause the agent to monitor non-existent files.

---

## Configuration Sync Flow

```
┌─────────────────────────────────────────────────────────────┐
│                        SERVER                                │
│                                                             │
│  Profile "production"                                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ subscriptions: [firehol_level1, spamhaus_drop]      │   │
│  │ brute_force_rules: [ssh_fast_brute, http_auth]      │   │
│  │ flush_interval_seconds: 30                          │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                   │
│                    SSE push / check-in                       │
└──────────────────────────┼──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                        AGENT                                 │
│                                                             │
│  Local config (YAML + runtime_feeds.json)                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ subscriptions: [firehol_level1, abuse_ch_feodo]     │   │
│  │ brute_force_rules: [ssh_fast_brute, my_custom]      │   │
│  │ flush_interval_seconds: 5                           │   │
│  │ allowlist: [127.0.0.1/32, 10.0.0.0/8]              │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                   │
│                  Conflict Resolution                         │
│                   (server-wins)                              │
│                          │                                   │
│                          ▼                                   │
│  Effective config (what the agent actually runs)            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ subscriptions: [firehol_level1*, spamhaus_drop*,    │   │
│  │                  abuse_ch_feodo†]                    │   │
│  │ brute_force_rules: [ssh_fast_brute*, http_auth*,    │   │
│  │                      my_custom†]                     │   │
│  │ flush_interval_seconds: 30*                         │   │
│  │ allowlist: [127.0.0.1/32, 10.0.0.0/8]†             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  * = from profile    † = from local (not in profile)        │
└─────────────────────────────────────────────────────────────┘
```

Note: `allowlist` stays local in this example because the profile doesn't include a `allowlist` key. If the profile DID include `allowlist`, it would replace the local one entirely.

---

## Detection Pack Filtering

Config profiles support per-node detection pack filtering, which controls which detection rule packs are distributed to nodes. This ensures nodes only receive rules relevant to the services they monitor.

### Important: Two Gates for Rule Delivery

A common point of confusion: per-node filtering does **not** replace the global enable/disable toggle on the Security → Detection Rules page. A rule must pass **two independent gates** to reach a node:

| Gate | Where | What It Controls |
|------|-------|-----------------|
| **1. Global Enable** | Security → Detection Rules page | Whether the rule exists in the distribution pool at all |
| **2. Node Relevance** | Per-node filtering (automatic) | Whether the rule is relevant to a specific node's log sources |

**If a pack shows "0/10 ACTIVE" on the Security → Detection Rules page**, none of its rules will be distributed to any node — even if the node's parsers match. You must enable the rules first.

**If a pack shows "14/14 ACTIVE" but a node doesn't monitor that service**, the rules are enabled globally but won't be sent to that particular node (filtered out by parser mismatch).

```
Security → Detection Rules: Pack enabled?
     │
    YES → Per-node filter: Node monitors this service?
              │
             YES → Rule delivered to node
             NO  → Rule NOT delivered (irrelevant)
     │
    NO → Rule NOT delivered to anyone
```

### New Profile Settings Fields

Two optional fields can be added to a profile's `settings` JSON:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `detection_pack_mode` | string | `"auto"` | Controls how packs are selected for the node. Either `"auto"` or `"explicit"`. |
| `detection_packs` | list of strings | `[]` | List of pack names to assign. Only used when mode is `"explicit"`. |

**Example profile settings with detection pack fields:**

```json
{
  "log_sources": [
    {"path": "/var/log/apache2/access.log", "parser": "apache"},
    {"path": "/var/log/auth.log", "parser": "secure"}
  ],
  "subscriptions": [...],
  "allowlist": [...],
  "detection_pack_mode": "auto",
  "detection_packs": ["apache-attacks", "postfix-attacks"],
  "fleet_blocklist_report_enabled": true
}
```

### Pack Mode: `auto` (default)

When `detection_pack_mode` is `"auto"` (or omitted), the server determines which packs to distribute based on log_sources overlap:

- For **managed nodes**: the profile's `log_sources` parsers are matched against each pack's rule log_sources. Only packs with overlapping parsers are distributed.
- For **standalone nodes**: the node's heartbeat-reported `active_parsers` are used for matching.

In auto mode, the `detection_packs` field is ignored.

**Example:** A node with `log_sources` containing parsers `["secure", "apache"]` automatically receives the `openssh-attacks` and `apache-attacks` packs, but not `postfix-attacks`.

### Pack Mode: `explicit`

When `detection_pack_mode` is `"explicit"`, only the packs listed in `detection_packs` are distributed to the node. No automatic matching occurs.

- If `detection_packs` is empty (`[]`), the node receives only non-pack rules (user-created brute force rules matching its active parsers and custom rules).
- Explicit assignment takes precedence over any auto-detection logic.

**Example:** A profile with `"detection_pack_mode": "explicit"` and `"detection_packs": ["apache-attacks"]` ensures the node receives only the `apache-attacks` pack rules, even if the node also monitors SSH logs.

### Resolution Priority

When the distribution endpoint determines which packs to send to a node, it follows this priority chain:

1. **Explicit profile assignment** — if the node's profile has `detection_pack_mode: "explicit"`, only listed packs are sent.
2. **Auto from profile log_sources** — if the managed node's profile has `detection_pack_mode: "auto"`, packs are matched from the profile's configured log_sources parsers.
3. **Auto from heartbeat active_parsers** — for standalone nodes (or managed nodes without log_sources in their profile), packs are matched from the node's heartbeat-reported active_parsers.
4. **No filtering (backward compat)** — if no active_parsers information is available (legacy node, never heartbeated), all enabled rules are sent.

### Backward Compatibility

- Both fields are **optional**. Existing profiles without these fields continue to work exactly as before.
- The default behavior (`detection_pack_mode: "auto"`) means existing managed nodes automatically benefit from filtering once they report active_parsers — no profile changes required.
- Nodes that have never reported `active_parsers` (pre-upgrade agents) continue to receive all rules.

---

## FAQ

**Q: If I add a feed via the Feeds page to a server-managed node, will it disappear on the next sync?**

A: No. It persists as a local addition. The layered merge keeps it alongside profile feeds.

**Q: What if I want to REMOVE a feed that the profile provides?**

A: You can't remove it from the node side — the profile is authoritative for its entries. Edit the profile to remove the feed.

**Q: Can I have some nodes with extra feeds and others without?**

A: Yes. Deploy extra feeds to specific nodes via the Feeds page. They layer on top of whatever the profile provides. Or create different profiles for different groups.

**Q: What happens if the server goes down?**

A: The agent keeps running with its last-known config (cached locally). When the server comes back, it reconnects via SSE and picks up any missed updates.

**Q: Does the agent need to restart when a profile changes?**

A: No. Config updates are applied via hot-reload (no restart needed). Detection rules, feeds, allowlist, and all other settings take effect within seconds.

**Q: What's the difference between "server-managed" and "standalone" for an agent that has a SERVER_URL configured?**

A: `standalone` means the agent connects to the server for event upload, fleet blocklist, and rule sync — but NOT for centralized config management. `server-managed` adds the config profile sync on top of everything else.

**Q: The node detail page shows a pack with "0 RULES" even though the node's parsers match. Why?**

A: Per-node filtering and global rule enablement are two separate things. The node detail page shows which packs are *relevant* to the node (parser match), but if the pack's rules are disabled on the Security → Detection Rules page (e.g., "0/10 ACTIVE"), there are no rules to deliver. Go to Security → Detection Rules and click "Enable All" on the pack to activate its rules. Once enabled, they'll be distributed to matching nodes on the next poll cycle.

**Q: Do I need to set `detection_pack_mode` in a profile for filtering to work?**

A: No. Filtering works automatically in `auto` mode (the default) as soon as a node reports `active_parsers` in its heartbeat. You only need to set `detection_pack_mode: "explicit"` if you want to override the automatic matching and manually control which packs a node receives.

**Q: A node shows all 4 packs on its detail page but I only want it to receive Apache rules. How?**

A: Two options:
1. **Auto mode** — adjust the node's `log_sources` so it only monitors Apache logs. The node will only report `["apache"]` as active parsers, and only the Apache pack will match.
2. **Explicit mode** — assign a config profile with `"detection_pack_mode": "explicit"` and `"detection_packs": ["apache-attacks"]`. This overrides auto-detection and sends only the listed packs.

**Q: What happens when a node first connects and hasn't sent a heartbeat yet?**

A: The node has no `active_parsers` data, so the server returns all enabled rules (backward-compatible behavior). Once the node sends its first heartbeat with `active_parsers`, filtering kicks in on the next rule poll.
