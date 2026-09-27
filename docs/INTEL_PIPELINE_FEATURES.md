# Intelligence Pipeline

The Vespid Intelligence Pipeline collects, scores, and visualizes IP threat
data from across the fleet.  It provides a centralized reputation database,
multi-vector attack detection, and a searchable dashboard for security
analysts.

---

## Overview

When agents detect and block threats, those events are ingested into the
server's intelligence database.  Each IP accumulates a threat profile
including block history, sighting counts, geographic data, ASN information,
and a computed reputation score.

---

## 1. Fleet Block Visibility

**What it does:** When a node applies a preemptive block via fleet sync (because another node flagged the IP), that event is now stored for operational visibility without inflating threat counters.

**How it works:**
- The DataBus ships fleet-originated events (metadata.reason starts with "fleet:") to the server with `event_kind="fleet_block"`
- These events are stored in `ip_intel_events` but do NOT increment `total_times_seen`, `total_times_blocked`, or modify `reporting_node_list`
- The IP Detail page shows a "Fleet Blocks" section listing which nodes applied preemptive blocks and when

**Key behavior:**
- Fleet blocks are visually distinct (orange/warning badge) from active blocks (red) and sightings (blue)
- `total_times_seen` only counts block + sighting events, never fleet_block events
- `reporting_node_list` only contains nodes that independently detected the threat

---

## 2. Multi-Vector Attack Detection & Scoring

**What it does:** Identifies IPs that trigger multiple distinct detection rules (e.g., SSH brute force AND HTTP probing AND port scanning) and amplifies their threat score.

**How it works:**
- Each event's `detection_rule` (or `metadata.threat_tag`) is accumulated into the IP's `threat_tags` array (deduplicated)
- The "Attack Vectors" section on the IP Detail page shows each distinct rule and how many times it fired
- A "Multi-Vector" badge appears when an IP has 3+ distinct threat tags

**Scoring bonus:**
- 3 tags → 1.1x multiplier on the threat score
- 4 tags → 1.2x
- 5 tags → 1.3x
- 7+ tags → 1.5x (cap)

**Tag diversity signal:** `min(distinct_tags / 5, 1.0)` — contributes 10% weight to the overall score.

---

## 3. Block Lifecycle Tracking

**What it does:** Tracks when IPs are blocked, unblocked, and re-blocked to identify repeat offenders — IPs that keep coming back after being released.

**New columns on `ip_intel`:**
| Column | Purpose |
|--------|---------|
| `last_unblocked_at` | Timestamp of most recent unblock event |
| `block_episode_count` | Number of distinct block→unblock→block cycles |
| `repeat_offender_since` | When the IP was first classified as a repeat offender |

**Key behavior:**
- UNBLOCKED events update `last_unblocked_at` without incrementing any counters
- A new "block episode" starts when a block event arrives after an unblock
- `repeat_offender = TRUE` when `block_episode_count >= 2` (blocked, released, blocked again)
- High `total_times_blocked` from a single continuous episode does NOT trigger repeat offender
- `total_times_blocked` also feeds the fleet recidive system: the Propagation Engine reads this counter to escalate fleet block TTL for repeat offenders (see [Server Guide](server/guide.md#fleet-block-recidive))

**UI additions:**
- "Block Status" indicator: Active (green) or Inactive (gray) based on last_blocked_at vs last_unblocked_at
- "Block Episodes" counter in Key Metrics
- "Repeat Offender" badge on IPs with 2+ episodes

---

## 4. Raw Request Volume Tracking

**What it does:** Tracks the actual number of malicious requests (e.g., 15 failed SSH logins) rather than just counting detection events. This distinguishes a noisy attacker from a one-shot scanner.

**New columns:**
| Table | Column | Purpose |
|-------|--------|---------|
| `ip_intel` | `total_requests` | Sum of all request_count values across ingested events |
| `ip_intel_events` | `request_count` | Per-event raw request count (default 1) |

**How it works:**
- Agents attach `metadata.request_count` to events (e.g., "15 failed SSH logins triggered this block")
- If not provided, defaults to 1
- Fleet_block events do NOT contribute to `total_requests`
- The `volume` scoring signal now uses `total_requests` instead of `total_times_seen`

**UI additions:**
- "Total Requests" stat in Key Metrics (alongside "Total Events")
- "Requests" column in event history table
- Sortable "Requests" column in search results

---

## 5. Timestamp Validation

**What it does:** Prevents future-dated events from corrupting the timeline while accepting delayed past events.

**Rules:**
- Events with timestamps more than 5 minutes in the future are rejected
- Past timestamps (any age) are accepted — delayed events are normal
- `server_received_at` is recorded for audit purposes (detecting clock skew)
- Recency windows (24h/7d/30d) use the agent-provided timestamp, not server time

**New column:** `ip_intel_events.server_received_at` — server UTC time when the event was received.

---

## 6. Dual-Database Support (SQLite + MySQL/MariaDB)

**What it does:** The upsert logic now uses database-appropriate atomic operations for both backends.

**SQLite:** `INSERT OR IGNORE` + separate `UPDATE`
**MySQL/MariaDB:** `INSERT ... ON DUPLICATE KEY UPDATE` for true atomicity

**Concurrency protection:**
- MySQL connections use `READ COMMITTED` isolation level
- The `reporting_node_list` read-modify-write is wrapped in an explicit transaction
- Schema migrations run automatically on startup (ALTER TABLE ADD COLUMN for missing columns)

---

## 7. Reputation Score Formula

The threat score (0.0–100.0) is computed from 6 weighted signals:

| Signal | Weight | Computation |
|--------|--------|-------------|
| Block Ratio | 30% | `total_times_blocked / total_times_seen` |
| Fleet Breadth | 20% | `total_reporting_nodes / 10` (capped at 1.0) |
| Volume | 15% | `log(1 + total_requests) / log(1001)` |
| Recency | 15% | Weighted sum of 24h/7d/30d activity |
| Tag Diversity | 10% | `distinct_tags / 5` (capped at 1.0) |
| Repeat Offender | 10% | 1.0 if repeat_offender, else 0.0 |

After the weighted sum, the multi-vector bonus multiplier is applied (1.0x–1.5x), then the result is clamped to [0.0, 100.0] and rounded to 1 decimal place.

---

## 8. Search Results Enhancements

New columns and indicators in the IP search results:

- **Block Status:** Active/Inactive indicator based on block lifecycle
- **Multi-Vector badge:** Shown for IPs with 3+ distinct threat tags
- **Block Episodes:** Sortable column showing distinct blocking episodes
- **Total Requests:** Sortable column showing raw request volume
- **Reputation Score:** Sortable column with color-coded display
- **Primary Threat:** Most frequently fired detection rule for each IP

---

## Database Schema Reference

### ip_intel (summary record per IP)

```sql
-- New columns added by this upgrade:
total_requests        INT NOT NULL DEFAULT 0
last_unblocked_at     VARCHAR(255) DEFAULT NULL
block_episode_count   INT NOT NULL DEFAULT 0
repeat_offender_since VARCHAR(255) DEFAULT NULL
```

### ip_intel_events (event history)

```sql
-- New columns added by this upgrade:
request_count      INT NOT NULL DEFAULT 1
server_received_at VARCHAR(255) NOT NULL DEFAULT ''
```

### Automatic Migration

On server startup, `init_intel_db()` automatically runs ALTER TABLE statements to add any missing columns. This is idempotent — safe to run on both fresh and existing databases.

---

## Event Routing Summary

| action_taken | event_type | Routing |
|-------------|-----------|---------|
| BLOCKED | NFT_ACTION | → `process_block_event()` (increments counters) |
| BLOCKED | Other | Skipped (only NFT_ACTION is authoritative) |
| OBSERVED | Any | → `process_sighting()` (increments total_times_seen only) |
| DETECTED | Any | Skipped entirely from intel |
| UNBLOCKED | Any | → `process_unblock_event()` (updates last_unblocked_at only) |
| Any (event_kind="fleet_block") | Any | → `process_fleet_block_event()` (stored for visibility, no counter changes) |

---

## Intelligence dashboard

The web dashboard (**Intelligence → IP Search**) provides:

- **IP search** — search by IP prefix, filter by threat tag, minimum score,
  or repeat offender status
- **Threat profiles** — detailed view per IP with block history, sighting
  timeline, geographic data, ASN, attack vectors, and score breakdown
- **Analytics** — fleet-wide threat metrics, top attackers, geographic
  distribution, and trend charts
- **Block status indicators** — active (green) or inactive (gray) based on
  block lifecycle
- **Multi-vector badges** — visual indicator for IPs triggering 3+ distinct
  detection rules
- **Sortable columns** — sort by threat score, total blocks, requests, or
  block episodes

### IP detail page

The detail page for a single IP shows:

| Section | Contents |
|---------|----------|
| Key Metrics | Threat score, total events, total requests, block episodes, reporting nodes |
| Block Status | Active/inactive, last blocked, last unblocked |
| Attack Vectors | Distinct detection rules with hit counts |
| Score Breakdown | Weight and value for each of the 6 scoring signals |
| Event Timeline | Chronological list of all block, sighting, and fleet_block events |
| Fleet Blocks | Which nodes applied preemptive blocks via fleet sync |
| Geographic Data | Country, ASN, ISP |

## CLI commands

```bash
# Search by IP prefix
vespid-cli intel search 192.168.0

# Filter by threat tag
vespid-cli intel search --tag scanner

# High-threat IPs only
vespid-cli intel search --min-score 70

# Full threat profile
vespid-cli intel ip 1.2.3.4

# JSON output for scripting
vespid-cli intel ip 1.2.3.4 --json | jq '.record.threat_score'
```

## API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/intel/sightings` | Bearer | Submit a sighting event |
| POST | `/api/v1/intel/blocks` | Bearer | Submit a block event |
| POST | `/api/v1/intel/batch` | Bearer | Submit up to 500 events |
| GET | `/api/v1/intel/ips` | Session/Bearer | Search IP records |
| GET | `/api/v1/intel/ips/<ip>` | Session/Bearer | Full threat profile |
| GET | `/api/v1/intel/blocklist` | Session/Bearer | Export IP blocklist |

See the [Server API Reference](server/api.md#intelligence-api) for request/response
details.
