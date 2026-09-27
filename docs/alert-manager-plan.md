# Alert Manager — Implementation Plan

## Overview

Unified alert system that evaluates both **PromQL metric queries** and **Nagios-style health check results**, with per-user personal rules and global rules manageable via CLI/YAML. Includes notification delivery, maintenance windows, flap protection, and safe multi-worker execution.

**Designed for future inventory integration** — the schema and eval loop use freeform labels for runtime identity, with optional nullable columns for canonical entity references. This lets the alert system ship now and link to inventory later without breaking changes.

---

## Phase 1 — Database Schema

### `alert_rules` table (migration 17)

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | auto |
| `user_id` | INTEGER? | NULL = global rule, else personal rule |
| `name` | TEXT | required |
| `query` | TEXT? | PromQL — NULL if using check_name |
| `check_name` | TEXT? | NULL if using PromQL — matches check_results.name |
| `operator` | TEXT | `>`, `<`, `==`, `>=`, `<=` |
| `threshold` | REAL | for PromQL: value threshold; for checks: exit_code threshold |
| `resolve_threshold` | REAL? | optional separate threshold for resolving (hysteresis) |
| `severity` | TEXT | `warning` / `critical` |
| `for_duration` | INTEGER | seconds must persist before firing (optional debounce) |
| `cooldown_secs` | INTEGER? | minimum seconds after resolve before rule can re-fire (flap protection) |
| `interval_secs` | INTEGER | evaluate interval (default 60) |
| `tags` | TEXT? | JSON — e.g. `{"team": "ops", "service": "api", "env": "prod"}`. Unused now; reserved for future inventory-driven routing and policy-based rules. |
| `enabled` | BOOLEAN | default true |
| `created_at` | TEXT | ISO 8601 |
| `updated_at` | TEXT | ISO 8601 |

### `alert_events` table (migration 17)

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | auto |
| `rule_id` | INTEGER FK | → alert_rules.id |
| `entity_id` | INTEGER? | **Nullable FK to future `inventory_entities` table.** For now always NULL. Later, the eval loop resolves runtime labels (e.g. `agent_id`) to canonical inventory IDs and stores them here. This enables "show all alerts for this host" in the inventory UI without parsing JSON. |
| `labels` | TEXT | JSON — series labels (PromQL) or `{agent_id, hostname}` (checks). **This is the runtime identity.** Kept freeform so the system doesn't hardcode `agent_id` / `hostname` as first-class columns. |
| `value` | REAL | the value / exit_code that triggered |
| `state` | TEXT | `firing` / `resolved` / `acknowledged` |
| `fired_at` | TEXT | ISO 8601 |
| `resolved_at` | TEXT? | nullable |
| `acknowledged_by` | INTEGER? | user_id |
| `notified_at` | TEXT? | ISO 8601 — when notification was dispatched |

### `notification_channels` table (migration 17)

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | auto |
| `name` | TEXT | human-readable label (e.g. "Ops Slack") |
| `type` | TEXT | `email` / `slack` / `webhook` / `pagerduty` |
| `config` | TEXT | JSON — type-specific config (see below) |
| `enabled` | BOOLEAN | default true |
| `created_at` | TEXT | ISO 8601 |
| `updated_at` | TEXT | ISO 8601 |

**Config JSON by type:**

- `email`: `{"recipients": ["ops@example.com"], "subject_prefix": "[Vespid]"}`
- `slack`: `{"webhook_url": "https://hooks.slack.com/...", "channel": "#alerts"}`
- `webhook`: `{"url": "https://...", "method": "POST", "headers": {"X-Token": "..."}}`
- `pagerduty`: `{"routing_key": "...", "severity_map": {"critical": "critical", "warning": "warning"}}`

### `rule_notification_channels` table (migration 17)

| Column | Type | Notes |
|---|---|---|
| `rule_id` | INTEGER FK | → alert_rules.id |
| `channel_id` | INTEGER FK | → notification_channels.id |

Composite PK on (rule_id, channel_id). If a rule has no channel associations, it uses all enabled channels as the default (configurable via app config `ALERT_DEFAULT_NOTIFY_ALL=true`).

### `alert_silences` table (migration 17)

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | auto |
| `matchers` | TEXT | JSON — label matchers to silence (see below) |
| `rule_id` | INTEGER? | NULL = match all rules, else specific rule only |
| `starts_at` | TEXT | ISO 8601 |
| `ends_at` | TEXT | ISO 8601 |
| `reason` | TEXT | required — why this silence exists |
| `created_by` | INTEGER FK | → users.id |
| `created_at` | TEXT | ISO 8601 |

**Matchers JSON format:**

```json
[
  {"label": "hostname", "op": "=", "value": "web-1"},
  {"label": "agent_id", "op": "=~", "value": "prod-.*"}
]
```

A silence matches an event if ALL matchers match the event's labels. Supported ops: `=`, `!=`, `=~` (regex), `!~`.

### `alert_eval_lock` table (migration 17)

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | always 1 (singleton row) |
| `locked_by` | TEXT | worker identifier (hostname:pid) |
| `locked_at` | TEXT | ISO 8601 |
| `expires_at` | TEXT | ISO 8601 — auto-expire if worker dies |
| `last_eval_at` | TEXT? | ISO 8601 — heartbeat for meta-monitoring |

### Indexes

- idx_alert_events_state ON alert_events(state)
- idx_alert_events_rule ON alert_events(rule_id)
- idx_alert_events_entity ON alert_events(entity_id)  -- reserved for future inventory
- idx_alert_rules_enabled ON alert_rules(enabled)
- idx_alert_silences_active ON alert_silences(starts_at, ends_at)
- idx_notification_channels_enabled ON notification_channels(enabled)

### MySQL schema

Add all tables to `schema_mysql.sql` alongside existing tables.

---

## Phase 2 — Model Helpers

All in `app/models.py`:

### Rules & Events (existing)

```
get_alert_rules(enabled=None, user_id=None)
  → list, admins see all, users see personal + global

get_alert_rule(id)            → single rule dict

create_alert_rule(db, user_id, name, query=None, check_name=None, ...)
  → insert, return dict

update_alert_rule(db, id, **fields)
  → update, return dict

delete_alert_rule(db, id)
  → also resolve any firing events for this rule

create_alert_event(db, rule_id, labels, value, state, entity_id=None)
  → insert event

get_active_alerts(db, user_id=None)
  → currently firing events (unresolved + unacknowledged)

get_alert_event_count(db, severity=None)
  → count of firing alerts

resolve_alert_event(db, event_id)
  → set state='resolved', resolved_at=now

acknowledge_alert(db, event_id, user_id)
  → set state='acknowledged', acknowledged_by=user_id
```

### Notification Channels

```
get_notification_channels(enabled=None)
  → list all channels

get_notification_channel(id)
  → single channel dict

create_notification_channel(db, name, type, config)
  → insert, return dict

update_notification_channel(db, id, **fields)
  → update, return dict

delete_notification_channel(db, id)
  → also removes rule_notification_channels associations

get_channels_for_rule(db, rule_id)
  → list of channels linked to this rule (or all enabled if none linked)

set_rule_channels(db, rule_id, channel_ids)
  → replace rule's channel associations
```

### Silences

```
get_active_silences(db)
  → silences where now() is between starts_at and ends_at

get_silences(db, include_expired=False)
  → all silences (for UI listing)

create_silence(db, matchers, rule_id, starts_at, ends_at, reason, created_by)
  → insert, return dict

delete_silence(db, id)
  → remove silence

is_silenced(db, rule_id, labels)
  → bool — checks if any active silence matches this rule+labels
```

### Eval Lock

```
acquire_eval_lock(db, worker_id, ttl_secs=120)
  → bool — attempts to acquire lock, returns True if acquired
  → uses UPDATE WHERE (locked_by = worker_id OR expires_at < now())

release_eval_lock(db, worker_id)
  → releases the lock

refresh_eval_lock(db, worker_id, ttl_secs=120)
  → extends expires_at (heartbeat during long eval cycles)
```

---

## Phase 3 — Evaluate Loop

New file: `app/alert_manager.py`

### Startup

In `app/__init__.py`, after app creation:

```python
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()
scheduler.add_job(
    func=evaluate_rules,
    trigger='interval',
    seconds=30,
    args=[app],
    id='alert_evaluator',
    replace_existing=True,
)
scheduler.start()
```

### Multi-Worker Lock

```python
import socket, os

WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"

def evaluate_rules(app):
    with app.app_context():
        db = get_db(...)
        if not acquire_eval_lock(db, WORKER_ID, ttl_secs=120):
            db.close()
            return  # another worker holds the lock
        try:
            rules = get_alert_rules(enabled=True)
            for rule in rules:
                if rule["check_name"]:
                    _evaluate_check_rule(db, rule)
                else:
                    _evaluate_promql_rule(db, rule)
        finally:
            release_eval_lock(db, WORKER_ID)
            db.close()
```

Only one worker will evaluate at a time. If a worker dies mid-eval, the lock expires after `ttl_secs` and another worker picks it up on the next cycle.

### Meta-Monitoring (Eval Loop Health)

The `last_eval_at` column in `alert_eval_lock` is updated every cycle. Expose a health endpoint:

```
GET /health/alerts
  → 200 if last_eval_at < 2 minutes ago
  → 503 if stale (eval loop may be stuck or dead)
```

This is the "dead man's switch" — if the eval loop stops, something external can alert on it.

### _evaluate_promql_rule()

1. Run `_vm_query(rule["query"])`
2. For each result series:
   - Extract labels → JSON
   - Extract value
   - **Optional: resolve labels to `entity_id`** (future inventory integration)
     - When inventory exists, map runtime labels (e.g. `agent_id`) to canonical `inventory_entities.id`
     - For now, `entity_id` is always NULL
   - Compare using rule["operator"] against rule["threshold"]
   - Look up existing event for this rule+labels
   - **If threshold met AND no firing event:**
     - Check cooldown: if a resolved event exists for this rule+labels and `resolved_at + cooldown_secs > now()` → skip (still in cooldown)
     - Check silence: if `is_silenced(db, rule_id, labels)` → skip
     - Otherwise → `create_alert_event(state='firing', entity_id=entity_id)` → `_dispatch_notifications(db, rule, event)`
   - **If threshold NOT met AND firing event exists:**
     - Use `resolve_threshold` if set, otherwise use same `threshold`
     - If resolve condition met → `resolve_alert_event()` → `_dispatch_resolve_notifications(db, rule, event)`

### _evaluate_check_rule()

1. Query `check_results` table for `name = rule["check_name"]`
   - Get latest result per agent_id (`GROUP BY agent_id`)
2. For each check result:
   - Labels = `{agent_id, hostname}`
   - **Optional: resolve `agent_id` → `entity_id`** (future inventory integration)
   - Compare `exit_code` against `rule["threshold"]` using `rule["operator"]`
   - Same fire/resolve/cooldown/silence logic as PromQL rules

### Debounce

If `rule["for_duration"]` is set, only fire if the condition persists for that many seconds. Track pending state in a simple in-memory dict `{rule_id+labels: first_seen_at}`.

### Flap Protection (Cooldown)

When `cooldown_secs` is set on a rule:
- After an event resolves, the rule+labels combination enters a cooldown period
- During cooldown, even if the threshold is exceeded again, no new event fires
- Tracked by checking `resolved_at` of the most recent resolved event for that rule+labels
- Example: rule with `cooldown_secs=300` means after resolve, the alert won't re-fire for at least 5 minutes

### Hysteresis (Resolve Threshold)

When `resolve_threshold` is set:
- The **fire** condition uses `threshold` (e.g., fire when CPU > 90%)
- The **resolve** condition uses `resolve_threshold` (e.g., resolve when CPU < 80%)
- This prevents flapping when a value hovers near a single threshold
- If `resolve_threshold` is NULL, resolve uses the inverse of the fire condition against `threshold`

### Notification Dispatch

```python
def _dispatch_notifications(db, rule, event):
    channels = get_channels_for_rule(db, rule["id"])
    for channel in channels:
        _send_to_channel(channel, rule, event, state="firing")
    # mark event as notified
    db.execute("UPDATE alert_events SET notified_at = ? WHERE id = ?",
               (now_iso(), event["id"]))

def _dispatch_resolve_notifications(db, rule, event):
    channels = get_channels_for_rule(db, rule["id"])
    for channel in channels:
        _send_to_channel(channel, rule, event, state="resolved")
```

### Channel Dispatchers

```python
def _send_to_channel(channel, rule, event, state):
    config = json.loads(channel["config"])
    if channel["type"] == "slack":
        _send_slack(config, rule, event, state)
    elif channel["type"] == "email":
        _send_email(config, rule, event, state)
    elif channel["type"] == "webhook":
        _send_webhook(config, rule, event, state)
    elif channel["type"] == "pagerduty":
        _send_pagerduty(config, rule, event, state)
```

Each dispatcher formats a message using rule name, severity, labels, value, and state. Dispatch failures are logged but do not block the eval loop (fire-and-forget with retry queue as future enhancement).

---

## Phase 4 — API Endpoints

New blueprint or inline in `app/metrics.py`:

### Rules & Events

```
GET    /alerts/api/rules              → list (admin sees all, user sees personal+global)
POST   /alerts/api/rules              → create (body: name, query/check_name, operator, ...)
PUT    /alerts/api/rules/<id>         → update
DELETE /alerts/api/rules/<id>         → delete

GET    /alerts/api/active             → active events
GET    /alerts/api/active/count       → count (for nav badge, optional ?severity=critical)
POST   /alerts/api/events/<id>/ack    → acknowledge

GET    /alerts                        → Active Alerts page
GET    /alerts/rules                  → Alert Rules management page
GET    /alerts/history                → Resolved alert history
```

### Notification Channels

```
GET    /alerts/api/channels           → list all channels
POST   /alerts/api/channels           → create channel
PUT    /alerts/api/channels/<id>      → update channel
DELETE /alerts/api/channels/<id>      → delete channel
POST   /alerts/api/channels/<id>/test → send test notification
```

### Silences

```
GET    /alerts/api/silences           → list active (+ optional ?include_expired=true)
POST   /alerts/api/silences           → create silence
DELETE /alerts/api/silences/<id>      → expire/remove silence
```

### Authorization

- Read endpoints: `require_role("viewer")`
- Write endpoints (rules): `require_role("admin")` OR (for personal rules) the user can write their own
- Write endpoints (channels, silences): `require_role("admin")`
- DELETE: `require_role("admin")` or own rule

**Future-proofing for inventory/teams:** Keep the authorization check abstract. Instead of inline `if rule.user_id == current_user.id`, use a helper like `can_manage_rule(rule, user)` that can later be extended to support team ownership without rewriting every endpoint.

---

## Phase 5 — UI

### Nav tab update

In `base.html`, add to nav:

```html
<a href="{{ url_for('metrics.alerts') }}" class="nav-item">
    🔔 Alerts <span id="alertBadge" class="nav-badge" style="display:none"></span>
</a>
```

JS in base.html polls `/alerts/api/active/count` every 30s, shows badge if > 0.

### Active Alerts page (`/alerts`)

Table of currently firing events:

| Severity | Rule | Labels | Value | Duration | Actions |
|---|---|---|---|---|---|
| 🔴 Critical | High CPU | host=web-1 | 94% | 5m | Acknowledge |
| 🟡 Warning | Disk Space | host=db-2 | 88% | 12m | Acknowledge |

- Severity badge (red dot for critical, yellow for warning)
- Rule name (linked to rule detail)
- Labels as comma-separated pills
- Value with units
- Duration (fired_at relative)
- Acknowledge button (POST /alerts/api/events/<id>/ack)
- Silenced alerts shown greyed out with "silenced" badge

Empty state: "No active alerts — everything looks good 🟢"

### Alert Rules page (`/alerts/rules`)

Table of configured rules:

| Enabled | Name | Type | Query/Check | Severity | Threshold | Cooldown | Channels | Actions |
|---|---|---|---|---|---|---|---|---|
| ✅ | High CPU | PromQL | `cpu_usage > 90` | critical | > 90 (resolve < 80) | 5m | Slack, Email | ✏️ 🗑️ |
| ✅ | Disk Check | Check | `disk_root` | warning | ≥ 2 | — | Slack | ✏️ 🗑️ |

- Enable/disable toggle (AJAX PUT)
- Type badge: "PromQL" or "Check"
- Inline "New Rule" button → modal form
  - Name, Type (dropdown: PromQL / Check)
  - If PromQL: query textarea, operator dropdown, threshold input
  - If Check: check_name text input, operator, threshold
  - Severity, interval, for_duration
  - Resolve threshold (optional, for hysteresis)
  - Cooldown seconds (optional, for flap protection)
  - Tags (optional JSON) — reserved for future inventory use
  - Channel multi-select (checkboxes of available channels)
- Edit icon opens same modal pre-filled
- Delete with confirmation

### Notification Channels page (`/alerts/channels`)

| Name | Type | Target | Enabled | Actions |
|---|---|---|---|---|
| Ops Slack | slack | #alerts | ✅ | Test ✏️ 🗑️ |
| On-Call Email | email | ops@example.com | ✅ | Test ✏️ 🗑️ |

- "New Channel" button → modal with type selector and dynamic config fields
- "Test" button sends a test notification to verify config
- Enable/disable toggle

### Silences page (`/alerts/silences`)

| Status | Rule | Matchers | Reason | Starts | Ends | Created By | Actions |
|---|---|---|---|---|---|---|---|
| Active | High CPU | hostname=web-1 | Deploy window | 14:00 | 15:00 | admin | 🗑️ |
| Expired | — | agent_id=~prod-.* | Maintenance | Yesterday | Yesterday | admin | — |

- "New Silence" button → modal form
  - Rule (optional dropdown, or "All rules")
  - Matchers (dynamic key/op/value rows, add/remove)
  - Start time, End time (datetime pickers)
  - Reason (required text)
- Active silences highlighted, expired shown muted
- Delete removes active silence immediately

### History page (`/alerts/history`)

Paginated table of resolved/acknowledged events:

| Rule | Labels | Value | Fired | Resolved | Duration |
|---|---|---|---|---|---|
| High CPU | host=web-1 | 94% | 2h ago | 30m ago | 1.5h |

---

## Phase 6 — CLI (YAML Round-trip)

New commands on the existing `vespid` CLI entrypoint:

```
vespid alerts apply <file.yaml>    → upsert global rules from YAML
vespid alerts dump                 → export global rules to YAML (stdout)
vespid alerts silence add          → create silence interactively or via flags
vespid alerts silence list         → list active silences
vespid alerts silence rm <id>      → remove silence
vespid alerts channels list        → list notification channels
```

### YAML format

```yaml
rules:
  - name: High CPU
    query: '100 - (avg(rate(cpu_idle[2m])) * 100)'
    operator: '>'
    threshold: 90
    resolve_threshold: 80
    severity: critical
    interval_secs: 60
    cooldown_secs: 300
    tags:
      team: ops
      service: api
      env: prod
    channels: [Ops Slack, On-Call Email]
    enabled: true

  - name: Root Disk Check
    check_name: disk_root
    operator: '>='
    threshold: 2
    severity: critical
    interval_secs: 120
    channels: [Ops Slack]
    enabled: true

channels:
  - name: Ops Slack
    type: slack
    config:
      webhook_url: '${SLACK_WEBHOOK_URL}'
      channel: '#alerts'
    enabled: true

  - name: On-Call Email
    type: email
    config:
      recipients: ['ops@example.com']
    enabled: true
```

### apply behavior

- Look up rule by `name` — if exists, update; if not, create
- Only touches global rules (`user_id = NULL`)
- Channels section: upsert channels by name, resolve channel references in rules
- Environment variable interpolation in config values (`${VAR}` syntax)
- Output summary: "3 rules applied (2 updated, 1 created), 2 channels applied"

### dump behavior

- SELECT all global rules + channels, serialize to YAML
- Output to stdout (pipe to file as needed)
- **Security note:** channel configs containing secrets (webhook URLs, routing keys) will be serialized in plaintext. Consider masking sensitive values or piping to a secrets-aware store.

Implementation in `app/cli.py` or a new `app/alert_cli.py`.

---

## Phase 7 — Overview Banner

On the metrics overview page, if any critical alert is firing, show a dismissible banner:

```
⚠️ N critical alerts firing — View Alerts
```

- Fetch via JS: `fetch('/alerts/api/active/count?severity=critical')`
- If count > 0, show banner above the fleet stats
- Click "View Alerts" → navigate to `/alerts`
- Dismiss sets a session flag or localStorage key to hide for this session

---

## Future: Inventory Integration

When the inventory system is built, the alert system can link to it with **zero breaking changes**:

1. **Add `inventory_entities` table** (separate migration, separate feature)
2. **Update eval loop** to resolve runtime labels → `entity_id`:
   - `resolve_labels_to_entity(db, labels)` → looks up `agent_id` / `hostname` in inventory, returns `entity_id` or NULL
   - Store `entity_id` in `alert_events` at creation time
3. **Inventory UI queries** `alert_events` by `entity_id` to show "Alerts for this host" without parsing JSON
4. **Policy-based rules** (future): rules with `tags` but no explicit `query`/`check_name` auto-generate monitoring based on inventory tags (e.g., "all hosts tagged `env:prod` should have a CPU rule")
5. **Team ownership** (future): extend `can_manage_rule()` to check team membership, not just `user_id`

**What NOT to do now:**
- Don't add `inventory_entities` FK constraints yet (the table doesn't exist)
- Don't hardcode `agent_id` or `hostname` as first-class columns in `alert_events`
- Don't bake team ownership into the auth layer yet

---

## Key Design Decisions

1. **Single event per rule+labels** — each unique label set (e.g., per host) creates one event. If the same rule fires on 3 hosts, you get 3 events.
2. **Resolve on threshold clear** — when the value drops below (or recovers past) the threshold, the event auto-resolves. No manual cleanup. Hysteresis (`resolve_threshold`) prevents flapping at boundary.
3. **Acknowledge** — silences from further UI notifications but keeps the event in `acknowledged` state for audit. Resolved events also still show in history.
4. **Check integration** — PromQL and check-backed rules share the same event lifecycle, UI, and API. The only difference is the data source.
5. **Per-user rules** — personal rules are evaluated globally (the loop doesn't filter by owner) but only visible to the owner in the UI. This means a personal alert can still fire based on any data.
6. **Notification delivery** — notifications fire on state transitions (firing → resolved). Acknowledged events do NOT re-notify. Channel dispatch is fire-and-forget; failures are logged but don't block evaluation.
7. **Silences are label-based** — inspired by Prometheus Alertmanager. A silence matches events by label predicates, allowing broad ("silence all alerts for host web-1 during deploy") or narrow ("silence this one rule for this one host") suppression.
8. **Cooldown prevents flap storms** — after an alert resolves, the cooldown period prevents immediate re-fire if the metric briefly crosses threshold again. This is per rule+labels, not global.
9. **Single-writer eval loop** — the DB-based lock ensures exactly one worker evaluates at any time, even with multiple gunicorn workers. Lock TTL ensures recovery if the evaluating worker crashes.
10. **Labels are runtime identity, entities are canonical identity** — `labels` JSON holds the ephemeral runtime context (`agent_id`, `hostname`). `entity_id` is the stable canonical reference to inventory. This decoupling means the alert system works standalone today and links to inventory later without schema changes.
11. **Auth is abstract, not user-centric** — rule ownership uses `user_id` now, but authorization is checked through a `can_manage_rule()` helper. When teams arrive, the helper extends without rewriting endpoints.

---

## Implementation Order

```
Phase 1: DB schema + migration 17 + MySQL schema
         (alert_rules, alert_events, notification_channels,
          rule_notification_channels, alert_silences, alert_eval_lock)
Phase 2: Model helpers (CRUD for rules, events, channels, silences, lock)
Phase 3: Evaluate loop (lock → evaluate → silence check → cooldown → fire → notify)
         + meta-monitoring heartbeat
Phase 4: API endpoints (rules, events, channels, silences)
Phase 5: UI pages (Active / Rules / Channels / Silences / History) + nav badge
Phase 6: CLI apply/dump + silence management
Phase 7: Overview banner
```

Each phase is self-contained and deployable.
