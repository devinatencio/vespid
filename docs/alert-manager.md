# Vespid Alert Manager

A unified alerting subsystem that evaluates both **PromQL metric queries** and **Nagios-style health check results**, with per-user personal rules, global rules, notification delivery, maintenance windows, flap protection, and safe multi-worker execution.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Database Schema](#database-schema)
3. [Concepts](#concepts)
4. [Default Conditions](#default-conditions)
5. [Configuration](#configuration)
6. [Web UI](#web-ui)
7. [API Reference](#api-reference)
8. [CLI Reference](#cli-reference)
9. [YAML Format](#yaml-format)
10. [Notification Channels](#notification-channels)
11. [Silences](#silences)
12. [Eval Loop](#eval-loop)
13. [Multi-Worker Safety](#multi-worker-safety)
14. [Future: Inventory Integration](#future-inventory-integration)
15. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Data Sources                         │
│  ┌────────────────┐  ┌──────────────────┐  ┌────────────┐   │
│  │VictoriaMetrics │  │  check_results   │  │   Agents   │   │
│  │    (PromQL)    │  │  (Nagios-style)  │  │ (runtime)  │   │
│  └────────┬───────┘  └─────────┬────────┘  └──────┬─────┘   │
└───────────┼────────────────────┼──────────────────┼─────────┘
            │                    │                  │
            └────────────────────┼──────────────────┘
                                 ▼
                     ┌──────────────────────┐
                     │      Eval Loop       │
                     │  (alert_manager.py)  │
                     │      • DB lock       │
                     │   • Silence check    │
                     │      • Cooldown      │
                     │    • Fire/Resolve    │
                     └───────────┬──────────┘
                                 │
                   ┌─────────────┼─────────────┐
                   ▼             ▼             ▼
              ┌─────────┐  ┌──────────┐  ┌───────────┐
              │  Slack  │  │  Email   │  │  Webhook  │
              └─────────┘  └──────────┘  └───────────┘
```

The eval loop runs every 30 seconds (configurable), acquires a distributed DB lock, evaluates all enabled rules against both PromQL and check data, and dispatches notifications on state transitions.

---

## Database Schema

### `alert_rules`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | auto |
| `user_id` | INTEGER? | NULL = global rule, else personal rule |
| `name` | TEXT | required |
| `query` | TEXT? | PromQL — NULL if using check_name |
| `check_name` | TEXT? | NULL if using PromQL |
| `operator` | TEXT | `>`, `<`, `==`, `>=`, `<=` |
| `threshold` | REAL | value threshold |
| `resolve_threshold` | REAL? | separate threshold for resolving (hysteresis) |
| `severity` | TEXT | `warning` / `critical` |
| `for_duration` | INTEGER | seconds condition must persist before firing |
| `cooldown_secs` | INTEGER? | minimum seconds after resolve before re-fire |
| `interval_secs` | INTEGER | evaluate interval (default 60) |
| `tags` | TEXT? | JSON — reserved for future inventory/policy use |
| `enabled` | BOOLEAN | default true |

### `alert_events`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | auto |
| `rule_id` | INTEGER FK | → alert_rules.id |
| `entity_id` | INTEGER? | **Nullable FK to future inventory_entities** |
| `labels` | TEXT | JSON — runtime labels (agent_id, hostname, etc.) |
| `value` | REAL | the value that triggered |
| `state` | TEXT | `firing` / `resolved` / `acknowledged` |
| `fired_at` | TEXT | ISO 8601 |
| `resolved_at` | TEXT? | nullable |
| `acknowledged_by` | INTEGER? | user_id |
| `notified_at` | TEXT? | when notification dispatched |

### `notification_channels`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | auto |
| `name` | TEXT | human-readable |
| `type` | TEXT | `email` / `slack` / `webhook` / `pagerduty` |
| `config` | TEXT | JSON — type-specific configuration |
| `enabled` | BOOLEAN | default true |

### `rule_notification_channels`

Many-to-many join table linking rules to channels.

### `alert_silences`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | auto |
| `matchers` | TEXT | JSON — label matchers |
| `rule_id` | INTEGER? | NULL = match all rules |
| `starts_at` | TEXT | ISO 8601 |
| `ends_at` | Text | ISO 8601 |
| `reason` | Text | required |
| `created_by` | INTEGER FK | → users.id |

### `alert_eval_lock`

Singleton row for distributed eval coordination.

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | always 1 |
| `locked_by` | TEXT | worker identifier |
| `locked_at` | Text | ISO 8601 |
| `expires_at` | Text | ISO 8601 — auto-expire if worker dies |
| `last_eval_at` | Text? | heartbeat for meta-monitoring |

---

## Concepts

### Rule Types

**PromQL rules** evaluate a PromQL query against VictoriaMetrics. Each result series becomes a separate alert event (e.g., one event per host).

**Check rules** evaluate the latest result from the `check_results` table for a given check name. Each `agent_id` gets its own event.

### Event Lifecycle

```
Eval Loop
    │
    ├─ threshold met ──→ create event (state='firing')
    │                        │
    │                        ├─ dispatch notification
    │                        │
    │    ┌───────────────────┘
    │    │
    ├─ threshold cleared ──→ resolve event (state='resolved')
    │                           │
    │                           └─ dispatch resolve notification
    │
    ├─ user acknowledges ──→ state='acknowledged'
```

### Debounce (`for_duration`)

A condition must persist for `for_duration` seconds before firing. Prevents spurious alerts from transient blips.

### Cooldown (`cooldown_secs`)

After an event resolves, the rule+labels combination enters a cooldown period. Even if the threshold is exceeded again during cooldown, no new event fires. Prevents flap storms.

### Hysteresis (`resolve_threshold`)

Optional separate threshold for resolving vs. firing:
- **Fire** at CPU > 90%
- **Resolve** at CPU < 80%

Prevents rapid fire/resolve cycles when a value hovers near a single threshold.

### Labels vs. Entity IDs

- **Labels** (`labels` JSON): Runtime identity — ephemeral, agent-reported values like `agent_id`, `hostname`.
- **Entity ID** (`entity_id`): Canonical inventory reference. Always NULL today. When the inventory system arrives, the eval loop resolves runtime labels to canonical IDs and stores them here.

This decoupling means the alert system works standalone now and links to inventory later without schema changes.

---

## Default Conditions

When a new "Linux Servers" monitoring group is created (automatically on first deploy), eight default conditions are added:

| Condition | Metric | What it measures | Threshold | Severity | Duration |
|---|---|---|---|---|---|
| **High CPU** | `vespid_monitor_cpu_*` | CPU utilization — percentage of time the CPU spent in non-idle state across all cores | > 90% | critical | 5 min |
| **High CPU Pressure** | `vespid_monitor_psi_avg10{resource="cpu",level="some"}` | CPU stall — percentage of time tasks were **runnable but waiting** for a CPU core (scheduler contention); high utilization + high pressure means overload | > 50% | warning | 5 min |
| **High IO Pressure** | `vespid_monitor_psi_avg10{resource="io",level="some"}` | IO stall — percentage of time tasks were **blocked waiting for disk/storage I/O** to complete | > 50% | warning | 5 min |
| **High Memory Pressure** | `vespid_monitor_psi_avg10{resource="memory",level="some"}` | Memory stall — percentage of time tasks were **stalled waiting for memory** (typically due to swapping/reclaim under pressure); > 20% indicates active thrashing | > 20% | critical | 5 min |
| **High Memory** | `vespid_monitor_memory_used_percent` | Memory utilization — percentage of RAM in use (excluding buffers/cache) | > 90% | critical | 5 min |
| **High Disk Usage** | `vespid_monitor_disk_used_percent` | Disk usage — percentage of each block device's capacity used; fires per-device, one alert per unique disk | > 90% | critical | 10 min |
| **High Load Average (5min)** | `vespid_monitor_loadavg_5min` | System load — number of tasks in the run queue averaged over 5 minutes; a load exceeding the number of CPU cores indicates overload | > 4.0 | warning | 5 min |
| **Zombie Processes** | `vespid_monitor_process_zombies_count` | Zombie processes — count of defunct (reaped but not waited-on) processes lingering in the process table | > 0 | warning | 5 min |

**Disabled by default** (enable in the UI if needed):

| Condition | Metric | What it measures | Threshold | Severity | Duration |
|---|---|---|---|---|---|
| **High Process Count** | `vespid_monitor_process_count_total` | Total processes running on the system — indicates fork bombs or runaway apps | > 1000 | warning | 5 min |
| **High Running Processes** | `vespid_monitor_process_running` | Runnable processes (state R) — many running tasks indicates CPU contention or thread explosion | > 20 | warning | 5 min |
| **High Swap Usage** | `vespid_monitor_memory_swap_used_percent` | Swap space utilization — significant swap usage means the system is memory-constrained and may be thrashing | > 50% | critical | 5 min |
| **Network Errors** | `rate(vespid_monitor_network_errors_sent_total[5m])` | Rate of outbound NIC errors — any errors indicate hardware/driver issues on the network interface | > 0 | warning | 5 min |

> These conditions require the `process` or `memory` collectors to be enabled in the agent's `agent.yaml` (`collectors.process.enabled: true`). Swap and network collectors are enabled by default.

**Pressure Stall (PSI)** conditions use `/proc/pressure/*` metrics from the Linux kernel — they measure time spent stalled rather than time spent busy, making them a more direct signal of resource contention than traditional utilization metrics.

---

## Configuration

```json
{
  "ALERTS_ENABLED": true,
  "ALERT_EVAL_INTERVAL_SECONDS": 30
}
```

| Key | Default | Description |
|---|---|---|
| `ALERTS_ENABLED` | `true` | Enable/disable the alert subsystem |
| `ALERT_EVAL_INTERVAL_SECONDS` | `30` | How often the eval loop runs |

---

## Web UI

### Active Alerts (`/alerts`)

Shows all currently firing events. Columns: severity, rule name, labels, value, duration, actions (Acknowledge, Resolve).

### Alert Rules (`/alerts/rules`)

Manage configured rules. Create/edit via modal form. Supports both PromQL and Check types. Configure threshold, operator, severity, debounce, cooldown, and channel associations.

### History (`/alerts/history`)

Paginated table of resolved and acknowledged events. Shows duration, fired/resolved timestamps.

### Channels (`/alerts/channels`) — Admin only

Manage notification channels. Supports Slack, Email, Webhook, and PagerDuty. Test button sends a test notification.

### Silences (`/alerts/silences`) — Admin only

Create maintenance windows. Define matchers (label + op + value) with start/end times. Supports exact match (`=`), not-equal (`!=`), regex match (`=~`), and regex negative match (`!~`).

### Nav Badge

The sidebar polls `/alerts/api/active/count` every 30 seconds and shows a badge when alerts are firing.

---

## API Reference

All endpoints require authentication via session or Bearer token.

### Rules

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/alerts/api/rules` | viewer | List rules (admin sees all, user sees personal + global) |
| POST | `/alerts/api/rules` | admin | Create a new rule |
| PUT | `/alerts/api/rules/<id>` | admin | Update a rule |
| DELETE | `/alerts/api/rules/<id>` | admin | Delete a rule (resolves firing events) |

### Events

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/alerts/api/active` | viewer | List firing events |
| GET | `/alerts/api/active/count` | viewer | Count firing events (optional `?severity=critical`) |
| POST | `/alerts/api/events/<id>/ack` | admin | Acknowledge an event |
| POST | `/alerts/api/events/<id>/resolve` | admin | Manually resolve an event |
| GET | `/alerts/api/history` | viewer | Resolved/acknowledged history (paginated) |

### Channels

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/alerts/api/channels` | admin | List channels |
| POST | `/alerts/api/channels` | admin | Create channel |
| PUT | `/alerts/api/channels/<id>` | admin | Update channel |
| DELETE | `/alerts/api/channels/<id>` | admin | Delete channel |
| POST | `/alerts/api/channels/<id>/test` | admin | Send test notification |

### Silences

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/alerts/api/silences` | admin | List silences (optional `?include_expired=true`) |
| POST | `/alerts/api/silences` | admin | Create silence |
| DELETE | `/alerts/api/silences/<id>` | admin | Remove silence |

### Health

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/health/alerts` | none | Eval loop health (200 = healthy, 503 = stale) |

---

## CLI Reference

The alert CLI is a subcommand of `vespid-server`:

```bash
vespid-server --config /etc/vespid/config.json alerts <subcommand>
```

### `apply <file.yaml>`

Upsert global rules and channels from a YAML file.

```bash
vespid-server alerts apply /etc/vespid/alerts.yaml
```

Output: `Applied 3 rules (2 updated, 1 created), 2 channels (1 updated, 1 created)`

### `dump`

Export global rules and channels to YAML on stdout.

```bash
vespid-server alerts dump > /backup/alerts-$(date +%Y%m%d).yaml
```

### `silence add`

Create a silence interactively or via flags.

```bash
vespid-server alerts silence add \
  --matcher "hostname=web-1" \
  --duration 3600 \
  --reason "Deploy window"
```

### `silence list`

List active silences.

### `silence rm <id>`

Remove a silence.

### `channels`

List notification channels.

---

## YAML Format

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
      from_address: 'vespid-alerts@example.com'
      smtp_host: 'smtp.example.com'
      smtp_port: 587
      smtp_tls: 'starttls'
      smtp_user: '${SMTP_USER}'
      smtp_password: '${SMTP_PASSWORD}'
      subject_prefix: '[Vespid]'
    enabled: true
```

### Environment Variable Interpolation

Channel config values can use `${ENV_VAR}` syntax. The CLI resolves these at apply time.

---

## Notification Channels

### Slack

Config:
```json
{"webhook_url": "https://hooks.slack.com/...", "channel": "#alerts"}
```

Sends a formatted message with rule name, severity, value, and labels.

### Email

Config:
```json
{
  "recipients": ["ops@example.com", "oncall@example.com"],
  "from_address": "vespid-alerts@example.com",
  "smtp_host": "smtp.example.com",
  "smtp_port": 587,
  "smtp_tls": "starttls",
  "smtp_user": "vespid-alerts@example.com",
  "smtp_password": "app-password-here",
  "subject_prefix": "[Vespid]"
}
```

Sends a plain-text email via the configured SMTP relay. Vespid connects, authenticates (if credentials are provided), sends the message, and disconnects. No retry queue — delivery reliability is the relay's responsibility.

**Required fields:**

| Field | Description |
|---|---|
| `recipients` | List of recipient email addresses |
| `smtp_host` | SMTP relay hostname or IP |
| `from_address` | Sender email address |

**Optional fields:**

| Field | Default | Description |
|---|---|---|
| `smtp_port` | 587 (starttls) / 465 (ssl) | SMTP server port |
| `smtp_tls` | `starttls` | TLS mode: `starttls`, `ssl`, or `none` |
| `smtp_user` | *(empty)* | Username for SMTP authentication |
| `smtp_password` | *(empty)* | Password for SMTP authentication |
| `subject_prefix` | `[Vespid]` | Prefix prepended to email subject lines |

**Recommended relays:** Any standard SMTP relay works — your org's mail gateway, Amazon SES, SendGrid, Mailgun, Postmark, or a local Postfix instance. Point `smtp_host` at the relay and let it handle SPF/DKIM/deliverability.

### Webhook

Config:
```json
{"url": "https://...", "method": "POST", "headers": {"X-Token": "..."}}
```

POSTs a JSON payload with rule, severity, state, value, labels, and fired_at.

### PagerDuty

Config:
```json
{"routing_key": "...", "severity_map": {"critical": "critical", "warning": "warning"}}
```

Uses PagerDuty Events API v2. Sends `trigger` on firing, `resolve` on recovery. Deduplicates by rule+labels.

---

## Silences

Silences suppress alert notifications by matching event labels. They are inspired by Prometheus Alertmanager.

### Matcher Syntax

```json
[
  {"label": "hostname", "op": "=", "value": "web-1"},
  {"label": "agent_id", "op": "=~", "value": "prod-.*"}
]
```

Supported operators:
- `=` — exact match
- `!=` — not equal
- `=~` — regex match
- `!~` — regex negative match

A silence matches an event if **all** matchers match the event's labels. If `rule_id` is set, the silence only applies to that specific rule.

### Use Cases

- **Deploy window**: Silence all alerts for `hostname=web-1` during a deploy
- **Maintenance**: Silence `agent_id=~prod-.*` for a known maintenance window
- **Known issue**: Silence a specific rule for a specific host while investigating

---

## Eval Loop

### Startup

The eval loop is started by the Flask app factory using APScheduler:

```python
from apscheduler.schedulers.background import BackgroundScheduler
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=evaluate_rules,
    trigger="interval",
    seconds=30,
    args=[app],
    id="alert_evaluator",
    replace_existing=True,
)
scheduler.start()
```

### Flow

1. Acquire DB lock (or skip if another worker holds it)
2. Fetch all enabled rules
3. For each rule:
   - If PromQL: query VictoriaMetrics, iterate result series
   - If Check: query `check_results` for latest per agent_id
   - For each series/check result:
     - Compare value against threshold
     - Check `for_duration` debounce
     - Check `cooldown_secs` (look at last resolved event)
     - Check if silenced
     - If firing and no existing event → create event, dispatch notifications
     - If not firing and event exists → check resolve threshold, resolve event, dispatch resolve notifications
4. Release DB lock

### Error Handling

- PromQL query failures are logged but do not crash the eval loop
- Notification dispatch failures are logged but do not block evaluation
- The eval lock TTL (default 120s) ensures recovery if a worker crashes mid-eval

---

## Multi-Worker Safety

When running gunicorn with multiple workers, each worker would try to evaluate rules simultaneously, causing duplicate alerts.

The solution is a **DB-based singleton lock** (`alert_eval_lock` table):

- Only one worker can hold the lock at a time
- Lock has a TTL (default 120s) — if the evaluating worker dies, another worker picks it up after expiry
- The lock is refreshed after each eval cycle
- Workers that fail to acquire the lock simply skip evaluation for that cycle

This works across multiple nodes as long as they share the same database.

---

## Future: Inventory Integration

The schema is designed for a future inventory system with **zero breaking changes**:

1. **`entity_id` on `alert_events`** — currently always NULL. Later, the eval loop resolves runtime labels (e.g., `agent_id`) to canonical `inventory_entities.id` and stores it. This enables "show all alerts for this host" in the inventory UI without parsing JSON.

2. **`tags` on `alert_rules`** — reserved for future policy-based rules (e.g., "all hosts tagged `env:prod` should have a CPU rule").

3. **Abstract auth** — `can_manage_rule()` helper can be extended to support team ownership instead of just user ownership.

When inventory arrives, the migration is: add `inventory_entities` table, update eval loop to resolve labels → entity_id, done. No changes to the alert system schema.

---

## Troubleshooting

### Eval loop not running

Check `/health/alerts`:
```bash
curl http://localhost/health/alerts
```

Returns `200` if healthy, `503` if stale (last eval > 2 minutes ago).

### Duplicate alerts

Check that the DB lock is working:
```sql
SELECT locked_by, locked_at, expires_at, last_eval_at FROM alert_eval_lock WHERE id = 1;
```

If `locked_by` is stale (expired), another worker should pick it up on the next cycle.

### Notifications not sending

1. Check that channels are enabled: `SELECT * FROM notification_channels WHERE enabled = 1`
2. Check that rules have channel associations (or default to all enabled)
3. Check application logs for dispatch errors
4. Use the "Test" button on the Channels page to verify channel config

### Alerts firing when they shouldn't

1. Check for active silences: `/alerts/api/silences`
2. Check cooldown: a recently resolved alert won't re-fire until cooldown expires
3. Check `for_duration`: the condition must persist for that many seconds
4. Verify the PromQL query in the Query Explorer

### Schema not created

Run database initialization:
```bash
vespid-server --config /etc/vespid/config.json init-db
```

The migration system is idempotent — safe to run on existing databases.
