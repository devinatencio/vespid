# Noise Suppression

Host Threat Detection uses auditd process creation monitoring, which
generates a high volume of events from normal system operations.  The
noise suppression system filters out known false positives so security
analysts can focus on genuine threats.

## How it works

The server ships with 20 curated noise rules covering common Linux
operations that trigger Sigma detections during normal use.  Each rule
maps a Sigma rule name to a suppression strategy.

## Suppression strategies

| Strategy | Behavior |
|----------|----------|
| `suppress` | Events matching the rule are silently discarded — never stored or displayed |
| `group` | Repeated events from the same rule are collapsed into a single entry with a count |
| `threshold` | Events are shown only if they exceed a minimum count within a time window |

## Default noise rules

These rules are applied automatically when Host Threat Detection is
enabled.

### Suppressed rules (fully filtered)

| Rule | Reason |
|------|--------|
| Cron job execution | Regular scheduled task execution |
| Python process spawning | Web servers, automation scripts |
| Shell pipe operations | Normal shell pipeline usage |
| System command execution (`uname`, `id`, `whoami`) | Health check scripts, login shells |
| `curl` / `wget` invocations | Package managers, health checks |
| File cleanup operations (`rm`, `find -delete`) | Log rotation, temp cleanup |
| Interactive shell startup | Normal user logins |
| System discovery commands | Monitoring agents, automation |

### Grouped rules

Repeated instances of the same detection from the same host within a
short window are collapsed into a single event with a hit count,
reducing dashboard clutter without losing visibility.

### Threshold rules

| Setting | Default |
|---------|---------|
| Minimum count | 10 |
| Window | 60 minutes |

Events below the threshold are treated as noise.  Above the threshold,
they are displayed — a spike in normally-benign activity can indicate
compromise.

## Noise analysis panel

The Host Threat Detection dashboard includes a **Noise Analysis** panel
that shows:

- Total events suppressed in the last 24 hours
- Top noise rules by hit count
- Suppression rate per host

This helps admins tune noise rules and identify hosts that generate
unusual volumes of benign events.

## Customizing noise rules

### Adding custom noise rules

Custom noise rules can be added via the dashboard under
**Admin → Host Threats → Noise Rules** to suppress site-specific
false positives.

### Disabling default noise rules

Individual default noise rules can be disabled if your environment
needs visibility into those events.  For example, if `curl` usage is
unexpected on your servers, disable the curl suppression rule to see
all curl process creation events.

## API

```
GET  /admin/host-threats          # includes noise analysis panel
GET  /admin/host-threats/summary  # per-host summary with noise stats
```

## Interaction with threat scoring

Suppressed events do **not** contribute to host threat scores.
Grouped events contribute once (not per-repetition).  Threshold events
contribute only when the threshold is exceeded.

This ensures threat scores reflect genuine security signals rather
than operational noise.
