# Synthetic Monitoring

Proactive health checks run from distributed worker nodes. Verify that your services
are reachable, responsive, and returning expected results — before your users notice.

## Supported check types

| Type      | What it tests                                            | Executor        |
|-----------|----------------------------------------------------------|-----------------|
| **ICMP**  | Network reachability, latency, packet loss               | `ping` binary   |
| **HTTP**  | HTTPS response status, body matching, response time      | reqwest (Rust)  |
| **TCP**   | Port connectivity, connect time                          | tokio TcpStream |
| **DNS**   | Name resolution, lookup time, expected answers           | `dig` binary    |
| **SSL**   | Certificate expiry, chain validation, TLS handshake      | `openssl` binary|

## How it works

```
┌──────────────┐   creates job    ┌──────────────┐   polls for jobs   ┌──────────────┐
│  Vespid   │────────────────►│   MySQL       │◄──────────────────│  Worker      │
│  Server      │  (scheduler)    │   job queue   │                   │  (Rust)      │
│  (Flask)     │                 │               │                   │              │
└──────────────┘                 └──────────────┘                   └──────┬───────┘
                                                                          │
                                                                   executes checks
                                                                   at remote locations
                                                                          │
                                                                   ┌──────▼───────┐
                                                                   │ 1.1.1.1:ICMP │
                                                                   │ you.com:HTTPS│
                                                                   │ db:5432:TCP  │
                                                                   │ dns:A        │
                                                                   └──────────────┘
```

1. **Server schedules checks** — every 10 seconds, finds due checks and creates jobs
2. **Workers poll** — each worker polls for assigned jobs every 5 seconds
3. **Workers execute** — run the check from its location, capture results
4. **Server stores results** — writes result to job record + updates check status + pushes to VictoriaMetrics
5. **Alert rules evaluate** — fires/resolves alerts based on conditions you define

## Concepts

### Check

A monitoring target — an ICMP, HTTP, TCP, or DNS check with a target, interval,
and set of locations. Each check can define optional success criteria (see below).

### Location

Worker nodes are tagged with a `location` label. Checks specify which `locations`
they should run from. Each check cycle fans out one job per location.

**Example:** Ping `api.example.com` from `nyc`, `sfo`, `london` — three jobs per cycle.

### Worker

The same binary as the system agent (`vespid-agent`) running in `--mode=worker`.
Workers register their capabilities (which check types they can run) and labels
(especially `location`). The scheduler only assigns jobs a worker can handle.

### Alert rules

Alert rules come in two types:

#### Failure Count (default)
Alert after N consecutive failed checks. A check is "failed" when:
- Protocol error: timeout, connection refused, no DNS answer, ping failed
- Success criteria not met: status code outside expected range, body mismatch, RTT > threshold, etc.

```
Example: Site is down → alert after 3 consecutive failures
```

#### Metric Threshold
Alert when a specific metric crosses a threshold for N consecutive checks.
Operators: `>` (greater than), `>=`, `<` (less than), `<=`, `==`, `!=`.

| Condition              | Check type | Config                                    |
|------------------------|------------|-------------------------------------------|
| Ping RTT > 1000ms      | icmp       | metric=rtt_avg_ms, >, 1000, 3x consecutive |
| HTTP slow responses    | http       | metric=response_time_ms, >, 2000, 5x      |
| HTTP returning 5xx     | http       | metric=status_code, >=, 500, 2x           |
| DNS taking too long    | dns        | metric=duration_ms, >, 500, 3x            |
| TCP port not responding | tcp       | condition_type=failure, failures=3        |

When triggered, sends notification via Slack, Discord, or any configured notification
channel (reuses existing notification channels from alert management).

---

## Check config reference

### HTTP check options

| Field              | Description                                                 | Default     |
|--------------------|-------------------------------------------------------------|-------------|
| `expected_status`  | HTTP status code range that means "success"                 | `200-399`   |
| `body_match`       | Required substring in response body (check fails if missing)| (none)      |
| `max_duration_ms`  | Max acceptable response time in ms (check fails if slower)  | (none)      |

Status ranges can be `200-399` (range), `200,301,302` (commas), or `200` (exact).

### ICMP check options

| Field         | Description                                              | Default   |
|---------------|----------------------------------------------------------|-----------|
| `max_rtt_ms`  | Max acceptable round-trip time in ms (check fails above) | (none)    |

### TCP check options

| Field              | Description                                               | Default   |
|--------------------|-----------------------------------------------------------|-----------|
| `port`             | Target port (can also be specified as `host:port` target) | 443       |
| `max_connect_ms`   | Max acceptable connect time in ms (check fails if slower) | (none)    |

### DNS check options

| Field             | Description                                                | Default   |
|-------------------|------------------------------------------------------------|-----------|
| `nameserver`      | Specific DNS server to query (`@server` passed to dig)    | (system)  |
| `expected_value`  | Required answer (check fails if not in DNS response)      | (none)    |

### SSL check options

| Field             | Description                                                | Default   |
|-------------------|------------------------------------------------------------|-----------|
| `port`            | Target port for TLS connection                            | 443       |
| `sni`             | SNI hostname (defaults to the host part of target)        | (target)  |
| `check_chain`     | Validate full certificate chain (not just leaf cert)      | on        |

---

## Worker configuration

Create `/etc/vespid-agent/worker.yaml`:

```yaml
server:
  url: "https://vespid.example.com"
  api_key: "ue_your-enrollment-key"

worker:
  capabilities: ["http", "icmp", "tcp", "dns", "ssl"]   # Which checks this worker can run
  labels:
    location: "nyc"                                 # Required — where this worker is
    environment: "production"                       # Optional — extra matching labels
  max_concurrent: 10                                # Max simultaneous checks
  poll_interval_secs: 5                             # How often to ask for new jobs

# Log level: trace, debug, info, warn, error (default: info)
log_level: "info"
```

### Labels and matching

A job is assigned to a worker only if **all** worker labels match the check's
requirements. The special `location` label must match one of the check's `locations`.

```yaml
# This check runs in nyc on worker nodes tagged with environment=production
locations: ["nyc"]
labels:
  environment: "production"
```

### Capabilities

A worker must declare the check types it can run. Remove capabilities you don't
want this worker to handle:

```yaml
worker:
  capabilities: ["http", "icmp"]   # Only web and ping checks
```

Skip `icmp` to avoid installing the `ping` binary. ICMP and DNS checks use system
binaries (`ping`, `dig`) — they must be installed on the worker node.

### Draining a worker

Set `max_concurrent: 0` and restart. The worker will send heartbeats but not accept
new jobs. Pending jobs timeout and get reassigned.

---

## Start the worker

```bash
# Installation (same RPM as the system agent)
dnf install vespid-agent-1.0.0-1.el9.x86_64.rpm

# Edit the worker config
vim /etc/vespid-agent/worker.yaml

# Start
systemctl enable --now vespid-worker
systemctl status vespid-worker
journalctl -u vespid-worker -f
```

## Dual-mode on the same host

You can run both modes on one machine — system agent collecting metrics and
worker running synthetic checks — with two separate services:

```bash
systemctl enable --now vespid-agent    # System metrics collector
systemctl enable --now vespid-worker    # Synthetic check worker
```

Each uses its own config file (`agent.yaml` vs `worker.yaml`). The same binary
handles both modes via the `--mode` flag.

---

## Creating checks (web UI)

1. Navigate to **Synthetic Checks** in the sidebar
2. Click **New Check**
3. Choose check type, enter target, configure success criteria
4. Select locations, set interval and timeout
5. The scheduler picks it up within 10 seconds

## Creating alert rules (web UI)

1. Navigate to **Synthetic Alerts** in the sidebar
2. Click **New Alert Rule**
3. Select the check and notification channel(s)
4. Choose alert condition type:
   - **Failure Count**: fires after N consecutive failed checks
   - **Metric Threshold**: fires when a metric crosses a threshold for N consecutive checks
5. Set severity and save

Alert rules are evaluated every 10 seconds alongside the scheduler. A resolved
alert re-arms after the condition stops being true.

### Default Alert Policies

When a check is created, the system can auto-create an alert rule for it using
one of the following **default alert policies**. Each policy targets a specific
check type and condition:

| Policy               | Check type | Condition               |
|----------------------|------------|-------------------------|
| SSL Certificate Expiry | ssl      | days_remaining < 14     |
| HTTP Failure         | http       | 3 consecutive failures  |
| TCP Failure          | tcp        | 3 consecutive failures  |
| DNS Failure          | dns        | 3 consecutive failures  |
| DNS Answer Change    | dns        | 1 change, persist until resolved |

For DNS checks, the system picks the right policy based on your check config:
- If you set an **Expected Value** → **DNS Failure** is used (alerts when the
  resolved answer doesn't match, after 3 tries)
- If you leave **Expected Value** blank → **DNS Answer Change** is used
  (alerts whenever the answers change between runs, and keeps firing until
  manually acknowledged)

You can toggle each policy on/off, edit the auto-created rule, or create a
custom rule that prevents the policy from applying. A checkbox on the New Check
form lets you opt out of auto-creation entirely.

---

## Check lifecycle

```
active ─────► check runs every interval_secs
  │
  ▼
job created (status=pending)
  │
  ▼
worker picks up (status=assigned, assigned_at set)
  │
  ├── success ► (status=completed, result posted, check updated)
  │
  └── timeout ► (status=timed_out, reassigned up to max_attempts)
       │
       └── after max_attempts ► (status=failed)
```

## Server-side scheduler

The scheduler runs every 10 seconds inside the gunicorn worker process (started
via `post_fork`). It handles:

- Finding checks due for execution (jitter: interval ± random(interval/8))
- Matching workers by capabilities and labels (filters on `location` match first)
- Creating job records with `status=pending`, notifying via SSE
- Reassigning timed-out jobs (worker heartbeated but didn't complete in time)
- Marking workers stale (no heartbeat in 60s) and reassigning their pending jobs
- Purging job history older than 30 days
- Evaluating alert rules (both failure count and metric threshold conditions)

## Retention

Job history is retained for **30 days**. After that, old jobs are purged. The
`synthetic_checks` table carries the latest result (`last_result_status`,
`last_duration_ms`, `last_result_at`, `last_error`) for dashboard display
regardless of job purge.

---

## Metrics published to VictoriaMetrics

Each completed job pushes these metrics (Prometheus text format to `/api/v1/import/prometheus`):

| Metric                                | Check types | Labels                            | Description                     |
|---------------------------------------|-------------|-----------------------------------|---------------------------------|
| `vespid_synthetic_check_duration_ms`| all        | check_id, check_name, check_type, location | Total execution duration  |
| `vespid_synthetic_check_success`    | all        | check_id, check_name, check_type, location | 1 = success, 0 = failure        |
| `vespid_synthetic_check_status_code`| http      | check_id, check_name, check_type, location | HTTP status code                |
| `vespid_synthetic_check_rtt_ms`     | icmp       | check_id, check_name, check_type, location | ICMP average round-trip time    |
| `vespid_synthetic_check_body_match` | http       | check_id, check_name, check_type, location | 1 = body matched, 0 = not       |
| `vespid_synthetic_check_dns_answers`| dns        | check_id, check_name, check_type, location | Number of DNS answers returned  |
| `vespid_synthetic_check_connect_time_ms` | tcp        | check_id, check_name, check_type, location | TCP connection time             |
| `vespid_synthetic_check_days_remaining` | ssl        | check_id, check_name, check_type, location | Days until certificate expires  |

### PromQL examples

```promql
-- Average ping RTT over last hour
avg_over_time(vespid_synthetic_check_rtt_ms{check_name="Homepage"}[1h])

-- Uptime: percentage of successful checks in last 24h
avg_over_time(vespid_synthetic_check_success{check_name="API"}[24h]) * 100

-- Count currently failing checks
count(vespid_synthetic_check_success == 0) by (check_name)

-- HTTP 5xx errors in last 5 minutes
vespid_synthetic_check_status_code{check_name="API"} >= 500

-- DNS answer count changes (fewer answers might indicate problems)
delta(vespid_synthetic_check_dns_answers{check_name="MX Lookup"}[5m])
```

### Using PromQL for alerting (optional)

If you prefer PromQL-based alerts over the built-in alert rules, query
VictoriaMetrics directly:

```promql
# Alert: Ping latency > 1000ms for 5 minutes
avg_over_time(vespid_synthetic_check_rtt_ms{check_name="Homepage"}[5m]) > 1000

# Alert: HTTP errors in last 5 minutes
rate(vespid_synthetic_check_success{check_name="API"}[5m]) < 1
```

---

## Troubleshooting

**Worker not picking up jobs:**
- Check `journalctl -u vespid-worker -f` for registration errors
- Verify `server.api_key` has agent role
- Verify `worker.labels.location` matches a check's `locations`
- Verify `worker.capabilities` includes the check type
- Check scheduler logs: `grep check_scheduler /var/log/vespid-server/vespid-server.log`

**ICMP checks failing:**
- `ping` binary must be installed and the worker user must be able to execute it
- Some VPS providers block raw ICMP — the check will report timeout

**DNS checks failing:**
- `dig` binary must be installed (from `bind-utils` package on RHEL, `dnsutils` on Debian)

**SSL checks failing:**
- `openssl` binary must be installed and the worker user must be able to execute it
- Verify the target is reachable over HTTPS: `openssl s_client -connect host:port`
- Chain validation failures (verify error) indicate a misconfigured intermediate or root CA

**Checks failing due to success criteria:**
- HTTP status outside `expected_status` range (default: 200-399)
- Body text not found (if `body_match` is set)
- Response time exceeding `max_duration_ms`
- DNS answer doesn't contain `expected_value`
- ICMP RTT exceeding `max_rtt_ms`
- TCP connect time exceeding `max_connect_ms`
- Check logs for the specific error message in the failure detail

**Alert rules not firing:**
- Failure alerts require N consecutive failures with no success in between — a single success resets the counter
- Metric alerts require N consecutive checks where the condition is true
- Verify the notification channel works: test it from the Alerts page first
- Check scheduler logs for alert evaluation: `grep "Synthetic.*alert" /var/log/vespid-server/vespid-server.log`

**VictoriaMetrics data not appearing:**
- Verify `VICTORIAMETRICS_URL` is set in server config
- Confirm VM is running: `curl http://localhost:8428/api/v1/query?query=up`
- Check server logs for push errors: `grep "Failed to push" /var/log/vespid-server/vespid-server.log`
