# 05 — MVP Scope & Roadmap

## V1 Scope (Solo Dev, ~6 months)

### What Ships in V1

| Component | Scope | Est. Effort |
|-----------|-------|-------------|
| **hivemonitor-agent** (Rust) | 5 collectors (CPU, Mem, Disk, Net, systemd), HTTP transport, file buffer, config file | 4-6 weeks |
| **Flask metrics blueprint** | `/api/v1/metrics/write` ingestion, PromQL proxy, simple status API | 2 weeks |
| **Flask dashboard** | Fleet overview page, host detail page with gauges + line charts | 3 weeks |
| **VictoriaMetrics integration** | Forward writes, proxy queries, `-retentionPeriod=90d` | 1 week |
| **MariaDB extensions** | Extend nodes table (agent_type, last_seen, etc.) | 1 week |
| **systemd + RPM packaging** | `.spec` for agent, systemd unit, post-install scripts | 2 weeks |
| **Tests + docs** | Integration tests, agent unit tests, README | 2 weeks |
| **Total** | | **15-17 weeks** |

### Collector Detail

| Collector | Source | Key Metrics |
|-----------|--------|-------------|
| CPU | `/proc/stat` | usage %, user %, system %, iowait %, steal % |
| Memory | `/proc/meminfo` | total, available, used, used %, swap total/used/% |
| Disk | `/proc/mounts`, `statfs`, `/proc/diskstats` | space total/used/%, inode %, IO rate, IO latency |
| Network | `/proc/net/dev`, `/sys/class/net/*/statistics` | bytes/packets sent/recv, errors, drops |
| systemd | dbus or `systemctl` | unit active state, sub state, restart count |

### Dashboard Pages

| Page | Content |
|------|---------|
| Fleet Overview | Table of all agents (hostname, status, CPU%, Mem%, Disk% worst, last seen), "attention needed" section |
| Host Detail | For one host: CPU gauge + line chart, memory gauge + line chart, disk gauges per mount, network line chart, systemd failed units |
| `/metrics` nav | New top-level nav item in existing Vespid dashboard |

### Excluded from V1

| Feature | Reason |
|---------|--------|
| Process collector | Added complexity, `top`/`ps` work for now |
| Kernel metrics | Niche use case |
| SELinux state | Security agent already monitors this |
| nftables state | Security agent already manages this |
| PSI metrics | Advanced, deferred |
| Package update awareness | Requires distro-specific package manager polling |
| gRPC streaming | HTTP is sufficient |
| NATS event bus | In-process is sufficient |
| Remote config push | Local config file is fine for V1 |
| Alerting engine | Client-side thresholds in dashboard are enough |
| Health scoring | Needs metric history and tuning |
| Plugin system | Compiled-in is fine |
| eBPF | Advanced, deferred |
| Multi-tenancy | Not needed |
| HA/clustering | Not needed for <500 agents |

## V2 Plan (Months 7-12)

### Additions

| Feature | Effort |
|---------|--------|
| **Process collector** — Top-N by CPU/mem, process count, zombie detection | 1 week |
| **Kernel collector** — tainted state, loaded modules, boot parameters | 1 week |
| **SELinux collector** — enforcing/permissive/disabled, AVC denial count | 1 week |
| **nftables collector** — table/chain/rule count, drops counter | 1 week |
| **Package collector** — updates available count, security updates count | 2 weeks |
| **PSI collector** — `/proc/pressure/*` metrics | 1 week |
| **Alert rules engine** — Server-side PromQL evaluation, threshold comparison, alert event tracking in MariaDB | 3 weeks |
| **Alert notifications** — Webhook integration, basic email digest | 2 weeks |
| **Remote config** — Agent polls server for config updates, applies atomically | 2 weeks |
| **gRPC transport** — Optional gRPC streaming as alternative to HTTP batch | 3 weeks |
| **NATS integration** — Event bus for config push and inter-service comm | 3 weeks |
| **Health scoring v1** — Simple composite score per host based on thresholds | 1 week |
| **React UI** — Begin migration of metric pages to React (HTMX stays for security) | 4 weeks |
| **Multi-node server** — Stateless Flask behind load balancer, shared MariaDB + VM | 2 weeks |
| **Total** | | **26 weeks** (parallelizable to ~16) |

### V1→V2 Breaking Changes

- None. V2 is additive. All V1 agents continue working.
- gRPC is optional alongside HTTP.
- Remote config is opt-in per agent.

## Collector Extension Mechanisms (V2)

Three tiers of collector extensibility, from simplest (zero user code) to fully
custom (arbitrary scripts):

### Tier 1: Compiled-in Collectors (V1/V2)

Already works today. Add a Rust module implementing the `Collector` trait, register
it in `collectors/mod.rs`. Used for all official collectors (CPU, memory, disk,
network, systemd, and V2 additions like process, kernel, SELinux, nftables, PSI,
packages). Static binary, zero runtime overhead, no attack surface.

```rust
// crates/vespid-agent/src/collectors/psi.rs
pub struct PsiCollector;

impl Collector for PsiCollector {
    fn name(&self) -> &'static str { "psi" }
    fn default_interval(&self) -> Duration { Duration::from_secs(60) }
    fn enabled(&self, config: &CollectorsConfig) -> bool { config.psi.enabled }
    fn collect(&self) -> Vec<Metric> { /* read /proc/pressure/* */ }
}
```

Registration is one line in `mod.rs`:
```rust
let psi = psi::PsiCollector;
if psi.enabled(&self.config) { collectors.push(Box::new(psi)); }
```

### Tier 2: Config-driven procfs Collector (V2 — ~200 lines)

A generic collector that reads arbitrary `/proc` and `/sys` values from config.
Covers "I just want to monitor this kernel value" without Rust code.

```yaml
collectors:
  procfs:
    enabled: true
    interval_secs: 60
    metrics:
      - name: "vespid_conntrack_count"
        path: "/proc/sys/net/netfilter/nf_conntrack_count"
        help: "Active connection tracking entries"
        type: gauge

      - name: "vespid_file_nr"
        path: "/proc/sys/fs/file-nr"
        help: "Allocated file handles"
        parse: first_field       # "first_field" | "line_count" | "raw_bytes"

      - name: "vespid_netstat_tcp_timewait"
        path: "/proc/net/snmp"
        help: "TCP connections in TIME_WAIT"
        parse: snmp              # Specialized parser for /proc/net/snmp format
        key: "Tcp.TW"            # Dot-delimited key within parsed map
```

**Parse strategies:**

| Strategy | Use case | Example |
|----------|----------|---------|
| `value` | File contains a single number | `/proc/sys/...` files |
| `first_field` | First whitespace-separated field | `/proc/sys/fs/file-nr` |
| `line_count` | Count non-empty lines | Counting processes in a cgroup |
| `snmp` | SNMP-style key-value | `/proc/net/snmp`, `/proc/net/netstat` |
| `kv_pairs` | `key: value` per line | `/proc/meminfo`-style files |

The collector reads the path on each interval, applies the parse strategy, emits
one metric with the given name. This covers ~80% of custom metric requests.

### Tier 3: Subprocess Collector (V2.5 — ~300 lines)

Runs arbitrary commands and captures their stdout in Prometheus exposition format
or JSON. The user controls the logic entirely via script.

```yaml
collectors:
  exec:
    enabled: true
    interval_secs: 60
    scripts:
      - name: "postgres_connections"
        command: ["/usr/local/bin/pg-connections.sh"]
        timeout_secs: 5

      - name: "smart_health"
        command: ["/usr/local/bin/smart_monitor.py"]
        timeout_secs: 10
        format: prometheus_text     # "prometheus_text" | "json" | "value"
```

**Output format: prometheus_text** (preferred)

```bash
#!/bin/bash
echo "# HELP pg_active_connections Active PostgreSQL connections"
echo "# TYPE pg_active_connections gauge"
echo "pg_active_connections $(psql -tAc 'SELECT count(*) FROM pg_stat_activity')"
```

**Output format: json**

```json
[{"name": "pg_connections", "value": 42, "labels": {"state": "active"}}]
```

**Output format: value**

Just prints a number to stdout. Uses the script name as the metric name.

**Safety guarantees:**
- Each script runs in a child process with a configurable timeout
- stdout is captured to a bounded buffer (256KB max)
- stderr is logged at warn level
- If the script exceeds timeout, the process is killed (SIGTERM → SIGKILL)
- Script failures don't crash the agent — they log an error and retry next interval
- Scripts run sequentially (not concurrently) to prevent resource exhaustion

### Why not dynamic library plugins (.so)?

- **ABI fragility** — Rust doesn't have a stable ABI. Any compiler version change breaks plugins
- **Safety** — `.so` code runs in-process with full memory access. A crash takes down the agent
- **Build complexity** — Plugins must be compiled with the exact same Rust toolchain as the agent
- **Subprocess is safer** — Kernel-enforced isolation, timeouts, memory limits, crash isolation
- **Procfs config covers the simple cases** — 80% of requests don't need a script at all

### Rollout recommendation

| Phase | What ships |
|-------|-----------|
| V1 | Tier 1 only — 5 compiled-in collectors |
| V2 | Tier 1 + Tier 2 — procfs config collector ships alongside V2 compiled-in collectors |
| V2.5 | Tier 1 + Tier 2 + Tier 3 — subprocess collector for arbitrary scripts |

## V3 Vision (Months 13-18)

Advanced features dependent on having enough fleet data and operational experience:

- **eBPF collector framework** — perf events, network observability, syscall tracing
- **AI-assisted anomaly detection** — Train on historical patterns, flag deviations
- **Fleet health scoring v2** — Trend-aware, ML-assisted scoring
- **Topology awareness** — Discover relationships between hosts (services, dependencies)
- **Remediation automation hooks** — Trigger actions on alerts (restart service, scale, notify)
- **Security telemetry correlation** — Correlate monitoring alerts with security events
- **Multi-tenancy** — Organization/tenant isolation for SaaS
- **SaaS deployment model** — Managed platform option
- **HA/clustering** — NATS cluster, VictoriaMetrics cluster, multi-node server with leader election

## Repository Structure

```
hivemonitor/
├── Cargo.toml                    # Workspace root
├── Cargo.lock
├── README.md
├── plans/                        # Architecture docs (these files)
├── crates/
│   ├── hivemonitor-agent/        # Agent binary
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── config.rs
│   │       ├── runtime.rs
│   │       ├── buffer.rs
│   │       ├── transport.rs
│   │       ├── enrollment.rs
│   │       └── collectors/
│   │           ├── mod.rs
│   │           ├── cpu.rs
│   │           ├── memory.rs
│   │           ├── disk.rs
│   │           ├── network.rs
│   │           └── systemd.rs
│   └── hivemonitor-common/       # Shared types
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── metrics.rs
│           └── error.rs
├── packaging/
│   ├── hivemonitor-agent.spec    # RPM spec
│   ├── hivemonitor-agent.service # systemd unit
│   └── postinst.sh
├── deploy/
│   ├── install.sh                # One-line installer
│   └── docker-compose.yml        # Dev environment (VM + MariaDB)
└── tests/
    ├── agent/
    │   ├── test_cpu.rs           # Unit tests against sample /proc data
    │   └── test_buffer.rs
    └── integration/
        └── test_agent_shipping.py
```

**Note:** The Flask server components live in the existing `vespid-server/` repo,
not here. The `hivemonitor` repo is:
1. The Rust agent (this is the main deliverable)
2. Architecturally, it references and extends the existing Vespid server

## CI/CD Recommendations

### Agent (Rust)

- GitHub Actions: `cargo build --release`, `cargo test`, `cargo clippy`, `cargo fmt --check`
- Cross-compile targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`
- Build RPMs for `el9`, `el8`
- Release: Tag triggers release build + GitHub Release with binary artifacts + RPM

### Server (Flask)

- Extend existing Vespid CI if one exists
- Integration tests: start VictoriaMetrics, start agent, POST metrics, verify queries work
- No separate CI pipeline needed — the Flask code is in the Vespid repo

## Testing Strategy

### Agent Tests

| Type | Approach | Coverage |
|------|----------|----------|
| Unit tests | Parse sample /proc files, verify metric output | Each collector |
| Buffer tests | Write metrics, crash, recover, verify no data loss | Buffer module |
| Transport tests | Mock HTTP server, verify Prom remote write encoding | Transport module |
| Integration tests | Real agent → real VM, end-to-end metric delivery | Full pipeline |

### Server Tests

| Type | Approach |
|------|----------|
| Unit tests | Flask test client against metrics blueprint |
| Integration tests | Agent → Flask → VM → query → assert values |
| Load tests | 100 agents simulated, verify no backpressure or dropped metrics |

## Biggest Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Rust async learning curve | Delays agent development | Start with sync /proc parsing in tokio::spawn_blocking |
| /proc parsing edge cases | Incorrect metrics | Extensive unit tests against real /proc dumps from different kernels |
| VictoriaMetrics disk usage | Fills disk, stops ingesting | Retention flag, disk space monitoring, alert on VictoriaMetrics's own metrics |
| Agent crashes on target hosts | Operators lose monitoring | systemd auto-restart, watchdog, file buffer survives restart |
| Scope creep | V1 never ships | This document is the contract. If it's not listed in V1 scope, it ships in V2+ |
| Stale agent cleanup | Confusing fleet view, wasted queries | Auto-decommission agents not seen in 1h (configurable) |

## What Intentionally NOT to Build (Ever or Very Late)

1. **Custom query language** — PromQL is the standard. Never invent your own.
2. **Log aggregation** — This is a metrics platform. Logs are Vespid Security's domain.
3. **APM/tracing** — Separate problem space. Don't conflate with system monitoring.
4. **Windows/macOS support** — Linux-first. Forever.
5. **Dynamic library plugins** (.so/.dylib loading in-process) — Subprocess and config-driven collectors are safer, simpler, and cover all use cases. See [Collector Extension Mechanisms](#collector-extension-mechanisms-v2) for the alternative approach.
6. **Grafana clone dashboard builder** — Opinionated pre-built views.
7. **Complex RBAC beyond admin/operator/viewer** — Simple roles work for the target scale.
8. **Horizontal agent scaling** — One agent per host. Always.
9. **Custom notification system** — Webhook is the escape hatch. Integrate with existing systems.
10. **Container/K8s monitoring** — Host-first. Container awareness is a feature, not the foundation.
