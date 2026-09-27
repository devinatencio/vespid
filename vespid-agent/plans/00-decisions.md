# 00 — Design Decisions & Tradeoffs

## Final Architecture Summary

HiveMonitor is a lightweight monitoring subsystem that extends the existing Vespid
Flask server with metrics collection and visualization. A Rust agent collects system
metrics from Linux hosts and ships them via HTTP to the Flask server, which forwards
them to VictoriaMetrics for storage and querying.

## Key Decisions

### 1. Extend Flask server — do NOT build a new Rust server

**Why:** The existing Vespid Flask server already has auth, RBAC, SSE streaming,
a working dashboard with 14+ pages, enrollment, config management, and chart.js
vendored in static assets. Adding a "Metrics" nav item with a few new pages is a
weekend of work.

**Tradeoff:** Flask won't handle 10,000 concurrent dashboard users. It will handle
50 operators comfortably. If/when UI outgrows Flask, swap to React incrementally.

### 2. Rust agent, NOT Python agent for monitoring

**Why:** The Rust agent is a static binary (~5MB), 10-20MB idle memory, zero runtime
dependencies. The existing Python agent (Nuitka) is 100MB+ with 40-80MB idle memory.
For a monitoring agent that reads /proc constantly, Rust's zero-cost abstractions
and direct syscall access matter.

**Tradeoff:** Learning curve. Rust async requires understanding. Mitigated by the
agent being a small, focused codebase (~2000 lines).

### 3. VictoriaMetrics for metrics, MariaDB for metadata

**Why:** MySQL is not a time-series database. Storing metrics in MySQL means you
write schema migrations, partition management, index tuning, rollup queries, retention
pruning, and custom SQL for every chart — forever. VictoriaMetrics is one binary,
one command, zero ongoing maintenance. PromQL is purpose-built for metric queries.

**Tradeoff:** One more binary to run. But `victoria-metrics-prod` is 10MB, uses
50MB RAM idle, and requires zero configuration beyond `-retentionPeriod=90d`.

### 4. HTTP batch POST, NOT gRPC streaming

**Why:** Prometheus remote write over HTTP is an industry standard. It works through
any proxy, needs no protobuf service definition, and is sufficient for thousands of
agents. gRPC adds codegen, schema management, and complexity with no benefit at this scale.

**Tradeoff:** No real-time streaming push from server to agent. Not needed — agents
poll config, push metrics. The direction is always agent → server.

### 5. 60-second collection interval, NOT 10-second

**Why:** System monitoring doesn't need sub-minute granularity. "Disk filling up,"
"CPU hot," "service down" — all visible at 60s. 10s is Prometheus convention, not
an operational requirement for system-level monitoring.

**Tradeoff:** Can't see sub-60-second spikes. For system monitoring (not application
profiling), this is fine. Configurable per-collector if needed.

### 6. Separate agent binary — coexist with security agents

**Why:** The hivemonitor-agent runs alongside vespid-scout (Go security agent) and
the Python agent on the same host. They share nothing except the host. Each does one
thing well.

**Tradeoff:** Two agents to deploy per host instead of one. Mitigated by the agent
being a single static binary — `scp` one file, drop in a systemd unit.

### 7. 5 collectors for V1, NOT 12+

**Why:** CPU, memory, disk, network, and systemd cover 95% of operational monitoring
needs. Process, kernel, SELinux, nftables, PSI, packages are nice-to-have but don't
need to block V1.

**Tradeoff:** Operators can't see per-process metrics or SELinux state in V1. They
have `top`, `ps`, and `sestatus` for that until V2.

### 8. Compiled-in collectors, NO plugin system

**Why:** A plugin system (.so loading, subprocess IPC, WASM) is months of work and
a maintenance burden. Compiled-in collectors via a trait are 50 lines each. All V1
collectors read /proc — no external dependencies to manage.

**Tradeoff:** New collectors require recompiling the agent. For a Rust binary that
compiles in 60 seconds, this is fine for V1/V2.

### 9. Prometheus remote write format as the wire protocol

**Why:** Industry standard. Compatible with VictoriaMetrics, Prometheus, Thanos,
Mimir, Cortex. No lock-in. Any future TSDB migration requires zero agent changes.

**Tradeoff:** The format is protobuf + snappy compression — slightly more complex
to generate than plain JSON. Trivial with the `prometheus` Rust crate.

### 10. Simple API key enrollment, NOT mTLS

**Why:** The existing Vespid already uses API keys for agent enrollment. It works.
mTLS is more secure but adds CA management, certificate rotation, and enrollment
complexity no one will appreciate in V1.

**Tradeoff:** Shared secrets are less secure than certificates. Acceptable for V1.

## Technology Stack Summary

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Agent | Rust (tokio, reqwest) | Static binary, low resources, /proc parsing speed |
| Server | Python Flask (extend existing) | Already exists, already has auth/dashboard |
| Metrics storage | VictoriaMetrics | Purpose-built, zero config, PromQL |
| Metadata storage | MariaDB (existing) | Already running, already backed up |
| Transport | HTTP batch POST | Standard, simple, sufficient |
| Wire format | Prometheus remote write | Standard, no lock-in |
| UI | Flask/HTMX + chart.js (existing) | Already vendored, no build step |
| Packaging | RPM + systemd | Linux-native, matches existing Vespid |

## Explicitly Avoided

| Avoided | Why |
|---------|-----|
| New Rust server for monitoring | Extend Flask instead |
| React UI (initially) | HTMX + chart.js works now |
| NATS event bus | No need without multiple services |
| gRPC streaming | HTTP is simpler |
| Metrics in MySQL | Not a time-series database |
| Plugin system | Compiled-in is fine |
| 10s collection interval | 60s is sufficient |
| 12+ collectors | 5 covers 95% |
| eBPF, AI, health scoring | V3 territory |
| Multi-tenancy, SaaS | Not needed yet |
| Kubernetes-first design | Linux-first, systemd-native |
