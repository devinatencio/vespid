# Vespid Documentation

Vespid is a lightweight, high-performance security platform for Linux
systems running `nftables`.  It consists of two components:

| Component | Purpose |
|-----------|---------|
| **Vespid Agent** | Node-level daemon — tails local logs, detects brute-force and reconnaissance activity, manages `nftables` blocklists, syncs external threat feeds, and communicates with the server for fleet-wide sharing. |
| **Vespid Server** | Centralized dashboard — receives events from agents, provides real-time SSE streaming, fleet blocklist propagation, centralized rule/config management, threat intelligence orchestration, and a web UI with HTMX and Chart.js. |

## Getting started

New to Vespid? Start with the **[Quickstart Guide](quickstart.md)** to get a
single agent and server running in under 10 minutes.

## Quick links

### Agent

- **[Agent Guide](agent/guide.md)** — installation, configuration, detection rules, fleet sharing, management modes
- **[Agent CLI Reference](agent/cli.md)** — all `vespid-cli` commands with examples

### Server

- **[Server Guide](server/guide.md)** — installation, configuration, dashboard pages, enrollment, centralized rules
- **[Server API Reference](server/api.md)** — REST API endpoints (ingestion, heartbeat, commands, SSE, fleet, intel)
- **[Fleet Blocklist Sharing](server/fleet.md)** — propagation engine, corroboration, SSE, offline queuing, recidive
- **[Auto-Enrollment](server/enrollment.md)** — zero-touch agent credential provisioning
- **[Detection Rule Packs](server/rule-packs.md)** — built-in and Sigma-converted detection rules
- **[Noise Suppression](server/noise-suppression.md)** — reducing false positives in host threat detection
- **[Inventory (CMDB)](server/inventory.md)** — asset tracking, entity resolution, relationships
- **[Deployment](server/deployment.md)** — MySQL backend, Gunicorn sizing, database backup, troubleshooting

### Security features

- **[Host Threat Detection](HOST_THREAT_DETECTION.md)** — auditd-based process monitoring, kill chain timeline, threat scoring
- **[Alert Manager](alert-manager.md)** — PromQL and check-based alerting with Slack, email, webhook, and PagerDuty
- **[Intelligence Pipeline](INTEL_PIPELINE_FEATURES.md)** — IP reputation scoring, multi-vector detection, block lifecycle tracking

### Reference

- **[Architecture](architecture.md)** — how the agent and server fit together
- **[Building & Packaging](building.md)** — Debian/RPM packaging and Nuitka compilation
- **[Sigma Rule Integration](SIGMA_INTEGRATION.md)** — converting Sigma rules into Vespid detection packs
- **[Centralized Config Management](CENTRALIZED_CONFIG_MANAGEMENT.md)** — profiles, rollouts, conflict resolution
- **[HAProxy Logging](HAPROXY_LOGGING.md)** — HAProxy log parsing and detection
- **[Allowlist Convergence](ALLOWLIST_CONVERGENCE.md)** — how allowlists sync across agent and server
- **[Threading Architecture](THREADING_ARCHITECTURE.md)** — agent threading model
- **[Connection Debug Monitor](CONNECTION_DEBUG_MONITOR.md)** — server connection diagnostics

## Supported platforms

- **Linux distros:** AlmaLinux, RHEL, Rocky, Debian, Ubuntu, SUSE, openSUSE
  (automatic distro detection with correct default log paths)
- **Python:** 3.10+
- **Database (server):** SQLite (zero-config) or MySQL/MariaDB 8.0+
- **Firewall:** nftables (firewalld coexistence supported)

## Project layout

```
vespid/
├── vespid/               # Agent source
├── vespid-server/        # Server source (Flask + HTMX)
├── docs/                 # Documentation (you are here)
├── config/               # Example config files
├── data/                 # Shared data (country codes)
├── debian/               # Debian packaging
├── rpmbuild/             # RPM build artifacts
├── tests/                # Agent test suite
└── mkdocs.yml            # This doc site config
```
