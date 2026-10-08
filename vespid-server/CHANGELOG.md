# Changelog

## Unreleased

## 1.0.1 — 2026-10-08

### Added
- `vespid-server-admin rules` CLI:
  - `rules update` — validate, diff and apply a rule pack bundle from a directory,
    a `.tar.gz`/`.zip` archive, or an `http(s)://` URL, with a confirmation
    prompt, `--check`, `--dry-run`, and `--yes` modes
  - `rules export` — build a distributable pack bundle (directory or archive) with
    a `manifest.json`
  - `rules status` — list installed packs, rule counts, and bundle provenance
- Bundle validation before applying anything: regexes must compile on the
  server's Python, log-based rules must include a `(?P<ip>…)` group, rule names
  must be unique, and thresholds must be sane
- Automatic backup of the previous packs to `packs/.backups/<timestamp>/` on
  every apply
- `manifest.json` provenance (source commit + per-file SHA-256 + rule counts),
  written by the Sigma importer and carried through `rules export`

### Changed
- Pack reconcile is now **rename-aware** — a rule renamed upstream (same Sigma
  UUID, new name) is renamed in place instead of inserting a duplicate, and
  pristine pack rules that a pack no longer ships are **retired**
- User-edited (`user_modified`) rules are still never touched by reconcile
- `_seed_apache_attack_templates` (the pack reconcile) accepts an explicit packs
  directory, used by the update command

### Fixed
- Per-node active-parser resolution replaced the node's heartbeat
  `active_parsers` with the profile's `log_sources`, so detection packs for
  sources the profile didn't list (e.g. HAProxy) stopped being distributed.
  It now unions the profile parsers with the heartbeat parsers.
- Sigma importer double-counted every SSH rule because `rules/linux/builtin/sshd`
  and its parent `rules/linux/builtin` were both scanned; the importer now
  deduplicates by Sigma UUID and by rule name
- Converted Sigma regexes containing mid-pattern inline flags (e.g. `(?i)`)
  compiled on older Pythons but raised `re.error` on Python 3.11+; flags are now
  hoisted to the start of the pattern

## 1.0.0 — 2026-08-02

### Initial Release

**Dashboard & UI**
- HTMX-powered web dashboard with real-time updates
- Event search/filter page with SQL-like query support
- Node management page with health status, block lists, and feed toggles
- Geographic breakdown page with country-level threat visualization
- Trend charts (Chart.js) with time-series analytics
- Per-IP detail pages with reputation scoring via Intel dashboard
- Role-based access control (admin, analyst, viewer)
- Responsive mobile layout
- Dark and light theme support

**Configuration Management**
- Configuration profiles with templated settings for telemetry, network, fleet, rules, feeds, log sources, detection packs, and auditd monitoring
- Agent groups for bulk profile assignment
- Staged rollout engine for gradual configuration deployment
- Per-node effective configuration resolution with layered merging

**API**
- Bearer-token and session-based authentication
- RESTful API with automatic OpenAPI/Swagger documentation
- Event ingestion API with batch processing (rate-limited per key)
- Fleet-wide blocklist management with propagation engine
- SSE streaming for real-time config, fleet, and alert updates
- Agent enrollment with key binding and automatic profile assignment
- Rate limiting with Redis backend (configurable per-API-key and per-node)

**Threat Intelligence**
- Centralized intelligence feed management (12 pre-seeded feeds)
- Automatic feed fetching, parsing (CIDR, plain, JSON), and block creation
- Reputation scoring engine with attack vector analysis
- Repeat offender tracking and trend analytics
- Fleet block propagation to all enrolled nodes
- Allow-list support for suppressing known-safe IPs

**Detection**
- Detection rule engine for brute-force and custom patterns
- Rule packs loaded from YAML (Apache, NGINX, HAProxy, OpenSSH, Postfix, CMS probes, and Sigma rule sets)
- HAProxy log parsing for HTTP and TCP modes — including default `option httplog` lines (optional `%sq/%bq` queue field) and SSL/TLS handshake-failure detection (`haproxy_ssl_handshake_probe`) for cipher/TLS scanning
- Live rule-pack reload from disk — admin **Reload Packs from Disk** button / `POST /api/v1/rules/packs/reload` picks up edited packs and pushes changes to agents without a server restart
- Non-destructive, content-addressed pack reconcile — new rules are inserted disabled, pristine rules are refreshed when their shipped definition changes (the user's enabled state is preserved), and user-edited rules are left untouched (tracked via per-rule `content_hash` + `user_modified`)
- Restart-safe detection — content-based event IDs plus persisted detector state (sliding-window buckets and correlation cooldowns) prevent duplicate events, fleet-block re-processing, and re-detection floods after a restart or log catchup; event timestamps reflect when the attack occurred
- Host-based threat detection via auditd integration
- Log source auto-detection (Debian, RedHat, SUSE)
- Configurable threshold rules per profile

**Host Threats Dashboard**
- Dedicated Host Threats dashboard with per-host threat scoring using exponential time-decay (configurable half-life and alert threshold)
- Kill chain timeline visualization mapping detections to MITRE ATT&CK tactics
- Threat Score History charts with a selectable time window (1h–7d) and 288-point timeseries
- Active host threats production view sorted by score, with per-host summary cards
- Noise analysis panel with rule-level suppression, grouping, and thresholding per config profile
- Process tree visualization for forensic investigation
- Host learning/detecting/alerting modes with episode-based alert notifications and cooldown

**Synthetic Checks**
- Synthetic monitoring checks (HTTP, HTTPS, TCP, DNS, ICMP)
- Configurable check intervals, timeouts, and thresholds
- Per-check status timeline and failure alerts
- Geographic distribution of check results

**Alerts**
- Multi-channel alert evaluation engine (email, webhook, Slack)
- Configurable alert rules with time-window aggregation
- Monitoring groups with alert routing
- Alert dashboard with filtering, acknowledgment, and suppression

**Metrics**
- VictoriaMetrics integration for host-level metrics collection
- Dashboard pages for overview, host detail, query explorer, and checks
- Prometheus-compatible metric export
- Agent heartbeat and health monitoring

**Inventory**
- Asset inventory with provider synchronization (Proxmox support)
- Asset deduplication, merging, and alias management
- Stale asset detection and pruning
- Inventory dashboard with provider view

**GeoIP**
- MaxMind-compatible MMDB database support (bundled DB-IP Lite)
- IP-to-country, IP-to-city, and IP-to-ASN resolution
- Automatic database discovery with environment variable overrides
- Geographic trend analysis and visualization

**Operations**
- CLI wrapper (`vespid-server-admin`) for common management tasks
- Database backup scheduler with automatic purging
- SQLite (default) and MySQL/MariaDB backend support
- Migration from SQLite to MySQL included
- Schema migration from SQL to SQLite included
- Configurable retention policies for events, alerts, and commands
- Connection debug monitor with JSON-lines snapshot log and localhost-only `/_debug/connections` endpoint for diagnosing worker saturation and slow requests

**Security**
- Random SECRET_KEY generation on first install
- CSRF protection on all browser-submitted forms
- Audit logging for all administrative actions
- API key management with scoped permissions
- Bearer token authentication for API endpoints
- Rate limiting on all API endpoints
- No hardcoded secrets — all credentials in config with env var overrides

**Deployment**
- Systemd service with security hardening (NoNewPrivileges, ProtectSystem, PrivateTmp, ReadWritePaths)
- Gunicorn with gevent workers for high concurrency
- Pre-configured environment file for tuning worker count and bind address
- RPM package (RHEL/CentOS/Fedora) with automatic venv and database setup
- DEB package (Debian/Ubuntu) with automatic venv and database setup
- Graceful reload support via systemctl reload
- Structured logging with JSON option for SIEM integration
- Health check endpoints (`/healthz`, `/readyz`)

### Configuration Reference

Full configuration documentation is in [README.md](README.md#configuration-reference).
All settings support `VESPID_` environment variable overrides.

### Upgrade Notes

- First install auto-creates an admin user with a generated password (displayed in install output)
- DB-IP Lite GeoIP databases are pre-installed — no manual setup needed
- To use MaxMind GeoLite2 databases instead, replace the `.mmdb` files in `/etc/vespid-server/geoip/`
