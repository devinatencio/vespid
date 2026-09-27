# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-18

Initial release. Vespid is a lightweight, high-performance security daemon for
Linux systems running nftables.

### Added

- **Agent (`vespid`)** — log-driven intrusion detection and nftables blocking:
  - Sliding-window brute-force detection for SSH, Apache/NGINX, and HAProxy.
  - HAProxy sub-parsers (`haproxy`, `haproxy_bad_request`, `haproxy_not_found`,
    `haproxy_scanner_ua`, `haproxy_ssl_fail`) plus custom log-format support.
  - Multi-signal correlation detection and repeat-offender (recidive) escalation.
  - External subscription feeds, fleet blocklist sharing, and server-managed
    rule/config subscription with offline spooling.
  - GeoIP enrichment (MaxMind / DB-IP) and auditd host-threat detection.
  - `vespid-cli` local management/control plane over a UNIX socket.
- **Server (`vespid-server`)** — Flask dashboard and management server:
  - Event ingestion API, SSE streaming, node inventory, and intel pipeline.
  - Detection-rule packs under `vespid-server/packs/`.
  - Enrollment with credential rotation, role-based access control, alerting.
  - SQLite and MySQL/MariaDB backends.
- **Rust agent (`vespid-agent`)** — system metrics collector and synthetic
  check worker with enrollment support.
- CI for the Python agent (3.10–3.14), the server (3.11, 3.13), and the Rust
  agent (fmt, clippy, tests).

### Fixed

- HAProxy default `httplog` lines dropped the `%sq/%bq` queue field, so common
  access-log lines were silently ignored.
- HAProxy TLS handshake failures (`haproxy_ssl_fail`) were documented and
  expected by the server but never emitted by the agent.
- `repeat_offender` was keyed off total block count instead of distinct
  block→unblock→re-block episodes, contradicting the documented behaviour.
- Enrollment could auto-rotate credentials using a node's own stored host id,
  allowing a caller who knew a `node_id` to obtain a fresh API key without
  credentials.
- The server `nodes` schema drifted between SQLite and MySQL (obsolete
  `last_block_list` column retained on SQLite).
- Missing `requests` dependency in the server.

### Changed

- Packaging consolidated onto `pyproject.toml`; `setup.cfg` removed.
- `vespid-server` is now a standalone project with its own `pyproject.toml`
  and Python requirement (3.11+).
- Ruff and mypy are clean across the Python agent; ruff is clean across the
  server.

[1.0.0]: https://github.com/vespid/vespid/releases/tag/v1.0.0
