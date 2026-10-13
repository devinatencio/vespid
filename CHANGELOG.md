# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Multi-signal correlation no longer counts ordinary successful HTTP responses
  (`apache_other` / `haproxy_other`) as a distinct signal category. A
  legitimate browser session that mixes normal 2xx traffic with a transient
  4xx or TLS handshake failure — exactly what an ISP IP rotation produces —
  could otherwise cross `min_categories` and trigger a false-positive
  `RECON_CORRELATION` block.

## [1.0.2] - 2026-10-12

### Added

- **Automatic packaging toolchain install** — `make package` (and
  `package-rpm`/`package-deb`) now depends on `package-deps` and installs the
  host's build toolchain before compiling: RPM/DEB build tools,
  `systemd-rpm-macros`, `python3-devel`, `protobuf-compiler`, and a rustup Rust
  toolchain (>= 1.85). The step is idempotent and installs only what is
  missing, so a fresh clone can go straight to `make package`.

### Fixed

- The file tailer no longer mistakes a **rename-style rotation** for an
  in-place truncation. When `logrotate` (or `auditd`) renamed the live file
  away and created a smaller one at the same path, the truncation check
  compared the *new* file's size against the *old* open handle's offset and
  rewound the stale handle forever — re-reading the rotated-out file in a tight
  loop and never following the new one (observed as endless
  `truncated in place ... rewinding to start` lines for
  `/var/log/audit/audit.log`). The check now confirms the path still resolves
  to the open inode before treating a size decrease as an in-place truncation.
- The Rust agent's RPM/DEB build scripts now derive their version from the
  component spec instead of a hardcoded literal, so the source tarball name and
  package metadata can no longer drift from `%{version}`.

## [1.0.1] - 2026-10-08

### Added

- **Runtime log-source reconciliation** — log sources added by a configuration
  profile are tailed immediately, and sources removed by a profile have their
  tailer stopped, without a daemon restart. The tailer set was previously built
  once at startup, so profile-added sources were silently ignored until the
  daemon was restarted.
- **Detection rule pack update workflow** — `vespid-server-admin rules update`
  validates, diffs and applies a pack bundle from a directory, a `.tar.gz`/`.zip`
  archive, or an `http(s)://` URL. `rules export` builds distributable bundles
  and `rules status` shows installed packs and their provenance. Applying a
  bundle backs up the previous packs (`packs/.backups/<timestamp>/`) and
  reconciles the database non-destructively. See the new *Rule Pack Updates*
  documentation and the updated *Sigma Rule Integration* guide.
- The Sigma importer now writes `packs/manifest.json` (source commit + per-file
  SHA-256 + rule counts) and can build a distributable bundle in one step:
  `python -m vespid.scripts.sigma_import --sync --bundle dist/sigma-packs.tar.gz`
  (also supports `--output-dir DIR`). A `make sigma-bundle` target wraps this.

### Changed

- Pack reconcile now handles upstream rule **renames** by stable Sigma UUID
  (renaming in place rather than creating a duplicate) and **retires** pristine
  rules that a pack no longer ships. User-enabled and user-edited rules are
  still preserved.

### Fixed

- The file tailer now survives `logrotate` **`copytruncate`** rotation and any
  in-place truncation: it detects a shrunk file (same inode) and saved offsets
  that point past EOF, and rewinds instead of stalling. HAProxy attack detection
  was silently lost after the first rotation.
- A configuration profile could not **remove** a log source it had added
  previously: conflict resolution compared the profile against the
  already-mutated in-memory configuration, so a server-added source looked
  "local" and was never removed. Resolution now uses a pristine startup baseline.
- Server: per-node active-parser resolution replaced the node's heartbeat
  `active_parsers` with the profile's `log_sources`, so detection packs for
  unlisted sources (e.g. HAProxy) stopped being distributed. It now unions the
  profile parsers with the heartbeat parsers.
- The Sigma importer imported every SSH rule twice because it scanned both
  `rules/linux/builtin` and its child `rules/linux/builtin/sshd`.
- Converted Sigma rules containing mid-pattern inline regex flags (e.g. `(?i)`)
  compiled on older Pythons but failed on Python 3.11+; flags are now hoisted to
  the start of the pattern.

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

[1.0.2]: https://github.com/vespid/vespid/releases/tag/v1.0.2
[1.0.1]: https://github.com/vespid/vespid/releases/tag/v1.0.1
[1.0.0]: https://github.com/vespid/vespid/releases/tag/v1.0.0
