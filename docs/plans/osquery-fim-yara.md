# Plan: osquery-driven FIM + YARA in Vespid

- Status: approved / in progress
- Owner: devin
- Related docs: `docs/HOST_THREAT_DETECTION.md`, `docs/CENTRALIZED_CONFIG_MANAGEMENT.md`
- Confirmed decisions:
  1. Integration target: **Python security daemon** (`vespid/` + `vespid-server/`), mirroring the auditd pipeline.
  2. Data path: **tail osqueryd results log** (JSON lines) for evented FIM/YARA + `osqueryi --json` for on-demand scans.
  3. Server scope: **full pipeline** — new event kinds, DB table, validation module, config/rule distribution, dashboard section.
  4. Deployment: **osqueryd as a separate privileged systemd service**; the Vespid agent stays non-root.

## Goal

Wire the already-installed `osqueryd` on the demo box into the Python security
daemon so Vespid can:

1. Detect changes to critical files (FIM via osquery `file_events` table).
2. Run YARA rules (evented `yara_events` table + on-demand `yara` table scans).

Findings flow into the Vespid server dashboard the same way auditd host detections
do today.

## How osquery provides each capability

osqueryd writes JSON lines to `/var/log/osquery/osqueryd.results.log`; each line has
`name` (query/table name), `action` (`added`/`removed`), and `columns` (the row).

- **FIM** — `file_events` table (needs `--enable_file_events=true` + `file_paths` config).
  `columns` = `action` (`CREATED`/`MODIFIED`/`DELETED`/...), `target_path`, `category`,
  `sha256`, `size`, `uid`, `mode`, `time`.
- **YARA (evented)** — `yara_events` table (needs `--enable_yara_events=true` + `yara`
  config + `/etc/osquery/yara.conf`). `columns` = `target_path`, `matches`, `count`,
  `sig_group`, `sigfile`, `category`.
- **YARA (on-demand)** — `osqueryi --json "SELECT * FROM yara WHERE path=... AND sigfile=...;"`
  (or `sig_group`); also `hash`/`file` tables for hash baselines.

This mirrors the auditd pattern exactly: agent tails an external daemon's log,
parses, detects, publishes `SecurityEvent`s.

## Phase 0 — osqueryd on the demo box (external, manual setup)

Deliver sample configs under `vespid/config/osquery/`:

- `osquery.flags` — `--enable_file_events=true`, `--enable_yara_events=true`,
  `--logger_path=/var/log/osquery`, `--database_path=/var/lib/osquery/osquery.db`.
- `osquery.conf` — `file_paths` (critical dirs: `/etc`, `/usr/local/etc`, `/var/www`,
  sshd config, ...), `yara` section mapping path groups → sig groups, plus a couple
  scheduled queries.
- `yara.conf` — sig-group → rule-file mapping.
- `osqueryd.service` — separate privileged unit (root/`CAP_DAC_OVERRIDE`), since the
  Vespid agent stays non-root (its systemd sandbox has `NoNewPrivileges` +
  `CAP_DAC_READ_SEARCH` only).

## Phase 1 — Agent-side (`vespid/`)

New `vespid/osquery/` package, modeled on `vespid/auditd/`:

- `prerequisites.py` — advisory check that `osqueryd` is installed/running and the
  right flags are set (copy `auditd/prerequisites.py`).
- `events.py` — frozen dataclasses `FileChangeEvent` (`target_path`, `action`,
  `category`, `sha256`, `uid`, `mode`, `time`) and `YaraMatchEvent` (`target_path`,
  `matches`, `count`, `sig_group`, `sigfile`).
- `parser.py` — JSON-line parser for the results log; routes by `name == "file_events"`
  vs `"yara_events"`.
- `detector.py` — immediate-match (like `HostDetector`), severity mapped by
  category/`target_path` (e.g. `/etc/shadow`, `/etc/ssh` → critical/high; yara match →
  high; benign → informational). No scoring curve needed for v1.
- `yara_scanner.py` — optional on-demand `osqueryi --json` scans of configured targets.

Wiring changes:

- `vespid/config.py:369` — add `OsqueryConfig` dataclass (`enabled`,
  `results_log_path`, watch categories, yara rule dirs, scan targets/interval),
  alongside `AuditdConfig` at `config.py:310`.
- `vespid/log_parsers.py` — add `_osquery_passthrough_parser` (mirror
  `_auditd_passthrough_parser` at line 538).
- `vespid/log_processor.py` — spawn an osquery results-log tailer reusing `tail_file`
  (mirror `_spawn_auditd_tailer_tasks` at line 142); add `_process_osquery_line` →
  `_publish_osquery_event` publishing `SecurityEvent`s with
  `event_kind: "file_change"` / `"yara_match"` (mirror `_publish_host_threat` at line 288).
  **Tailer startup**: seek to `SEEK_END` on launch to avoid replaying stale log entries;
  use inotify with poll fallback; handle log rotation by detecting inode change and
  re-opening the new file.
- `vespid/daemon.py:124` — wire `on_osquery_updated=self.logproc.update_osquery_config`
  into `ConfigSubscriber`, construct the osquery pipeline in `__init__` (mirror auditd wiring).
- `vespid/databus.py:252` — confirm new `event_kind`s pass the noise filter
  (they will — filter only drops `LOG_MATCH`/`DETECTED`/fleet).
- `event_kind` naming: use `"file_change"` and `"yara_match"` for now; if more integrity
  event types are added later (e.g. registry, DNS), consider `"file_integrity_event"` as
  the umbrella kind.

## Phase 2 — Server-side ingest & storage (`vespid-server/`)

- `app/routes/api.py:209-251` — extend the `host_threat` batch-split to route
  `file_change`/`yara_match` events to a new handler.
- `app/file_integrity_ingest.py` — new module mirroring `app/host_ingest.py`:
  `validate_file_change` / `validate_yara_match` / `store_*`.
- `schema_mysql.sql` — new `file_integrity_events` table mirroring `host_events` at
  line 848 (`target_path`, `action`, `category`, `sha256`, `matches`, `sig_group`,
  `severity`, `raw_line`, `node_id`, ...), plus the matching SQLite DDL in the DB init
  module. Add a versioned migration (`migrations/0XX_file_integrity_events.sql`) so the
  new table is created on upgrade without manual DDL.

## Phase 3 — Config/rule distribution + dashboard

- `vespid-server/app/routes/rules.py:1158` — extend `distribution()` payload with an
  `osquery` section (`fim_paths`, `yara_groups`) + yara rule pack content (ETag-aware,
  like existing).
- `vespid-server/packs/` — new YAML packs (e.g. `osquery-fim.yaml`, `yara-rules.yaml`)
  loaded via existing `pack_loader.py`.
- `vespid-server/app/routes/config_mgmt.py` — add an `osquery` profile section so server
  pushes config to agents via `ConfigSubscriber._apply_osquery` (mirror `_apply_auditd`
  at `config_subscriber.py:1132`).
  **Config drift detection**: after pushing config, trigger `osqueryctl config-check`
  (or equivalent) to validate; log a warning if osqueryd's active config differs from
  the expected state.
- Agent `vespid/rule_subscriber.py` — parse the new `osquery`/`yara` payload; write YARA
  rule files to a path osqueryd reads (e.g. `/var/osquery/yara/`); hot-reload hook.
  **Atomic writes**: write to a temp file then `os.rename()` (atomic on same filesystem) to
  prevent osqueryd reading a half-written rule file.
- `app/routes/host_threats.py` — add a File Integrity / YARA section (or new blueprint)
  rendering `file_integrity_events`.

## Phase 4 — On-demand scans + hardening (stretch)

- **Primary path**: run YARA scans as **scheduled queries inside osqueryd** (emitted to
  the results log) so the agent never needs elevated reads. This avoids the privilege
  escalation concern entirely.
- **Fallback path** (on-demand `osqueryi`): caveat — `osqueryi` reads files as the calling
  user, so the non-root agent can't scan `/etc/shadow`-class files. Options: restrict
  on-demand scans to agent-readable paths for the demo, or scope a `sudoers` NOPASSWD
  rule to `osqueryi` only. Preferable long-term: run these as scheduled queries inside
  osqueryd so the agent never needs elevated reads.

## Testing

- **Unit (agent)**: pytest for parser/detector/publisher with fixture result-log JSON
  lines (mirror `tests/`), incl. malformed/partial lines and log rotation.
- **Unit (server)**: validation + storage tests for the new event kinds (mirror
  `host_ingest` tests).
- **Demo-box smoke**: `touch` a watched file → `file_change` event on the dashboard;
  drop an EICAR test file into a scanned dir → `yara_match`. Run `make test` / `ruff`
  for the touched packages.
- **Integration (agent)**: tail a synthetic results log file end-to-end — write JSON lines
  to a temp file, verify the correct `SecurityEvent`s are published with expected fields
  and severity.

## Open considerations

- No new Python dependencies required (stdlib `json` + `subprocess`) — osqueryd does the
  heavy lifting.
- YARA rule lifecycle: rules distributed by the server need osqueryd to reload its config
  to pick up new sig files (restart or `osqueryd --config_check`); the on-demand `yara`
  table with explicit `sigfile` avoids that entirely for targeted scans.
- Severity is a flat map for v1; the auditd scorer/mode-manager can be grafted on later
  if you want learning/alerting tiers.
- **Alerting stub**: v1 sends events to the dashboard only. For a future iteration, add a
  webhook/email notification hook for `critical` severity events (e.g. file integrity
  violations in `/etc/shadow` or YARA matches) — even a stub `notify()` call with a log
  line is worth adding now so the hook point exists.

## Task tracking

- [ ] Phase 0 — osqueryd configs under `vespid/config/osquery/` + demo-box setup
- [ ] Phase 1 — agent-side `vespid/osquery/` package + wiring
- [ ] Phase 2 — server-side ingest, validation, `file_integrity_events` table
- [ ] Phase 3 — config/rule distribution + dashboard section
- [ ] Phase 4 — on-demand scans + hardening (stretch)
- [ ] Unit tests (agent + server) + demo-box smoke test
