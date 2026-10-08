# Sigma Rule Integration

Vespid can import detection rules from the [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
community repository — an open standard with over 3,000 peer-reviewed detection
rules maintained by professional detection engineers. Every imported rule is
mapped to [MITRE ATT&CK](https://attack.mitre.org/) technique IDs and can be
kept up to date with upstream releases. Three packs are generated across
web, SSH, and auditd detection surfaces.

---

## Overview

### What is Sigma?

Sigma is a generic, open signature format that describes log events in
structured YAML. It is for log files what Snort is for network traffic and YARA
is for files. Sigma rules are vendor-agnostic and can be converted into
queries for Splunk, Elastic, QRadar, and dozens of other SIEMs.

Vespid imports a subset of Sigma rules — those targeting log sources the
agent already parses — and converts them into Vespid `CustomRule` objects
that run through the existing sliding-window detection engine.

### What gets imported

| Sigma source | Rules | Vespid parser | Example detections |
|---|---|---|---|
| `rules/web/webserver_generic/` | ~13 | `apache` | SQL injection, XSS, path traversal, JNDI/Log4Shell, SSTI, webshells |
| `rules/web/proxy_generic/` | ~25 | `apache` | Suspicious user agents, C2 tools, download cradles, scanner UA, IPFS credential harvesting |
| `rules/linux/builtin/sshd/` | 1 | `secure` | SSHD exploitation errors (buffer overflow, CRC32, bad DH, corrupted MAC) |
| `rules/linux/process_creation/` + `rules/linux/builtin/` | ~116 | `auditd` | Reverse shells, privilege escalation, credential dumping, C2, defense evasion (via execve events) |

**Total imported: ~155 rules** (38 web + 1 SSH + 116 host-threat/auditd) as of the current Sigma release.

### What is NOT imported (and why)

| Rule type | Reason |
|---|---|
| Windows Event Log rules | Vespid is Linux-only; no Windows log parsing |
| macOS `Image` / `CommandLine` fields (outside builtin) | No macOS log parsing in Vespid |
| Cloud rules (Azure, AWS, GCP) | No cloud log parsing in Vespid |
| macOS rules | Not a supported platform |
| Rules with `all of selection_*` conditions | Too complex to flatten into a single regex |
| Host-header-based proxy rules | Apache combined log format does not include the `Host` header |

---

## Architecture

```
SigmaHQ/sigma                   Converter                     Vespid
(GitHub repo)                       │                         Packs
    │                                │                            │
    ├─ rules/web/*.yml ──────► sigma_converter.py ──────► sigma-web-attacks.yaml
    ├─ rules/linux/.../*.yml ─►   (YAML → CustomRule)    ► sigma-ssh-attacks.yaml
    ├─ rules/linux/process_creation/*.yml ───────────────► sigma-host-threats.yaml
    │   rules/linux/builtin/*.yml                            (auditd rules)
    │                                │                            │
    │                          sigma_import.py                   │
    │                          (CLI: --init --sync)              │
    │                                │                            │
    │                          sigma_state.json         pack_loader.py
    │                          (sync tracking)          (loads packs → DB)
    │                                                       │
    ▼                                                       ▼
  git shallow clone                     vespid-server-admin rules update
  (~/.cache/vespid/sigma/)              (applies pack bundles / manifest)
```

### Conversion pipeline

1. **Parse** — Sigma YAML is parsed with `pyyaml`
2. **Classify** — each rule is checked for log-source compatibility and condition complexity
3. **Build regex** — Sigma's field-based detection is converted into a single Vespid-compatible regex. Web and SSH rules get a `(?P<ip>...)` capture group; host-threat (auditd) rules omit it since they lack a source IP
4. **Map metadata** — Sigma severity (`critical`/`high`/`medium`/`low`) → Vespid thresholds, ATT&CK tags preserved, Sigma UUID stored for sync tracking

### Field mapping (Apache combined log format)

| Sigma field | Position in Apache log line |
|---|---|
| `cs-method` | HTTP method (`"GET ...`) |
| `cs-uri-query\|contains` | Inside the request URI |
| `cs-user-agent\|contains` | Last quoted string |
| `cs-referer` | Second-to-last quoted string (`"-"` if null) |
| `sc-status` | After the request closing quote |

### Severity → threshold mapping

| Sigma level | `max_attempts` | `window_seconds` |
|---|---|---|
| `critical` | 1 | 60 |
| `high` | 2 | 120 |
| `medium` | 3 | 300 |
| `low` / `informational` | 5 | 600 |

---

## Quick Start

### 1. Initial import

```bash
cd /path/to/vespid
python -m vespid.scripts.sigma_import --init
```

This will:

- Shallow-clone the SigmaHQ/sigma repo to `~/.cache/vespid/sigma/`
- Sparse-checkout the `rules/web/`, `rules/linux/builtin/`, and `rules/linux/process_creation/` directories
- Convert all compatible rules into Vespid pack YAMLs
- Write output to `vespid-server/packs/sigma-web-attacks.yaml`, `sigma-ssh-attacks.yaml`, and `sigma-host-threats.yaml`
- Write `vespid-server/packs/manifest.json` recording the source Sigma commit and a SHA-256 per pack — making the output directory a ready-to-ship **bundle**
- Save sync state to `~/.cache/vespid/sigma_state.json`

### 2. Restart the server

The server's `pack_loader.py` auto-loads all `*.yaml` files in the packs
directory on startup. Restart the server to pick up the new Sigma packs:

```bash
sudo systemctl restart vespid-server
```

### 3. Enable rules

Imported Sigma rules are **disabled by default**. An admin must review and
enable them through the Admin UI or the Rules API.

**Via Admin Dashboard:** Navigate to **Detection Packs** → **Sigma Web Attack
Detection** / **Sigma SSH Attack Detection** → toggle individual rules.

**Via API:**

```bash
curl -X PUT http://server:5000/api/v1/rules/custom/42 \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: ..." \
  -d '{"enabled": true}'
```

---

## CLI Reference

The `sigma_import.py` CLI provides four commands:

### `--init`

First-time setup: clone the Sigma repo, convert rules, and generate pack YAMLs.

```bash
python -m vespid.scripts.sigma_import --init
```

### `--check`

Check whether upstream Sigma has published new rules since the last sync.
Exit code `0` means up-to-date, `1` means updates are available.

```bash
python -m vespid.scripts.sigma_import --check
echo $?  # 0 = current, 1 = stale, 2 = error
```

Suitable for cron jobs or monitoring:

```bash
0 6 * * * cd /opt/vespid && python -m vespid.scripts.sigma_import --check || \
  python -m vespid.scripts.sigma_import --sync
```

### `--sync`

Pull the latest Sigma rules, re-convert, regenerate packs, and log the diff:

```bash
python -m vespid.scripts.sigma_import --sync
```

Output includes the number of new, removed, and unchanged rules. The sync
state file is updated so the next `--check` won't re-trigger.

Both `--init` and `--sync` accept:

- `--bundle PATH` — also package the generated Sigma packs + `manifest.json`
  into `PATH` (a directory, `.tar.gz`/`.tgz`, or `.zip`) for distribution via
  `vespid-server-admin rules update`.
- `--output-dir DIR` — write the generated packs somewhere other than the
  default `vespid-server/packs/`.

### `--report`

Show the current sync status, imported rule count, and whether upstream updates
are available:

```bash
python -m vespid.scripts.sigma_import --report
```

Example output:

```
Last sync:     2026-10-08T16:59:07Z
Sigma commit:  8a4813404ea3
Rules imported: 155
  sigma-web-attacks: 38 rules (.../packs/sigma-web-attacks.yaml)
  sigma-ssh-attacks: 1 rules (.../packs/sigma-ssh-attacks.yaml)
  sigma-host-threats: 116 rules (.../packs/sigma-host-threats.yaml)

Up to date (HEAD: 8a4813404ea3)
```

---

## Applying Updates on a Server

Once you have a bundle (the `packs/` directory produced by `--init`/`--sync`,
optionally packaged as a `.tar.gz`/`.zip`), apply it on each installation with
the server CLI:

```bash
vespid-server-admin rules status
vespid-server-admin rules update --from https://packs.example.com/sigma-packs.tar.gz --check
vespid-server-admin rules update --from https://packs.example.com/sigma-packs.tar.gz --yes
sudo systemctl restart vespid-server
```

`rules update` validates every rule, backs up the previous packs, installs the
new ones, and reconciles the database non-destructively (user-enabled rules and
edits are preserved; upstream renames are applied in place; pristine removed
rules are retired). The detection-rules revision is bumped so agents re-pull.

See [Rule Pack Updates](server/rule-pack-updates.md) for the full workflow.

!!! note "Legacy endpoint"
    The old `POST /api/v1/rules/sigma/sync` admin endpoint shells out to the
    source-tree importer and is **not available in packaged installs**. Use the
    `rules update` command instead.

---

## Admin Workflow

### Enabling Sigma rules as a premium feature

Sigma packs are marked as **templates** (`is_template: 1`) and start
**disabled** (`enabled: 0`). The admin workflow is:

1. **Run `--init`** (or call the sync endpoint) to generate the packs.
2. **Review** the imported rules in the Detection Packs dashboard.
3. **Enable** select rules or the entire pack via the toggle UI.
4. **Assign** Sigma packs to specific nodes via the Config Profile
   `detection_packs` list (explicit mode) — useful for premium/paid tiers.

### Adding Sigma to a Config Profile

In the **Config Profiles** admin page, set `detection_pack_mode` to `explicit`
and add the Sigma pack names to `detection_packs`:

```json
{
  "detection_pack_mode": "explicit",
  "detection_packs": ["sigma-web-attacks", "sigma-ssh-attacks", "sigma-host-threats"]
}
```

Only nodes assigned to this profile will receive the Sigma rules.

---

## Schema Additions

Three new columns were added to the `detection_rules_custom` table to support
Sigma metadata:

| Column | Type | Purpose |
|---|---|---|
| `tags` | `TEXT` (JSON array) | MITRE ATT&CK technique IDs and category labels |
| `sigma_id` | `VARCHAR(64)` | Sigma rule UUID for sync tracking |
| `sigma_status` | `VARCHAR(32)` | Sigma maturity: `test`, `stable`, `experimental`, `deprecated` |

The `CustomRule` dataclass on the agent side was extended with matching fields:

```python
@dataclass
class CustomRule:
    ...
    tags: list[str] = field(default_factory=list)
    sigma_id: str = ""
    sigma_status: str = ""
```

These fields are **read-only metadata** — they do not affect the detection
engine. They are populated by the converter and preserved across syncs.

---

## Auto-Sync (Cron)

For fully automated updates, host a bundle and let each server check/apply it
daily:

```cron
# /etc/cron.d/vespid-rule-updates
0 5 * * * root vespid-server-admin rules update \
  --from https://packs.example.com/sigma-packs.tar.gz --check && \
  (vespid-server-admin rules update \
     --from https://packs.example.com/sigma-packs.tar.gz --yes && \
   systemctl reload vespid-server)
```

On a build host, regenerate and publish the bundle in one step:

```bash
cd /opt/vespid
python -m vespid.scripts.sigma_import --sync \
  --bundle /srv/www/sigma-packs.tar.gz
```

---

## Testing

To verify the converter is working correctly:

```bash
# Run converter unit tests (27 tests)
pytest tests/test_sigma_converter.py -v

# Run full integration: clone → convert → validate all regexes compile
python -m vespid.scripts.sigma_import --init
python -c "
import re, yaml
from pathlib import Path
for pack in Path('vespid-server/packs').glob('sigma-*.yaml'):
    data = yaml.safe_load(pack.read_text())
    for rule in data['rules']:
        c = re.compile(rule['regex'])
        assert 'ip' in c.groupindex, f'{rule[\"name\"]}: missing (?P<ip>)'
print('All rules valid.')
"
```
