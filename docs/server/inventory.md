# Inventory (Asset CMDB)

The Inventory service is the authoritative source of truth for all infrastructure,
compute resources, and discovered assets within the Vespid ecosystem.

Every module can consume inventory data rather than maintaining its own copy:

- **Monitor** discovers CPU utilization → references an asset
- **Intelligence** discovers external IP reputation → references an asset  
- **Agent** discovers packages → feeds asset metadata
- **Proxmox sync** discovers VMs → creates assets
- **Inventory** stores the canonical asset records

---

## Core Concepts

### Permanent asset identity

Every asset receives a permanent UUID (`asset_id`) that never changes, even if the
host is renamed, migrated, or reimaged. All external identifiers (hostname, IP, MAC,
VMID, machine-id) are stored as **aliases** — they can change without breaking
referential integrity.

### Entity resolution

When a discovery source reports a new host, the system attempts to find an existing
asset by checking its known identifiers in priority order:

| Identifier | Confidence | Example |
|---|---|---|
| `machine_id` | 100% | `/etc/machine-id` |
| `sync_id` | 98% | Provider-scoped ID (`proxmox:qemu/102`) |
| `vmid` | 95% | Proxmox VMID |
| `mac` | 85% | Network interface MAC |
| `hostname` | 70% | `hostname` / `hostname -f` |
| `fqdn` | 65% | Fully qualified domain name |
| `ipv4` | 50% | IP address |

If an asset is found, the new source is merged (new aliases added, metadata enriched).
If no match exists, a new asset is created.

### Localhost / loopback filtering

Identifiers for `localhost`, `localhost.localdomain`, `127.0.0.1`, `::1`, and
`00:00:00:00:00:00` are automatically skipped — they appear on every host and add
no value.

---

## Database Schema

### `assets` table — canonical inventory records

```sql
CREATE TABLE assets (
    asset_id         CHAR(36) PRIMARY KEY,      -- permanent UUID
    asset_type       VARCHAR(32) NOT NULL DEFAULT 'host',  -- host, vm, container, hypervisor, cluster
    display_name     VARCHAR(255) NOT NULL,     -- human-readable name (hostname)
    parent_id        CHAR(36),                  -- parent asset (VM → hypervisor)
    metadata         JSON NOT NULL,             -- OS, kernel, CPU, memory, interfaces, ...
    labels           JSON NOT NULL,             -- user-defined key/value tags
    first_seen_at    DATETIME NOT NULL,
    last_seen_at     DATETIME,
    status           VARCHAR(16) NOT NULL DEFAULT 'active',  -- active, stale, gone
    created_by_source VARCHAR(64) NOT NULL       -- monitor, agent, sync, manual
);
```

### `asset_aliases` table — entity resolution

```sql
CREATE TABLE asset_aliases (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    asset_id         CHAR(36) NOT NULL,          -- FK → assets
    alias_type       VARCHAR(64) NOT NULL,       -- machine_id, hostname, mac, ipv4, vmid, sync_id
    alias_value      VARCHAR(255) NOT NULL,
    source           VARCHAR(64) NOT NULL,        -- monitor, agent, proxmox
    confidence       TINYINT NOT NULL DEFAULT 100,
    first_claimed_at DATETIME NOT NULL,
    last_confirmed_at DATETIME,
    UNIQUE(alias_type, alias_value)
);
```

### `asset_relationships` table — graph edges

```sql
CREATE TABLE asset_relationships (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    source_asset_id  CHAR(36) NOT NULL,
    target_asset_id  CHAR(36) NOT NULL,
    relationship     VARCHAR(32) NOT NULL,        -- RUNS_ON, BELONGS_TO, DEPENDS_ON, CONNECTS_TO
    metadata         JSON NOT NULL,
    created_at       DATETIME NOT NULL,
    UNIQUE(source_asset_id, target_asset_id, relationship)
);
```

---

## How Assets Are Created

### 1. Security agent enrollment

When the security agent enrolls via `POST /api/v1/enroll`, the server:

1. Calls `ensure_asset()` with `machine_id` and `hostname`
2. Stores the returned `asset_id` on the enrollment record
3. Returns `asset_id` in the enrollment response

The agent persists `asset_id` in its credentials file and includes it in every heartbeat.

### 2. Security agent heartbeat

Each heartbeat (`POST /api/v1/heartbeat`) includes `host_info` (OS, kernel, interfaces,
machine-id, etc.). The server:

1. Updates `assets.last_seen_at` (always, cheap PK update)
2. Deep-merges metadata only when values change (CPU, OS, kernel updates)
3. Creates MAC and IPv4 aliases from interface data
4. Links `nodes.asset_id` back to the canonical asset

### 3. Monitor agent metric shipment

When the monitor agent ships metrics to `POST /api/v1/metrics/write`, the server
reads `X-Agent-ID`, `X-Hostname`, and `X-Machine-ID` headers (no protobuf parsing):

1. Calls `ensure_asset()` to resolve or create an asset
2. Links `config_agent_status.asset_id` to the asset
3. Updates `last_seen_at`

### 4. Sync agent (Proxmox discovery)

A standalone `vespid-sync` agent polls the Proxmox PVE API and pushes discovered
VMs, containers, and hypervisors to `POST /api/v1/inventory/sync`. The server:

1. Creates assets with `asset_type='vm' | 'container' | 'hypervisor'`
2. Creates aliases for `vmid`, `hostname` (from guest agent), `mac`, `ipv4`
3. Creates `RUNS_ON` relationships (VM → hypervisor node)
4. Creates `BELONGS_TO` relationships (node → cluster)
5. Marks assets not in the current batch as `stale`

---

## Dashboard

### Asset list

**`GET /inventory`** — The main inventory view, with three modes:

- **All** — flat card grid, filterable by type and source
- **By Source** — grouped by discovery source (Proxmox, Monitor, Agent) with
  parent-child hierarchy (hypervisor → VMs, nodes → children)
- **Hosts** — physical hosts and hypervisors only

Each card shows:
- Asset name (hostname)
- Status indicator (green dot)
- Type badge (vm, hypervisor, etc.)
- Aliases (machine-id, MAC, IPv4)

### Asset detail

**`GET /inventory/<asset_id>`** — Full detail page with:

- Identity section (asset ID, type, source, status, parent)
- Timestamps (first seen, last seen)
- **Labels** — user-defined key/value tags, editable inline
- **Metadata** — OS, kernel, CPU, memory, interfaces table with MAC and IPs
- **Aliases** — all known identifiers with confidence badges
- **Relationships** — graph edges (RUNS_ON, BELONGS_TO, etc.)
- **Children** — assets with this asset as parent
- **Delete** button (admin only, with confirmation)

### Admin inventory

**`GET /admin/inventory`** — Admin-only cleanup page with:

- **All Assets** — full table with per-asset delete
- **Stale Assets** — assets with `status='stale'` or `'gone'` older than 24h,
  with bulk purge
- **Duplicate Assets** — assets sharing the same hostname or machine-id,
  with merge button
- **Orphaned Aliases** — aliases referencing deleted assets

### CMDB Query

**`GET /inventory/query`** — Interactive query builder:

- Free-text search across name and aliases
- Filter by type, source, status, label
- Pagination controls
- Results in table view or raw JSON
- "Copy as cURL" and "Export CSV"

---

## API Reference

All API endpoints return JSON and accept Bearer token auth (`Authorization: Bearer <key>`)
or session auth.

### Query assets

```
GET /inventory/api/query
```

| Param | Type | Description |
|---|---|---|
| `q` | string | Free-text search (name + aliases) |
| `type` | string | Filter by `asset_type` |
| `source` | string | Filter by `created_by_source` |
| `status` | string | Filter by `status` |
| `label` | string | Filter by label (`key=value`) |
| `parent` | string | Filter by `parent_id` |
| `limit` | int | Max results (default 100, max 1000) |
| `offset` | int | Pagination offset |
| `aliases` | bool | Include aliases (default true) |
| `metadata` | bool | Include parsed metadata (default false) |

Response:

```json
{
  "assets": [
    {
      "asset_id": "21a0612b-...",
      "asset_type": "vm",
      "display_name": "web01.example.com",
      "status": "active",
      "created_by_source": "monitor",
      "last_seen_at": "2026-06-03T15:28:06Z",
      "aliases": [
        {"alias_type": "machine_id", "alias_value": "abc123..."},
        {"alias_type": "ipv4", "alias_value": "15.204.59.125"}
      ]
    }
  ],
  "total": 1,
  "limit": 100,
  "offset": 0
}
```

### Export all assets

```
GET /inventory/api/export
```

Returns full dump of all assets with aliases, relationships, and metadata.
Supports `?format=csv` for CSV download.

### Relationship graph

```
GET /inventory/api/graph
```

Returns the full relationship graph in D3.js-compatible format:

```json
{
  "nodes": [
    {"id": "...", "label": "web01", "type": "vm", "source": "monitor", "status": "active"}
  ],
  "edges": [
    {"source": "...", "target": "...", "relationship": "RUNS_ON"}
  ],
  "total_nodes": 1
}
```

Optional `?asset_id=<id>` filters to the subgraph around a single asset.

### Per-asset relationships

```
GET /inventory/api/<asset_id>/relationships
```

### Sync endpoint (agent → server)

```
POST /api/v1/inventory/sync
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "provider": "proxmox",
  "cluster": "homelab",
  "assets": [
    {
      "external_id": "qemu/102",
      "display_name": "web01",
      "asset_type": "vm",
      "parent_external_id": "node/pve1",
      "metadata": {"cpu_cores": 4, "memory_mb": 8192},
      "labels": {"pool": "production"},
      "aliases": {"hostname": "web01.internal", "mac": "aa:bb:cc:dd:ee:ff", "ipv4": "10.0.1.5"},
      "status": "running"
    }
  ]
}
```

### Labels

```
POST /inventory/<asset_id>/labels        # Merge labels: {"env": "prod"}
DELETE /inventory/<asset_id>/labels/<key> # Remove one label
```

### Delete

```
POST /inventory/<asset_id>/delete        # Admin only, cascading cleanup
POST /admin/inventory/<asset_id>/delete  # Admin page variant
POST /admin/inventory/purge-stale        # Delete all stale assets
POST /admin/inventory/merge              # Merge duplicates (form: keep_id + discard_id)
```

---

## Labels

Assets support free-form key/value labels, managed through the detail page UI or API.

```
POST /inventory/<asset_id>/labels
{"env": "production", "tier": "web", "owner": "operations"}
```

Labels are deep-merged — existing keys are overwritten, new keys are added.
Remove a label with `DELETE /inventory/<asset_id>/labels/<key>`.

---

## Deployment: vespid-sync agent

The sync agent discovers infrastructure from hypervisors and pushes assets to
the Vespid server. It runs as a standalone process on a machine that can reach
the hypervisor API (e.g., a Proxmox node itself).

### Build and install

```bash
# On a Rocky Linux 8+ / AlmaLinux 9+ host:
dnf install rpm-build systemd-rpm-macros python3-devel
cd vespid-agent
./packaging/build-vespid-sync-rpm.sh

# Install
dnf install packaging/vespid-sync-*.rpm
```

The `%post` script creates a Python venv at `/opt/vespid-sync/.venv/` and
installs dependencies (`requests`, `pyyaml`, `proxmoxer`).

### Configuration

```yaml
# /etc/vespid-sync/config.yaml
sync:
  server_url: "https://vespid.example.com"
  api_key: "ue_sync_agent_key"          # API key with agent role
  cluster: "homelab"

providers:
  - name: "homelab"
    type: proxmox
    url: "https://pve.example.com:8006/api2/json"
    token_id: "vespid@pve!sync"
    token_secret: "${PVE_TOKEN}"
    verify_ssl: true
    # pools: ["production", "staging"]   # Optional: filter by resource pool
```

### Start

```bash
systemctl enable --now vespid-sync-agent.timer  # Every 5 minutes
systemctl start vespid-sync-agent                # Manual test run
```

---

## Configuration

The inventory subsystem is **always enabled** — no config toggle needed. The
`assets`, `asset_aliases`, and `asset_relationships` tables are created during
the first `init_db()` after deployment.

---

## Integration

| System | How it integrates |
|---|---|
| **Security agent** | Enrollment creates assets, heartbeat enriches metadata |
| **Monitor agent** | Metric shipment headers resolve/create assets |
| **Proxmox sync** | Sync agent pushes discovered VMs + relationships |
| **VictoriaMetrics** | Not involved (inventory uses MySQL/MariaDB) |
| **Dashboard** | Inventory pages under 🗄️ Inventory module |
| **Admin** | Cleanup, merge, purge under ⚙️ Admin → Inventory |
