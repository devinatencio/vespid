# 06 — Vespid Inventory (CMDB Integration)

## Overview

Vespid Inventory is a lightweight CMDB that unifies security, monitoring, and
third-party asset data into a single view. It extends the existing Vespid Flask
server and MariaDB schema — not a separate system.

## Architecture Principle

**Sync is a background operation, not an HTTP request.** A Proxmox cluster with 500
VMs takes 30-90 seconds to query. This must never block a Flask worker.

```
┌─────────────────┐     every 5 min      ┌──────────────┐
│ vespid-sync   │────────────────────►│  Proxmox API │
│ (systemd timer)  │◄────────────────────│              │
│                  │  VM/CT/network list │              │
└────────┬─────────┘                     └──────────────┘
         │
         │ batch INSERT ON DUPLICATE KEY UPDATE
         ▼
┌─────────────────┐     reads             ┌──────────────┐
│    MariaDB       │◄─────────────────────│ Flask server │
│ (assets table)   │                      │ (inventory   │
│                  │                      │  dashboard)  │
└─────────────────┘                      └──────────────┘
```

## Component Boundaries

| System | Role in Inventory |
|--------|-------------------|
| **vespid-sync** (new) | Python script, systemd timer. Polls hypervisor APIs every 5 min, batch-writes to MariaDB. Provider-based: add a new provider class to support a new hypervisor. |
| **vespid-server** (Flask) | No new code for the sync itself. Serves inventory UI from the same MariaDB. An imported asset is just a row — Flask doesn't care who wrote it. |
| **hivemonitor-agent** (Rust) | No change. Agent reports `hostname` — the inventory dashboard matches imported assets to monitoring agents by hostname. Unmatched assets show as "unmonitored." |

## Database: Unified Assets Table

The existing `nodes` table serves as the foundation. Extend it to become a generic
`assets` concept rather than duplicating with a separate table.

```sql
-- Extend existing nodes table (or create assets table)
ALTER TABLE nodes
    ADD COLUMN asset_type ENUM(
        'host', 'vm', 'container', 'switch', 'router',
        'hypervisor', 'storage', 'application', 'other'
    ) NOT NULL DEFAULT 'host',

    ADD COLUMN source ENUM('manual', 'agent', 'sync', 'discovery')
        NOT NULL DEFAULT 'manual',

    ADD COLUMN sync_source VARCHAR(64) NULL
        COMMENT 'Provider name: proxmox, vmware, aws, etc.',

    ADD COLUMN sync_external_id VARCHAR(255) NULL
        COMMENT 'ID from the external system (VM UUID, instance ID)',

    ADD COLUMN sync_last_seen TIMESTAMP NULL
        COMMENT 'Last time the sync provider confirmed this asset exists',

    ADD COLUMN parent_id CHAR(36) NULL
        COMMENT 'Parent asset (VM → hypervisor, container → host)',

    ADD COLUMN relationships JSON NULL
        COMMENT 'Arbitrary relationship data: depends_on, connects_to, etc.',

    ADD UNIQUE INDEX idx_source_external (sync_source, sync_external_id),
    ADD INDEX idx_asset_type (asset_type),
    ADD INDEX idx_parent (parent_id),
    ADD INDEX idx_sync_last_seen (sync_last_seen);
```

## Sync Provider Interface

```python
# vespid-sync/providers/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

@dataclass
class Asset:
    hostname: str
    asset_type: str              # host, vm, container, etc.
    source: str = "sync"
    sync_source: str = ""        # provider name
    sync_external_id: str = ""   # VM UUID in Proxmox
    parent_hostname: Optional[str] = None
    labels: dict = field(default_factory=dict)
    ip_addresses: list = field(default_factory=list)
    cpu_cores: Optional[int] = None
    memory_mb: Optional[int] = None
    os_name: Optional[str] = None
    status: str = "unknown"      # running, stopped, suspended

class Provider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier: 'proxmox', 'vmware', 'aws'"""
        ...

    @abstractmethod
    async def list_vms(self) -> list[Asset]:
        """Return all VMs and containers"""
        ...

    @abstractmethod
    async def list_hosts(self) -> list[Asset]:
        """Return hypervisor hosts"""
        ...

    async def list_networks(self) -> list[Asset]:
        """Override to return virtual networks"""
        return []

    async def list_storage(self) -> list[Asset]:
        """Override to return datastores/volumes"""
        return []
```

## Sync Worker (vespid-sync)

A separate Python process, not part of the Flask server:

```
vespid-sync/
├── sync.py              # Entry point: loads config, runs providers
├── providers/
│   ├── base.py          # Provider ABC + Asset dataclass
│   ├── proxmox.py       # Proxmox PVE API (qemu + lxc)
│   └── vmware.py        # VMware vSphere API
└── config.yaml          # Provider credentials
```

**Operation:**
1. systemd timer fires every 5 minutes
2. sync.py loads providers from config
3. Each provider. list_vms(), list_hosts(), etc. — sequentially, not in parallel (don't hammer APIs)
4. Batch INSERT/UPDATE to MariaDB: 500 rows per batch, `ON DUPLICATE KEY UPDATE`
5. Assets NOT returned by the sync (gone from hypervisor) get `status='gone'` or are deleted after a grace period
6. Exit 0 → timer sleeps until next run

**Config:**
```yaml
sync:
  interval_seconds: 300
  db_url: "mysql://..."

providers:
  - name: proxmox
    type: proxmox
    url: "https://pve.example.com:8006"
    token_id: "vespid@pve!sync"
    token_secret: "${PVE_TOKEN}"
    verify_ssl: true
```

## Scale Considerations

| Concern | Handling |
|---------|----------|
| 2000+ VMs across 10 clusters | Providers run sequentially (not concurrent). Proxmox API returns 2000 VMs in ~5s. Batch INSERT at 500 rows/batch — 4 batches. Total sync time <15s. |
| 5-minute sync window | Even at 10,000 assets, MariaDB batch writes handle it in under 30 seconds. The timer fires every 5 min — sync finishes before the next one starts. |
| Stale assets | `sync_last_seen` tracks when the provider last confirmed the asset. Assets not seen for 3 sync cycles → marked `stale`. 24h without confirmation → `gone`. |
| Concurrent updates | Sync is a single process (no parallel providers). One writer to the assets table at a time. Flask reads use normal SELECTs — no locking conflicts. |
| Monitoring agent matching | Assets are matched to monitoring agents by hostname (or custom label). If a synced VM has no agent installed, the dashboard shows "unmonitored" with an "Install Agent" button. |

## What Vespid Inventory Is NOT

- **NOT a real-time asset database** — Syncs every 5 minutes. If a VM is deleted between syncs, it's caught on the next run.
- **NOT a replacement for hypervisor UI** — It's a unified view across hypervisors, not a management interface.
- **NOT an event-driven sync** — No webhooks from Proxmox/VMware. Polling is simpler, more reliable, and sufficient.
- **NOT a graph database** — MariaDB with a `parent_id` column and JSON `relationships` handles the hierarchy. A full graph DB is overkill until you need complex path queries across 10,000+ nodes.

## Integration Points with Other Systems

| System | Integration |
|--------|-------------|
| **vespid-server** (security) | Security events already reference `node_id`. With the unified assets table, every security event is automatically tagged with the asset's type, parent, and sync source. |
| **hivemonitor** (metrics) | Monitoring agent matches by hostname. Inventory dashboard shows CPU/memory from metrics next to allocated resources from the hypervisor — "you gave this VM 8GB, it's using 6.2GB." |
| **Alerting** (future) | Alerts can filter by asset type, sync source, or parent. "Alert only on production VMs in the proxmox homelab cluster." |

## Rollout Plan

| Phase | What |
|-------|------|
| V1 (0-3 months) | Nothing. Inventory is a demand-pull, not a blocker. |
| V2 (3-6 months) | Add `asset_type`, `source`, `sync_source`, `parent_id` columns to nodes table. Write `vespid-sync` with Proxmox provider. |
| V3 (6-12 months) | VMware provider. Inventory dashboard in Flask. Agent matching (monitored/unmonitored flag). |

## Why This Stays in Flask/MariaDB

The existing Vespid server already tracks nodes, their state, labels, and
relationships. Inventory is not a new concept — it's extending the `nodes` table
into a richer `assets` model. The operational complexity stays at one server, one
database, one deployment workflow. A separate inventory microservice would add
another process, another database, another deployment — for data that Flask already
serves from MariaDB today.
