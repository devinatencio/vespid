"""Provider interface for asset discovery sources.

Each provider polls an external system (Proxmox, VMware, AWS, …) and returns
a list of ``SyncAsset`` records. The sync engine then batch-POSTs them to the
Vespid server's ``/api/v1/inventory/sync`` endpoint.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SyncAsset:
    """A discovered asset returned by a provider.

    The sync engine maps this to an ``assets`` row on the server via
    ``ensure_asset()``.
    """

    external_id: str
    """Provider-specific unique ID (e.g. ``qemu/102``, ``i-12345``)."""

    display_name: str
    """Human-readable name (hostname from guest agent or VM config name)."""

    asset_type: str = "vm"
    """One of ``vm``, ``container``, ``hypervisor``, ``cluster``, ``storage``."""

    parent_external_id: str | None = None
    """External ID of the parent asset (e.g. node for a VM). Used for RUNS_ON."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Key-value metadata: cpu_cores, memory_mb, disk_gb, os, kernel, …"""

    labels: dict[str, str] = field(default_factory=dict)
    """Tags or labels (e.g. pool=production, tags=web,nginx…)."""

    aliases: dict[str, str | list[str]] = field(default_factory=dict)
    """Identifiers for entity resolution: hostname, machine_id, mac, ipv4, …"""

    status: str = "running"
    """``running``, ``stopped``, ``paused``, ``unknown``."""


class Provider(ABC):
    """Base class for a discovery source provider.

    Subclasses override :meth:`discover` to return all assets discovered
    from the external system. Optional :meth:`discover_nodes` and
    :meth:`discover_clusters` return additional hierarchy assets.
    """

    def __init__(self, config: dict) -> None:
        self.config = config

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name — stored in the sync_id alias prefix."""
        ...

    @abstractmethod
    def discover(self) -> list[SyncAsset]:
        """Return all VMs, containers, or compute instances."""
        ...

    def discover_nodes(self) -> list[SyncAsset]:
        """Return hypervisor hosts or nodes.

        Override if the provider exposes the underlying infrastructure.
        """
        return []

    def discover_clusters(self) -> list[SyncAsset]:
        """Return logical cluster or datacenter groupings.

        Override to provide the ``BELONGS_TO`` hierarchy level.
        """
        return []
