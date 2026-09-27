"""Proxmox PVE provider — discovers VMs, containers, and hypervisor nodes.

Requires the ``proxmoxer`` library and a PVE API token with read access to
``/``, ``/nodes``, ``/pools``, and ``/cluster``.
"""

from __future__ import annotations

import logging
from typing import Any

from providers.base import Provider, SyncAsset

log = logging.getLogger(__name__)


class ProxmoxProvider(Provider):
    """Poll a Proxmox PVE cluster and return discovered assets."""

    @property
    def name(self) -> str:
        return self.config.get("name", "proxmox")

    def _connect(self):
        """Return a proxmoxer client for this provider's PVE endpoint."""
        import proxmoxer

        url = self.config["url"]
        token_id = self.config["token_id"]
        token_secret = self.config["token_secret"]
        verify_ssl = self.config.get("verify_ssl", True)

        # Strip /api2/json suffix if present — proxmoxer adds it
        base = url.rstrip("/")
        if base.endswith("/api2/json"):
            base = base[: -len("/api2/json")]

        return proxmoxer.ProxmoxAPI(
            base,
            user=token_id,
            token_name="",
            token_value=token_secret,
            verify_ssl=verify_ssl,
            service="proxmox",
        )

    def discover_clusters(self) -> list[SyncAsset]:
        """Return the cluster itself as an asset."""
        proxmox = self._connect()
        assets = []
        try:
            status = proxmox.cluster.status.get()
            cluster_name = None
            for entry in status:
                if entry.get("type") == "cluster":
                    cluster_name = entry.get("name") or entry.get("id", "cluster")
                    break
            if not cluster_name:
                cluster_name = self.config.get("name", "proxmox-cluster")
            assets.append(SyncAsset(
                external_id=f"cluster/{cluster_name}",
                display_name=cluster_name,
                asset_type="cluster",
                metadata={"source": "proxmox"},
                status="running",
            ))
        except Exception:
            log.exception("Failed to discover cluster for %s", self.name)
        return assets

    def discover_nodes(self) -> list[SyncAsset]:
        """Return hypervisor nodes."""
        proxmox = self._connect()
        assets = []
        try:
            nodes = proxmox.nodes.get()
            for node in nodes:
                node_name = node.get("node", "")
                if not node_name:
                    continue
                meta = {}
                try:
                    node_status = proxmox.nodes(node_name).status.get()
                    cpu_info = node_status.get("cpuinfo", {})
                    meta = {
                        "cpu_model": cpu_info.get("model", ""),
                        "cpu_sockets": cpu_info.get("sockets", 0),
                        "cpu_cores": cpu_info.get("cores", 0) or cpu_info.get("cpus", 0),
                        "memory_mb": (node_status.get("memory", {}).get("total", 0) or 0) // (1024 * 1024),
                        "uptime_seconds": node_status.get("uptime", 0),
                    }
                except Exception:
                    log.warning("Could not get node status for %s", node_name)
                assets.append(SyncAsset(
                    external_id=f"node/{node_name}",
                    display_name=node_name,
                    asset_type="hypervisor",
                    metadata=meta,
                    aliases={"hostname": node_name},
                    status="running" if node.get("status") == "online" else "stopped",
                ))
        except Exception:
            log.exception("Failed to discover nodes for %s", self.name)
        return assets

    def discover(self) -> list[SyncAsset]:
        """Return all VMs (QEMU) and containers (LXC) across all nodes."""
        proxmox = self._connect()
        assets = []

        # Filter by resource pools if configured
        allowed_pools = self.config.get("pools")

        try:
            nodes = proxmox.nodes.get()
        except Exception:
            log.exception("Failed to list nodes for %s", self.name)
            return assets

        # Discover pools → VM mapping (to filter by pool)
        pool_vms: set[str] = set()
        if allowed_pools:
            try:
                pools = proxmox.pools.get()
                for pool in pools:
                    if pool.get("poolid") in allowed_pools:
                        members = proxmox.pools(pool["poolid"]).get()
                        for m in members.get("members", []):
                            pool_vms.add(f"{m.get('node', '')}/{m.get('vmid', 0)}")
            except Exception:
                log.warning("Failed to discover pools, sync all")

        for node_info in nodes:
            node_name = node_info.get("node", "")
            if not node_name:
                continue

            # QEMU VMs
            try:
                vms = proxmox.nodes(node_name).qemu.get()
                for vm in vms:
                    vmid = vm.get("vmid", 0)
                    if not vmid:
                        continue
                    key = f"{node_name}/{vmid}"
                    if allowed_pools and key not in pool_vms:
                        continue
                    asset = self._vm_to_asset(proxmox, node_name, vm)
                    if asset:
                        assets.append(asset)
            except Exception:
                log.warning("Failed to list QEMU VMs on node %s", node_name)

            # LXC containers
            try:
                cts = proxmox.nodes(node_name).lxc.get()
                for ct in cts:
                    vmid = ct.get("vmid", 0)
                    if not vmid:
                        continue
                    key = f"{node_name}/{vmid}"
                    if allowed_pools and key not in pool_vms:
                        continue
                    asset = self._ct_to_asset(proxmox, node_name, ct)
                    if asset:
                        assets.append(asset)
            except Exception:
                log.warning("Failed to list LXC containers on node %s", node_name)

        return assets

    # ── VM asset builder ──────────────────────────────────────────────────

    def _vm_to_asset(self, proxmox, node_name: str, vm: dict) -> SyncAsset | None:
        vmid = str(vm["vmid"])
        name = vm.get("name", f"vm-{vmid}")
        tags = self._parse_tags(vm.get("tags", ""))

        # Basic metadata from the PVE list endpoint
        meta: dict[str, Any] = {
            "cpu_cores": vm.get("maxcpu", 0),
            "memory_mb": (vm.get("maxmem", 0) or 0) // (1024 * 1024),
        }

        # Enrich with config + guest agent data
        try:
            config = proxmox.nodes(node_name).qemu(vmid).config.get()
            meta["os"] = config.get("ostype", "")
            meta["disk_gb"] = self._calc_disk_gb(config)
            # Tags from config if not present in list
            if not tags:
                tags = self._parse_tags(config.get("tags", ""))
        except Exception:
            config = {}

        # Aliases
        aliases: dict[str, str | list[str]] = {
            "vmid": f"{node_name}/{vmid}",
        }

        agent_data = self._get_guest_agent_info(proxmox, node_name, vmid)
        if agent_data:
            if agent_data.get("hostname"):
                aliases["hostname"] = agent_data["hostname"]
            if agent_data.get("mac"):
                aliases["mac"] = agent_data["mac"]
            if agent_data.get("ipv4"):
                aliases["ipv4"] = agent_data["ipv4"]
            meta.update(agent_data.get("metadata", {}))

        # Labels from Proxmox tags
        labels = {}
        if tags:
            labels["tags"] = ",".join(tags)
        if config.get("pool"):
            labels["pool"] = config["pool"]

        status = (
            "running" if vm.get("status") == "running"
            else "stopped" if vm.get("status") == "stopped"
            else "unknown"
        )

        return SyncAsset(
            external_id=f"qemu/{vmid}",
            display_name=agent_data.get("hostname") or name,
            asset_type="vm",
            parent_external_id=f"node/{node_name}",
            metadata=meta,
            labels=labels,
            aliases=aliases,
            status=status,
        )

    # ── Container (LXC) asset builder ───────────────────────────────────

    def _ct_to_asset(self, proxmox, node_name: str, ct: dict) -> SyncAsset | None:
        vmid = str(ct["vmid"])
        name = ct.get("name", f"ct-{vmid}")
        tags = self._parse_tags(ct.get("tags", ""))

        meta: dict[str, Any] = {
            "cpu_cores": ct.get("maxcpu", 0),
            "memory_mb": (ct.get("maxmem", 0) or 0) // (1024 * 1024),
        }

        try:
            config = proxmox.nodes(node_name).lxc(vmid).config.get()
            meta["os"] = config.get("ostype", "")
            meta["disk_gb"] = self._calc_disk_gb(config)
            if not tags:
                tags = self._parse_tags(config.get("tags", ""))
        except Exception:
            config = {}

        aliases: dict[str, str | list[str]] = {
            "vmid": f"{node_name}/{vmid}",
        }
        if name:
            aliases["hostname"] = name

        labels = {}
        if tags:
            labels["tags"] = ",".join(tags)
        if config.get("pool"):
            labels["pool"] = config["pool"]

        status = (
            "running" if ct.get("status") == "running"
            else "stopped" if ct.get("status") == "stopped"
            else "unknown"
        )

        return SyncAsset(
            external_id=f"lxc/{vmid}",
            display_name=name,
            asset_type="container",
            parent_external_id=f"node/{node_name}",
            metadata=meta,
            labels=labels,
            aliases=aliases,
            status=status,
        )

    # ── Guest agent ──────────────────────────────────────────────────────

    def _get_guest_agent_info(self, proxmox, node_name: str, vmid: str) -> dict | None:
        """Try to get hostname, IPs, and MAC from the QEMU guest agent.

        Returns None if the guest agent is not running or unreachable.
        """
        try:
            net = proxmox.nodes(node_name).qemu(vmid).agent("network-get-interfaces").get()
            iface = net.get("result", [])
            hostname_data = proxmox.nodes(node_name).qemu(vmid).agent("get-hostname").get()
            hostname = (hostname_data.get("result", {}) or {}).get("host-name", "")
        except Exception:
            return None

        macs: list[str] = []
        ips: list[str] = []
        for iface_entry in iface:
            if iface_entry.get("name") == "lo":
                continue
            hwaddr = iface_entry.get("hardware-address", "")
            if hwaddr and hwaddr.lower() not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                macs.append(hwaddr)
            for addr in iface_entry.get("ip-addresses", []):
                ip = addr.get("ip-address", "")
                prefix = addr.get("prefix", 0)
                if ip and not ip.startswith("127.") and not ip.startswith("fe80:") and not ip == "::1":
                    ips.append(f"{ip}/{prefix}")

        return {
            "hostname": hostname or None,
            "mac": macs or None,
            "ipv4": ips or None,
            "metadata": {"os": None},  # Guest agent doesn't expose OS string
        }

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _parse_tags(raw: str | None) -> list[str]:
        if not raw or not raw.strip():
            return []
        return [t.strip() for t in raw.split(";") if t.strip()]

    @staticmethod
    def _calc_disk_gb(config: dict) -> float:
        """Sum all disk sizes from a VM/CT config into GB."""
        total = 0.0
        for key, value in config.items():
            if key.startswith("virtio") or key.startswith("scsi") or key.startswith("ide") or key.startswith("sata"):
                if isinstance(value, str) and "," in value:
                    size_part = value.split(",")[0]
                    try:
                        size_str = size_part.rstrip("GgMmKk")
                        suffix = size_part[-1].lower() if size_part else ""
                        size = float(size_str)
                        if suffix == "m":
                            size /= 1024
                        elif suffix == "k":
                            size /= (1024 * 1024)
                        total += size
                    except (ValueError, IndexError):
                        pass
        return round(total, 1)
