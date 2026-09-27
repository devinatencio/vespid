"""Allowlist management mixin for NFTablesManager.

Hot add/remove of allowlist entries via CLI, plus persistence.

The mixin maintains three tiers of allowlist entries:

* ``self_allowlist``  — auto-detected local IPs (system-protected, never
  removable and never skipped by config sync).
* ``config``          — entries from the local config file / server profile.
* ``runtime``         — entries added at runtime via CLI or server API.

``is_allowlisted()`` checks self first, then config/runtime.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import subprocess
from collections.abc import Iterable
from typing import Any

from .logging_setup import audit

log = logging.getLogger("vespid.nft")


class AllowlistMixin:
    """Mixin providing allowlist management for NFTablesManager."""

    @staticmethod
    def _normalize_allowlist(entries: Iterable[str]) -> list[ipaddress._BaseNetwork]:
        nets = []
        for raw in entries:
            try:
                nets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                log.warning("Ignoring invalid allowlist entry %r", raw)
        return nets

    def is_allowlisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if any(addr in net for net in self._self_allowlist):
            return True
        return any(addr in net for net in self._allowlist)

    def _populate_self_allowlist(self) -> None:
        """Auto-detect all local IPs and add to the protected self-allowlist.

        Uses ``ip -o addr show scope global`` to discover IPv4 and IPv6
        addresses on all non-loopback interfaces, plus DNS fallbacks for
        the primary hostname.  Runs once on startup.
        """
        import ipaddress as _ipaddr

        discovered: set[_ipaddr._BaseNetwork] = set()

        try:
            result = subprocess.run(
                ["ip", "-o", "addr", "show", "scope", "global"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                for i, p in enumerate(parts):
                    if p in ("inet", "inet6"):
                        cidr = parts[i + 1] if i + 1 < len(parts) else ""
                        if "/" in cidr:
                            try:
                                discovered.add(_ipaddr.ip_network(cidr, strict=False))
                            except ValueError:
                                pass
        except (subprocess.SubprocessError, OSError):
            pass

        try:
            hostname = socket.gethostname()
            for _af, _socktype, _proto, _canonname, sa in socket.getaddrinfo(
                hostname, None, 0, 0, socket.IPPROTO_TCP
            ):
                ip = sa[0]
                try:
                    addr = _ipaddr.ip_address(ip)
                    if not addr.is_link_local:
                        discovered.add(_ipaddr.ip_network(ip, strict=False))
                except ValueError:
                    pass
        except (socket.gaierror, OSError):
            pass

        with self._lock:
            before = len(self._self_allowlist)
            self._self_allowlist.update(discovered)
            added = len(self._self_allowlist) - before

        if added:
            self._save_self_allowlist()
            log.info(
                "Self-allowlist: discovered %d local IP(s) (%d new)",
                len(discovered),
                added,
            )

    def _load_self_allowlist(self) -> None:
        """Load previously persisted self-allowlist from disk."""
        try:
            with open(self._self_allowlist_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return
        except (json.JSONDecodeError, OSError) as exc:
            log.debug("Failed to load self-allowlist from %s: %s", self._self_allowlist_path, exc)
            return

        if not isinstance(data, list):
            return

        loaded = 0
        with self._lock:
            for entry in data:
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                    if net not in self._self_allowlist:
                        self._self_allowlist.add(net)
                        loaded += 1
                except ValueError:
                    pass

        if loaded:
            log.info("Loaded %d self-allowlist entries from disk", loaded)

    def _save_self_allowlist(self) -> None:
        """Persist self-allowlist to disk for recovery across restarts."""
        try:
            os.makedirs(os.path.dirname(self._self_allowlist_path), exist_ok=True)
            tmp = self._self_allowlist_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(sorted(str(n) for n in self._self_allowlist), fh, indent=2)
            os.replace(tmp, self._self_allowlist_path)
        except OSError as exc:
            log.warning(
                "Failed to persist self-allowlist to %s: %s", self._self_allowlist_path, exc
            )

    def _load_runtime_allowlist(self) -> None:
        try:
            with open(self._runtime_allowlist_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return
        except (json.JSONDecodeError, OSError) as exc:
            log.warning(
                "Failed to load runtime allowlist from %s: %s", self._runtime_allowlist_path, exc
            )
            return

        if not isinstance(data, list):
            log.warning("Invalid runtime allowlist format in %s", self._runtime_allowlist_path)
            return

        for entry in data:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                self._runtime_allowlist.add(str(net))
                if net not in self._allowlist:
                    self._allowlist.append(net)
            except ValueError:
                log.warning("Ignoring invalid runtime allowlist entry %r", entry)

        if self._runtime_allowlist:
            log.info("Loaded %d runtime allowlist entries from disk", len(self._runtime_allowlist))

    def _save_runtime_allowlist(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._runtime_allowlist_path), exist_ok=True)
            tmp = self._runtime_allowlist_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(sorted(self._runtime_allowlist), fh, indent=2)
            os.replace(tmp, self._runtime_allowlist_path)
        except OSError as exc:
            log.warning(
                "Failed to persist runtime allowlist to %s: %s", self._runtime_allowlist_path, exc
            )

    def allowlist_add(self, entry: str) -> dict[str, Any]:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return {"ok": False, "error": f"invalid IP or CIDR: {entry}"}

        normalized = str(net)

        with self._lock:
            if net in self._self_allowlist:
                return {"ok": True, "already": True, "entry": normalized, "source": "system"}

            if net in self._allowlist and normalized not in self._runtime_allowlist:
                return {"ok": True, "already": True, "entry": normalized, "source": "config"}

            if normalized in self._runtime_allowlist:
                return {"ok": True, "already": True, "entry": normalized, "source": "runtime"}

            self._allowlist.append(net)
            self._runtime_allowlist.add(normalized)
            self._save_runtime_allowlist()

            unblocked = []
            for ip in list(self._local.keys()):
                try:
                    if ipaddress.ip_address(ip) in net:
                        unblocked.append(ip)
                except ValueError:
                    continue

        for ip in unblocked:
            self.unblock_local(ip, reason="allowlisted")

            audit("allowlist_add", entry=normalized, unblocked=unblocked)
        log.info("WHITELIST_ADD %s (unblocked %d existing entries)", normalized, len(unblocked))

        self.bus.publish(
            source_ip=normalized.split("/")[0],
            event_type="WHITELIST_ADD",
            action_taken="WHITELISTED",
            metadata={"entry": normalized, "unblocked": unblocked},
        )

        return {"ok": True, "added": True, "entry": normalized, "unblocked": unblocked}

    def allowlist_remove(self, entry: str) -> dict[str, Any]:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return {"ok": False, "error": f"invalid IP or CIDR: {entry}"}

        normalized = str(net)

        with self._lock:
            if net in self._self_allowlist:
                return {
                    "ok": False,
                    "error": f"{normalized} is a protected system IP and cannot be removed",
                }
            if normalized not in self._runtime_allowlist:
                if net in self._allowlist:
                    return {
                        "ok": False,
                        "error": f"{normalized} is defined in the config "
                        f"file — edit the config and restart to remove it",
                    }
                return {"ok": False, "error": f"{normalized} is not in the allowlist"}

            self._runtime_allowlist.discard(normalized)
            try:
                self._allowlist.remove(net)
            except ValueError:
                pass
            self._save_runtime_allowlist()

        audit("allowlist_remove", entry=normalized)
        log.info("WHITELIST_REMOVE %s", normalized)

        self.bus.publish(
            source_ip=normalized.split("/")[0],
            event_type="WHITELIST_REMOVE",
            action_taken="UNWHITELISTED",
            metadata={"entry": normalized},
        )

        return {"ok": True, "removed": True, "entry": normalized}

    def allowlist_list(self) -> dict[str, Any]:
        with self._lock:
            entries = []
            seen = set()
            for net in sorted(self._self_allowlist, key=str):
                key = str(net)
                entries.append({"entry": key, "source": "system"})
                seen.add(key)
            config_nets = self._normalize_allowlist(self.config.allowlist)
            for net in config_nets:
                key = str(net)
                if key not in seen:
                    entries.append({"entry": key, "source": "config"})
                    seen.add(key)
            for key in sorted(self._runtime_allowlist):
                if key not in seen:
                    entries.append({"entry": key, "source": "runtime"})
        return {"ok": True, "entries": entries, "count": len(entries)}
