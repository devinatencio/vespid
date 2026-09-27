"""Host information collector.

Gathers system-level details about the node (hostname, OS, network
interfaces, etc.) for reporting to the central server via heartbeat.
"""

from __future__ import annotations

import logging
import os
import platform
import socket
from typing import Any

log = logging.getLogger("vespid.host_info")


def collect() -> dict[str, Any]:
    """Collect host information and return as a JSON-serializable dict.

    Returns a dict with keys:
        hostname: FQDN or short hostname
        os: OS description (e.g. "Ubuntu 24.04" or "Debian GNU/Linux 12")
        kernel: Kernel version string
        machine_id: D-Bus machine ID (/etc/machine-id) or None
        uptime_seconds: System uptime in seconds (None if unavailable)
        cpu_count: Number of logical CPUs
        memory_total_mb: Total physical memory in MiB (None if unavailable)
        interfaces: List of network interface dicts
    """
    return {
        "hostname": _get_hostname(),
        "os": _get_os_description(),
        "kernel": platform.release(),
        "machine_id": _get_machine_id(),
        "virt_type": _detect_virt_type(),
        "uptime_seconds": _get_uptime(),
        "cpu_count": os.cpu_count(),
        "cpu_model": _get_cpu_model(),
        "memory_total_mb": _get_memory_total_mb(),
        "interfaces": _get_interfaces(),
    }


_VIRT_HINTS = {
    "kvm",
    "qemu",
    "vmware",
    "virtualbox",
    "virtual machine",
    "hvm domU",
    "xen",
    "bochs",
    "openstack",
    "nutanix",
}


def _detect_virt_type() -> str | None:
    """Detect virtualization type from DMI data or systemd-detect-virt.

    Returns ``'vm'`` if running inside a virtual machine, ``'host'`` if bare
    metal, or ``None`` if detection is unavailable.
    """
    try:
        with open("/sys/class/dmi/id/product_name") as fh:
            name = fh.read().strip().lower()
            for hint in _VIRT_HINTS:
                if hint in name:
                    return "vm"
            if name and name != "system product name":
                return "host"
    except OSError:
        pass
    try:
        import subprocess

        out = subprocess.check_output(
            ["systemd-detect-virt"], timeout=5, stderr=subprocess.DEVNULL, text=True
        ).strip()
        if out and out != "none":
            return "vm"
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None


def _get_cpu_model() -> str | None:
    """Read CPU model name from /proc/cpuinfo."""
    try:
        with open("/proc/cpuinfo") as fh:
            for line in fh:
                if line.startswith("model name"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
    except OSError:
        pass
    return None


def _get_hostname() -> str:
    """Return the FQDN, falling back to the short hostname."""
    fqdn = socket.getfqdn()
    if fqdn and fqdn != "localhost":
        return fqdn
    return socket.gethostname()


_MACHINE_ID_PATHS = ("/etc/machine-id", "/var/lib/dbus/machine-id")


def _get_machine_id() -> str | None:
    """Read the D-Bus machine ID.

    Tries ``/etc/machine-id`` first, then ``/var/lib/dbus/machine-id``
    as a fallback for older containers.
    """
    for path in _MACHINE_ID_PATHS:
        try:
            with open(path) as fh:
                value = fh.read().strip()
                if value:
                    return value
        except OSError:
            continue
    return None


def _get_os_description() -> str:
    """Return a human-readable OS description.

    On Linux, reads /etc/os-release for PRETTY_NAME.
    Falls back to platform.platform().
    """
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    # Strip key, quotes, and newline
                    value = line.split("=", 1)[1].strip().strip('"')
                    if value:
                        return value
    except OSError:
        pass
    return platform.platform()


def _get_uptime() -> int | None:
    """Return system uptime in seconds, or None if unavailable."""
    try:
        with open("/proc/uptime", encoding="utf-8") as fh:
            return int(float(fh.read().split()[0]))
    except (OSError, ValueError, IndexError):
        pass
    return None


def _get_memory_total_mb() -> int | None:
    """Return total physical memory in MiB, or None if unavailable."""
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    # Value is in kB
                    parts = line.split()
                    kb = int(parts[1])
                    return kb // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def _get_interfaces() -> list[dict[str, Any]]:
    """Return a list of network interface dicts with name, MAC, and IPs.

    Each dict has:
        name: Interface name (e.g. "eth0")
        mac: MAC address string or None (for virtual interfaces)
        ipv4: List of IPv4 address strings
        ipv6: List of IPv6 address strings (link-local excluded)
    """
    interfaces: list[dict[str, Any]] = []

    try:
        import netifaces  # type: ignore

        return _get_interfaces_netifaces(netifaces)
    except ImportError:
        pass

    # Fallback: parse /sys/class/net on Linux
    try:
        return _get_interfaces_sysfs()
    except Exception as exc:
        log.debug("Could not enumerate interfaces: %s", exc)

    return interfaces


def _get_interfaces_netifaces(netifaces) -> list[dict[str, Any]]:
    """Gather interface info using the netifaces library."""
    import netifaces as nf

    interfaces = []
    for iface_name in nf.interfaces():
        if iface_name == "lo":
            continue

        addrs = nf.ifaddresses(iface_name)
        mac = None
        mac_list = addrs.get(nf.AF_LINK, [])
        if mac_list:
            mac = mac_list[0].get("addr")
            if mac == "00:00:00:00:00:00":
                mac = None

        ipv4 = [a["addr"] for a in addrs.get(nf.AF_INET, [])]
        ipv6 = [
            a["addr"].split("%")[0]
            for a in addrs.get(nf.AF_INET6, [])
            if not a["addr"].startswith("fe80:")
        ]

        interfaces.append(
            {
                "name": iface_name,
                "mac": mac,
                "ipv4": ipv4,
                "ipv6": ipv6,
            }
        )

    return interfaces


def _get_interfaces_sysfs() -> list[dict[str, Any]]:
    """Gather interface info from /sys/class/net (Linux only)."""

    net_dir = "/sys/class/net"
    interfaces: list[dict[str, Any]] = []

    if not os.path.isdir(net_dir):
        return interfaces

    for iface_name in sorted(os.listdir(net_dir)):
        if iface_name == "lo":
            continue

        # Read MAC address
        mac = None
        mac_path = os.path.join(net_dir, iface_name, "address")
        try:
            with open(mac_path, encoding="utf-8") as fh:
                mac = fh.read().strip()
                if mac == "00:00:00:00:00:00":
                    mac = None
        except OSError:
            pass

        # Get IP addresses from ip command output
        ipv4, ipv6 = _get_ips_for_interface(iface_name)

        interfaces.append(
            {
                "name": iface_name,
                "mac": mac,
                "ipv4": ipv4,
                "ipv6": ipv6,
            }
        )

    return interfaces


def _get_ips_for_interface(iface_name: str) -> tuple:
    """Get IPv4 and IPv6 addresses for an interface using `ip addr`."""
    import subprocess

    ipv4: list[str] = []
    ipv6: list[str] = []

    try:
        output = subprocess.check_output(
            ["ip", "-o", "addr", "show", "dev", iface_name],
            timeout=5,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in output.strip().splitlines():
            parts = line.split()
            # Format: index: name family addr/prefix ...
            try:
                family_idx = next(i for i, p in enumerate(parts) if p in ("inet", "inet6"))
                family = parts[family_idx]
                addr_with_prefix = parts[family_idx + 1]
                addr = addr_with_prefix.split("/")[0]

                if family == "inet":
                    ipv4.append(addr)
                elif family == "inet6" and not addr.startswith("fe80:"):
                    ipv6.append(addr)
            except (StopIteration, IndexError):
                continue
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        pass

    return ipv4, ipv6
