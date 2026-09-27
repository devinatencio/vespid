"""Auditd log monitoring subpackage for Vespid.

Provides host-based process creation detection via Linux auditd logs.
"""

from vespid.auditd.events import HostEvent

__all__ = ["HostEvent"]
