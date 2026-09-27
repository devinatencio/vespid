"""Host detection components: ProcessTree and HostDetector.

ProcessTree maintains an in-memory pid→ppid mapping with TTL-based eviction,
enabling parent-child resolution for detection rules that reference
ParentImage / ParentCommandLine attributes.

HostDetector evaluates HostEvents against auditd CustomRules with
immediate-match semantics (a single match produces a detection instantly).
"""

from __future__ import annotations

import bisect
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass

from vespid.auditd.events import HostEvent


@dataclass
class ProcessEntry:
    """A single process execution record stored in the ProcessTree."""

    pid: int
    ppid: int
    exe: str
    command_line: str
    timestamp: float


class ProcessTree:
    """In-memory pid→ppid mapping with TTL-based eviction.

    Stores process entries keyed by pid, with each pid potentially having
    multiple entries (sorted by timestamp) to handle PID reuse correctly.
    """

    def __init__(self, ttl_seconds: int = 3600, max_entries: int = 100_000) -> None:
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        # pid -> list of ProcessEntry, sorted by timestamp ascending
        self._entries: dict[int, list[ProcessEntry]] = defaultdict(list)
        self._total_count: int = 0

    def record(self, event: HostEvent) -> None:
        """Add a process entry from a HostEvent. Called before rule evaluation (Req 4.7).

        Creates a ProcessEntry from the event and inserts it into the
        timestamp-sorted list for that pid. If total entries exceed max_entries,
        evicts oldest entries until at the limit (Req 4.6).
        """
        entry = ProcessEntry(
            pid=event.pid,
            ppid=event.ppid,
            exe=event.exe,
            command_line=event.command_line,
            timestamp=event.timestamp,
        )

        pid_list = self._entries[entry.pid]
        # Use bisect to maintain sorted order by timestamp
        timestamps = [e.timestamp for e in pid_list]
        insert_pos = bisect.bisect_right(timestamps, entry.timestamp)
        pid_list.insert(insert_pos, entry)
        self._total_count += 1

        # Enforce max_entries by evicting oldest entries globally
        if self._total_count > self._max_entries:
            self._evict_to_limit()

    def lookup_parent(self, ppid: int, child_timestamp: float) -> ProcessEntry | None:
        """Find the parent process entry for a given ppid at the given time.

        Returns the most recent entry for that pid with timestamp ≤ child_timestamp.
        This handles PID reuse correctly (Req 4.5) by selecting the entry whose
        timestamp is closest to but not exceeding the child's timestamp.

        Returns None if ppid not found (Req 4.3).
        """
        pid_list = self._entries.get(ppid)
        if not pid_list:
            return None

        # Binary search for the rightmost entry with timestamp <= child_timestamp
        timestamps = [e.timestamp for e in pid_list]
        idx = bisect.bisect_right(timestamps, child_timestamp)

        if idx == 0:
            # No entry has timestamp <= child_timestamp
            return None

        return pid_list[idx - 1]

    def evict_expired(self, now: float | None = None) -> int:
        """Remove entries older than TTL (Req 4.4). Returns number evicted."""
        if now is None:
            now = time.time()

        cutoff = now - self._ttl_seconds
        evicted = 0

        # Collect pids to remove entirely (empty after eviction)
        pids_to_remove: list[int] = []

        for pid, pid_list in self._entries.items():
            # Since entries are sorted by timestamp, find the first non-expired entry.
            # Use bisect_left so that entries at exactly the cutoff are kept
            # ("older than TTL" means timestamp < cutoff, not <=).
            first_valid = bisect.bisect_left([e.timestamp for e in pid_list], cutoff)
            if first_valid > 0:
                evicted += first_valid
                del pid_list[:first_valid]

            if not pid_list:
                pids_to_remove.append(pid)

        for pid in pids_to_remove:
            del self._entries[pid]

        self._total_count -= evicted
        return evicted

    def _evict_to_limit(self) -> None:
        """Evict oldest entries by timestamp until total_count <= max_entries."""
        while self._total_count > self._max_entries:
            # Find the pid with the oldest entry
            oldest_pid: int | None = None
            oldest_ts = float("inf")

            for pid, pid_list in self._entries.items():
                if pid_list and pid_list[0].timestamp < oldest_ts:
                    oldest_ts = pid_list[0].timestamp
                    oldest_pid = pid

            if oldest_pid is None:
                break

            # Remove the oldest entry from that pid
            self._entries[oldest_pid].pop(0)
            self._total_count -= 1

            # Clean up empty lists
            if not self._entries[oldest_pid]:
                del self._entries[oldest_pid]

    def __len__(self) -> int:
        """Total entries across all PIDs."""
        return self._total_count


# ---------------------------------------------------------------------------
# Severity weight mapping (Req 5.1)
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 50,
    "high": 25,
    "medium": 10,
    "low": 5,
    "informational": 1,
}

# ASCII Record Separator — used as field delimiter in flattened string.
_RS = "\x1e"


@dataclass
class HostDetection:
    """Result of a rule matching a HostEvent."""

    rule_name: str
    event_type: str
    severity_weight: int  # critical=50, high=25, medium=10, low=5, informational=1
    hostname: str
    pid: int
    ppid: int
    exe: str
    command_line: str
    uid: int
    auid: int
    timestamp: float
    parent_exe: str = ""
    parent_command_line: str = ""


class HostDetector:
    """Evaluates HostEvents against auditd CustomRules with immediate-match semantics.

    Rules are compiled at construction time.  Each call to ``evaluate()``
    checks exclusion filters first, records the event in the ProcessTree,
    resolves parent fields, and then runs all compiled regex patterns against
    the flattened event string.  Every matching rule produces a separate
    HostDetection result (Req 3.1, 3.2).
    """

    def __init__(
        self,
        rules: list,  # list of CustomRule (duck-typed: needs name, event_type, regex, severity, enabled)
        process_tree: ProcessTree,
        daemon_pid: int | None = None,
        exclude_uids: list[int] | None = None,
        exclude_exe_prefixes: list[str] | None = None,
    ) -> None:
        self._process_tree = process_tree
        self._daemon_pid = daemon_pid if daemon_pid is not None else os.getpid()
        self._exclude_uids: set[int] = set(exclude_uids or [])
        self._exclude_exe_prefixes: tuple[str, ...] = tuple(exclude_exe_prefixes or [])

        # Compile enabled rules — auditd rules do NOT require (?P<ip>...) (Req 3.3)
        self._compiled_rules: list[tuple[object, re.Pattern[str]]] = []
        for rule in rules:
            # Support both dataclass-like objects and dicts (from server JSON)
            if isinstance(rule, dict):
                if not rule.get("enabled", True):
                    continue
                regex_str = rule.get("regex", "")
            else:
                if not getattr(rule, "enabled", True):
                    continue
                regex_str = getattr(rule, "regex", "")
            try:
                pattern = re.compile(regex_str)
            except re.error:
                # Skip rules with invalid regex — they cannot match anything.
                continue
            self._compiled_rules.append((rule, pattern))

    def _is_excluded(self, event: HostEvent) -> bool:
        """Check if event should be excluded before rule evaluation.

        Exclusions (Req 3.8, 3.9, 7.7):
        - event.pid matches daemon PID (self-exclusion)
        - event.uid in exclude_uids
        - event.exe starts with any prefix in exclude_exe_prefixes
        """
        if event.pid == self._daemon_pid:
            return True
        if event.uid in self._exclude_uids:
            return True
        if self._exclude_exe_prefixes and event.exe.startswith(self._exclude_exe_prefixes):
            return True
        return False

    def evaluate(self, event: HostEvent) -> list[HostDetection]:
        """Evaluate a HostEvent against all enabled auditd rules.

        Returns empty list if event is excluded.
        Returns all matching detections (multiple rules can match one event).

        Flow:
        1. Check exclusion → return [] if excluded
        2. Record event in ProcessTree (Req 4.7: record before evaluation)
        3. Lookup parent via ProcessTree
        4. Build flattened string with parent fields appended
        5. Match each compiled rule regex via search (Req 3.4)
        6. Return list of HostDetection for all matches
        """
        # Step 1: exclusion check
        if self._is_excluded(event):
            return []

        # Step 2: record in process tree before evaluation (Req 4.7)
        self._process_tree.record(event)

        # Step 3: lookup parent
        parent = self._process_tree.lookup_parent(event.ppid, event.timestamp)

        # Step 4: build flattened string with parent fields (Req 3.12)
        parent_exe = parent.exe if parent else ""
        parent_cmdline = parent.command_line if parent else ""
        flattened = (
            event.flattened()
            + _RS
            + f"parent_exe={parent_exe}"
            + _RS
            + f"parent_cmdline={parent_cmdline}"
        )

        # Step 5 & 6: match rules and collect detections
        detections: list[HostDetection] = []
        for rule, pattern in self._compiled_rules:
            if pattern.search(flattened):
                # Helper to get field from rule (dict or object).
                # `rule` is bound as a default arg to capture the current
                # loop value (avoids late-binding).
                def _rf(field, default="", rule=rule):
                    if isinstance(rule, dict):
                        return rule.get(field, default)
                    return getattr(rule, field, default)

                # Resolve severity weight from rule
                severity_str = _rf("severity", "medium")
                weight = SEVERITY_WEIGHTS.get(
                    str(severity_str).lower().strip(), SEVERITY_WEIGHTS["medium"]
                )

                detections.append(
                    HostDetection(
                        rule_name=_rf("name", ""),
                        event_type=_rf("event_type", ""),
                        severity_weight=weight,
                        hostname=event.hostname,
                        pid=event.pid,
                        ppid=event.ppid,
                        exe=event.exe,
                        command_line=event.command_line,
                        uid=event.uid,
                        auid=event.auid,
                        timestamp=event.timestamp,
                        parent_exe=parent_exe,
                        parent_command_line=parent_cmdline,
                    )
                )

        return detections
