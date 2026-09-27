"""Sliding-window brute-force detector and multi-signal correlation detector.

Implementation note: we keep a per-(rule, ip) deque of recent attempt
timestamps. On every new attempt the deque is trimmed to the rule's window
and the length compared to ``max_attempts``. This is O(1) amortised and
naturally supports both fast brute force (X attempts / minute) and *slow*
brute force (X attempts / many hours).

The ``CorrelationDetector`` complements the per-rule approach by tracking
*distinct signal categories* per IP.  An IP that triggers observations
across multiple categories (e.g. scanner UA + bad request + TLS probe)
within a time window is flagged as performing multi-vector reconnaissance,
even if no single rule's threshold was reached.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .config import BruteForceRule, CorrelationRule


@dataclass
class Detection:
    rule: BruteForceRule
    source_ip: str
    attempts: int
    first_seen: float
    last_seen: float
    context_lines: list[dict] | None = None


class SlidingWindowDetector:
    """One detector instance can host many rules."""

    def __init__(self, rules: Iterable[BruteForceRule], persist_path: str | None = None) -> None:
        self.rules: list[BruteForceRule] = list(rules)
        # (rule_name, ip) -> deque[(timestamp, raw_line)]
        self._buckets: dict[tuple[str, str], deque[tuple[float, str]]] = defaultdict(deque)
        # rule_name -> ip -> cooldown_until (avoid event spam after a hit)
        self._cooldown: dict[str, dict[str, float]] = defaultdict(dict)
        self.cooldown_seconds = 300
        self._persist_path = persist_path
        if persist_path:
            self._load()

    def save(self) -> None:
        """Persist current buckets and cooldowns to disk."""
        if not self._persist_path:
            return
        buckets_data = []
        for (rule_name, ip), entries in self._buckets.items():
            buckets_data.append(
                {
                    "rule": rule_name,
                    "ip": ip,
                    "timestamps": [ts for ts, _ in entries],
                }
            )
        cooldown_data = {}
        for rule_name, ip_map in self._cooldown.items():
            cooldown_data[rule_name] = dict(ip_map)
        data = {
            "buckets": buckets_data,
            "cooldown": cooldown_data,
        }
        path = Path(self._persist_path)
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(data, separators=(",", ":")))
            tmp.replace(path)
        except OSError:
            pass

    def _load(self) -> None:
        """Restore buckets and cooldowns from disk."""
        if not self._persist_path:
            return
        path = Path(self._persist_path)
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            expired_cutoff = time.time() - 86400 * 7  # drop state older than 7 days
            for entry in data.get("buckets", []):
                rule_name = entry.get("rule", "")
                ip = entry.get("ip", "")
                raw_list = entry.get("timestamps", [])
                surviving = [
                    (ts, "")
                    for ts in raw_list
                    if isinstance(ts, (int, float)) and ts > expired_cutoff
                ]
                if surviving:
                    surviving.sort(key=lambda x: x[0])
                    self._buckets[(rule_name, ip)] = deque(surviving)
            for rule_name, ip_map in data.get("cooldown", {}).items():
                for ip, until in ip_map.items():
                    if until > time.time():
                        self._cooldown[rule_name][ip] = until
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass

    def prune_stale(self, now: float | None = None) -> int:
        """Remove buckets and cooldowns for IPs with no recent activity.

        Returns the number of bucket keys removed.  Should be called
        periodically (e.g. every few minutes) to bound memory usage on
        long-running daemons that see many unique IPs.
        """
        ts = now if now is not None else time.time()
        pruned = 0

        # Find the longest window across all rules so we keep any bucket
        # that *might* still contribute to a detection.
        max_window = max((r.window_seconds for r in self.rules), default=0)
        cutoff = ts - max_window - self.cooldown_seconds

        stale_keys = [
            key for key, bucket in self._buckets.items() if not bucket or bucket[-1][0] < cutoff
        ]
        for key in stale_keys:
            del self._buckets[key]
            pruned += 1

        # Prune expired cooldowns
        for _rule_name, ip_map in list(self._cooldown.items()):
            expired = [ip for ip, until in ip_map.items() if until < ts]
            for ip in expired:
                del ip_map[ip]

        return pruned

    def record(
        self,
        *,
        parser: str,
        source_ip: str,
        timestamp: float | None = None,
        raw_line: str | None = None,
    ) -> list[Detection]:
        """Record an attempt and return any rules that just tripped."""
        ts = timestamp if timestamp is not None else time.time()
        fired: list[Detection] = []
        raw = raw_line or ""

        for rule in self.rules:
            if rule.parser != parser:
                continue

            cd = self._cooldown[rule.name].get(source_ip, 0.0)
            if ts < cd:
                continue

            key = (rule.name, source_ip)
            bucket = self._buckets[key]
            bucket.append((ts, raw))

            cutoff = ts - rule.window_seconds
            while bucket and bucket[0][0] < cutoff:
                bucket.popleft()

            if len(bucket) >= rule.max_attempts:
                context = [{"raw": r, "trigger": False} for _, r in bucket]
                if context:
                    context[-1]["trigger"] = True
                fired.append(
                    Detection(
                        rule=rule,
                        source_ip=source_ip,
                        attempts=len(bucket),
                        first_seen=bucket[0][0],
                        last_seen=bucket[-1][0],
                        context_lines=context,
                    )
                )
                self._cooldown[rule.name][source_ip] = ts + self.cooldown_seconds
                bucket.clear()

        return fired


# ---------------------------------------------------------------------------
# Multi-signal correlation detector
# ---------------------------------------------------------------------------


@dataclass
class CorrelationHit:
    """Represents a signal category observation for correlation tracking."""

    category: str
    timestamp: float


@dataclass
class CorrelationDetection:
    """Fired when an IP triggers enough distinct signal categories."""

    rule: CorrelationRule
    source_ip: str
    categories_seen: list[str]
    first_seen: float
    last_seen: float


class CorrelationDetector:
    """Detects multi-vector reconnaissance by correlating distinct signal types.

    Instead of counting repeated hits on a *single* rule, this detector
    tracks how many *different* signal categories an IP triggers within a
    time window.  This catches the "low and slow" pattern where an attacker
    does one or two things from each category — never enough to trip any
    individual rule — but the combination is a clear indicator of recon.

    Signal categories are derived from parser names by default:
        - "secure"                → "ssh_auth_fail"
        - "secure_recon_strong"   → "ssh_recon"
        - "secure_recon_weak"     → "ssh_recon_weak"
        - "secure_negotiate_fail" → "ssh_negotiate"
        - "apache"                → "http_auth_fail"
        - "apache_bad_request"    → "http_bad_request"
        - "apache_not_found"      → "http_probe"
        - "apache_other"          → "http_other"
        - "messages"              → "firewall_deny"
        - "custom:*"              → "custom:<name>"

    The mapping is intentionally coarse — we want to count *types* of
    misbehaviour, not individual events.
    """

    # Parser → correlation category mapping
    CATEGORY_MAP: dict[str, str] = {
        "secure": "ssh_auth_fail",
        "secure_recon_strong": "ssh_recon",
        "secure_recon_weak": "ssh_recon_weak",
        "secure_negotiate_fail": "ssh_negotiate",
        "apache": "http_auth_fail",
        "apache_bad_request": "http_bad_request",
        "apache_not_found": "http_probe",
        "apache_other": "http_other",
        "apache_scanner_ua": "http_scanner_ua",
        "messages": "firewall_deny",
        "haproxy": "http_auth_fail",
        "haproxy_bad_request": "http_bad_request",
        "haproxy_not_found": "http_probe",
        "haproxy_scanner_ua": "http_scanner_ua",
        "haproxy_other": "http_other",
    }

    def __init__(self, rules: Iterable[CorrelationRule], persist_path: str | None = None) -> None:
        self.rules: list[CorrelationRule] = list(rules)
        # ip -> list of (category, timestamp)
        self._observations: dict[str, list[CorrelationHit]] = defaultdict(list)
        # ip -> cooldown_until (per rule name)
        self._cooldown: dict[tuple[str, str], float] = {}
        self.cooldown_seconds = 300
        self._persist_path = persist_path
        if persist_path:
            self._load()

    def _categorize(self, parser: str) -> str:
        """Map a parser name to a coarse signal category."""
        if parser.startswith("custom:"):
            return parser  # Keep custom rules as their own category
        return self.CATEGORY_MAP.get(parser, parser)

    def record(
        self,
        *,
        parser: str,
        source_ip: str,
        timestamp: float | None = None,
    ) -> list[CorrelationDetection]:
        """Record an observation and check if any correlation rule fires.

        Returns a list of CorrelationDetection for each rule that tripped.
        """
        ts = timestamp if timestamp is not None else time.time()
        category = self._categorize(parser)
        fired: list[CorrelationDetection] = []

        # Append observation
        self._observations[source_ip].append(CorrelationHit(category=category, timestamp=ts))

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Check cooldown
            cd_key = (rule.name, source_ip)
            cd_until = self._cooldown.get(cd_key, 0.0)
            if ts < cd_until:
                continue

            # Trim observations to the rule's window
            cutoff = ts - rule.window_seconds
            obs = self._observations[source_ip]

            # Collect distinct categories within the window
            categories_in_window: set[str] = set()
            for hit in obs:
                if hit.timestamp >= cutoff:
                    categories_in_window.add(hit.category)

            if len(categories_in_window) >= rule.min_categories:
                # Find time bounds of the contributing observations
                relevant_times = [
                    h.timestamp
                    for h in obs
                    if h.timestamp >= cutoff and h.category in categories_in_window
                ]
                fired.append(
                    CorrelationDetection(
                        rule=rule,
                        source_ip=source_ip,
                        categories_seen=sorted(categories_in_window),
                        first_seen=min(relevant_times),
                        last_seen=max(relevant_times),
                    )
                )
                self._cooldown[cd_key] = ts + self.cooldown_seconds
                # Clear observations for this IP to avoid re-firing
                self._observations[source_ip] = []
                break  # One correlation detection per record() call is enough

        return fired

    def save(self) -> None:
        """Persist current observations and cooldowns to disk."""
        if not self._persist_path:
            return
        observations_data = {}
        for ip, hits in self._observations.items():
            observations_data[ip] = [
                {"category": h.category, "timestamp": h.timestamp} for h in hits
            ]
        cooldown_data = {f"{k[0]}|{k[1]}": v for k, v in self._cooldown.items()}
        data = {
            "observations": observations_data,
            "cooldown": cooldown_data,
        }
        path = Path(self._persist_path)
        tmp = path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(data, separators=(",", ":")))
            tmp.replace(path)
        except OSError:
            pass

    def _load(self) -> None:
        """Restore observations and cooldowns from disk."""
        if not self._persist_path:
            return
        path = Path(self._persist_path)
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            expired_cutoff = time.time() - 86400 * 7
            for ip, hits_data in data.get("observations", {}).items():
                hits = [
                    CorrelationHit(category=h["category"], timestamp=h["timestamp"])
                    for h in hits_data
                    if h["timestamp"] > expired_cutoff
                ]
                if hits:
                    self._observations[ip] = hits
            for key, until in data.get("cooldown", {}).items():
                if until > time.time():
                    parts = key.split("|", 1)
                    if len(parts) == 2:
                        self._cooldown[(parts[0], parts[1])] = until
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass

    def prune_stale(self, now: float | None = None) -> int:
        """Remove stale observation data for IPs with no recent activity.

        Returns the number of IP keys removed.
        """
        ts = now if now is not None else time.time()
        max_window = max((r.window_seconds for r in self.rules), default=0)
        cutoff = ts - max_window - self.cooldown_seconds
        pruned = 0

        stale_ips = [
            ip for ip, obs in self._observations.items() if not obs or obs[-1].timestamp < cutoff
        ]
        for ip in stale_ips:
            del self._observations[ip]
            pruned += 1

        # Prune expired cooldowns
        expired_keys = [k for k, until in self._cooldown.items() if until < ts]
        for k in expired_keys:
            del self._cooldown[k]

        return pruned
