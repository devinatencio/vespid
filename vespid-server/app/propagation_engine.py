"""Propagation Engine for fleet-wide blocklist sharing.

Evaluates block reports against configurable policies (corroboration threshold,
rate limits, allow-lists) and distributes approved blocks to all subscribed
nodes via the Fleet SSE channel.

Requirements: 1.3, 1.4, 1.5, 3.1, 3.2, 3.3, 3.4, 3.5, 4.1, 4.2, 4.3, 4.4,
              4.5, 4.6, 5.1, 5.2, 5.5, 7.1, 7.2, 7.3, 7.4, 7.6, 8.2, 8.3,
              9.1, 9.2, 9.3, 9.4
"""

from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from .fleet_sse import FleetSSEManager
from .intel_models import process_unblock_event
from .models import get_db, record_audit

logger = logging.getLogger(__name__)
reaper_logger = logging.getLogger("app.reaper")


def _utcnow() -> datetime:
    """Return the current UTC time."""
    return datetime.now(UTC)


def _format_ts(dt: datetime) -> str:
    """Format a datetime as ISO-8601 UTC string."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _generate_fleet_block_id() -> str:
    """Generate a unique fleet block ID."""
    return f"fb-{uuid.uuid4()}"


def parse_duration(value: str) -> int:
    """Parse a human-friendly duration string into seconds.

    Supported formats:
        - "30s" or "30S" → 30 seconds
        - "5m" or "5M"  → 300 seconds
        - "2h" or "2H"  → 7200 seconds
        - "1d" or "1D"  → 86400 seconds
        - "3600"         → 3600 seconds (plain integer fallback)
        - "0m", "0s"    → 0 (immediate)

    Args:
        value: The duration string to parse.

    Returns:
        The duration in seconds as an integer.

    Raises:
        ValueError: If the format is not recognized.
    """
    value = str(value).strip().lower()
    if not value:
        raise ValueError("Empty duration string")

    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}

    if value[-1] in multipliers:
        try:
            num = int(value[:-1])
        except ValueError as exc:
            raise ValueError(f"Invalid duration: {value!r}") from exc
        return num * multipliers[value[-1]]

    # Plain integer (seconds)
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"Invalid duration: {value!r}") from exc


class PropagationEngine:
    """Evaluates block reports and manages fleet-wide block propagation.

    This is a stateless service class that operates on the database directly.
    It encapsulates all policy logic: corroboration, rate limiting, allow-list
    checks, and TTL management.
    """

    def __init__(
        self,
        db_path: str,
        fleet_sse: FleetSSEManager,
        config: dict | None = None,
    ):
        """Initialize the PropagationEngine.

        Args:
            db_path: Path to the SQLite database file.
            fleet_sse: The FleetSSEManager instance for publishing events.
            config: Optional override config dict. If None, config is loaded
                from the fleet_config table on each operation.
        """
        self.db_path = db_path
        self.fleet_sse = fleet_sse
        self._config_override = config
        # Determine DB backend for SQL dialect differences
        if isinstance(db_path, dict):
            self._db_type = db_path.get("DATABASE_TYPE", "sqlite").lower()
        else:
            self._db_type = "sqlite"

    def _get_db(self) -> sqlite3.Connection:
        """Get a database connection."""
        return get_db(self.db_path)

    def _load_config(self) -> dict:
        """Load configuration from the fleet_config table.

        Returns a dict with typed values (int for numeric keys, bool for
        propagation_paused, list for excluded_event_types).
        """
        if self._config_override is not None:
            return self._config_override

        conn = self._get_db()
        try:
            rows = conn.execute("SELECT config_key, config_value FROM fleet_config").fetchall()
        finally:
            conn.close()

        config: dict[str, Any] = {}
        for row in rows:
            key = row["config_key"]
            value = row["config_value"]

            if key in (
                "corroboration_threshold",
                "max_fleet_blocks_per_hour",
                "max_reports_per_node_per_hour",
                "reaper_interval_seconds",
            ):
                config[key] = int(value)
            elif key in (
                "corroboration_window_seconds",
                "fleet_block_ttl_seconds",
                "expired_block_retention_seconds",
                "fleet_recidive_decay_seconds",
            ):
                config[key] = parse_duration(value)
            elif key == "fleet_recidive_tiers":
                try:
                    config[key] = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    config[key] = [86400, 259200, 604800, 2592000]
            elif key == "propagation_paused":
                config[key] = value.lower() in ("true", "1", "yes")
            elif key == "excluded_event_types":
                try:
                    config[key] = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    config[key] = []
            else:
                config[key] = value

        # Ensure defaults for any missing keys
        defaults = {
            "corroboration_threshold": 1,
            "corroboration_window_seconds": 3600,
            "fleet_block_ttl_seconds": 86400,
            "max_fleet_blocks_per_hour": 100,
            "max_reports_per_node_per_hour": 50,
            "propagation_paused": False,
            "excluded_event_types": [],
            "reaper_interval_seconds": 60,
            "expired_block_retention_seconds": 86400,
            "fleet_recidive_tiers": [86400, 259200, 604800, 2592000],
            "fleet_recidive_decay_seconds": 2592000,
        }
        for k, v in defaults.items():
            if k not in config:
                config[k] = v

        return config

    def _get_fleet_strike(self, source_ip: str) -> int:
        """Return the number of prior fleet blocks for this IP.

        Queries ``ip_intel.total_times_blocked`` — the full history of
        every block across the entire fleet.  Since NFT_ACTION events are
        filtered from the block counter (api.py:430), each increment
        corresponds to an actual detection event, not a local application.

        Applies ``fleet_recidive_decay_seconds``: if the IP's most recent
        block was longer ago than the decay window, the strike resets to 0.

        Returns 0 for first offense (tier 0 = 1d), 1 for second offense
        (tier 1 = 3d), etc.
        """
        conn = self._get_db()
        try:
            row = conn.execute(
                "SELECT total_times_blocked, last_blocked_at FROM ip_intel WHERE ip_address = ?",
                (source_ip,),
            ).fetchone()
            if row is None or row[0] is None:
                return 0

            total_blocked = int(row[0])
            if total_blocked == 0:
                return 0

            # Decay: if last block was too long ago, reset strike
            last_blocked = row[1]
            if last_blocked:
                config = self._load_config()
                decay_seconds = config.get("fleet_recidive_decay_seconds", 2592000)
                try:
                    last = datetime.fromisoformat((last_blocked or "").replace("Z", "+00:00"))
                    delta = (_utcnow() - last).total_seconds()
                    if delta > decay_seconds:
                        return 0
                except (ValueError, TypeError, OSError):
                    pass

            return total_blocked
        finally:
            conn.close()

    def _ttl_for_fleet_strike(self, strike: int) -> int:
        """Return the fleet block TTL for the given strike count.

        Uses the configured ``fleet_recidive_tiers``.  The *strike* value is the
        number of prior times the IP was blocked (0 = first offense).  It maps
        directly to a tier index: 0 → first tier (e.g. 1d), 1 → second tier
        (e.g. 3d), etc.  If the strike count exceeds the number of tiers, the
        last tier is used (maximum penalty).
        """
        config = self._load_config()
        tiers: list[int] = config.get("fleet_recidive_tiers", [86400, 259200, 604800, 2592000])
        if not tiers:
            return config["fleet_block_ttl_seconds"]
        idx = min(strike, len(tiers) - 1)
        return tiers[idx]

    def check_allowlist(self, source_ip: str) -> bool:
        """Check if an IP matches any active entry in the fleet_allowlist.

        Supports both exact IP matching and CIDR range matching using
        Python's ipaddress module.

        Args:
            source_ip: The IP address to check.

        Returns:
            True if the IP is on the allow-list (should be blocked from
            propagation), False otherwise.
        """
        conn = self._get_db()
        try:
            rows = conn.execute("SELECT entry FROM fleet_allowlist WHERE is_active = 1").fetchall()
        finally:
            conn.close()

        if not rows:
            return False

        try:
            ip_addr = ipaddress.ip_address(source_ip)
        except ValueError:
            # If the source_ip is not a valid IP, it can't match
            return False

        for row in rows:
            entry = row["entry"]
            try:
                if "/" in entry:
                    # CIDR range
                    network = ipaddress.ip_network(entry, strict=False)
                    if ip_addr in network:
                        return True
                else:
                    # Exact IP match
                    if ip_addr == ipaddress.ip_address(entry):
                        return True
            except ValueError:
                # Skip malformed entries
                continue

        return False

    def check_corroboration(self, source_ip: str) -> int:
        """Count distinct nodes reporting the IP within the corroboration window.

        Args:
            source_ip: The IP address to check corroboration for.

        Returns:
            The number of distinct nodes that have reported this IP within
            the configured corroboration time window.
        """
        config = self._load_config()
        window_seconds = config["corroboration_window_seconds"]
        cutoff = _format_ts(_utcnow() - timedelta(seconds=window_seconds))

        conn = self._get_db()
        try:
            row = conn.execute(
                "SELECT COUNT(DISTINCT node_id) as cnt "
                "FROM fleet_block_reports "
                "WHERE source_ip = ? AND reported_at >= ?",
                (source_ip, cutoff),
            ).fetchone()
        finally:
            conn.close()

        return row["cnt"] if row else 0

    def check_rate_limits(self, node_id: str) -> tuple[bool, bool]:
        """Check both fleet-wide and per-node hourly rate limits.

        Args:
            node_id: The node ID to check per-node limits for.

        Returns:
            A tuple (fleet_limit_ok, node_limit_ok) where True means
            the limit has NOT been exceeded.
        """
        config = self._load_config()
        max_fleet = config["max_fleet_blocks_per_hour"]
        max_node = config["max_reports_per_node_per_hour"]
        one_hour_ago = _format_ts(_utcnow() - timedelta(hours=1))

        conn = self._get_db()
        try:
            # Fleet-wide: count blocks approved in the last hour
            fleet_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM fleet_blocks "
                "WHERE status = 'active' AND approved_at >= ?",
                (one_hour_ago,),
            ).fetchone()
            fleet_count = fleet_row["cnt"] if fleet_row else 0

            # Per-node: count reports from this node in the last hour
            node_row = conn.execute(
                "SELECT COUNT(*) as cnt FROM fleet_block_reports "
                "WHERE node_id = ? AND reported_at >= ?",
                (node_id, one_hour_ago),
            ).fetchone()
            node_count = node_row["cnt"] if node_row else 0
        finally:
            conn.close()

        fleet_limit_ok = fleet_count < max_fleet
        node_limit_ok = node_count < max_node

        return (fleet_limit_ok, node_limit_ok)

    def _is_enrolled_agent_ip(self, source_ip: str) -> bool:
        """Return True if source_ip belongs to an enrolled Vespid agent/node.

        Looks up the IP in the inventory service's asset_aliases table and
        verifies the alias is linked to a node record.  Agent IPs must never
        be blocked, regardless of detections.  Loopback addresses are
        skipped (they cannot represent a remote agent).
        """
        try:
            ip_addr = ipaddress.ip_address(source_ip)
            if ip_addr.is_loopback:
                return False
        except ValueError:
            return False

        conn = self._get_db()
        try:
            row = conn.execute(
                "SELECT 1 FROM asset_aliases aa "
                "JOIN nodes n ON n.asset_id = aa.asset_id "
                "WHERE aa.alias_type IN ('ipv4', 'ipv6') "
                "  AND aa.alias_value = ? "
                "LIMIT 1",
                (source_ip,),
            ).fetchone()
        finally:
            conn.close()
        return row is not None

    def process_block_report(self, report: dict) -> dict:
        """Process a block report from a node.

        Main entry point: validate, check allowlist, check rate limits,
        store report, check corroboration, approve if threshold met.

        Args:
            report: A dict containing at minimum:
                - source_ip: The blocked IP
                - node_id: The reporting node
                - event_type: The detection event type
                - detection_rule: The rule that triggered (optional)
                - block_ttl_seconds: TTL for the block (optional)
                - event_id: The originating event ID (optional)

        Returns:
            A status dict with keys:
                - status: "accepted", "propagated", "rejected", "rate_limited"
                - reason: Human-readable explanation
                - fleet_block_id: If propagated, the fleet block ID
        """
        source_ip = report.get("source_ip", "")
        node_id = report.get("node_id", "")
        event_type = report.get("event_type", "")
        detection_rule = report.get("detection_rule", report.get("detection_rule_name", ""))
        block_ttl_seconds = report.get("block_ttl_seconds", 86400)
        event_id = report.get("event_id", "")

        # Validate required fields
        if not source_ip or not node_id or not event_type:
            return {
                "status": "rejected",
                "reason": "Missing required fields (source_ip, node_id, event_type)",
            }

        config = self._load_config()

        # Check excluded event types
        excluded = config.get("excluded_event_types", [])
        if event_type in excluded:
            self._audit(
                "fleet_block_rejected",
                source_ip,
                {
                    "node_id": node_id,
                    "event_type": event_type,
                    "reason": "excluded_event_type",
                },
                actor=node_id,
            )
            return {
                "status": "rejected",
                "reason": f"Event type '{event_type}' is excluded from propagation",
            }

        # Enrolled agents/nodes must never be blocked, regardless of detections.
        if self._is_enrolled_agent_ip(source_ip):
            self._audit(
                "fleet_block_rejected",
                source_ip,
                {
                    "node_id": node_id,
                    "event_type": event_type,
                    "reason": "enrolled_agent_ip",
                },
                actor=node_id,
            )
            return {
                "status": "rejected",
                "reason": f"IP {source_ip} belongs to an enrolled agent and cannot be blocked",
            }

        # Check allow-list
        if self.check_allowlist(source_ip):
            self._audit(
                "fleet_block_rejected",
                source_ip,
                {
                    "node_id": node_id,
                    "event_type": event_type,
                    "reason": "allowlisted",
                },
                actor=node_id,
            )
            return {
                "status": "rejected",
                "reason": f"IP {source_ip} is on the global allow-list",
            }

        # Check rate limits
        fleet_limit_ok, node_limit_ok = self.check_rate_limits(node_id)

        if not node_limit_ok:
            self._audit(
                "fleet_block_rejected",
                source_ip,
                {
                    "node_id": node_id,
                    "event_type": event_type,
                    "reason": "per_node_rate_limit_exceeded",
                },
                actor=node_id,
            )
            return {
                "status": "rate_limited",
                "reason": f"Node {node_id} has exceeded per-node rate limit",
            }

        # Store the report (upsert for idempotency on same node+IP)
        now = _format_ts(_utcnow())
        fleet_block_id = _generate_fleet_block_id()
        conn = self._get_db()
        try:
            if self._db_type == "sqlite":
                conn.execute(
                    "INSERT OR REPLACE INTO fleet_block_reports "
                    "(source_ip, node_id, event_type, detection_rule, "
                    "block_ttl_seconds, reported_at, event_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        source_ip,
                        node_id,
                        event_type,
                        detection_rule,
                        block_ttl_seconds,
                        now,
                        event_id,
                    ),
                )
            else:
                conn.execute(
                    "REPLACE INTO fleet_block_reports "
                    "(source_ip, node_id, event_type, detection_rule, "
                    "block_ttl_seconds, reported_at, event_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        source_ip,
                        node_id,
                        event_type,
                        detection_rule,
                        block_ttl_seconds,
                        now,
                        event_id,
                    ),
                )
            conn.commit()
        finally:
            conn.close()

        # Check if there's already an active block for this IP (TTL renewal)
        conn = self._get_db()
        try:
            existing = conn.execute(
                "SELECT fleet_block_id, originating_node_id, ttl_seconds, expires_at "
                "FROM fleet_blocks WHERE source_ip = ? AND status = 'active'",
                (source_ip,),
            ).fetchone()
        finally:
            conn.close()

        if existing:
            # If the block has already expired (reaper hasn't caught up),
            # expire it now and fall through to create a fresh block instead
            # of renewing a stale one.
            block_still_active = True
            expires_at = existing["expires_at"]
            if expires_at:
                if isinstance(expires_at, str):
                    exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                elif getattr(expires_at, "tzinfo", None) is None:
                    # MySQL returns naive datetimes — assume UTC
                    exp_dt = expires_at.replace(tzinfo=UTC)
                else:
                    exp_dt = expires_at
                if exp_dt < _utcnow():
                    conn = self._get_db()
                    try:
                        conn.execute(
                            "UPDATE fleet_blocks SET status = 'expired' WHERE fleet_block_id = ?",
                            (existing["fleet_block_id"],),
                        )
                        conn.commit()
                    finally:
                        conn.close()
                    logger.info(
                        "Fleet block %s for %s expired (reaper catch-up on new report)",
                        existing["fleet_block_id"],
                        source_ip,
                    )
                    block_still_active = False

            if block_still_active:
                originating = existing["originating_node_id"]
                existing_ttl = existing["ttl_seconds"]
                if originating and node_id and node_id != originating:
                    fleet_strike = self._get_fleet_strike(source_ip)
                    ttl = self._ttl_for_fleet_strike(fleet_strike)
                    ttl = max(ttl, existing_ttl)
                else:
                    ttl = existing_ttl
                new_expires = _format_ts(_utcnow() + timedelta(seconds=ttl))
                conn = self._get_db()
                try:
                    conn.execute(
                        "UPDATE fleet_blocks SET last_renewed_at = ?, expires_at = ?, ttl_seconds = ? "
                        "WHERE fleet_block_id = ?",
                        (now, new_expires, ttl, existing["fleet_block_id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()

                # Publish renewal event
                message = json.dumps(
                    {
                        "action": "renew",
                        "source_ip": source_ip,
                        "fleet_block_id": existing["fleet_block_id"],
                        "ttl_seconds": ttl,
                        "timestamp": now,
                    }
                )
                self.fleet_sse.publish(existing["fleet_block_id"], message)

                return {
                    "status": "accepted",
                    "reason": "TTL renewed for existing active block",
                    "fleet_block_id": existing["fleet_block_id"],
                }

        # Check corroboration
        corroboration_count = self.check_corroboration(source_ip)
        threshold = config["corroboration_threshold"]

        if corroboration_count >= threshold:
            if not fleet_limit_ok:
                self._audit(
                    "fleet_block_rejected",
                    source_ip,
                    {
                        "node_id": node_id,
                        "event_type": event_type,
                        "reason": "fleet_rate_limit_exceeded",
                        "corroboration_count": corroboration_count,
                    },
                    actor=node_id,
                )
                return {
                    "status": "rate_limited",
                    "reason": "Fleet-wide hourly rate limit exceeded",
                }

            # Check if propagation is paused
            if config.get("propagation_paused", False):
                return {
                    "status": "accepted",
                    "reason": "Report stored; propagation is paused",
                }

            # Approve and propagate
            fleet_block_id = self.approve_and_propagate(
                source_ip,
                event_type=event_type,
                detection_rule=detection_rule,
                node_id=node_id,
                corroboration_count=corroboration_count,
                fleet_block_id=fleet_block_id,
            )
            return {
                "status": "propagated",
                "reason": "Corroboration threshold met; block propagated",
                "fleet_block_id": fleet_block_id,
            }

        return {
            "status": "accepted",
            "reason": (
                f"Report stored; awaiting corroboration ({corroboration_count}/{threshold})"
            ),
        }

    def approve_and_propagate(
        self,
        source_ip: str,
        *,
        event_type: str = "",
        detection_rule: str = "",
        node_id: str = "",
        reason: str = "",
        corroboration_count: int = 1,
        fleet_block_id: str | None = None,
    ) -> str:
        """Mark a fleet block as active and publish an SSE message.

        Creates or updates the fleet_blocks record, sets expires_at based
        on the configured TTL, and publishes a block directive via SSE.

        Args:
            source_ip: The IP to block fleet-wide.
            event_type: The detection event type.
            detection_rule: The detection rule name.
            node_id: The originating node ID.
            reason: Optional reason string.
            corroboration_count: Number of nodes that corroborated.
            fleet_block_id: Optional pre-generated ID. If None, one is generated.

        Returns:
            The fleet_block_id of the approved block.
        """
        # Defense-in-depth: never approve propagation for enrolled agent IPs.
        if self._is_enrolled_agent_ip(source_ip):
            self._audit(
                "fleet_block_rejected",
                source_ip,
                {
                    "node_id": node_id,
                    "event_type": event_type,
                    "reason": "enrolled_agent_ip",
                },
                actor=node_id or "system",
            )
            logger.warning(
                "Refused to approve fleet block for enrolled agent IP %s",
                source_ip,
            )
            raise ValueError(f"IP {source_ip} belongs to an enrolled agent and cannot be blocked")

        fleet_strike = self._get_fleet_strike(source_ip)
        ttl = self._ttl_for_fleet_strike(fleet_strike)
        now = _utcnow()
        now_str = _format_ts(now)
        expires_at = _format_ts(now + timedelta(seconds=ttl))
        if fleet_block_id is None:
            fleet_block_id = _generate_fleet_block_id()

        if not reason:
            reason = f"{event_type} detected by {node_id}"

        conn = self._get_db()
        try:
            conn.execute(
                "INSERT INTO fleet_blocks "
                "(fleet_block_id, source_ip, status, first_reported_at, "
                "last_renewed_at, approved_at, expires_at, "
                "reporting_node_count, originating_node_id, event_type, "
                "detection_rule, reason, ttl_seconds) "
                "VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    fleet_block_id,
                    source_ip,
                    now_str,
                    now_str,
                    now_str,
                    expires_at,
                    corroboration_count,
                    node_id,
                    event_type,
                    detection_rule,
                    reason,
                    ttl,
                ),
            )
            # Link reports to this fleet block
            conn.execute(
                "UPDATE fleet_block_reports SET fleet_block_id = ? WHERE source_ip = ?",
                (fleet_block_id, source_ip),
            )
            conn.commit()
        finally:
            conn.close()

        self._mark_intel_blocked(source_ip, now_str)

        # Publish SSE message
        message = json.dumps(
            {
                "action": "block",
                "source_ip": source_ip,
                "reason": reason,
                "originating_node_id": node_id,
                "ttl_seconds": ttl,
                "timestamp": now_str,
                "fleet_block_id": fleet_block_id,
            }
        )
        self.fleet_sse.publish(fleet_block_id, message)

        # Audit
        self._audit(
            "fleet_block_propagated",
            source_ip,
            {
                "fleet_block_id": fleet_block_id,
                "corroboration_count": corroboration_count,
                "originating_node_id": node_id,
                "event_type": event_type,
                "ttl_seconds": ttl,
            },
            actor="system",
        )

        return fleet_block_id

    def manual_add(self, source_ip: str, reason: str, actor: str) -> dict:
        """Admin manually adds a fleet block bypassing corroboration.

        Args:
            source_ip: The IP to block.
            reason: The reason for the manual block.
            actor: The admin username performing the action.

        Returns:
            A status dict with the fleet_block_id.
        """
        # Enrolled agents/nodes must never be blocked, even manually.
        if self._is_enrolled_agent_ip(source_ip):
            self._audit(
                "fleet_block_rejected",
                source_ip,
                {
                    "reason": "enrolled_agent_ip",
                    "source": "manual_add",
                },
                actor=actor,
            )
            return {
                "status": "rejected",
                "reason": f"IP {source_ip} belongs to an enrolled agent and cannot be blocked",
            }

        # Check allow-list first
        if self.check_allowlist(source_ip):
            return {
                "status": "rejected",
                "reason": f"IP {source_ip} is on the global allow-list",
            }

        config = self._load_config()
        ttl = config["fleet_block_ttl_seconds"]
        now = _utcnow()
        now_str = _format_ts(now)
        expires_at = _format_ts(now + timedelta(seconds=ttl))
        fleet_block_id = _generate_fleet_block_id()

        conn = self._get_db()
        try:
            # Check if already active
            existing = conn.execute(
                "SELECT fleet_block_id FROM fleet_blocks WHERE source_ip = ? AND status = 'active'",
                (source_ip,),
            ).fetchone()

            if existing:
                conn.close()
                return {
                    "status": "exists",
                    "reason": f"IP {source_ip} is already actively blocked",
                    "fleet_block_id": existing["fleet_block_id"],
                }

            conn.execute(
                "INSERT INTO fleet_blocks "
                "(fleet_block_id, source_ip, status, first_reported_at, "
                "last_renewed_at, approved_at, expires_at, "
                "reporting_node_count, originating_node_id, event_type, "
                "detection_rule, reason, ttl_seconds) "
                "VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    fleet_block_id,
                    source_ip,
                    now_str,
                    now_str,
                    now_str,
                    expires_at,
                    0,
                    "admin",
                    "manual",
                    "",
                    reason,
                    ttl,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        self._mark_intel_blocked(source_ip, now_str)

        # Publish SSE message (unless paused)
        if not config.get("propagation_paused", False):
            message = json.dumps(
                {
                    "action": "block",
                    "source_ip": source_ip,
                    "reason": reason,
                    "originating_node_id": "admin",
                    "ttl_seconds": ttl,
                    "timestamp": now_str,
                    "fleet_block_id": fleet_block_id,
                }
            )
            self.fleet_sse.publish(fleet_block_id, message)

        # Audit
        self._audit(
            "fleet_block_manual_add",
            source_ip,
            {
                "fleet_block_id": fleet_block_id,
                "reason": reason,
                "ttl_seconds": ttl,
            },
            actor=actor,
        )

        return {
            "status": "propagated",
            "reason": "Manual fleet block added",
            "fleet_block_id": fleet_block_id,
        }

    def manual_remove(self, source_ip: str, actor: str) -> dict:
        """Admin removes a fleet block and publishes an unblock directive.

        Also updates the IP Intelligence record (last_unblocked_at) so that
        the Block Status correctly transitions from Active to Inactive.

        Args:
            source_ip: The IP to unblock.
            actor: The admin username performing the action.

        Returns:
            A status dict.
        """
        now_str = _format_ts(_utcnow())

        conn = self._get_db()
        try:
            row = conn.execute(
                "SELECT fleet_block_id FROM fleet_blocks WHERE source_ip = ? AND status = 'active'",
                (source_ip,),
            ).fetchone()

            if not row:
                conn.close()
                return {
                    "status": "not_found",
                    "reason": f"No active fleet block found for {source_ip}",
                }

            fleet_block_id = row["fleet_block_id"]

            conn.execute(
                "UPDATE fleet_blocks SET status = 'removed' WHERE fleet_block_id = ?",
                (fleet_block_id,),
            )

            # Wipe the corroboration-report history for this IP so the next
            # detection event from a node cannot immediately re-meet the
            # corroboration threshold and re-create the block. Without this,
            # an ongoing attack would re-block within milliseconds of the
            # unblock SSE reaching the nodes.
            reports_deleted = conn.execute(
                "DELETE FROM fleet_block_reports WHERE source_ip = ?",
                (source_ip,),
            ).rowcount
            conn.commit()
        finally:
            conn.close()

        # Update IP Intelligence record so Block Status shows Inactive
        try:
            intel_conn = self._get_db()
            try:
                process_unblock_event(
                    conn=intel_conn,
                    ip_address=source_ip,
                    timestamp=now_str,
                )
                intel_conn.commit()
            finally:
                intel_conn.close()
        except Exception:
            logger.warning(
                "Failed to update intel record for removed fleet block %s",
                source_ip,
            )

        # Publish unblock directive
        message = json.dumps(
            {
                "action": "unblock",
                "source_ip": source_ip,
                "reason": f"Manually removed by {actor}",
                "originating_node_id": "",
                "ttl_seconds": 0,
                "timestamp": now_str,
                "fleet_block_id": fleet_block_id,
            }
        )
        self.fleet_sse.publish(fleet_block_id, message)

        # Audit
        self._audit(
            "fleet_block_manual_remove",
            source_ip,
            {
                "fleet_block_id": fleet_block_id,
                "removed_by": actor,
                "reports_cleared": reports_deleted,
            },
            actor=actor,
        )

        return {
            "status": "removed",
            "reason": f"Fleet block for {source_ip} removed",
            "fleet_block_id": fleet_block_id,
            "reports_cleared": reports_deleted,
        }

    def reenable_block(self, source_ip: str, actor: str) -> dict:
        """Re-enable an expired or removed fleet block with a fresh TTL.

        Finds the most recent non-active block for the given IP, sets it
        back to 'active' with a new expires_at based on the current
        configured TTL, and publishes a block directive via SSE.

        Args:
            source_ip: The IP to re-enable blocking for.
            actor: The admin username performing the action.

        Returns:
            A status dict with the fleet_block_id.
        """
        # Enrolled agents/nodes must never be blocked.
        if self._is_enrolled_agent_ip(source_ip):
            self._audit(
                "fleet_block_rejected",
                source_ip,
                {
                    "reason": "enrolled_agent_ip",
                    "source": "reenable_block",
                },
                actor=actor,
            )
            return {
                "status": "rejected",
                "reason": f"IP {source_ip} belongs to an enrolled agent and cannot be blocked",
            }

        # Check allow-list first
        if self.check_allowlist(source_ip):
            return {
                "status": "rejected",
                "reason": f"IP {source_ip} is on the global allow-list",
            }

        config = self._load_config()
        ttl = config["fleet_block_ttl_seconds"]
        now = _utcnow()
        now_str = _format_ts(now)
        expires_at = _format_ts(now + timedelta(seconds=ttl))

        conn = self._get_db()
        try:
            # Check if already active
            active = conn.execute(
                "SELECT fleet_block_id FROM fleet_blocks WHERE source_ip = ? AND status = 'active'",
                (source_ip,),
            ).fetchone()

            if active:
                conn.close()
                return {
                    "status": "exists",
                    "reason": f"IP {source_ip} is already actively blocked",
                    "fleet_block_id": active["fleet_block_id"],
                }

            # Find the most recent expired or removed block for this IP
            row = conn.execute(
                "SELECT * FROM fleet_blocks "
                "WHERE source_ip = ? AND status IN ('expired', 'removed') "
                "ORDER BY approved_at DESC LIMIT 1",
                (source_ip,),
            ).fetchone()

            if not row:
                conn.close()
                return {
                    "status": "not_found",
                    "reason": f"No expired or removed block found for {source_ip}",
                }

            fleet_block_id = row["fleet_block_id"]

            conn.execute(
                "UPDATE fleet_blocks SET status = 'active', "
                "last_renewed_at = ?, expires_at = ?, ttl_seconds = ? "
                "WHERE fleet_block_id = ?",
                (now_str, expires_at, ttl, fleet_block_id),
            )
            conn.commit()
        finally:
            conn.close()

        self._mark_intel_blocked(source_ip, now_str)

        # Publish SSE block directive (unless paused)
        if not config.get("propagation_paused", False):
            message = json.dumps(
                {
                    "action": "block",
                    "source_ip": source_ip,
                    "reason": f"Re-enabled by {actor}",
                    "originating_node_id": "admin",
                    "ttl_seconds": ttl,
                    "timestamp": now_str,
                    "fleet_block_id": fleet_block_id,
                }
            )
            self.fleet_sse.publish(fleet_block_id, message)

        # Audit
        self._audit(
            "fleet_block_reenabled",
            source_ip,
            {
                "fleet_block_id": fleet_block_id,
                "reason": f"Re-enabled by {actor}",
                "ttl_seconds": ttl,
            },
            actor=actor,
        )

        return {
            "status": "reenabled",
            "reason": f"Fleet block for {source_ip} re-enabled with {ttl}s TTL",
            "fleet_block_id": fleet_block_id,
        }

    def reset_block_ttl(self, source_ip: str, actor: str) -> dict:
        """Reset an active fleet block's TTL to the current fleet default.

        Loads the fleet default TTL from config, updates the block's
        ttl_seconds and recalculates expires_at from now.

        Args:
            source_ip: The IP whose block TTL should be reset.
            actor: The admin username performing the action.

        Returns:
            A status dict with the fleet_block_id and new TTL.
        """
        config = self._load_config()
        default_ttl = config["fleet_block_ttl_seconds"]
        now = _utcnow()
        now_str = _format_ts(now)
        expires_at = _format_ts(now + timedelta(seconds=default_ttl))

        conn = self._get_db()
        try:
            row = conn.execute(
                "SELECT fleet_block_id, ttl_seconds FROM fleet_blocks "
                "WHERE source_ip = ? AND status = 'active'",
                (source_ip,),
            ).fetchone()

            if not row:
                conn.close()
                return {
                    "status": "not_found",
                    "reason": f"No active block found for {source_ip}",
                }

            fleet_block_id = row["fleet_block_id"]
            old_ttl = row["ttl_seconds"]

            conn.execute(
                "UPDATE fleet_blocks SET ttl_seconds = ?, "
                "last_renewed_at = ?, expires_at = ? "
                "WHERE fleet_block_id = ?",
                (default_ttl, now_str, expires_at, fleet_block_id),
            )
            conn.commit()
        finally:
            conn.close()

        # Audit
        self._audit(
            "fleet_block_ttl_reset",
            source_ip,
            {
                "fleet_block_id": fleet_block_id,
                "old_ttl_seconds": old_ttl,
                "new_ttl_seconds": default_ttl,
                "expires_at": expires_at,
            },
            actor=actor,
        )

        # Publish renewal event so agents can reset their local TTL
        message = json.dumps(
            {
                "action": "renew",
                "source_ip": source_ip,
                "fleet_block_id": fleet_block_id,
                "ttl_seconds": default_ttl,
                "timestamp": now_str,
            }
        )
        self.fleet_sse.publish(fleet_block_id, message)

        return {
            "status": "reset",
            "reason": f"TTL for {source_ip} reset to fleet default ({default_ttl}s)",
            "fleet_block_id": fleet_block_id,
            "ttl_seconds": default_ttl,
            "expires_at": expires_at,
        }

    def add_allowlist_entry(self, entry: str, actor: str) -> dict:
        """Add an entry to the global allow-list.

        If any active fleet blocks match the new entry, they are removed
        and unblock directives are published.

        Args:
            entry: An IP address or CIDR range to allow-list.
            actor: The admin username performing the action.

        Returns:
            A status dict with the entry ID and count of removed blocks.
        """
        now_str = _format_ts(_utcnow())

        conn = self._get_db()
        try:
            # Insert the allowlist entry
            if self._db_type == "sqlite":
                cursor = conn.execute(
                    "INSERT OR IGNORE INTO fleet_allowlist "
                    "(entry, reason, created_by, created_at) "
                    "VALUES (?, '', ?, ?)",
                    (entry, actor, now_str),
                )
            else:
                cursor = conn.execute(
                    "INSERT IGNORE INTO fleet_allowlist "
                    "(entry, reason, created_by, created_at) "
                    "VALUES (?, '', ?, ?)",
                    (entry, actor, now_str),
                )
            conn.commit()

            if cursor.rowcount == 0:
                # Entry already exists, reactivate it
                conn.execute(
                    "UPDATE fleet_allowlist SET is_active = 1 WHERE entry = ?",
                    (entry,),
                )
                conn.commit()

            entry_id = conn.execute(
                "SELECT id FROM fleet_allowlist WHERE entry = ?",
                (entry,),
            ).fetchone()["id"]

            # Find and remove matching active blocks
            active_blocks = conn.execute(
                "SELECT fleet_block_id, source_ip FROM fleet_blocks WHERE status = 'active'"
            ).fetchall()
        finally:
            conn.close()

        removed_count = 0
        for block in active_blocks:
            block_ip = block["source_ip"]
            if self._ip_matches_entry(block_ip, entry):
                # Remove this block
                conn2 = self._get_db()
                try:
                    conn2.execute(
                        "UPDATE fleet_blocks SET status = 'removed' WHERE fleet_block_id = ?",
                        (block["fleet_block_id"],),
                    )
                    conn2.commit()
                finally:
                    conn2.close()

                # Publish unblock directive
                message = json.dumps(
                    {
                        "action": "unblock",
                        "source_ip": block_ip,
                        "reason": f"Allow-listed by {actor} (entry: {entry})",
                        "originating_node_id": "",
                        "ttl_seconds": 0,
                        "timestamp": now_str,
                        "fleet_block_id": block["fleet_block_id"],
                    }
                )
                self.fleet_sse.publish(block["fleet_block_id"], message)
                removed_count += 1

        # Audit
        self._audit(
            "fleet_allowlist_modified",
            entry,
            {
                "action": "add",
                "entry": entry,
                "blocks_removed": removed_count,
            },
            actor=actor,
        )

        return {
            "status": "added",
            "entry_id": entry_id,
            "blocks_removed": removed_count,
        }

    def remove_allowlist_entry(self, entry_id: int, actor: str) -> dict:
        """Deactivate an allow-list entry.

        Args:
            entry_id: The ID of the allow-list entry to deactivate.
            actor: The admin username performing the action.

        Returns:
            A status dict.
        """
        conn = self._get_db()
        try:
            row = conn.execute(
                "SELECT entry FROM fleet_allowlist WHERE id = ?",
                (entry_id,),
            ).fetchone()

            if not row:
                conn.close()
                return {
                    "status": "not_found",
                    "reason": f"Allow-list entry {entry_id} not found",
                }

            entry_value = row["entry"]

            conn.execute(
                "UPDATE fleet_allowlist SET is_active = 0 WHERE id = ?",
                (entry_id,),
            )
            conn.commit()
        finally:
            conn.close()

        # Audit
        self._audit(
            "fleet_allowlist_modified",
            entry_value,
            {
                "action": "remove",
                "entry_id": entry_id,
                "entry": entry_value,
            },
            actor=actor,
        )

        return {
            "status": "removed",
            "entry": entry_value,
        }

    def reap_expired(self) -> int:
        """Find and expire blocks past their TTL, publish unblock directives.

        Also updates the IP Intelligence record (last_unblocked_at) so that
        the Block Status correctly transitions from Active to Inactive when
        a fleet block expires.

        Returns:
            The number of blocks expired.
        """
        now_str = _format_ts(_utcnow())

        conn = self._get_db()
        try:
            expired_blocks = conn.execute(
                "SELECT fleet_block_id, source_ip FROM fleet_blocks "
                "WHERE status = 'active' AND expires_at <= ?",
                (now_str,),
            ).fetchall()

            if not expired_blocks:
                conn.close()
                return 0

            for block in expired_blocks:
                conn.execute(
                    "UPDATE fleet_blocks SET status = 'expired' WHERE fleet_block_id = ?",
                    (block["fleet_block_id"],),
                )

            conn.commit()
        finally:
            conn.close()

        # Update IP Intelligence records so Block Status shows Inactive
        for block in expired_blocks:
            try:
                intel_conn = self._get_db()
                try:
                    process_unblock_event(
                        conn=intel_conn,
                        ip_address=block["source_ip"],
                        timestamp=now_str,
                    )
                    intel_conn.commit()
                finally:
                    intel_conn.close()
            except Exception:
                logger.warning(
                    "Failed to update intel record for expired fleet block %s (%s)",
                    block["source_ip"],
                    block["fleet_block_id"],
                )

        # Publish unblock directives and audit for each expired block
        for block in expired_blocks:
            message = json.dumps(
                {
                    "action": "unblock",
                    "source_ip": block["source_ip"],
                    "reason": "TTL expired",
                    "originating_node_id": "",
                    "ttl_seconds": 0,
                    "timestamp": now_str,
                    "fleet_block_id": block["fleet_block_id"],
                }
            )
            self.fleet_sse.publish(block["fleet_block_id"], message)

            self._audit(
                "fleet_block_expired",
                block["source_ip"],
                {
                    "fleet_block_id": block["fleet_block_id"],
                },
                actor="system",
            )

        reaper_logger.info(
            "Expired %d block(s): %s",
            len(expired_blocks),
            ", ".join(
                "{} ({})".format(b["source_ip"], b["fleet_block_id"]) for b in expired_blocks
            ),
        )

        return len(expired_blocks)

    def purge_old_blocks(self) -> int:
        """Delete expired/removed blocks older than the retention period.

        Uses the configured ``expired_block_retention_seconds`` to determine
        the cutoff. Blocks with status 'expired' or 'removed' whose
        ``expires_at`` is older than the cutoff are permanently deleted,
        along with their associated fleet_block_reports rows.

        Also catches zombie blocks: entries still marked 'active' whose
        ``expires_at`` is older than the cutoff (i.e., the reaper failed
        to transition them). These are set to 'expired' first, then deleted.

        Returns:
            The number of blocks purged.
        """
        config = self._load_config()
        retention = config["expired_block_retention_seconds"]
        cutoff = _format_ts(_utcnow() - timedelta(seconds=retention))

        conn = self._get_db()
        try:
            # First, catch zombie 'active' blocks whose expires_at is past
            # the retention cutoff — these should have been expired but weren't
            # (e.g., server was down when they expired).
            conn.execute(
                "UPDATE fleet_blocks SET status = 'expired' "
                "WHERE status = 'active' AND expires_at <= ?",
                (cutoff,),
            )

            # Delete related fleet_block_reports first (FK constraint)
            conn.execute(
                "DELETE FROM fleet_block_reports WHERE fleet_block_id IN ("
                "  SELECT fleet_block_id FROM fleet_blocks "
                "  WHERE status IN ('expired', 'removed') AND expires_at <= ?"
                ")",
                (cutoff,),
            )

            cursor = conn.execute(
                "DELETE FROM fleet_blocks "
                "WHERE status IN ('expired', 'removed') AND expires_at <= ?",
                (cutoff,),
            )
            conn.commit()
            count = cursor.rowcount
        finally:
            conn.close()

        return count

    def _ip_matches_entry(self, ip_str: str, entry: str) -> bool:
        """Check if an IP address matches an allow-list entry.

        Args:
            ip_str: The IP address to check.
            entry: An IP address or CIDR range.

        Returns:
            True if the IP matches the entry.
        """
        try:
            ip_addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        try:
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                return ip_addr in network
            else:
                return ip_addr == ipaddress.ip_address(entry)
        except ValueError:
            return False

    def _mark_intel_blocked(self, source_ip: str, timestamp: str) -> None:
        """Update ip_intel.last_blocked_at so Block Status reflects active block.

        Called whenever a fleet block transitions to 'active' (new propagation,
        manual add, or re-enable). Ensures last_blocked_at > last_unblocked_at
        so the Intelligence Service Block Status shows Active.
        """
        conn = self._get_db()
        try:
            conn.execute(
                "UPDATE ip_intel SET last_blocked_at = ? WHERE ip_address = ?",
                (timestamp, source_ip),
            )
            conn.commit()
        except Exception as exc:
            logger.warning("Failed to update intel last_blocked_at for %s: %s", source_ip, exc)
        finally:
            conn.close()

    def _audit(
        self,
        action_type: str,
        target: str,
        details: dict,
        actor: str = "system",
    ) -> None:
        """Record an audit log entry.

        Args:
            action_type: The audit action type.
            target: The target of the action (usually an IP).
            details: Additional details dict.
            actor: The actor performing the action.
        """
        conn = self._get_db()
        try:
            record_audit(
                conn,
                actor=actor,
                actor_ip=None,
                action_type=action_type,
                target=target,
                details=details,
            )
        finally:
            conn.close()
