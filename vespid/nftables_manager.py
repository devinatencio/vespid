"""NFTables Manager with dual-set logic.

Two named sets live inside the ``shield`` table:

* ``shield_local``      - dynamic, populated by the LogProcessor; every
                          element has a TTL so blocks expire automatically.
* ``shield_subscribed`` - static feed-driven set, replaced wholesale by the
                          SubscriptionManager every refresh.

The manager shells out to ``nft`` (the standard CLI) so it works on any
AlmaLinux 10 install without extra Python dependencies. When ``nft`` is not
available (for example during unit tests) the manager falls back to a
tracked in-memory shadow state which is still reflected on the DataBus.

Repeat-offender escalation (recidive)
--------------------------------------
Each IP's block history is tracked in ``recidive.json``.  When an IP is
blocked again, the manager looks up its strike count and picks a TTL from
the configured ``recidive_tiers`` list (default: 24 h → 3 d → 7 d → 30 d).
If the IP stays clean for ``recidive_decay_seconds`` (default 30 days) the
strike count resets.

Expiry reaper
-------------
A periodic task (``reap_expired()``, called by the daemon every
``expiry_reap_interval`` seconds) removes entries from the in-memory
``_local`` dict once their TTL has passed, keeping ``list-local`` clean.

Firewalld compatibility
-----------------------
On systems running firewalld with the nftables backend, firewalld owns the
main ruleset and may flush/rebuild its tables on reload.  The ``shield``
table is intentionally standalone (priority -150, well before firewalld's
default priority 10) so it never conflicts.

To survive firewalld reloads **and** full reboots the manager:

1. Persists the table structure to ``/etc/nftables/shield.rules`` after
   every successful ``ensure_infrastructure()`` call.
2. Ensures ``/etc/sysconfig/nftables.conf`` includes that file so the
   nftables *service* loads the shield table at boot — before firewalld
   starts.
3. Provides a ``health_check()`` method (called periodically by the daemon)
   that detects a missing table and rebuilds it, re-injecting all active
   blocks from the in-memory / on-disk state.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterable
from contextlib import contextmanager
from typing import Any

from .config import CONFIG, ShieldConfig
from .databus import BUS, DataBus
from .logging_setup import audit
from .nftables_allowlist import AllowlistMixin
from .nftables_recidive import RecidiveMixin

log = logging.getLogger("vespid.nft")

# Paths for nftables persistence (firewalld coexistence)
_NFT_RULES_DIR = "/etc/nftables"
_NFT_RULES_PATH = os.path.join(_NFT_RULES_DIR, "shield.rules")
_NFT_SYSCONFIG = "/etc/sysconfig/nftables.conf"
_NFT_INCLUDE_LINE = 'include "/etc/nftables/shield.rules"'


class NFTablesError(RuntimeError):
    pass


def _parse_nft_counters(json_output: str) -> list[dict[str, Any]]:
    """Extract ``(set, chain, family, packets, bytes)`` from ``nft -j`` output.

    Walks the JSON array returned by ``nft -j list table``, finds every rule
    whose ``expr`` contains a ``counter`` statement referencing an ``saddr @set``
    match, and extracts the chain/family context from the parent objects.
    """
    import json

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        log.warning("Failed to parse nft JSON output")
        return []

    if not isinstance(data, dict) or "nftables" not in data:
        return []

    results: list[dict[str, Any]] = []

    for entry in data["nftables"]:
        if not isinstance(entry, dict):
            continue
        rule = entry.get("rule")
        if not isinstance(rule, dict):
            continue

        family = rule.get("family", "")
        chain_name = rule.get("chain", "")
        expr_list = rule.get("expr", [])
        if not isinstance(expr_list, list):
            continue

        set_name = ""
        packets = 0
        bytes_count = 0

        for expr in expr_list:
            if not isinstance(expr, dict):
                continue
            # Look for "match" with saddr @set
            if "match" in expr:
                match = expr["match"]
                if isinstance(match, dict):
                    left = match.get("left", {})
                    right = match.get("right", "")
                    if isinstance(left, dict) and isinstance(right, str) and right.startswith("@"):
                        set_name = right[1:]  # strip "@" prefix
            # Look for "counter" with packets/bytes
            if "counter" in expr:
                counter = expr["counter"]
                if isinstance(counter, dict):
                    packets = int(counter.get("packets", 0))
                    bytes_count = int(counter.get("bytes", 0))

        if set_name:
            results.append(
                {
                    "set": set_name,
                    "chain": chain_name,
                    "family": family,
                    "packets": packets,
                    "bytes": bytes_count,
                }
            )

    results.sort(key=lambda r: r["packets"], reverse=True)
    return results


class NFTablesManager(AllowlistMixin, RecidiveMixin):
    def __init__(
        self,
        config: ShieldConfig | None = None,
        bus: DataBus | None = None,
    ) -> None:
        self.config = config or CONFIG
        self.bus = bus or BUS
        self._lock = threading.RLock()
        self._nft = shutil.which("nft")
        # Shadow state: helps unit tests and `vespid-cli status`.
        # _local maps ip -> {"reason", "blocked_at", "expires_at", "rule"}
        self._local: dict[str, dict[str, Any]] = {}
        # Per-feed sets: maps feed_name -> set of CIDR strings
        self._feed_sets: dict[str, set[str]] = {}
        # Legacy compat: flat view of all subscribed entries
        self._subscribed: set[str] = set()
        self._allowlist = self._normalize_allowlist(self.config.allowlist)
        # Runtime allowlist additions (persisted separately from config)
        self._runtime_allowlist: set[str] = set()
        self._runtime_allowlist_path = os.path.join(
            os.environ.get("VESPID_STATE_DIR", "/var/lib/vespid"),
            "allowlist.json",
        )
        self._load_runtime_allowlist()
        # Self-allowlist: auto-detected local IPs that can never be blocked
        # or removed.  Populated on startup and persisted across restarts.
        self._self_allowlist: set[ipaddress._BaseNetwork] = set()
        self._self_allowlist_path = os.path.join(
            os.environ.get("VESPID_STATE_DIR", "/var/lib/vespid"),
            "self_allowlist.json",
        )
        self._load_self_allowlist()
        self._populate_self_allowlist()
        # Ring buffer of recent decisions for `vespid-cli recent`.
        self._recent: list[dict[str, Any]] = []
        self._recent_max = 200
        self._recent_path = os.path.join(
            os.environ.get("VESPID_STATE_DIR", "/var/lib/vespid"),
            "recent_decisions.json",
        )
        self._load_recent()
        # Persistence path for local block list
        self._persist_path = os.path.join(
            os.environ.get("VESPID_STATE_DIR", "/var/lib/vespid"),
            "local_blocks.json",
        )
        # Repeat-offender (recidive) tracker
        self._recidive_path = os.path.join(
            os.environ.get("VESPID_STATE_DIR", "/var/lib/vespid"),
            "recidive.json",
        )
        # Maps ip -> {"count": int, "first_seen": float, "last_seen": float}
        self._recidive: dict[str, dict[str, Any]] = {}
        self._load_recidive()
        # Defer persistence during bulk operations (e.g. fleet initial sync)
        self._persist_deferred = False
        self._persist_needed = False

    # ------------------------------------------------------------------
    # Bulk operation support — defer persistence
    # ------------------------------------------------------------------

    @contextmanager
    def defer_persist(self):
        """Context manager to batch multiple block/unblock ops with a single persist.

        Usage:
            with nft.defer_persist():
                for ip in ips:
                    nft.block_local(ip, ...)
            # Single persist happens here on exit
        """
        self._persist_deferred = True
        self._persist_needed = False
        try:
            yield
        finally:
            self._persist_deferred = False
            if self._persist_needed:
                self._persist_rules()
                self._persist_needed = False

    # ------------------------------------------------------------------
    # Expiry reaper — prune expired entries from the in-memory state
    # ------------------------------------------------------------------
    def reap_expired(self) -> int:
        """Remove entries from _local whose TTL has passed.

        Returns the number of entries reaped.  The daemon calls this
        periodically so that `list-local` stays clean.
        """
        now = time.time()
        expired_ips: list[str] = []

        with self._lock:
            for ip, meta in list(self._local.items()):
                expires_at = meta.get("expires_at")
                if expires_at is not None and expires_at <= now:
                    expired_ips.append(ip)

            for ip in expired_ips:
                del self._local[ip]

            if expired_ips:
                self._save_local()

        if expired_ips:
            log.info(
                "Reaped %d expired entries from shield_local: %s",
                len(expired_ips),
                ", ".join(expired_ips[:10]) + ("..." if len(expired_ips) > 10 else ""),
            )

        return len(expired_ips)

    # ------------------------------------------------------------------
    # Persistence — save/load local block list across restarts
    # ------------------------------------------------------------------
    def _save_local(self) -> None:
        """Persist the local block list to disk as JSON."""
        try:
            os.makedirs(os.path.dirname(self._persist_path), exist_ok=True)
            tmp = self._persist_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._local, fh, indent=2)
            os.replace(tmp, self._persist_path)
        except OSError as exc:
            log.warning("Failed to persist local block list to %s: %s", self._persist_path, exc)

    def _load_local(self) -> None:
        """Load the local block list from disk and restore non-expired entries.

        Expired entries are discarded. Allowlisted entries are removed.
        Valid entries are re-added to the nftables set so they survive
        daemon restarts.
        """
        try:
            with open(self._persist_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Failed to load local block list from %s: %s", self._persist_path, exc)
            return

        if not isinstance(data, dict):
            log.warning("Invalid local block list format in %s", self._persist_path)
            return

        now = time.time()
        restored = 0
        expired = 0
        allowlisted = 0
        for ip, meta in data.items():
            expires_at = meta.get("expires_at")
            if expires_at is not None and expires_at <= now:
                expired += 1
                continue
            if self.is_allowlisted(ip):
                allowlisted += 1
                continue
            self._local[ip] = meta
            restored += 1

        # Re-add all restored IPs to the nftables set in one batch
        if self._local:
            ips = list(self._local.keys())
            self._add_set_element(self.config.nft_set_local, ips)

        if restored or expired or allowlisted:
            log.info(
                "Restored %d local blocks from disk (%d expired, %d allowlisted — discarded)",
                restored,
                expired,
                allowlisted,
            )

        # Save immediately to clean out expired/allowlisted entries from the file
        if expired or allowlisted:
            self._save_local()

    # ------------------------------------------------------------------
    # Bootstrap
    # ------------------------------------------------------------------
    def _feed_set_name(self, feed_name: str) -> str:
        """Return the nftables set name for a feed (v4)."""
        # Strict allowlist: nftables set names allow [a-zA-Z0-9_]
        safe = re.sub(r"[^a-zA-Z0-9]", "_", feed_name)
        return f"shield_feed_{safe}"

    def _build_ruleset(self) -> str:
        """Return the nft script that declares the shield table.

        The table lives in the ``inet`` family so a single table handles
        both IPv4 and IPv6.  Sets:

        * ``shield_local``  / ``shield_local6``  — dynamic, per-IP blocks
        * ``shield_feed_<name>`` / ``shield_feed_<name>6`` — one per subscription feed

        Each chain matches against all sets so that traffic is blocked
        regardless of protocol version or source.
        """
        family = self.config.nft_family
        table = self.config.nft_table
        local = self.config.nft_set_local
        local6 = f"{local}6"
        ttl = self.config.nft_local_block_ttl

        # Build per-feed set declarations and chain rules
        feed_set_decls = ""
        feed_chain_rules = ""
        for feed in self.config.subscriptions:
            sname = self._feed_set_name(feed.name)
            sname6 = f"{sname}6"
            feed_set_decls += f"""
    set {sname} {{
        type ipv4_addr
        flags interval
    }}
    set {sname6} {{
        type ipv6_addr
        flags interval
    }}"""
            feed_chain_rules += f"""
        ip saddr @{sname} counter drop
        ip6 saddr @{sname6} counter drop"""

        # Also include sets for any feeds that were dynamically added
        # (present in _feed_sets but not in config.subscriptions)
        config_feed_names = {f.name for f in self.config.subscriptions}
        for feed_name in self._feed_sets:
            if feed_name not in config_feed_names:
                sname = self._feed_set_name(feed_name)
                sname6 = f"{sname}6"
                feed_set_decls += f"""
    set {sname} {{
        type ipv4_addr
        flags interval
    }}
    set {sname6} {{
        type ipv6_addr
        flags interval
    }}"""
                feed_chain_rules += f"""
        ip saddr @{sname} counter drop
        ip6 saddr @{sname6} counter drop"""

        return f"""
table {family} {table} {{
    set {local} {{
        type ipv4_addr
        flags timeout
        timeout {ttl}s
    }}
    set {local6} {{
        type ipv6_addr
        flags timeout
        timeout {ttl}s
    }}{feed_set_decls}
    chain shield_prerouting {{
        type filter hook prerouting priority raw; policy accept;{feed_chain_rules}
        ip saddr @{local} counter drop
        ip6 saddr @{local6} counter drop
    }}
    chain shield_input {{
        type filter hook input priority -150; policy accept;{feed_chain_rules}
        ip saddr @{local} counter drop
        ip6 saddr @{local6} counter drop
    }}
    chain shield_forward {{
        type filter hook forward priority -150; policy accept;{feed_chain_rules}
        ip saddr @{local} counter drop
        ip6 saddr @{local6} counter drop
    }}
}}
""".strip()

    def ensure_infrastructure(self) -> None:
        """Make sure the table, sets and chain hooks exist.

        Performs a clean rebuild: deletes the existing table (if any) and
        recreates it from scratch with the current feed list. This ensures
        no stale sets or duplicate chain rules accumulate.

        After successfully applying the ruleset to the kernel this also:
        * writes ``/etc/nftables/shield.rules`` so the table survives a
          reboot (the nftables service loads it before firewalld starts);
        * ensures ``/etc/sysconfig/nftables.conf`` includes that file.
        """
        if not self._nft:
            log.warning("nft binary not found; running in shadow-only mode")
            return

        # Delete the old table to remove stale sets and duplicate rules
        family = self.config.nft_family
        table = self.config.nft_table
        try:
            self._run_nft(f"delete table {family} {table}")
            log.info("Deleted old shield table for clean rebuild")
        except NFTablesError:
            pass  # Table didn't exist yet — that's fine

        ruleset = self._build_ruleset()

        try:
            self._run_nft_stdin(ruleset)
            log.info("nftables infrastructure ensured (table %s %s)", family, table)
        except NFTablesError as exc:
            log.error("Failed to apply nftables ruleset: %s", exc)
            return  # don't persist a broken state

        # Persist the table structure to disk for boot-time survival.
        self._persist_rules()
        self._ensure_sysconfig_include()

        # Restore persisted local blocks from disk
        self._load_local()

    # ------------------------------------------------------------------
    # Firewalld coexistence — persistence & health check
    # ------------------------------------------------------------------
    def _persist_rules(self) -> None:
        """Dump the live shield table to /etc/nftables/shield.rules.

        The output is validated before writing: it must contain the table
        declaration and a closing brace.  An empty or corrupted dump is
        never written — that would break the nftables service on next boot.

        If persistence is deferred (via :meth:`defer_persist`), the write
        is postponed until the context manager exits.
        """
        if self._persist_deferred:
            self._persist_needed = True
            return

        if not self._nft:
            return

        try:
            output = self._run_nft(f"list table {self.config.nft_family} {self.config.nft_table}")
        except NFTablesError as exc:
            log.warning("Cannot dump shield table for persistence: %s", exc)
            return

        # Validate: must contain the table header and a closing brace.
        if (
            f"table {self.config.nft_family} {self.config.nft_table}" not in output
            or "}" not in output
        ):
            log.error(
                "Refusing to persist shield rules — output looks empty or corrupted (len=%d)",
                len(output),
            )
            return

        try:
            os.makedirs(_NFT_RULES_DIR, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=_NFT_RULES_DIR, prefix="shield.rules.")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(output)
            os.replace(tmp, _NFT_RULES_PATH)
            log.info("Persisted shield rules to %s", _NFT_RULES_PATH)
        except OSError as exc:
            log.warning("Failed to write %s: %s", _NFT_RULES_PATH, exc)

    def _ensure_sysconfig_include(self) -> None:
        """Make sure /etc/sysconfig/nftables.conf includes shield.rules.

        This is idempotent — if the include line is already present the
        file is left untouched.
        """
        try:
            if os.path.isfile(_NFT_SYSCONFIG):
                with open(_NFT_SYSCONFIG, encoding="utf-8") as fh:
                    contents = fh.read()
                if _NFT_INCLUDE_LINE in contents:
                    return  # already present
                # Append the include at the end
                with open(_NFT_SYSCONFIG, "a", encoding="utf-8") as fh:
                    fh.write(f"\n{_NFT_INCLUDE_LINE}\n")
                log.info("Added shield include to %s", _NFT_SYSCONFIG)
            else:
                # File doesn't exist — create it with just the include.
                os.makedirs(os.path.dirname(_NFT_SYSCONFIG), exist_ok=True)
                with open(_NFT_SYSCONFIG, "w", encoding="utf-8") as fh:
                    fh.write(f"{_NFT_INCLUDE_LINE}\n")
                log.info("Created %s with shield include", _NFT_SYSCONFIG)
        except OSError as exc:
            log.warning("Could not update %s: %s", _NFT_SYSCONFIG, exc)

    def _table_exists(self) -> bool:
        """Return True if the shield table is present in the kernel."""
        if not self._nft:
            return False
        try:
            self._run_nft(f"list table {self.config.nft_family} {self.config.nft_table}")
            return True
        except NFTablesError:
            return False

    def health_check(self) -> bool:
        """Verify the shield table is alive; rebuild if missing.

        Returns True if the table is healthy (either already present or
        successfully rebuilt), False if recovery failed.

        The daemon should call this periodically (every 30-60 s) so that
        a firewalld reload that nukes the table is caught quickly.
        """
        if not self._nft:
            return True  # shadow-only mode, nothing to check

        if self._table_exists():
            return True

        log.warning("Shield table missing from kernel (firewalld reload?) — rebuilding")

        # Rebuild the table structure.
        ruleset = self._build_ruleset()
        try:
            self._run_nft_stdin(ruleset)
        except NFTablesError as exc:
            log.error("Failed to rebuild shield table: %s", exc)
            return False

        # Re-inject all active local blocks.
        with self._lock:
            ips = list(self._local.keys())
        if ips:
            self._add_set_element(self.config.nft_set_local, ips)
            log.info("Re-injected %d local blocks after rebuild", len(ips))

        # Re-inject all per-feed sets.
        total_subs = 0
        with self._lock:
            feeds_snapshot = dict(self._feed_sets)
        for fname, entries in feeds_snapshot.items():
            if entries:
                sname = self._feed_set_name(fname)
                self._add_set_element(sname, list(entries))
                total_subs += len(entries)
        if total_subs:
            log.info(
                "Re-injected %d subscribed entries across %d feeds after rebuild",
                total_subs,
                len(feeds_snapshot),
            )

        # Update the on-disk rules file.
        self._persist_rules()

        self.bus.publish(
            source_ip="0.0.0.0",
            event_type="NFT_HEALTH",
            action_taken="REBUILT",
            metadata={
                "local_restored": len(ips),
                "subscribed_restored": total_subs,
                "feed_sets": len(feeds_snapshot),
            },
        )
        audit("health_rebuild", local_restored=len(ips), subscribed_restored=total_subs)
        log.info("Shield table rebuilt successfully")
        return True

    # ------------------------------------------------------------------
    # shield_local (dynamic) operations
    # ------------------------------------------------------------------
    def block_local(
        self,
        ip: str,
        *,
        reason: str = "manual",
        ttl: int | None = None,
        detection_rule_name: str | None = None,
        threat_tag: str | None = None,
        request_count: int | None = None,
        surrounding_logs: list[dict] | None = None,
    ) -> bool:
        if self.is_allowlisted(ip):
            log.info("Refusing to block allowlisted IP %s", ip)
            return False
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            log.warning("Refusing to block invalid IP %r", ip)
            return False

        now = time.time()
        with self._lock:
            if ip in self._local:
                log.debug("Block requested for already-blocked %s", ip)
                return False

            # Only record an offense (increment strike) for local detections.
            # Fleet-propagated blocks are not independent attacks and should
            # not escalate the recidive counter.
            is_fleet = reason.startswith("fleet:")
            if is_fleet:
                strike = 1
                if ttl is None:
                    ttl = self._ttl_for_offense(strike)
            else:
                strike = self._record_offense(ip)
                if ttl is None:
                    ttl = self._ttl_for_offense(strike)

            self._add_set_element_with_timeout(self.config.nft_set_local, ip, ttl)
            self._local[ip] = {
                "reason": reason,
                "blocked_at": now,
                "expires_at": now + ttl,
                "strike": strike,
            }
            self._record_recent("BLOCK", ip, reason, strike=strike, ttl=ttl)
            self._save_local()

        # Kill existing connections so the attacker can't continue on
        # sessions established before the nftables rule took effect.
        self._flush_conntrack(ip)

        metadata = {
            "set": self.config.nft_set_local,
            "reason": reason,
            "strike": strike,
            "ttl": ttl,
        }
        # Include detection rule info for intel tracking
        if detection_rule_name:
            metadata["detection_rule_name"] = detection_rule_name
        if threat_tag:
            metadata["threat_tag"] = threat_tag
        # Include request_count so the intel DB reflects actual log volume
        if request_count is not None and request_count > 0:
            metadata["request_count"] = request_count
        # Include surrounding_logs so the intel DB can show the
        # matching requests that caused the block without relying on
        # cross-event linking on the server side.
        if surrounding_logs:
            metadata["surrounding_logs"] = surrounding_logs

        self.bus.publish(
            source_ip=ip,
            event_type="NFT_ACTION",
            action_taken="BLOCKED",
            metadata=metadata,
        )
        audit("block", ip=ip, set=self.config.nft_set_local, reason=reason, ttl=ttl, strike=strike)
        log.info(
            "BLOCK %s -> %s (reason=%s, strike=%d, ttl=%ss)",
            ip,
            self.config.nft_set_local,
            reason,
            strike,
            ttl,
        )
        self._persist_rules()
        return True

    def renew_local(self, ip: str, *, ttl: int) -> bool:
        """Renew the TTL for an existing entry in shield_local.

        If the IP is currently blocked locally, resets its expiry to
        ``now + ttl`` and updates the nftables timeout. If the IP is not
        present (already expired or never blocked), returns False so the
        caller can fall back to a full block.

        Args:
            ip: The IP address to renew.
            ttl: New TTL in seconds from now.

        Returns:
            True if the entry was renewed, False if the IP was not found.
        """
        now = time.time()
        with self._lock:
            if ip not in self._local:
                return False

            self._local[ip]["expires_at"] = now + ttl
            # Re-add to nftables with the new timeout (overwrites existing)
            self._add_set_element_with_timeout(self.config.nft_set_local, ip, ttl)
            self._save_local()

        log.info("RENEW %s in %s (new_ttl=%ds)", ip, self.config.nft_set_local, ttl)
        return True

    def unblock_local(self, ip: str, *, reason: str = "manual") -> bool:
        with self._lock:
            present = ip in self._local
            prior = self._local.pop(ip, None)
            self._delete_set_element(self.config.nft_set_local, [ip])
            self._record_recent("UNBLOCK", ip, reason, was_present=present)
            self._save_local()

        self.bus.publish(
            source_ip=ip,
            event_type="NFT_ACTION",
            action_taken="UNBLOCKED",
            metadata={
                "set": self.config.nft_set_local,
                "reason": reason,
                "was_present": present,
                "previous": prior or {},
            },
        )
        audit("unblock", ip=ip, set=self.config.nft_set_local, reason=reason, was_present=present)
        log.info(
            "UNBLOCK %s from %s (reason=%s, was_present=%s)",
            ip,
            self.config.nft_set_local,
            reason,
            present,
        )
        self._persist_rules()
        return present

    # ------------------------------------------------------------------
    # Per-feed set operations
    # ------------------------------------------------------------------
    def sync_feed(self, feed_name: str, entries: Iterable[str]) -> int:
        """Replace a single feed's nftables set with new entries.

        Each feed has its own set (shield_feed_<name>), so adding or
        removing a feed doesn't affect any other feed's entries.
        Overlapping CIDRs within a single feed are collapsed.
        Allowlisted entries are filtered out.

        Returns the number of entries committed.
        """
        v4_nets: list[ipaddress.IPv4Network] = []
        v6_nets: list[ipaddress.IPv6Network] = []
        for raw in entries:
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if any(net.overlaps(w) for w in self._allowlist):
                continue
            if isinstance(net, ipaddress.IPv4Network):
                v4_nets.append(net)
            else:
                v6_nets.append(net)

        # Collapse within this single feed to avoid interval conflicts
        collapsed_v4 = list(ipaddress.collapse_addresses(v4_nets))
        collapsed_v6 = list(ipaddress.collapse_addresses(v6_nets))
        clean = [str(n) for n in collapsed_v4] + [str(n) for n in collapsed_v6]

        set_name = self._feed_set_name(feed_name)

        with self._lock:
            # Ensure the set exists (may be a dynamically added feed)
            self._ensure_feed_set(feed_name)

        # Run nft commands OUTSIDE the lock to avoid blocking other
        # threads (especially the event loop) that need self._lock for
        # quick lookups like is_locally_blocked().
        self._flush_set(set_name)
        if clean:
            self._add_set_element(set_name, clean)

        with self._lock:
            self._feed_sets[feed_name] = set(clean)
            # Update the flat subscribed view
            self._rebuild_subscribed()

        log.info("SYNC feed %s -> %d entries committed to %s", feed_name, len(clean), set_name)
        self._persist_rules()
        return len(clean)

    def replace_subscribed(self, entries: Iterable[str]) -> int:
        """Legacy compat: replace all subscribed entries.

        This is called by sync_now() which merges all feeds. With per-feed
        sets, this is no longer the right approach — sync_now() should call
        sync_feed() per feed instead. This method is kept for backward
        compatibility but now delegates to the flat subscribed set update.
        """
        # This should not be called in the new per-feed model.
        # If it is, treat it as a single unnamed feed.
        return self.sync_feed("_legacy", entries)

    def create_feed_set(self, feed_name: str) -> None:
        """Create nftables sets for a new feed and rebuild chain rules.

        Called when a feed is dynamically added at runtime. Creates the
        v4/v6 interval sets, then rebuilds the table to add the
        corresponding chain rules cleanly (no duplicates).
        """
        if not self._nft:
            with self._lock:
                if feed_name not in self._feed_sets:
                    self._feed_sets[feed_name] = set()
            return

        with self._lock:
            if feed_name not in self._feed_sets:
                self._feed_sets[feed_name] = set()

        # Rebuild the entire table so the new feed gets its sets and
        # chain rules in one clean pass — no duplicate rules.
        self._rebuild_table()
        log.info("Created feed set for %s via table rebuild", feed_name)

    def destroy_feed_set(self, feed_name: str) -> None:
        """Remove a feed's nftables sets and clean up.

        Flushes the sets (removing all blocked IPs from that feed),
        then rebuilds the table to remove the sets and chain rules.
        """
        set_name = self._feed_set_name(feed_name)

        with self._lock:
            self._feed_sets.pop(feed_name, None)
            self._rebuild_subscribed()

        # Flush the set contents first
        self._flush_set(set_name)

        # Rebuild the entire table to remove the set declarations and
        # chain rules cleanly. This is the safest approach since nftables
        # doesn't support deleting sets that are referenced by rules.
        self._rebuild_table()

        log.info("Destroyed feed set %s", feed_name)

    def _ensure_feed_set(self, feed_name: str) -> None:
        """Ensure the feed is tracked. Creates nftables sets via rebuild if needed."""
        needs_rebuild = False
        with self._lock:
            if feed_name not in self._feed_sets:
                self._feed_sets[feed_name] = set()
                needs_rebuild = True

        if needs_rebuild and self._nft:
            # Check if the set actually exists in the kernel
            set_name = self._feed_set_name(feed_name)
            family = self.config.nft_family
            table = self.config.nft_table
            try:
                self._run_nft(f"list set {family} {table} {set_name}")
            except NFTablesError:
                # Set doesn't exist — rebuild to create it with chain rules
                self._rebuild_table()

    def _rebuild_subscribed(self) -> None:
        """Rebuild the flat _subscribed set from all per-feed sets."""
        combined: set[str] = set()
        for entries in self._feed_sets.values():
            combined.update(entries)
        self._subscribed = combined

    def _rebuild_table(self) -> None:
        """Rebuild the entire nftables table structure.

        Used after removing a feed to cleanly remove its sets and rules.
        Re-injects all local blocks and feed entries afterward.
        """
        if not self._nft:
            return

        # Delete the old table
        family = self.config.nft_family
        table = self.config.nft_table
        try:
            self._run_nft(f"delete table {family} {table}")
        except NFTablesError:
            pass  # Table might not exist

        # Rebuild with current feed list
        ruleset = self._build_ruleset()
        try:
            self._run_nft_stdin(ruleset)
        except NFTablesError as exc:
            log.error("Failed to rebuild table: %s", exc)
            return

        # Re-inject local blocks
        with self._lock:
            ips = list(self._local.keys())
        if ips:
            self._add_set_element(self.config.nft_set_local, ips)

        # Re-inject all feed entries
        with self._lock:
            feeds_snapshot = dict(self._feed_sets)
        for fname, entries in feeds_snapshot.items():
            if entries:
                sname = self._feed_set_name(fname)
                self._add_set_element(sname, list(entries))

        self._persist_rules()
        log.info("Table rebuilt with %d feed sets", len(feeds_snapshot))

    # ------------------------------------------------------------------
    # Inspection / status
    # ------------------------------------------------------------------
    def status(self) -> dict:
        with self._lock:
            fleet_count = sum(
                1 for meta in self._local.values() if meta.get("reason", "").startswith("fleet:")
            )
            return {
                "nft_available": bool(self._nft),
                "table": f"{self.config.nft_family} {self.config.nft_table}",
                "local_count": len(self._local),
                "subscribed_count": len(self._subscribed),
                "fleet_block_count": fleet_count,
                "local_sample": sorted(self._local.keys())[:20],
                "allowlist": [str(n) for n in self._allowlist],
                "self_allowlist": [str(n) for n in self._self_allowlist],
            }

    def get_counters(self) -> list[dict[str, Any]]:
        """Parse nftables counters from the live table via ``nft -j``.

        Returns a list of dicts, one per chain rule that references a set:
            {
                "set": "shield_feed_firehol_level1",
                "chain": "shield_prerouting",
                "family": "ip",
                "packets": 15955,
                "bytes": 2832851,
            }

        Results are sorted by packets descending so the most active
        rules appear first.
        """
        if not self._nft:
            return []

        try:
            output = self._run_nft_json(
                f"list table {self.config.nft_family} {self.config.nft_table}"
            )
        except NFTablesError as exc:
            log.warning("Cannot read counters: %s", exc)
            return []

        return _parse_nft_counters(output)

    @staticmethod
    def _parse_counters(nft_output: str) -> list[dict[str, Any]]:
        """Legacy text-parser — kept for backward compatibility.

        Deprecated in favour of ``nft -j`` JSON output.  Will be removed
        in a future release.
        """
        return _parse_nft_counters(nft_output)

    def is_locally_blocked(self, ip: str) -> bool:
        """Return True if the IP is currently blocked in shield_local.

        Excludes expired entries that the reaper hasn't cleaned yet.
        """
        now = time.time()
        with self._lock:
            meta = self._local.get(ip)
            if meta is None:
                return False
            expires = meta.get("expires_at")
            if expires is not None and expires <= now:
                return False
            return True

    def local_blocked_set(self) -> set:
        """Return the set of IPs currently blocked in shield_local.

        Lightweight check for bulk membership testing (e.g. initial sync).
        Excludes expired entries that the reaper hasn't cleaned yet.
        """
        now = time.time()
        with self._lock:
            return {
                ip
                for ip, meta in self._local.items()
                if meta.get("expires_at") is None or meta["expires_at"] > now
            }

    def local_fleet_blocked_set(self) -> set:
        """Return IPs in shield_local that were placed there by fleet propagation.

        These have a ``fleet:`` prefix in their reason field.  Used by the
        fleet subscriber to reconcile stale entries after an SSE outage.
        """
        now = time.time()
        with self._lock:
            return {
                ip
                for ip, meta in self._local.items()
                if meta.get("reason", "").startswith("fleet:")
                and (meta.get("expires_at") is None or meta["expires_at"] > now)
            }

    def unblock_local_bulk(self, ips: set[str], *, reason: str = "fleet:sync_cleanup") -> int:
        """Remove multiple IPs from shield_local in one pass (no per-IP events)."""
        count = 0
        with self._lock:
            for ip in ips:
                if ip in self._local:
                    del self._local[ip]
                    self._delete_set_element(self.config.nft_set_local, [ip])
                    count += 1
            if count:
                self._save_local()
        if count:
            log.info(
                "Fleet sync cleanup: removed %d stale fleet-propagated block(s) from shield_local",
                count,
            )
            self._persist_rules()
        return count

    def get_local_meta(self, ip: str) -> dict[str, Any]:
        """Return metadata for a locally-blocked IP, or empty dict."""
        with self._lock:
            return dict(self._local.get(ip, {}))

    def list_local(self) -> list[dict[str, Any]]:
        """Detailed listing of every IP currently in shield_local.

        Expired entries are excluded — they are cleaned up by the reaper.
        """
        now = time.time()
        with self._lock:
            rows = []
            for ip, meta in self._local.items():
                expires_at = meta.get("expires_at")
                if expires_at is not None and expires_at <= now:
                    # Skip expired entries (reaper will clean them shortly)
                    continue
                ttl_remaining = max(0, int(expires_at - now)) if expires_at else 0
                rows.append(
                    {
                        "ip": ip,
                        "reason": meta.get("reason"),
                        "blocked_at": meta.get("blocked_at"),
                        "expires_at": expires_at,
                        "ttl_remaining": ttl_remaining,
                        "strike": meta.get("strike", 1),
                    }
                )
        rows.sort(key=lambda r: r["blocked_at"] or 0, reverse=True)
        return rows

    def list_subscribed(self, limit: int | None = None) -> list[str]:
        """All entries currently across all feed sets."""
        with self._lock:
            entries = sorted(self._subscribed)
        if limit is not None:
            return entries[:limit]
        return entries

    def list_feed_sets(self) -> dict[str, int]:
        """Return a dict of feed_name -> entry count for all feed sets."""
        with self._lock:
            return {name: len(entries) for name, entries in self._feed_sets.items()}

    def is_blocked(self, ip: str) -> dict[str, Any]:
        """Check whether an IP is blocked, and where."""
        result: dict[str, Any] = {
            "ip": ip,
            "in_local": False,
            "in_subscribed": False,
            "allowlisted": self.is_allowlisted(ip),
            "local": None,
            "matching_subscribed": [],
        }
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            result["error"] = "invalid_ip"
            return result

        with self._lock:
            if ip in self._local:
                result["in_local"] = True
                result["local"] = dict(self._local[ip])
            for cidr in self._subscribed:
                try:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        result["in_subscribed"] = True
                        result["matching_subscribed"].append(cidr)
                except ValueError:
                    continue
        return result

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._recent[-limit:])[::-1]

    def _record_recent(self, action: str, ip: str, reason: str, **extra: Any) -> None:
        entry = {
            "ts": time.time(),
            "action": action,
            "ip": ip,
            "reason": reason,
            **extra,
        }
        self._recent.append(entry)
        if len(self._recent) > self._recent_max:
            del self._recent[: len(self._recent) - self._recent_max]
        self._save_recent()

    def _save_recent(self) -> None:
        """Persist the recent decisions ring buffer to disk."""
        try:
            os.makedirs(os.path.dirname(self._recent_path), exist_ok=True)
            tmp = self._recent_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._recent, fh, separators=(",", ":"))
            os.replace(tmp, self._recent_path)
        except OSError as exc:
            log.debug("Failed to persist recent decisions: %s", exc)

    def _load_recent(self) -> None:
        """Load the recent decisions ring buffer from disk."""
        try:
            with open(self._recent_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return
        except (json.JSONDecodeError, OSError) as exc:
            log.debug("Failed to load recent decisions from %s: %s", self._recent_path, exc)
            return

        if not isinstance(data, list):
            return

        # Keep only the most recent entries up to the max
        self._recent = data[-self._recent_max :]
        if self._recent:
            log.info("Restored %d recent decisions from disk", len(self._recent))

    # ------------------------------------------------------------------
    # Low level nft helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _is_v6(addr_or_cidr: str) -> bool:
        """Return True if *addr_or_cidr* is an IPv6 address or network."""
        try:
            return ipaddress.ip_address(addr_or_cidr).version == 6
        except ValueError:
            pass
        try:
            return ipaddress.ip_network(addr_or_cidr, strict=False).version == 6
        except ValueError:
            return False

    def _resolve_set_name(self, base_set: str, element: str) -> str:
        """Return the v6 set name if *element* is IPv6, else *base_set*."""
        return f"{base_set}6" if self._is_v6(element) else base_set

    def _add_set_element(self, set_name: str, elements: list[str]) -> None:
        if not self._nft or not elements:
            return
        # Split elements by address family so each goes to the right set.
        v4 = [e for e in elements if not self._is_v6(e)]
        v6 = [e for e in elements if self._is_v6(e)]
        for batch, sname in ((v4, set_name), (v6, f"{set_name}6")):
            if not batch:
                continue
            cmd = (
                f"add element {self.config.nft_family} {self.config.nft_table} "
                f"{sname} {{ {', '.join(batch)} }}"
            )
            try:
                self._run_nft(cmd)
            except NFTablesError as exc:
                log.warning("nft add element failed (%s): %s", sname, exc)

    def _add_set_element_with_timeout(self, set_name: str, element: str, timeout: int) -> None:
        """Add a single element with a per-element timeout override.

        This is used for escalated blocks where the TTL differs from the
        set's default timeout.
        """
        if not self._nft or not element:
            return
        sname = self._resolve_set_name(set_name, element)
        cmd = (
            f"add element {self.config.nft_family} {self.config.nft_table} "
            f"{sname} {{ {element} timeout {timeout}s }}"
        )
        try:
            self._run_nft(cmd)
        except NFTablesError as exc:
            log.warning("nft add element with timeout failed (%s): %s", sname, exc)

    def _delete_set_element(self, set_name: str, elements: list[str]) -> None:
        if not self._nft or not elements:
            return
        v4 = [e for e in elements if not self._is_v6(e)]
        v6 = [e for e in elements if self._is_v6(e)]
        for batch, sname in ((v4, set_name), (v6, f"{set_name}6")):
            if not batch:
                continue
            cmd = (
                f"delete element {self.config.nft_family} {self.config.nft_table} "
                f"{sname} {{ {', '.join(batch)} }}"
            )
            try:
                self._run_nft(cmd)
            except NFTablesError:
                # Element may not exist - that's fine.
                pass

    def _flush_set(self, set_name: str) -> None:
        """Flush both the v4 and v6 variants of a set."""
        if not self._nft:
            return
        for sname in (set_name, f"{set_name}6"):
            cmd = f"flush set {self.config.nft_family} {self.config.nft_table} {sname}"
            try:
                self._run_nft(cmd)
            except NFTablesError as exc:
                log.warning("nft flush set failed (%s): %s", sname, exc)

    def _flush_conntrack(self, ip: str) -> None:
        """Drop all tracked connections from *ip* via conntrack.

        This ensures that established sessions (e.g. an SSH connection
        already past the TCP handshake) are torn down immediately when
        an IP is blocked, rather than allowing the attacker to continue
        on an existing connection until it times out.

        Failures are logged but not raised — conntrack may not be
        installed or the kernel module may not be loaded, and the
        nftables block still prevents new connections regardless.
        """
        conntrack = shutil.which("conntrack")
        if not conntrack:
            log.debug("conntrack binary not found; skipping connection flush for %s", ip)
            return
        try:
            proc = subprocess.run(
                [conntrack, "-D", "-s", ip],
                check=False,
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                log.info("Flushed conntrack entries for %s", ip)
            elif "0 flow entries" in proc.stderr or proc.returncode == 1:
                # No entries to delete — not an error
                log.debug("No conntrack entries to flush for %s", ip)
            else:
                log.warning(
                    "conntrack -D -s %s failed: %s", ip, proc.stderr.strip() or proc.stdout.strip()
                )
        except OSError as exc:
            log.warning("Failed to run conntrack for %s: %s", ip, exc)

    def _run_nft(self, cmd: str) -> str:
        """Run a single nft command.

        Commands that contain braces (element add/delete) are piped via
        ``-f -`` (stdin) so the nft scripting parser handles them
        correctly.  Simple commands (list, flush) use ``-e`` which
        returns output on stdout.
        """
        assert self._nft is not None  # Callers guard with `if not self._nft`
        if "{" in cmd:
            # Brace-delimited commands must go through the script parser.
            proc = subprocess.run(
                [self._nft, "-f", "-"],
                input=cmd,
                check=False,
                capture_output=True,
                text=True,
            )
        else:
            proc = subprocess.run(
                [self._nft, "-e", cmd],
                check=False,
                capture_output=True,
                text=True,
            )
        if proc.returncode != 0:
            raise NFTablesError(proc.stderr.strip() or proc.stdout.strip())
        return proc.stdout

    def _run_nft_json(self, cmd: str) -> str:
        """Run an nft command with JSON output (``nft -j ...``).

        Uses ``-j`` instead of ``-e`` so the output is valid JSON that
        can be parsed with ``json.loads()``.
        """
        assert self._nft is not None
        proc = subprocess.run(
            [self._nft, "-j", cmd],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise NFTablesError(proc.stderr.strip() or proc.stdout.strip())
        return proc.stdout

    def _run_nft_stdin(self, script: str) -> str:
        assert self._nft is not None
        proc = subprocess.run(
            [self._nft, "-f", "-"],
            input=script,
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise NFTablesError(proc.stderr.strip() or proc.stdout.strip())
        return proc.stdout
