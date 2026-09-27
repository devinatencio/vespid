"""Config Subscriber.

Connects to the server's Config SSE channel and applies centrally-managed
configuration updates to the local agent.  Handles reconnection with
exponential backoff and ``Last-Event-ID`` replay.

Uses httpx async streaming with native read-timeout detection to
protect against silent TCP connection drops — replaces the previous
urllib + thread-based watchdog + raw-socket-close pattern.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import random
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx

from . import __version__
from .config import STATE_DIR, ShieldConfig
from .http_client import build_ssl_context
from .nftables_manager import NFTablesManager
from .subscription_manager import SubscriptionManager

log = logging.getLogger("vespid.config_sub")

# Reconnection backoff parameters
_BACKOFF_INITIAL = 5  # seconds
_BACKOFF_MAX = 300  # 5 minutes
_BACKOFF_FACTOR = 2
_BACKOFF_JITTER = 0.20  # ±20%

# Read timeout: if no data received for this many seconds, consider
# the connection dead and force a reconnect.  The server sends keepalive
# comments every 30s, so 60s gives 2 missed keepalives before triggering.
_KEEPALIVE_TIMEOUT = 60

# Fallback check-in interval — kept short (60s) because gunicorn
# multi-worker deployments route SSE connections and HTTP requests to
# different worker processes, so in-memory SSE fan-out misses cross-worker
# publishes.  The check-in polls the DB-backed endpoint and catches
# profile updates (auditd, rules, feeds, etc.) that SSE missed.
_CHECKIN_INTERVAL = 60  # 1 minute

# Interval for periodic re-sync of allowlist/blocklist from ip_rules.
# Allowlist/blocklist are decoupled from config profiles and synced
# independently via SSE list_update events + this periodic fallback.
_LIST_SYNC_INTERVAL = 300  # 5 minutes

# Local cache file path
_CACHE_FILE = STATE_DIR / "config_cache.json"


class ConfigSubscriber:
    """Asyncio task that subscribes to the Config SSE channel.

    Maintains a persistent SSE connection to the server for real-time
    config push notifications.  Performs an initial check-in on connect
    for version sync and health reporting.  Resolves conflicts with local
    settings and applies changes via hot-reload.
    """

    def __init__(
        self,
        config: ShieldConfig,
        on_rules_updated: Callable,
        subscription_manager: SubscriptionManager,
        nft_manager: NFTablesManager,
        credentials_ready: threading.Event | None = None,
        on_auth_failure: Callable[[], bool] | None = None,
        on_config_applied: Callable[[], None] | None = None,
        on_auditd_updated: Callable[[dict], dict] | None = None,
    ) -> None:
        self.config = config
        self._on_rules_updated = on_rules_updated
        self._subscription_manager = subscription_manager
        self._nft_manager = nft_manager
        self._credentials_ready = credentials_ready
        self._on_auth_failure = on_auth_failure
        self._on_config_applied = on_config_applied
        self._on_auditd_updated = on_auditd_updated

        self._last_event_id: str | None = None
        self._stop = asyncio.Event()
        self._backoff = _BACKOFF_INITIAL
        self._current_config_version: int = 0
        self._last_checkin_time: float = 0.0
        self._last_apply_failure: str | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Main loop: check standalone, initial check-in, then SSE loop.

        If management_mode is "standalone", exits immediately without
        connecting to the server.
        """
        self._stop.clear()

        # Skip everything if standalone mode
        if self._is_standalone():
            log.info("Config subscriber: standalone mode — skipping server connection")
            # Wait until stopped (so the task doesn't exit immediately
            # and can be stopped cleanly)
            await self._stop.wait()
            return

        log.info(
            "Config subscriber starting (server=%s, mode=%s)",
            self.config.SERVER_URL,
            self.config.management_mode,
        )

        # Wait for valid credentials before attempting connections
        if self._credentials_ready and not self._credentials_ready.is_set():
            log.info("Config subscriber waiting for credentials...")
            cred_task = asyncio.create_task(asyncio.to_thread(self._credentials_ready.wait))
            stop_task = asyncio.create_task(self._wait_event(self._stop))
            done, pending = await asyncio.wait(
                [cred_task, stop_task], return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()
            if self._stop.is_set():
                return
            log.info("Config subscriber credentials ready, connecting")

        # Load cached config if available (for offline resilience)
        cached = self._load_cache()
        if cached and cached.get("version", 0) > self._current_config_version:
            log.info(
                "Loaded cached config version %d from disk",
                cached["version"],
            )
            # Note: we do NOT set _current_config_version here — that happens
            # inside _handle_config_event after the settings are actually applied.
            # Setting it prematurely would cause the version guard to skip re-application.

        # Initial check-in for version sync — skipped intentionally.
        # The default asyncio ThreadPoolExecutor is unreliable on some
        # Python installs.  Config updates arrive via SSE anyway.
        server_reachable = False

        # Re-apply cached config on startup to restore server-managed state.
        # The in-memory config starts from the local config file, so managed
        # settings (subscriptions, rules, etc.) must be re-applied from cache
        # regardless of whether the server is reachable — the version check
        # will say "up to date" but the running config hasn't been hydrated yet.
        if cached and cached.get("settings"):
            if not server_reachable:
                log.info(
                    "Server unreachable — applying cached config (version %d) for offline resilience",
                    cached.get("version", 0),
                )
            else:
                log.info(
                    "Re-applying cached config (version %d) to restore managed state",
                    cached.get("version", 0),
                )
            try:
                self._handle_config_event(cached)
            except Exception as exc:
                log.warning("Failed to apply cached config: %s — using local config", exc)

        self._reconcile_allowlist_blocks()

        try:
            await self._initial_list_sync()
        except Exception as exc:
            log.warning("Initial list sync failed: %s", exc)

        checkin_task = asyncio.create_task(self._periodic_checkin_loop())
        list_sync_task = asyncio.create_task(self._periodic_list_sync_loop())

        # Main SSE loop with reconnection
        try:
            while not self._stop.is_set():
                try:
                    await self._connect_sse()
                    # If _connect_sse returns normally, the stream ended cleanly.
                    # Reset backoff and reconnect.
                    self._backoff = _BACKOFF_INITIAL
                except asyncio.CancelledError:
                    log.info("Config subscriber cancelled")
                    return
                except Exception as exc:
                    log.warning("Config SSE connection error: %s", exc)

                if self._stop.is_set():
                    break

                # Exponential backoff with jitter before reconnecting
                delay = self._compute_backoff()
                log.info(
                    "Config SSE reconnecting in %.1fs (backoff=%.1fs)",
                    delay,
                    self._backoff,
                )
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                    break  # stop was signaled during wait
                except asyncio.TimeoutError:
                    pass  # timeout expired, reconnect

                # Increase backoff for next failure
                self._backoff = min(self._backoff * _BACKOFF_FACTOR, _BACKOFF_MAX)
        finally:
            checkin_task.cancel()
            list_sync_task.cancel()

    async def _periodic_checkin_loop(self) -> None:
        """Periodic check-in that runs alongside the SSE connection.

        In multi-worker deployments (e.g. gunicorn with gevent), the
        in-memory ConfigSSEManager only fans out to clients connected to
        the same worker process. Profile updates submitted via the web UI
        may hit a different worker, so the SSE push never reaches the
        agent. This loop polls the DB-backed check-in endpoint every
        ``_CHECKIN_INTERVAL`` seconds to catch those missed updates.
        """
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=float(_CHECKIN_INTERVAL))
                break
            except asyncio.TimeoutError:
                pass
            try:
                await self._fallback_check_in()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.debug("Periodic check-in failed: %s", exc)

    def stop(self) -> None:
        """Signal the subscriber to stop."""
        self._stop.set()

    @staticmethod
    async def _wait_event(event: asyncio.Event) -> None:
        """Await an asyncio.Event (helper for wait/race patterns)."""
        await event.wait()

    # ------------------------------------------------------------------
    # Check-In
    # ------------------------------------------------------------------

    async def _initial_check_in(self) -> dict[str, Any] | None:
        """One-time check-in on startup for version sync and health report.

        POSTs to /api/v1/config/check-in with node_id, current_config_version,
        management_mode, agent_version, and health summary.

        If version is stale, receives full config payload in response.
        """
        payload = self._build_checkin_payload()
        log.info("Config initial check-in: POST %s", self._build_checkin_url())
        response = await self._checkin_async(payload)
        self._last_checkin_time = time.time()

        if response and response.get("config_update"):
            config_update = response["config_update"]
            log.info(
                "Initial check-in: received config update (version %s)",
                config_update.get("version"),
            )
            self._handle_config_event(config_update)
            return config_update

        log.info(
            "Initial check-in: config is up to date (version %d)", self._current_config_version
        )
        return None

    async def _fallback_check_in(self) -> dict[str, Any] | None:
        """Periodic fallback check-in every 5 minutes.

        POSTs to /api/v1/config/check-in with node_id, current_config_version,
        management_mode, agent_version, and health summary.

        Serves as a fallback mechanism when SSE connection is down.
        """
        if self._is_standalone():
            return None

        payload = self._build_checkin_payload()
        response = await self._checkin_async(payload)
        self._last_checkin_time = time.time()

        if response and response.get("config_update"):
            config_update = response["config_update"]
            log.info(
                "Fallback check-in: received config update (version %s)",
                config_update.get("version"),
            )
            self._handle_config_event(config_update)
            return config_update

        log.debug("Fallback check-in: no update needed")
        return None

    def _build_checkin_payload(self) -> dict[str, Any]:
        """Build the check-in request payload."""
        payload = {
            "node_id": self.config.node_id,
            "current_config_version": self._current_config_version,
            "management_mode": self.config.management_mode,
            "agent_version": __version__,
            "health": {
                "uptime": int(time.time()),  # placeholder
                "active_rules": len(self.config.brute_force_rules) + len(self.config.custom_rules),
                "blocked_ips": 0,  # placeholder — filled by nft_manager if available
            },
        }
        # Report failure reason from last failed config application
        if self._last_apply_failure:
            payload["last_failure_reason"] = self._last_apply_failure
            self._last_apply_failure = None  # Clear after reporting
        return payload

    async def _checkin_async(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """POST check-in (inline sync httpx — fast, avoids executor)."""
        url = self._build_checkin_url()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.API_KEY}",
            "User-Agent": f"Vespid/{__version__} ConfigSubscriber",
        }
        ctx = build_ssl_context(self.config.ssl_verify, self.config.ssl_cert, self.config.ssl_key)

        with httpx.Client(verify=ctx, timeout=30.0) as client:
            resp = client.post(url, headers=headers, json=payload)
            if resp.status_code == 401:
                log.error("Config check-in auth failed (401)")
                if self._on_auth_failure:
                    self._on_auth_failure()
                resp.raise_for_status()
            elif resp.status_code == 403:
                log.error("Config check-in forbidden (403)")
                resp.raise_for_status()
            elif resp.status_code >= 400:
                log.warning("Config check-in HTTP error %d", resp.status_code)
                resp.raise_for_status()
            try:
                return resp.json()
            except (json.JSONDecodeError, ValueError):
                return None

    # ------------------------------------------------------------------
    # SSE Connection
    # ------------------------------------------------------------------

    async def _connect_sse(self) -> None:
        """Connect to config SSE stream and process push events.

        Uses Last-Event-ID for reconnection replay.
        Reconnects with exponential backoff (5s initial, 300s max) on disconnect.
        """
        url = self._build_stream_url()
        headers = self._build_sse_headers()

        await self._sse_read_async(url, headers)

    async def _sse_read_async(self, url: str, headers: dict[str, str]) -> None:
        """SSE reader in a daemon thread, polled via asyncio.sleep."""
        ctx = build_ssl_context(self.config.ssl_verify, self.config.ssl_cert, self.config.ssl_key)
        done = threading.Event()
        error: list[Exception | None] = [None]

        def _run():
            try:
                with httpx.Client(
                    verify=ctx, timeout=httpx.Timeout(30.0, read=_KEEPALIVE_TIMEOUT)
                ) as client:
                    with client.stream("GET", url, headers=headers) as resp:
                        if resp.status_code == 401:
                            log.error("Config SSE auth failed (401)")
                            if self._on_auth_failure:
                                self._on_auth_failure()
                            resp.raise_for_status()
                        elif resp.status_code == 403:
                            log.error("Config SSE forbidden (403)")
                            resp.raise_for_status()
                        elif resp.status_code >= 400:
                            log.warning("Config SSE HTTP error %d", resp.status_code)
                            resp.raise_for_status()

                        self._backoff = _BACKOFF_INITIAL
                        log.info("Connected to Config SSE stream at %s", url)

                        event_id: str | None = None
                        event_type: str | None = None
                        data_lines: list = []

                        for raw_line in resp.iter_lines():
                            if self._stop.is_set():
                                return

                            line = raw_line.rstrip("\n\r")

                            if line == "":
                                if data_lines:
                                    data = "\n".join(data_lines)
                                    self._dispatch_event(event_id, event_type, data)
                                    if event_id:
                                        self._last_event_id = event_id
                                event_id = None
                                event_type = None
                                data_lines = []
                                continue

                            if line.startswith(":"):
                                continue

                            if line.startswith("id:"):
                                event_id = line[3:].strip()
                            elif line.startswith("event:"):
                                event_type = line[6:].strip()
                            elif line.startswith("data:"):
                                data_lines.append(line[5:].strip())
                            elif ":" in line:
                                pass
                            else:
                                pass
            except Exception as exc:
                error[0] = exc
            finally:
                done.set()

        t = threading.Thread(target=_run, name="config-sse", daemon=True)
        t.start()

        while not done.is_set():
            if self._stop.is_set():
                return
            await asyncio.sleep(1.0)

        if error[0] is not None:
            raise error[0]

    def _dispatch_event(
        self,
        event_id: str | None,
        event_type: str | None,
        data: str,
    ) -> None:
        """Dispatch a received SSE event to the appropriate handler."""
        try:
            event_data = json.loads(data)
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("Config SSE malformed JSON: %s (data=%r)", exc, data[:200])
            return

        if not isinstance(event_data, dict):
            log.warning("Config SSE event data is not a JSON object")
            return

        if event_type == "list_update":
            self._handle_list_update_event(event_data)
            return

        if event_type and event_type != "config_updated":
            log.debug("Ignoring SSE event type: %s", event_type)
            return

        self._handle_config_event(event_data)

    # ------------------------------------------------------------------
    # Config Event Handling
    # ------------------------------------------------------------------

    def _handle_config_event(self, event_data: dict[str, Any]) -> None:
        """Process a config_updated SSE event.

        Checks version (skip if already current), validates, resolves
        conflicts, and applies atomically.

        Note: Full implementation of _apply_config and _resolve_conflicts
        will be completed in tasks 8.4 and 8.7. This provides the skeleton
        with version checking and cache persistence.
        """
        version = event_data.get("version")
        if version is None:
            log.warning("Config event missing 'version' field — ignoring")
            return

        # Skip if already at this exact version (duplicate event)
        if version == self._current_config_version:
            log.debug(
                "Config event version %d == current %d — skipping",
                version,
                self._current_config_version,
            )
            return

        settings = event_data.get("settings")
        if not settings or not isinstance(settings, dict):
            log.warning("Config event has no valid 'settings' — ignoring")
            return

        profile_name = event_data.get("profile_name", "unknown")
        conflict_strategy = event_data.get(
            "conflict_strategy", self.config.config_conflict_strategy
        )

        log.info(
            "Processing config update: profile=%s version=%d strategy=%s",
            profile_name,
            version,
            conflict_strategy,
        )

        # Resolve conflicts between server settings and local config
        resolved = self._resolve_conflicts(settings, conflict_strategy)

        # Apply the resolved configuration
        try:
            self._apply_config(resolved, version)
        except Exception as exc:
            log.error(
                "Failed to apply config version %d: %s — retaining previous config",
                version,
                exc,
            )
            return

        # Persist to local cache for offline resilience
        self._persist_cache(event_data)

        # Update current version
        self._current_config_version = version
        log.info(
            "Config update applied successfully: profile=%s version=%d",
            profile_name,
            version,
        )

        if self._on_config_applied:
            try:
                self._on_config_applied()
            except Exception:
                log.exception("on_config_applied callback failed")

    # ------------------------------------------------------------------
    # List Update Handling (decoupled from config profiles)
    # ------------------------------------------------------------------

    def _handle_list_update_event(self, event_data: dict[str, Any]) -> None:
        """Process a list_update SSE event (allowlist/blocklist delta)."""
        action = event_data.get("action")
        key = event_data.get("key")
        entry = event_data.get("entry")

        if not all((action, key, entry)):
            log.warning("list_update event missing required fields: %s", event_data)
            return

        if key == "allowlist":
            if action == "add":
                result = self._nft_manager.allowlist_add(entry)
                if result.get("added"):
                    log.info("List SSE: allowlisted %s", entry)
            elif action == "remove":
                # Skip if this is a protected system IP
                try:
                    entry_net = ipaddress.ip_network(entry, strict=False)
                    with self._nft_manager._lock:
                        if entry_net in self._nft_manager._self_allowlist:
                            log.info(
                                "List SSE: skipping remove of protected system IP %s",
                                entry,
                            )
                            return
                except ValueError:
                    pass
                result = self._nft_manager.allowlist_remove(entry)
                if result.get("removed"):
                    log.info("List SSE: removed %s from allowlist", entry)
        elif key == "blocklist":
            if action == "add":
                blocked = self._nft_manager.block_local(entry, reason="blocklist_server")
                if blocked:
                    log.info("List SSE: blocked %s", entry)
            elif action == "remove":
                removed = self._nft_manager.unblock_local(entry, reason="blocklist_removed")
                if removed:
                    log.info("List SSE: unblocked %s", entry)
        else:
            log.debug("list_update unknown key: %s", key)

    async def _initial_list_sync(self) -> None:
        """Fetch current allowlist/blocklist from server and apply diffs."""
        if self._is_standalone():
            return

        url = self._build_list_sync_url()
        headers = {
            "Authorization": f"Bearer {self.config.API_KEY}",
            "User-Agent": f"Vespid/{__version__} ConfigSubscriber",
        }
        ctx = build_ssl_context(self.config.ssl_verify, self.config.ssl_cert, self.config.ssl_key)

        try:
            with httpx.Client(verify=ctx, timeout=30.0) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 401:
                    log.error("List sync auth failed (401)")
                    if self._on_auth_failure:
                        self._on_auth_failure()
                    return
                if resp.status_code >= 400:
                    log.warning("List sync HTTP error %d", resp.status_code)
                    return
                data = resp.json()
        except Exception as exc:
            log.warning("List sync request failed: %s", exc)
            return

        server_allowlist = set(data.get("allowlist", []))
        server_blocklist = set(data.get("blocklist", []))

        current_allowlist = set(
            str(n) for n in getattr(self._nft_manager, "_runtime_allowlist", set())
        )
        config_allowlist = set(getattr(self.config, "allowlist", []))
        local_allowlist = current_allowlist | config_allowlist

        # Never remove self-allowlisted entries (auto-detected local IPs)
        self_entries = set(str(n) for n in self._nft_manager._self_allowlist)

        al_to_add = server_allowlist - local_allowlist
        al_to_remove = (local_allowlist - server_allowlist) - self_entries

        for entry in al_to_add:
            self._nft_manager.allowlist_add(entry)
        for entry in al_to_remove:
            self._nft_manager.allowlist_remove(entry)

        current_blocklist = set(getattr(self.config, "blocklist", []))
        bl_to_add = server_blocklist - current_blocklist
        bl_to_remove = current_blocklist - server_blocklist

        for entry in bl_to_add:
            self._nft_manager.block_local(entry, reason="blocklist_server")
        for entry in bl_to_remove:
            self._nft_manager.unblock_local(entry, reason="blocklist_removed")

        self.config.blocklist = list(server_blocklist)

        if al_to_add or al_to_remove or bl_to_add or bl_to_remove:
            log.info(
                "List sync complete: allowlist +%d/-%d, blocklist +%d/-%d",
                len(al_to_add),
                len(al_to_remove),
                len(bl_to_add),
                len(bl_to_remove),
            )
        else:
            log.debug("List sync: no changes")

        self._reconcile_allowlist_blocks()

    async def _periodic_list_sync_loop(self) -> None:
        """Periodically re-sync allowlist/blocklist from ip_rules table."""
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_LIST_SYNC_INTERVAL)
                break
            except asyncio.TimeoutError:
                pass

            try:
                await self._initial_list_sync()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.warning("Periodic list sync error: %s", exc)

    def _build_list_sync_url(self) -> str:
        """Build the list sync endpoint URL."""
        base = self._get_api_base()
        return base + "config/rules/lists"

    # ------------------------------------------------------------------
    # Conflict Resolution (placeholder — filled by task 8.7)
    # ------------------------------------------------------------------

    def _resolve_conflicts(
        self, server_settings: dict[str, Any], strategy: str = "server-wins"
    ) -> dict[str, Any]:
        """Apply conflict resolution strategy.

        Delegates to the appropriate resolver in config_conflict module.
        Full implementation in task 8.7.
        """
        from .config_conflict import resolve_local_wins, resolve_merge, resolve_server_wins

        # Build local config dict for comparison
        local_config = self.config.to_dict()

        if strategy == "server-wins":
            return resolve_server_wins(server_settings, local_config)
        elif strategy == "local-wins":
            from .config import ShieldConfig

            defaults = ShieldConfig().to_dict()
            return resolve_local_wins(server_settings, local_config, defaults)
        elif strategy == "merge":
            return resolve_merge(server_settings, local_config)
        else:
            log.warning(
                "Unknown conflict strategy %r — falling back to server-wins",
                strategy,
            )
            return resolve_server_wins(server_settings, local_config)

    # ------------------------------------------------------------------
    # Config Application
    # ------------------------------------------------------------------

    def _apply_config(self, resolved_settings: dict[str, Any], version: int) -> None:
        """Apply configuration atomically with rollback on failure.

        Creates a checkpoint of the current state, then applies each
        setting category in order. If any category fails, all categories
        are rolled back to the checkpoint state.

        Categories applied in order:
        1. Detection rules (brute_force_rules, custom_rules)
        2. Subscription feeds (subscriptions)
        3. Telemetry settings (flush_interval_seconds, flush_batch_size, heartbeat_interval_seconds)
        4. Allowlist (allowlist)
        5. Fleet settings (fleet_blocklist_report_enabled, fleet_blocklist_subscribe_enabled, etc.)
        6. Log sources (log_sources)
        7. Excluded HTTP paths (excluded_http_paths)
        8. Auditd monitoring (auditd)

        Note: Blocklist is managed independently via list_update SSE events
        and periodic sync, not through config profiles.
        """

        # Persist a disk checkpoint for recovery purposes
        self._create_checkpoint()

        # Create in-memory checkpoint for atomic rollback
        checkpoint = self._create_rollback_checkpoint()

        # Track which categories were successfully applied (for logging)
        applied_categories: list = []
        changed_keys: list = []

        try:
            # --- Category 1: Detection Rules ---
            rules_changed = self._detect_rules_changes(resolved_settings)
            if rules_changed:
                self._apply_rules(resolved_settings)
                applied_categories.append("rules")
                if "brute_force_rules" in resolved_settings:
                    changed_keys.append("brute_force_rules")
                if "custom_rules" in resolved_settings:
                    changed_keys.append("custom_rules")

            # --- Category 2: Subscription Feeds ---
            feeds_changed = self._detect_feeds_changes(resolved_settings)
            if feeds_changed:
                self._apply_feeds(resolved_settings)
                applied_categories.append("feeds")
                changed_keys.append("subscriptions")

            # --- Category 3: Telemetry Settings ---
            telemetry_changed = self._detect_telemetry_changes(resolved_settings)
            if telemetry_changed:
                self._apply_telemetry(resolved_settings)
                applied_categories.append("telemetry")
                for key in (
                    "flush_interval_seconds",
                    "flush_batch_size",
                    "heartbeat_interval_seconds",
                ):
                    if key in resolved_settings and getattr(self.config, key) != checkpoint.get(
                        key
                    ):
                        changed_keys.append(key)

            # --- Category 4: Allowlist ---
            allowlist_changed = self._detect_allowlist_changes(resolved_settings)
            if allowlist_changed:
                self._apply_allowlist(resolved_settings)
                applied_categories.append("allowlist")
                changed_keys.append("allowlist")

            # --- Category 5: Fleet Settings ---
            fleet_changed = self._detect_fleet_changes(resolved_settings)
            if fleet_changed:
                self._apply_fleet(resolved_settings)
                applied_categories.append("fleet")
                for key in (
                    "fleet_blocklist_report_enabled",
                    "fleet_blocklist_subscribe_enabled",
                    "fleet_block_ttl_seconds",
                    "fleet_local_allow_list",
                ):
                    if key in resolved_settings and getattr(self.config, key) != checkpoint.get(
                        key
                    ):
                        changed_keys.append(key)

            # --- Category 6: Log Sources ---
            log_sources_changed = self._detect_log_sources_changes(resolved_settings)
            if log_sources_changed:
                self._apply_log_sources(resolved_settings)
                applied_categories.append("log_sources")
                changed_keys.append("log_sources")

            # --- Category 7: Excluded HTTP Paths ---
            excluded_paths_changed = self._detect_excluded_http_paths_changes(resolved_settings)
            if excluded_paths_changed:
                self._apply_excluded_http_paths(resolved_settings)
                applied_categories.append("excluded_http_paths")
                changed_keys.append("excluded_http_paths")

            # --- Category 8: Auditd Monitoring ---
            auditd_changed = self._detect_auditd_changes(resolved_settings)
            if auditd_changed:
                self._apply_auditd(resolved_settings)
                applied_categories.append("auditd")
                changed_keys.append("auditd")

        except Exception as exc:
            # Rollback all categories to checkpoint state
            failed_category = applied_categories[-1] if applied_categories else "unknown"
            log.error(
                "Config application failed at category '%s': %s — rolling back all categories",
                failed_category,
                exc,
            )
            self._rollback_to_checkpoint(checkpoint)
            # Store failure reason for reporting on next check-in
            self._last_apply_failure = f"Category '{failed_category}' failed: {exc}"
            raise

        # Log success with version and changed keys
        if changed_keys:
            log.info(
                "Config version %d applied successfully. Changed keys: %s",
                version,
                ", ".join(changed_keys),
            )
        else:
            log.info(
                "Config version %d applied (no effective changes detected)",
                version,
            )

    # ------------------------------------------------------------------
    # Change Detection Helpers
    # ------------------------------------------------------------------

    def _detect_rules_changes(self, settings: dict[str, Any]) -> bool:
        """Check if detection rules have changed."""
        if "brute_force_rules" in settings:
            current = [
                vars(r) if hasattr(r, "__dict__") else r for r in self.config.brute_force_rules
            ]
            new = settings["brute_force_rules"]
            if current != new:
                return True
        if "custom_rules" in settings:
            current = [vars(r) if hasattr(r, "__dict__") else r for r in self.config.custom_rules]
            new = settings["custom_rules"]
            if current != new:
                return True
        return False

    def _detect_feeds_changes(self, settings: dict[str, Any]) -> bool:
        """Check if subscription feeds have changed."""
        if "subscriptions" not in settings:
            return False
        current = [vars(f) if hasattr(f, "__dict__") else f for f in self.config.subscriptions]
        new = settings["subscriptions"]
        return current != new

    def _detect_telemetry_changes(self, settings: dict[str, Any]) -> bool:
        """Check if telemetry settings have changed."""
        for key in ("flush_interval_seconds", "flush_batch_size", "heartbeat_interval_seconds"):
            if key in settings and getattr(self.config, key) != settings[key]:
                return True
        return False

    def _detect_fleet_changes(self, settings: dict[str, Any]) -> bool:
        """Check if fleet settings have changed."""
        for key in (
            "fleet_blocklist_report_enabled",
            "fleet_blocklist_subscribe_enabled",
            "fleet_block_ttl_seconds",
            "fleet_local_allow_list",
        ):
            if key in settings and getattr(self.config, key) != settings[key]:
                return True
        return False

    def _detect_allowlist_changes(self, settings: dict[str, Any]) -> bool:
        """Check if the allowlist has changed."""
        if "allowlist" not in settings:
            return False
        current = list(self.config.allowlist)
        new = list(settings["allowlist"])
        return current != new

    def _detect_log_sources_changes(self, settings: dict[str, Any]) -> bool:
        """Check if log_sources have changed."""
        if "log_sources" not in settings:
            return False
        current = [vars(ls) if hasattr(ls, "__dict__") else ls for ls in self.config.log_sources]
        new = settings["log_sources"]
        if len(current) != len(new):
            return True
        for c, n in zip(current, new, strict=False):
            for k in n:
                if c.get(k) != n[k]:
                    return True
        return False

    # ------------------------------------------------------------------
    # Per-Category Application
    # ------------------------------------------------------------------

    def _apply_rules(self, settings: dict[str, Any]) -> None:
        """Apply detection rule changes via the on_rules_updated callback."""
        from .config import BruteForceRule, CorrelationRule, CustomRule

        brute_force_rules = self.config.brute_force_rules
        custom_rules = self.config.custom_rules
        correlation_rules = self.config.correlation_rules

        if "brute_force_rules" in settings:
            brute_force_rules = [
                BruteForceRule(**r) if isinstance(r, dict) else r
                for r in settings["brute_force_rules"]
            ]
            self.config.brute_force_rules = brute_force_rules

        if "custom_rules" in settings:
            custom_rules = [
                CustomRule(**r) if isinstance(r, dict) else r for r in settings["custom_rules"]
            ]
            self.config.custom_rules = custom_rules

        if "correlation_rules" in settings:
            correlation_rules = [
                CorrelationRule(**r) if isinstance(r, dict) else r
                for r in settings["correlation_rules"]
            ]
            self.config.correlation_rules = correlation_rules

        # Trigger hot-reload via the existing callback
        self._on_rules_updated(brute_force_rules, custom_rules, correlation_rules)
        log.debug("Applied detection rules update")

    def _apply_feeds(self, settings: dict[str, Any]) -> None:
        """Apply subscription feed changes via SubscriptionManager."""
        from .config import SubscriptionFeed

        old_feed_names = {f.name for f in self.config.subscriptions}

        new_feeds = [
            SubscriptionFeed(**f) if isinstance(f, dict) else f for f in settings["subscriptions"]
        ]
        self.config.subscriptions = new_feeds
        self._subscription_manager.config.subscriptions = new_feeds

        # Trigger an immediate sync so new/changed feeds are fetched now
        # rather than waiting for the next polling interval.
        # Use the subscription manager's stored loop reference (the main
        # event loop) rather than asyncio.get_running_loop() which returns
        # this subscriber thread's own loop.
        main_loop = self._subscription_manager._loop
        if main_loop is not None and not main_loop.is_closed():
            main_loop.call_soon_threadsafe(
                main_loop.create_task, self._subscription_manager.sync_now()
            )
        else:
            log.warning("Main event loop not available — feed sync deferred to next cycle")

        # Start feed loops for any newly added feeds
        new_feed_names = {f.name for f in new_feeds}
        added_feeds = new_feed_names - old_feed_names
        for feed in new_feeds:
            if feed.name in added_feeds:
                self._subscription_manager.start_feed_loop(feed)

        # Destroy nftables sets for removed feeds
        removed_feeds = old_feed_names - new_feed_names
        for name in removed_feeds:
            self._nft_manager.destroy_feed_set(name)

        log.debug(
            "Applied subscription feeds update (%d feeds, %d added, %d removed)",
            len(new_feeds),
            len(added_feeds),
            len(removed_feeds),
        )

    def _apply_allowlist(self, settings: dict[str, Any]) -> None:
        """Apply allowlist changes to both ShieldConfig and NFTablesManager."""
        new_allowlist = list(settings["allowlist"])

        # Validate/normalize through the nftables manager. This will raise
        # ValueError for invalid entries, triggering rollback.
        self._nft_manager._normalize_allowlist(new_allowlist)

        # Update both config objects so the runtime and persisted state agree.
        self.config.allowlist = new_allowlist
        self._nft_manager.config.allowlist = new_allowlist

        # Reconcile any existing local blocks that may now be allowlisted.
        self._reconcile_allowlist_blocks()

        log.debug("Applied allowlist update (%d entries)", len(new_allowlist))

    def _reconcile_allowlist_blocks(self) -> None:
        """Unblock any locally-blocked IPs that match the current allowlist.

        Called on startup (after cached config is applied) and whenever
        the allowlist is updated from the server. This ensures blocks
        that predate a allowlist addition are cleaned up.
        """
        to_unblock = []
        with self._nft_manager._lock:
            for ip in list(self._nft_manager._local.keys()):
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if any(addr in net for net in self._nft_manager._self_allowlist):
                    to_unblock.append(ip)
                    continue
                for net in self._nft_manager._allowlist:
                    if addr in net:
                        to_unblock.append(ip)
                        break

        for ip in to_unblock:
            self._nft_manager.unblock_local(ip, reason="allowlisted")

        if to_unblock:
            log.info("Allowlist reconciliation unblocked %d IPs: %s", len(to_unblock), to_unblock)

    def _apply_telemetry(self, settings: dict[str, Any]) -> None:
        """Apply telemetry setting changes to ShieldConfig."""
        for key in ("flush_interval_seconds", "flush_batch_size", "heartbeat_interval_seconds"):
            if key in settings:
                old_val = getattr(self.config, key)
                new_val = settings[key]
                setattr(self.config, key, new_val)
                log.debug("Applied telemetry setting %s: %r -> %r", key, old_val, new_val)

    def _apply_fleet(self, settings: dict[str, Any]) -> None:
        """Apply fleet setting changes to ShieldConfig."""
        for key in (
            "fleet_blocklist_report_enabled",
            "fleet_blocklist_subscribe_enabled",
            "fleet_block_ttl_seconds",
            "fleet_local_allow_list",
        ):
            if key in settings:
                old_val = getattr(self.config, key)
                new_val = settings[key]
                setattr(self.config, key, new_val)
                log.debug("Applied fleet setting %s: %r -> %r", key, old_val, new_val)

    def _apply_log_sources(self, settings: dict[str, Any]) -> None:
        """Apply log_sources changes from a config profile.

        Updates self.config.log_sources so that heartbeat active_parsers
        derivation reflects the profile's log sources for managed nodes.
        """
        from .config import LogSource

        new_log_sources = [
            LogSource(**ls) if isinstance(ls, dict) else ls for ls in settings["log_sources"]
        ]
        self.config.log_sources = new_log_sources
        log.debug("Applied log_sources update (%d sources)", len(new_log_sources))

    def _detect_excluded_http_paths_changes(self, settings: dict[str, Any]) -> bool:
        """Check if excluded_http_paths has changed."""
        if "excluded_http_paths" not in settings:
            return False
        return self.config.excluded_http_paths != settings["excluded_http_paths"]

    def _apply_excluded_http_paths(self, settings: dict[str, Any]) -> None:
        """Apply excluded_http_paths changes to ShieldConfig."""
        new_paths = settings["excluded_http_paths"]
        self.config.excluded_http_paths = new_paths
        log.debug(
            "Applied excluded_http_paths update (%d paths): %s",
            len(new_paths),
            new_paths,
        )

    def _detect_auditd_changes(self, settings: dict[str, Any]) -> bool:
        """Check if auditd configuration has changed."""
        if "auditd" not in settings:
            return False
        new = settings["auditd"]
        if not isinstance(new, dict):
            return False
        old = self.config.auditd
        for key in (
            "enabled",
            "log_path",
            "mode",
            "learning_duration_hours",
            "process_tree_ttl_seconds",
            "scorer_half_life_seconds",
            "scorer_threshold",
            "alert_cooldown_seconds",
        ):
            if key in new and getattr(old, key, None) != new[key]:
                return True
        if "exclude_uids" in new and set(old.exclude_uids) != set(new["exclude_uids"]):
            return True
        if "exclude_exe_prefixes" in new and list(old.exclude_exe_prefixes) != list(
            new["exclude_exe_prefixes"]
        ):
            return True
        return False

    def _apply_auditd(self, settings: dict[str, Any]) -> None:
        """Apply auditd configuration changes via the on_auditd_updated callback."""
        new_auditd = settings["auditd"]
        if self._on_auditd_updated:
            result = self._on_auditd_updated(new_auditd)
            changed = result.get("changed_keys", []) if isinstance(result, dict) else []
            restart = result.get("restart_required", False) if isinstance(result, dict) else False
            log.info(
                "Applied auditd config update (%d keys changed%s)",
                len(changed),
                ", restart required" if restart else "",
            )
        else:
            from .config import AuditdConfig

            try:
                self.config.auditd = AuditdConfig(**new_auditd)
            except TypeError as exc:
                log.warning("Failed to apply auditd config: %s", exc)
                return
            log.info("Applied auditd config update (no callback — config only)")

    # ------------------------------------------------------------------
    # Rollback Checkpoint
    # ------------------------------------------------------------------

    def _create_rollback_checkpoint(self) -> dict[str, Any]:
        """Snapshot current config state for in-memory rollback.

        Returns a dict containing the current values of all setting
        categories that _apply_config may modify.
        """
        return {
            "brute_force_rules": list(self.config.brute_force_rules),
            "custom_rules": list(self.config.custom_rules),
            "correlation_rules": list(self.config.correlation_rules),
            "subscriptions": list(self.config.subscriptions),
            "log_sources": list(self.config.log_sources),
            "allowlist": list(self.config.allowlist),
            "flush_interval_seconds": self.config.flush_interval_seconds,
            "flush_batch_size": self.config.flush_batch_size,
            "heartbeat_interval_seconds": self.config.heartbeat_interval_seconds,
            "fleet_blocklist_report_enabled": self.config.fleet_blocklist_report_enabled,
            "fleet_blocklist_subscribe_enabled": self.config.fleet_blocklist_subscribe_enabled,
            "fleet_block_ttl_seconds": self.config.fleet_block_ttl_seconds,
            "fleet_local_allow_list": list(self.config.fleet_local_allow_list),
            "excluded_http_paths": list(self.config.excluded_http_paths),
            "auditd": {
                "enabled": self.config.auditd.enabled,
                "log_path": self.config.auditd.log_path,
                "mode": self.config.auditd.mode,
                "learning_duration_hours": self.config.auditd.learning_duration_hours,
                "process_tree_ttl_seconds": self.config.auditd.process_tree_ttl_seconds,
                "scorer_half_life_seconds": self.config.auditd.scorer_half_life_seconds,
                "scorer_threshold": self.config.auditd.scorer_threshold,
                "alert_cooldown_seconds": self.config.auditd.alert_cooldown_seconds,
                "exclude_uids": list(self.config.auditd.exclude_uids),
                "exclude_exe_prefixes": list(self.config.auditd.exclude_exe_prefixes),
            },
        }

    def _rollback_to_checkpoint(self, checkpoint: dict[str, Any]) -> None:
        """Restore all setting categories to the checkpoint state.

        Called when any category fails during application to ensure
        atomic (all-or-nothing) behavior.
        """
        log.warning("Rolling back all config categories to checkpoint state")

        # Restore detection rules
        self.config.brute_force_rules = checkpoint["brute_force_rules"]
        self.config.custom_rules = checkpoint["custom_rules"]
        self.config.correlation_rules = checkpoint["correlation_rules"]
        # Re-trigger rules callback with original rules
        try:
            self._on_rules_updated(
                checkpoint["brute_force_rules"],
                checkpoint["custom_rules"],
                checkpoint["correlation_rules"],
            )
        except Exception as exc:
            log.error("Failed to rollback rules via callback: %s", exc)

        # Restore subscription feeds
        self.config.subscriptions = checkpoint["subscriptions"]
        self._subscription_manager.config.subscriptions = checkpoint["subscriptions"]

        # Restore log_sources
        self.config.log_sources = checkpoint["log_sources"]

        # Restore telemetry settings
        self.config.flush_interval_seconds = checkpoint["flush_interval_seconds"]
        self.config.flush_batch_size = checkpoint["flush_batch_size"]
        self.config.heartbeat_interval_seconds = checkpoint["heartbeat_interval_seconds"]

        # Restore allowlist
        self.config.allowlist = checkpoint["allowlist"]
        self._nft_manager.config.allowlist = checkpoint["allowlist"]
        self._nft_manager._normalize_allowlist(checkpoint["allowlist"])
        self._reconcile_allowlist_blocks()

        # Restore fleet settings
        self.config.fleet_blocklist_report_enabled = checkpoint["fleet_blocklist_report_enabled"]
        self.config.fleet_blocklist_subscribe_enabled = checkpoint[
            "fleet_blocklist_subscribe_enabled"
        ]
        self.config.fleet_block_ttl_seconds = checkpoint["fleet_block_ttl_seconds"]
        self.config.fleet_local_allow_list = checkpoint["fleet_local_allow_list"]

        # Restore excluded HTTP paths
        self.config.excluded_http_paths = checkpoint["excluded_http_paths"]

        # Restore auditd config
        if "auditd" in checkpoint:
            if self._on_auditd_updated:
                try:
                    self._on_auditd_updated(checkpoint["auditd"])
                except Exception as exc:
                    log.error("Failed to rollback auditd via callback: %s", exc)
            else:
                from .config import AuditdConfig

                try:
                    self.config.auditd = AuditdConfig(**checkpoint["auditd"])
                except TypeError:
                    pass

        log.info("Rollback to checkpoint complete")

    # ------------------------------------------------------------------
    # Cache Persistence and Checkpoints
    # ------------------------------------------------------------------

    def _persist_cache(self, payload: dict[str, Any]) -> None:
        """Write config to local cache file for offline resilience.

        Persists the full config payload to {STATE_DIR}/config_cache.json
        so the agent can operate with cached configuration when the server
        is unreachable on startup.
        """
        try:
            cache_data = {
                "profile_name": payload.get("profile_name", ""),
                "version": payload.get("version", 0),
                "settings": payload.get("settings", {}),
                "updated_at": payload.get("updated_at", ""),
                "conflict_strategy": payload.get(
                    "conflict_strategy", self.config.config_conflict_strategy
                ),
                "cached_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            _CACHE_FILE.write_text(json.dumps(cache_data, indent=2), encoding="utf-8")
            log.debug("Config cache persisted to %s", _CACHE_FILE)
        except (OSError, TypeError) as exc:
            log.warning("Failed to persist config cache: %s", exc)

    def _load_cache(self) -> dict[str, Any] | None:
        """Load cached config from disk on startup.

        Returns the cached payload dict or None if no valid cache exists.
        Handles corrupted cache by deleting the invalid file, falling back
        to local config, and logging a warning.
        """
        if not _CACHE_FILE.exists():
            return None

        try:
            text = _CACHE_FILE.read_text(encoding="utf-8")
            data = json.loads(text)
            if not isinstance(data, dict):
                log.warning("Config cache is not a JSON object — deleting invalid file")
                _CACHE_FILE.unlink(missing_ok=True)
                return None
            if "version" not in data or "settings" not in data:
                log.warning("Config cache missing required fields — deleting invalid file")
                _CACHE_FILE.unlink(missing_ok=True)
                return None
            return data
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Failed to load config cache: %s — deleting invalid file", exc)
            try:
                _CACHE_FILE.unlink()
            except OSError:
                pass
            return None

    _MAX_CHECKPOINTS = 10

    def _create_checkpoint(self) -> None:
        """Snapshot current config before applying a server update.

        Stores a timestamped checkpoint at
        {STATE_DIR}/config_checkpoints/checkpoint_{timestamp}.json
        containing the full config state for rollback purposes.

        Retains only the most recent ``_MAX_CHECKPOINTS`` files,
        deleting older ones after each new checkpoint is written.
        """
        try:
            checkpoint_dir = STATE_DIR / "config_checkpoints"
            checkpoint_dir.mkdir(parents=True, exist_ok=True)

            timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            checkpoint_path = checkpoint_dir / f"checkpoint_{timestamp}.json"

            checkpoint_data = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "trigger": "config_reload",
                "previous_mode": self.config.management_mode,
                "new_mode": self.config.management_mode,
                "config_version": self._current_config_version,
                "config_snapshot": self.config.to_dict(),
            }

            checkpoint_path.write_text(json.dumps(checkpoint_data, indent=2), encoding="utf-8")
            log.debug("Config checkpoint created at %s", checkpoint_path)

            # Prune old checkpoints, keeping only the most recent ones
            self._prune_checkpoints(checkpoint_dir)
        except (OSError, TypeError) as exc:
            log.warning("Failed to create config checkpoint: %s", exc)

    def _prune_checkpoints(self, checkpoint_dir) -> None:
        """Remove old checkpoint files exceeding the retention limit."""
        try:
            checkpoints = sorted(
                checkpoint_dir.glob("checkpoint_*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for old_file in checkpoints[self._MAX_CHECKPOINTS :]:
                old_file.unlink()
                log.debug("Pruned old checkpoint: %s", old_file.name)
        except OSError as exc:
            log.warning("Failed to prune old checkpoints: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_standalone(self) -> bool:
        """Check if the agent is in standalone mode."""
        mode = self.config.management_mode
        if not mode or mode == "standalone":
            return True
        # Also standalone if no server URL configured
        if (
            not self.config.SERVER_URL
            or self.config.SERVER_URL == "https://server.example.com/api/v1/events"
        ):
            return True
        return False

    def _build_stream_url(self) -> str:
        """Build the Config SSE stream URL from config."""
        base = self._get_api_base()
        return base + "config/stream"

    def _build_checkin_url(self) -> str:
        """Build the Config check-in URL from config."""
        base = self._get_api_base()
        return base + "config/check-in"

    def _get_api_base(self) -> str:
        """Extract the base API URL from SERVER_URL."""
        base = self.config.SERVER_URL
        if "/api/v1/" in base:
            base = base[: base.index("/api/v1/") + len("/api/v1/")]
        elif base.endswith("/"):
            base = base + "api/v1/"
        else:
            base = base + "/api/v1/"
        return base

    def _build_sse_headers(self) -> dict[str, str]:
        """Build HTTP headers for the SSE connection."""
        headers = {
            "Accept": "text/event-stream",
            "Authorization": f"Bearer {self.config.API_KEY}",
            "User-Agent": f"Vespid/{__version__} ConfigSubscriber",
            "Cache-Control": "no-cache",
        }
        if self._last_event_id:
            headers["Last-Event-ID"] = self._last_event_id
        return headers

    def _compute_backoff(self) -> float:
        """Compute the next backoff delay with ±20% jitter."""
        jitter_factor = 1.0 + random.uniform(-_BACKOFF_JITTER, _BACKOFF_JITTER)
        return self._backoff * jitter_factor
