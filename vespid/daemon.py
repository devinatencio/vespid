"""Vespid main daemon - wires every component together."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import signal
import threading
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from . import __version__
from .config import CONFIG, SubscriptionFeed
from .config_subscriber import ConfigSubscriber
from .control_socket import ControlServer
from .daemon_activity import ActivityTracker
from .databus import BUS
from .detectors import Detection
from .enrollment_client import EnrollmentClient, EnrollmentError
from .fleet_subscriber import FleetBlockSubscriber
from .http_client import HttpError, request
from .log_processor import LogProcessor
from .logging_setup import configure_logging
from .nftables_manager import NFTablesManager
from .rule_subscriber import RuleSubscriber
from .subscription_manager import SubscriptionManager

log = logging.getLogger("vespid")


def _make_rule_subscriber(config, on_rules_updated, credentials_ready, on_auth_failure):
    """Create a RuleSubscriber, handling older versions that lack credentials_ready."""
    import inspect

    sig = inspect.signature(RuleSubscriber.__init__)
    if "credentials_ready" in sig.parameters:
        return RuleSubscriber(
            config,
            on_rules_updated=on_rules_updated,
            credentials_ready=credentials_ready,
            on_auth_failure=on_auth_failure,
        )
    return RuleSubscriber(
        config,
        on_rules_updated=on_rules_updated,
        on_auth_failure=on_auth_failure,
    )


def _run_subscriber_loop(sub: Any) -> None:
    """Run a subscriber's ``run()`` coroutine in a dedicated event loop.

    Each subscriber (fleet, config, rule) gets its own thread and event
    loop so that ``asyncio.to_thread`` callbacks, ``asyncio.sleep``, and
    reconnection backoff work without contending with the main event
    loop's ``asyncio.wait(FIRST_COMPLETED)`` starvation on Python 3.12.
    """
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(sub.run())
    except Exception:
        log.exception("Subscriber thread crashed")
    finally:
        loop.close()


class Vespid:
    def __init__(self) -> None:
        self.config = CONFIG
        self.bus = BUS
        self._activity = ActivityTracker()
        self._credentials_ready = threading.Event()
        self._stop = asyncio.Event()
        self._main_loop: asyncio.AbstractEventLoop | None = None
        self._enrollment_poll_thread: threading.Thread | None = None
        self._auth_failure_suppressed = False  # Guard against 401 retry storms
        self._auth_failure_lock = threading.Lock()  # Prevent concurrent auth recovery
        self._credentials_received = threading.Event()  # Set by poll thread when key arrives

        self.enrollment = EnrollmentClient(self.config)
        self.nft = NFTablesManager(self.config, self.bus)
        self.subs = SubscriptionManager(self.nft, self.config, self.bus)
        self.logproc = LogProcessor(
            self.config,
            self.bus,
            on_block=self._on_detection,
            on_observed=self._activity.record_observed,
        )
        self.ctl = ControlServer(self._build_handlers(), self.config)
        self.fleet_sub = (
            FleetBlockSubscriber(
                self.config,
                self.nft,
                on_fleet_block=lambda: self._activity.record_block(fleet=True),
                credentials_ready=self._credentials_ready,
                on_auth_failure=self.handle_auth_failure,
            )
            if self.config.fleet_blocklist_subscribe_enabled
            else None
        )
        self.rule_sub = (
            _make_rule_subscriber(
                self.config,
                self._on_rules_updated,
                self._credentials_ready,
                self.handle_auth_failure,
            )
            if self.config.rule_subscribe_enabled
            else None
        )
        self.config_sub = (
            ConfigSubscriber(
                config=self.config,
                on_rules_updated=self._on_rules_updated,
                subscription_manager=self.subs,
                nft_manager=self.nft,
                credentials_ready=self._credentials_ready,
                on_auth_failure=self.handle_auth_failure,
                on_config_applied=self.bus.trigger_heartbeat,
                on_auditd_updated=self.logproc.update_auditd_config,
            )
            if self.config.management_mode == "server-managed"
            else None
        )
        self._runtime_feeds_path = os.path.join(
            os.environ.get("VESPID_STATE_DIR", "/var/lib/vespid"),
            "runtime_feeds.json",
        )
        self._load_runtime_feeds()

    # ------------------------------------------------------------------
    def _load_runtime_feeds(self) -> None:
        """Load dynamically added feeds from disk and merge into config.

        Feeds deployed from the server via feed_add are persisted to
        runtime_feeds.json so they survive daemon restarts. Config-file
        feeds take precedence — if a feed exists in both, the config
        version wins.
        """
        try:
            with open(self._runtime_feeds_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Failed to load runtime feeds from %s: %s", self._runtime_feeds_path, exc)
            return

        if not isinstance(data, list):
            log.warning("Invalid runtime feeds format in %s", self._runtime_feeds_path)
            return

        config_names = {f.name for f in self.config.subscriptions}
        loaded = 0
        for entry in data:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "")
            if not name or name in config_names:
                continue  # Skip duplicates or config-defined feeds
            feed = SubscriptionFeed(
                name=name,
                url=entry.get("url", ""),
                format=entry.get("format", "plain"),
                refresh_seconds=entry.get("refresh_seconds", 3600),
                enabled=entry.get("enabled", True),
            )
            self.config.subscriptions.append(feed)
            config_names.add(name)
            loaded += 1

        if loaded:
            log.info("Loaded %d runtime feeds from disk", loaded)

    def _save_runtime_feeds(self) -> None:
        """Persist dynamically added feeds to disk.

        Only saves feeds that are NOT defined in the original config file.
        This is determined by comparing against the config file's feed
        names at load time — we track which names came from the file.
        """
        # We save ALL current subscriptions that aren't in the original
        # config. Since _load_runtime_feeds merges into config.subscriptions,
        # we need to know which were original. We use a simple heuristic:
        # save everything currently in the runtime feeds file plus any new
        # additions, minus any removals.
        runtime_feeds = []
        # Load the original config to know which feeds are config-defined
        original_config = type(self.config).load()
        original_names = {f.name for f in original_config.subscriptions}

        for feed in self.config.subscriptions:
            if feed.name not in original_names:
                runtime_feeds.append(
                    {
                        "name": feed.name,
                        "url": feed.url,
                        "format": feed.format,
                        "refresh_seconds": feed.refresh_seconds,
                        "enabled": feed.enabled,
                    }
                )

        try:
            os.makedirs(os.path.dirname(self._runtime_feeds_path), exist_ok=True)
            tmp = self._runtime_feeds_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(runtime_feeds, fh, indent=2)
            os.replace(tmp, self._runtime_feeds_path)
        except OSError as exc:
            log.warning("Failed to persist runtime feeds: %s", exc)

    # ------------------------------------------------------------------
    # Enrollment integration
    # ------------------------------------------------------------------
    def _apply_credentials(self, credentials: dict) -> None:
        """Override config with enrolled credentials for databus auth.

        Only the API key is taken from the credentials file — the server URL
        in ``credentials.json`` is a snapshot from enrollment time and may be
        stale (e.g. ``http://localhost`` if enrolled before public DNS was
        configured).  The runtime ``SERVER_URL`` from the config file is
        always preferred.
        """
        api_key = credentials.get("api_key", "")
        if api_key:
            self.config.API_KEY = api_key
        # Clear suppression — we have valid credentials now
        self._auth_failure_suppressed = False
        log.info("Applied enrolled credentials")

    def _handle_enrollment(self) -> str:
        """Check for credentials and run enrollment if needed.

        Called before starting the databus. If credentials exist on disk,
        loads and applies them. Otherwise initiates enrollment. If enrollment
        returns pending (manual_approval mode), starts a background polling
        thread.  Transient failures (network errors, rate limits) are retried
        in the background so the agent does not give up on a temporarily
        unreachable server.

        Returns:
            "ready":   valid API key is available (from config, disk, or
                       immediate enrollment).
            "pending": enrollment is pending admin approval or retrying
                       after a transient failure (poll/retry thread started).
            "failed":  enrollment was permanently rejected.
        """
        if self._api_key_is_valid():
            log.debug("API key already configured, skipping enrollment")
            return "ready"

        if self.enrollment.has_credentials():
            creds = self.enrollment.load_credentials()
            if creds:
                self._apply_credentials(creds)
                log.info("Loaded existing enrollment credentials")
                return "ready"
            log.warning("Credentials file exists but is invalid, attempting enrollment")

        try:
            api_key = self.enrollment.enroll()
        except EnrollmentError as exc:
            log.warning("Enrollment failed: %s — will retry in background", exc)
            self._start_enrollment_retry()
            return "pending"

        if api_key is not None:
            creds = self.enrollment.load_credentials()
            if creds:
                self._apply_credentials(creds)
            else:
                self.config.API_KEY = api_key
            log.info("Enrollment completed (open mode)")
            return "ready"

        log.info("Enrollment pending approval, starting background poll thread")
        self._enrollment_poll_thread = threading.Thread(
            target=self._poll_enrollment_background,
            name="vespid-enrollment-poll",
            daemon=True,
        )
        self._enrollment_poll_thread.start()
        return "pending"

    def _start_enrollment_retry(self) -> None:
        """Start or restart a background thread that retries enrollment.

        Ensures only one retry thread is running at a time; if a previous
        retry or poll thread is alive it is left alone (it will either
        succeed or we are already in a poll/approval cycle).
        """
        existing = self._enrollment_poll_thread
        if existing and existing.is_alive():
            return  # already polling — let it finish

        self._enrollment_poll_thread = threading.Thread(
            target=self._enrollment_retry_background,
            name="vespid-enrollment-retry",
            daemon=True,
        )
        self._enrollment_poll_thread.start()

    def _enrollment_retry_background(self) -> None:
        """Retry enrollment with exponential backoff until it succeeds.

        Once enrollment succeeds the thread either applies the key directly
        (open mode) or delegates to :meth:`_poll_enrollment_background` for
        manual-approval polling.  Either path will eventually set
        ``_credentials_received`` so the credential watcher can finish the
        transition to operational state.
        """
        backoff = 30.0
        max_backoff = 300.0
        while True:
            time.sleep(backoff)
            try:
                api_key = self.enrollment.enroll()
            except EnrollmentError as exc:
                backoff = min(backoff * 2, max_backoff)
                log.warning("Enrollment retry failed: %s — retrying in %.0fs", exc, backoff)
                continue
            except Exception:
                backoff = min(backoff * 2, max_backoff)
                log.exception(
                    "Unexpected error during enrollment retry — retrying in %.0fs", backoff
                )
                continue

            if api_key is not None:
                try:
                    creds = self.enrollment.load_credentials()
                    if creds:
                        self._apply_credentials(creds)
                    else:
                        self.config.API_KEY = api_key
                    log.info("Enrollment retry succeeded (open mode)")
                    result = self._validate_api_key()
                    if result == "valid":
                        log.info("Enrollment retry key validated — ready for full operation")
                    elif result == "invalid":
                        log.error("Enrollment retry key rejected by server")
                    else:
                        log.info(
                            "Enrollment retry key received, validation deferred — server unreachable"
                        )
                except Exception:
                    log.exception("Unexpected error applying retry credentials")
                    backoff = min(backoff * 2, max_backoff)
                    continue
                self._credentials_received.set()
                return

            # Manual-approval mode — delegate to normal polling
            log.info("Enrollment retry succeeded, pending admin approval — switching to poll loop")
            try:
                self._poll_enrollment_background()
            except Exception:
                log.exception("Unexpected error in poll loop after retry — restarting retry cycle")
                backoff = min(backoff * 2, max_backoff)
                continue
            return

    def _poll_enrollment_background(self) -> None:
        """Background thread that polls until enrollment is approved.

        Once approved, applies the credentials and validates them against
        the server. Signals ``_credentials_received`` so the main loop can
        complete the transition to operational state.
        """
        try:
            api_key = self.enrollment.poll_until_approved()
        except EnrollmentError as exc:
            log.error("Enrollment polling failed permanently: %s", exc)
            return

        creds = self.enrollment.load_credentials()
        if creds:
            self._apply_credentials(creds)
            log.info("Enrollment approved — credentials applied")
        else:
            self.config.API_KEY = api_key
            log.info("Enrollment approved — API key applied directly")

        result = self._validate_api_key()
        if result == "valid":
            log.info("Enrollment key validated — ready for full operation")
        elif result == "invalid":
            log.error("Enrollment key rejected by server — enrollment will be retried")
        else:
            log.info("Enrollment key received, validation deferred — server unreachable")

        self._credentials_received.set()

    def _api_key_is_valid(self) -> bool:
        """Return True if the configured API_KEY is a non-empty string."""
        key = self.config.API_KEY
        return bool(key and isinstance(key, str) and key.strip())

    def _validate_api_key(self) -> str:
        """Validate the current API key by calling the server verify endpoint.

        Makes a synchronous HTTP GET to ``/api/v1/verify`` with Bearer
        auth.

        Returns:
            ``"valid"``       — 200 response, key is confirmed active.
            ``"invalid"``     — 401/403 response, key is definitively rejected.
            ``"unreachable"`` — connectivity error, timeout, or non-2xx/401/403
                                response (endpoint missing, server error, etc.).
        """
        from .http_client import build_ssl_context

        url = self._build_api_url("verify")
        ctx = build_ssl_context(self.config.ssl_verify, self.config.ssl_cert, self.config.ssl_key)
        try:
            with httpx.Client(verify=ctx, timeout=30.0) as client:
                resp = client.get(
                    url,
                    headers={
                        "Authorization": f"Bearer {self.config.API_KEY}",
                        "User-Agent": f"Vespid/{__version__} KeyValidator",
                    },
                )
            if resp.status_code == 200:
                return "valid"
            if resp.status_code in (401, 403):
                log.warning("API key validation failed: server returned %d", resp.status_code)
                return "invalid"
            log.warning(
                "API key validation returned unexpected status %d from %s — will retry",
                resp.status_code,
                url,
            )
            return "unreachable"
        except httpx.HTTPError as exc:
            log.warning("API key validation skipped — server unreachable: %s", exc)
            return "unreachable"

    def _build_api_url(self, path: str) -> str:
        """Build a URL path under the server's ``/api/v1/`` prefix."""
        base = self.config.SERVER_URL
        if "/api/v1/" in base:
            base = base[: base.index("/api/v1/") + len("/api/v1/")]
        elif base.endswith("/"):
            base = base + "api/v1/"
        else:
            base = base + "/api/v1/"
        return base + path

    def handle_auth_failure(self) -> bool:
        """Handle a 401 authentication failure during normal operation.

        Checks for rotated credentials first. If rotation provides new
        credentials, applies them and returns True. Otherwise falls back
        to re-enrollment.

        Includes a suppression guard: once enrollment is pending (or has
        failed), further 401s are silently ignored until credentials are
        resolved. This prevents retry storms that hammer the server.

        Thread-safe: uses a lock to prevent concurrent auth recovery attempts
        from multiple components (databus, fleet_sub, config_sub, etc.).

        Returns:
            True if credentials were refreshed, False otherwise.
        """
        # Use lock to prevent concurrent auth recovery attempts
        with self._auth_failure_lock:
            # If we already know enrollment is pending, don't retry
            if self._auth_failure_suppressed:
                return False

            log.warning("Authentication failure (401) detected, checking for rotated credentials")

            # First try rotation recovery
            try:
                new_key = self.enrollment.check_rotation()
            except Exception as exc:
                log.error("Rotation check error: %s", exc)
                new_key = None

            if new_key:
                if new_key == self.config.API_KEY:
                    log.warning(
                        "Rotated key is identical to current key — "
                        "401 is not a credential issue, suppressing further retries"
                    )
                    self._auth_failure_suppressed = True
                    return False
                creds = self.enrollment.load_credentials()
                if creds:
                    self._apply_credentials(creds)
                    log.info("Rotated credentials applied successfully")
                    return True
                # Fallback
                self.config.API_KEY = new_key
                log.info("Rotated API key applied directly")
                return True

            # Rotation didn't help — attempt re-enrollment
            log.warning("No rotated credentials available, attempting re-enrollment")
            try:
                api_key = self.enrollment.enroll()
            except EnrollmentError as exc:
                log.error(
                    "Re-enrollment failed: %s — suppressing further auth failure retries", exc
                )
                self._auth_failure_suppressed = True
                return False

            if api_key is not None:
                creds = self.enrollment.load_credentials()
                if creds:
                    self._apply_credentials(creds)
                else:
                    self.config.API_KEY = api_key
                log.info("Re-enrollment succeeded")
                return True

            # Pending — suppress further retries and start background poll
            log.info(
                "Enrollment pending approval — suppressing auth failure retries until resolved"
            )
            self._auth_failure_suppressed = True

            # Start background poll if not already running
            if not self._enrollment_poll_thread or not self._enrollment_poll_thread.is_alive():
                self._enrollment_poll_thread = threading.Thread(
                    target=self._poll_enrollment_background,
                    name="vespid-enrollment-poll",
                    daemon=True,
                )
                self._enrollment_poll_thread.start()
            return False

    # ------------------------------------------------------------------
    async def _nft_in_thread(self, fn, *args):
        """Run an nft method in a thread to avoid blocking the event loop."""
        return await asyncio.to_thread(fn, *args)

    # ------------------------------------------------------------------
    async def _on_detection(self, det: Detection) -> None:
        # Hook called by the LogProcessor on a confirmed detection.
        # ALL nft operations (including lock-acquiring checks) run in a
        # thread to avoid blocking the event loop when sync_feed holds
        # the nft lock for extended periods.

        def _do_detection():
            # Guard: never publish a fleet block report for allowlisted IPs.
            if self.nft.is_allowlisted(det.source_ip):
                log.debug(
                    "Detection for allowlisted IP %s ignored (rule=%s)",
                    det.source_ip,
                    det.rule.name,
                )
                return

            threat_tag = det.rule.event_type.lower().replace("_", "-")

            # If the IP is already blocked locally, skip.
            if self.nft.is_locally_blocked(det.source_ip):
                return

            # Publish the semantic block report
            metadata: dict[str, Any] = {"rule": det.rule.name}
            metadata["detection_rule_name"] = det.rule.name
            metadata["threat_tag"] = threat_tag
            if self.config.fleet_blocklist_report_enabled:
                metadata["block_ttl_seconds"] = self.config.fleet_block_ttl_seconds
            if det.context_lines:
                metadata["surrounding_logs"] = det.context_lines

            self.bus.publish(
                source_ip=det.source_ip,
                event_type=det.rule.event_type,
                action_taken="BLOCKED",
                metadata=metadata,
                timestamp=datetime.fromtimestamp(det.first_seen, tz=timezone.utc),
            )

            blocked = self.nft.block_local(
                det.source_ip,
                reason=det.rule.name,
                detection_rule_name=det.rule.name,
                threat_tag=threat_tag,
                request_count=det.attempts,
                surrounding_logs=det.context_lines,
            )
            if blocked:
                meta = self.nft.get_local_meta(det.source_ip)
                strike = meta.get("strike", 1)
                self._activity.record_block(escalated=(strike > 1))

        await self._nft_in_thread(_do_detection)

    # ------------------------------------------------------------------
    def _get_feed_snapshot(self) -> list[dict[str, Any]]:
        """Return a snapshot of subscription feed status for the heartbeat.

        Called directly from the DataBus heartbeat thread — bypasses the
        control socket so heartbeats work even if the socket is busy.
        """
        feeds = []
        for feed in self.config.subscriptions:
            info = self.subs.status().get("feeds", {}).get(feed.name, {})
            feeds.append(
                {
                    "name": feed.name,
                    "url": feed.url,
                    "enabled": feed.enabled,
                    "refresh_seconds": feed.refresh_seconds,
                    "last_sync_ts": info.get("ts"),
                    "last_sync_count": info.get("count", 0),
                }
            )
        return feeds

    def _dispatch_command(
        self, command_type: str, payload: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Execute a server command directly, bypassing the control socket."""
        try:
            if command_type == "allowlist_add":
                return self.nft.allowlist_add(payload.get("entry", ""))
            elif command_type == "allowlist_remove":
                return self.nft.allowlist_remove(payload.get("entry", ""))
            elif command_type == "block":
                ip = payload.get("ip", "")
                blocked = self.nft.block_local(
                    ip,
                    reason=payload.get("reason", "server_command"),
                )
                return {"ok": True, "blocked": blocked, "ip": ip}
            elif command_type == "unblock":
                ip = payload.get("ip", "")
                removed = self.nft.unblock_local(
                    ip,
                    reason=payload.get("reason", "server_command"),
                )
                return {"ok": True, "removed": removed, "ip": ip}
            elif command_type == "feed_enable":
                return self._handle_feed_enable(payload.get("name", ""))
            elif command_type == "feed_disable":
                return self._handle_feed_disable(payload.get("name", ""))
            elif command_type == "feed_add":
                return self._handle_feed_add(
                    name=payload.get("name", ""),
                    url=payload.get("url", ""),
                    fmt=payload.get("format", "plain"),
                    refresh_seconds=payload.get("refresh_seconds", 3600),
                )
            elif command_type == "feed_remove":
                return self._handle_feed_remove(payload.get("name", ""))
            elif command_type == "set_auditd_mode":
                mode = payload.get("mode", "")
                if not mode:
                    return {"ok": False, "error": "missing mode in payload"}
                try:
                    self.logproc.set_auditd_mode(mode)
                    return {"ok": True, "mode": mode}
                except ValueError as e:
                    return {"ok": False, "error": str(e)}
            else:
                return {"ok": False, "error": f"unknown command: {command_type}"}
        except Exception as exc:
            log.exception("Command dispatch failed: %s", command_type)
            return {"ok": False, "error": str(exc)}

    def _handle_feed_enable(self, name: str) -> dict:
        for f in self.config.subscriptions:
            if f.name == name:
                f.enabled = True
                self._save_runtime_feeds()
                # Schedule an immediate sync
                threading.Thread(target=self._sync_feed_sync, args=(name,), daemon=True).start()
                return {"ok": True, "feed": name, "enabled": True}
        return {"ok": False, "error": f"unknown feed: {name}"}

    def _handle_feed_disable(self, name: str) -> dict:
        for f in self.config.subscriptions:
            if f.name == name:
                f.enabled = False
                self._save_runtime_feeds()
                self.nft.destroy_feed_set(name)
                return {"ok": True, "feed": name, "enabled": False}
        return {"ok": False, "error": f"unknown feed: {name}"}

    def _handle_feed_add(
        self, name: str, url: str, fmt: str = "plain", refresh_seconds: int = 3600
    ) -> dict:
        from .config import SubscriptionFeed

        if not name or not url:
            return {"ok": False, "error": "name and url are required"}
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$", name):
            return {"ok": False, "error": "invalid feed name (use a-z, 0-9, -, _, .)"}
        for f in self.config.subscriptions:
            if f.name == name:
                return {"ok": False, "error": f"feed already exists: {name}"}
        feed = SubscriptionFeed(
            name=name, url=url, format=fmt, refresh_seconds=refresh_seconds, enabled=True
        )
        self.config.subscriptions.append(feed)
        self._save_runtime_feeds()
        self.subs.start_feed_loop(feed)
        threading.Thread(target=self._sync_feed_sync, args=(name,), daemon=True).start()
        return {"ok": True, "feed": name, "url": url}

    def _handle_feed_remove(self, name: str) -> dict:
        for i, f in enumerate(self.config.subscriptions):
            if f.name == name:
                del self.config.subscriptions[i]
                self._save_runtime_feeds()
                self.nft.destroy_feed_set(name)
                return {"ok": True, "feed": name}
        return {"ok": False, "error": f"unknown feed: {name}"}

    def _sync_feed_sync(self, name: str) -> None:
        """Run a one-shot feed sync in a background thread."""
        loop = self._main_loop
        if loop is None or loop.is_closed():
            return
        import time as _time

        _time.sleep(1)  # let the feed loop pick up the change
        loop.call_soon_threadsafe(lambda: loop.create_task(self.subs.sync_now()))

    def _on_rules_updated(self, brute_force_rules, custom_rules, correlation_rules) -> None:
        """Callback from RuleSubscriber when server pushes new rules."""
        self.logproc.reload_rules(brute_force_rules, custom_rules, correlation_rules)

    # ------------------------------------------------------------------
    def _build_handlers(self):
        async def status(_: dict[str, Any]) -> dict[str, Any]:
            fleet_queue = self.bus._fleet_queue
            # Gather detection pack info from rule subscriber cache
            detection_packs = []
            if self.rule_sub:
                detection_packs = self.rule_sub.get_active_packs()
            # Fallback: derive from current custom_rules in memory
            if not detection_packs and self.config.custom_rules:
                detection_packs = sorted(
                    set(
                        getattr(r, "pack_name", "")
                        for r in self.config.custom_rules
                        if getattr(r, "pack_name", "")
                    )
                )
            # Last resort: read directly from rules_cache.json on disk
            if not detection_packs:
                try:
                    import pathlib

                    cache_path = (
                        pathlib.Path(os.environ.get("VESPID_STATE_DIR", "/var/lib/vespid"))
                        / "rules_cache.json"
                    )
                    if cache_path.exists():
                        cached = json.loads(cache_path.read_text(encoding="utf-8"))
                        # Try explicit packs field first
                        detection_packs = cached.get("packs", [])
                        # Fall back to deriving from custom_rules
                        if not detection_packs:
                            detection_packs = sorted(
                                set(
                                    r.get("pack_name", "")
                                    for r in cached.get("custom_rules", [])
                                    if r.get("pack_name")
                                )
                            )
                except Exception as exc:
                    log.debug("Could not read rules cache for status: %s", exc)
            return {
                "ok": True,
                "node_id": self.config.node_id,
                "version": __version__,
                "nft": self.nft.status(),
                "subs": self.subs.status(),
                "bus": self.bus.stats(),
                "upload_enabled": self.config.upload_enabled,
                "server_url": self.config.SERVER_URL,
                "activity": self._activity.snapshot(),
                "fleet": {
                    "report_enabled": self.config.fleet_blocklist_report_enabled,
                    "subscribe_enabled": self.config.fleet_blocklist_subscribe_enabled,
                    "block_ttl_seconds": self.config.fleet_block_ttl_seconds,
                    "queue_pending": fleet_queue.size() if fleet_queue else 0,
                    "connected": self.fleet_sub is not None,
                    "allow_list_count": len(self.config.fleet_local_allow_list),
                    "server_active_blocks": self.bus.fleet_active_blocks,
                },
                "detection_packs": detection_packs,
            }

        async def stats(_: dict[str, Any]) -> dict[str, Any]:
            # Alias for status — kept for backward compatibility
            return await status(_)

        async def block(req: dict[str, Any]) -> dict[str, Any]:
            ip = req.get("ip", "")
            reason = req.get("reason", "cli")
            ok = self.nft.block_local(ip, reason=reason)
            return {"ok": True, "blocked": ok, "ip": ip}

        async def unblock(req: dict[str, Any]) -> dict[str, Any]:
            ip = req.get("ip", "")
            reason = req.get("reason", "cli")
            removed = self.nft.unblock_local(ip, reason=reason)
            return {"ok": True, "removed": removed, "ip": ip}

        async def sync_feeds(_: dict[str, Any]) -> dict[str, Any]:
            count = await self.subs.sync_now()
            return {"ok": True, "synced": count}

        async def list_local(_: dict[str, Any]) -> dict[str, Any]:
            return {"ok": True, "entries": self.nft.list_local()}

        async def list_subscribed(req: dict[str, Any]) -> dict[str, Any]:
            limit = req.get("limit")
            entries = self.nft.list_subscribed(limit=limit)
            return {
                "ok": True,
                "count": len(self.nft.list_subscribed()),
                "returned": len(entries),
                "entries": entries,
            }

        async def check(req: dict[str, Any]) -> dict[str, Any]:
            ip = req.get("ip", "")
            return {"ok": True, "result": self.nft.is_blocked(ip)}

        async def recent(req: dict[str, Any]) -> dict[str, Any]:
            limit = int(req.get("limit", 50))
            return {"ok": True, "entries": self.nft.recent(limit=limit)}

        async def allowlist_add(req: dict[str, Any]) -> dict[str, Any]:
            entry = req.get("entry", "")
            return self.nft.allowlist_add(entry)

        async def allowlist_remove(req: dict[str, Any]) -> dict[str, Any]:
            entry = req.get("entry", "")
            return self.nft.allowlist_remove(entry)

        async def allowlist_list(_: dict[str, Any]) -> dict[str, Any]:
            return self.nft.allowlist_list()

        async def recidive_info(req: dict[str, Any]) -> dict[str, Any]:
            ip = req.get("ip", "")
            return {"ok": True, "result": self.nft.recidive_info(ip)}

        async def feed_list(_: dict[str, Any]) -> dict[str, Any]:
            feeds = []
            for feed in self.config.subscriptions:
                sync_info = self.subs.status().get("feeds", {}).get(feed.name, {})
                feeds.append(
                    {
                        "name": feed.name,
                        "url": feed.url,
                        "enabled": feed.enabled,
                        "refresh_seconds": feed.refresh_seconds,
                        "last_sync_ts": sync_info.get("ts"),
                        "last_sync_count": sync_info.get("count", 0),
                    }
                )
            return {"ok": True, "feeds": feeds}

        async def feed_enable(req: dict[str, Any]) -> dict[str, Any]:
            name = req.get("name", "")
            for feed in self.config.subscriptions:
                if feed.name == name:
                    feed.enabled = True
                    self._save_runtime_feeds()
                    log.info("Feed %s enabled", name)
                    # Trigger an immediate re-sync to pick up the feed
                    count = await self.subs.sync_now()
                    return {"ok": True, "feed": name, "enabled": True, "synced": count}
            return {"ok": False, "error": f"unknown feed: {name}"}

        async def feed_disable(req: dict[str, Any]) -> dict[str, Any]:
            name = req.get("name", "")
            for feed in self.config.subscriptions:
                if feed.name == name:
                    feed.enabled = False
                    self._save_runtime_feeds()
                    log.info("Feed %s disabled", name)
                    # Destroy the feed's nftables set entirely so its
                    # chain rules (and their counters) are removed too.
                    self.nft.destroy_feed_set(name)
                    return {"ok": True, "feed": name, "enabled": False}
            return {"ok": False, "error": f"unknown feed: {name}"}

        async def feed_add(req: dict[str, Any]) -> dict[str, Any]:
            """Add a new subscription feed at runtime."""
            from urllib.parse import urlparse

            from .config import SubscriptionFeed

            name = req.get("name", "").strip()
            url = req.get("url", "").strip()
            fmt = req.get("format", "plain")
            refresh = req.get("refresh_seconds", 3600)

            if not name or not url:
                return {"ok": False, "error": "name and url are required"}
            if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$", name):
                return {"ok": False, "error": "invalid feed name (use a-z, 0-9, -, _, .)"}
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                return {"ok": False, "error": "url must be http(s) with a valid hostname"}
            # Check for duplicates
            for feed in self.config.subscriptions:
                if feed.name == name:
                    return {"ok": False, "error": f"feed '{name}' already exists"}
            new_feed = SubscriptionFeed(
                name=name,
                url=url,
                format=fmt,
                refresh_seconds=refresh,
                enabled=True,
            )
            self.config.subscriptions.append(new_feed)
            self._save_runtime_feeds()
            log.info("Feed %s added: %s", name, url)
            count = await self.subs.sync_now()
            # Start a periodic refresh loop for the new feed
            self.subs.start_feed_loop(new_feed)
            return {"ok": True, "feed": name, "added": True, "synced": count}

        async def feed_remove(req: dict[str, Any]) -> dict[str, Any]:
            """Remove a subscription feed at runtime."""
            name = req.get("name", "")
            for i, feed in enumerate(self.config.subscriptions):
                if feed.name == name:
                    self.config.subscriptions.pop(i)
                    self._save_runtime_feeds()
                    log.info("Feed %s removed", name)
                    # Destroy the feed's nftables set (removes all its IPs)
                    self.nft.destroy_feed_set(name)
                    return {"ok": True, "feed": name, "removed": True}
            return {"ok": False, "error": f"unknown feed: {name}"}

        async def counters(_: dict[str, Any]) -> dict[str, Any]:
            """Return nftables packet/byte counters for all sets."""
            return {"ok": True, "counters": self.nft.get_counters()}

        return {
            "status": status,
            "stats": stats,
            "block": block,
            "unblock": unblock,
            "sync_feeds": sync_feeds,
            "list_local": list_local,
            "list_subscribed": list_subscribed,
            "check": check,
            "recent": recent,
            "allowlist_add": allowlist_add,
            "allowlist_remove": allowlist_remove,
            "allowlist_list": allowlist_list,
            "recidive_info": recidive_info,
            "feed_list": feed_list,
            "feed_enable": feed_enable,
            "feed_disable": feed_disable,
            "feed_add": feed_add,
            "feed_remove": feed_remove,
            "counters": counters,
        }

    # ------------------------------------------------------------------
    async def run(self) -> None:
        configure_logging(level=self.config.log_level)

        # ── Startup banner ──
        version = __version__
        display = self.config.display_name or "—"
        node_id = self.config.node_id
        banner = (
            "\n"
            "  ┌──────────────────────────────────────────────────────────────┐\n"
            "  │{:<62}│\n"
            "  │{:<62}│\n"
            "  │{:<62}│\n"
            "  │{:<62}│\n"
            "  └──────────────────────────────────────────────────────────────┘"
        ).format(
            "                      Vespid Daemon",
            f"                        v{version}",
            f"  Name:    {display}",
            f"  Node ID: {node_id}",
        )
        log.info(banner)

        log.info(
            "Starting Vespid (node_id=%s, version=%s)",
            self.config.node_id,
            __version__,
        )
        log.info("Log sources: %s", ", ".join(s.path for s in self.config.log_sources))
        log.info(
            "Detection rules: %s",
            ", ".join(
                f"{r.name}({r.max_attempts}/{r.window_seconds}s)"
                for r in self.config.brute_force_rules
            ),
        )
        if self.config.custom_rules:
            enabled = [r for r in self.config.custom_rules if r.enabled]
            log.info(
                "Custom rules: %s",
                ", ".join(f"{r.name}({r.max_attempts}/{r.window_seconds}s)" for r in enabled)
                or "(none enabled)",
            )
        log.info(
            "Subscription feeds: %s",
            ", ".join(f.name for f in self.config.subscriptions) or "(none)",
        )

        # Handle enrollment before starting the databus
        state = self._handle_enrollment()

        if state == "ready":
            result = self._validate_api_key()
            if result == "valid":
                log.info("API key validated — entering operational state")
            elif result == "invalid":
                log.error("API key validation failed — clearing and retrying enrollment")
                self.config.API_KEY = ""
                self._credentials_received.clear()
                retry_state = self._handle_enrollment()
                if retry_state == "ready":
                    retry_result = self._validate_api_key()
                    if retry_result == "valid":
                        log.info("API key validated after retry — entering operational state")
                    elif retry_result == "invalid":
                        log.warning("API key still invalid after retry — restricted mode")
                    else:
                        log.info("API key present but server unreachable — will retry via watcher")
                else:
                    log.warning("Enrollment retry returned %s — restricted mode", retry_state)
            else:
                log.info("API key present but server unreachable — will retry via watcher")

        if self._api_key_is_valid() and self._validate_api_key() == "valid":
            log.info("Valid API key confirmed — signalling credentials ready")
            self._credentials_ready.set()
        elif state == "pending":
            log.info("Enrollment pending — waiting for approval before full operation")
        elif self._api_key_is_valid():
            log.info("API key present but validation deferred — watcher will retry")
        else:
            log.warning("No valid API key — operating in restricted local-only mode")

        log.info(
            "Telemetry upload: %s -> %s",
            "ENABLED" if self.config.upload_enabled else "DISABLED (spool only)",
            self.config.SERVER_URL,
        )

        self.nft.ensure_infrastructure()
        self.bus._on_auth_failure = self.handle_auth_failure
        self.bus._get_blocks = self.nft.list_local
        self.bus._get_feeds = self._get_feed_snapshot
        self.bus._get_counters_cb = self.nft.get_counters
        self.bus._exec_cmd = self._dispatch_command

        loop = asyncio.get_running_loop()
        self._main_loop = loop
        self.ctl.start()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self._request_stop)
            except NotImplementedError:  # pragma: no cover (Windows)
                pass

        # Ensure the default executor has enough threads for concurrent
        # blocking I/O from subscribers + httpx DNS resolution.  The default
        # (cpu_count + 4) is too small when multiple SSE streams, rule polls,
        # and feed downloads all need executor threads simultaneously.
        import concurrent.futures

        loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=16))

        def _shield(coro, task_name):
            async def _wrapper():
                try:
                    await coro
                except asyncio.CancelledError:
                    raise
                except Exception:
                    log.exception("Async task '%s' crashed — triggering shutdown", task_name)
                    self._request_stop()

            return asyncio.create_task(_wrapper(), name=task_name)

        tasks = [
            _shield(self.logproc.run(), "logproc"),
            _shield(self.subs.run(), "subs"),
            _shield(self._nft_health_loop(), "nft_health"),
            _shield(self._expiry_reap_loop(), "expiry_reap"),
            _shield(self._gc_loop(), "gc"),
            _shield(self._wait_stop(), "stop"),
        ]

        tasks.append(_shield(self._watch_for_credentials(), "cred_watch"))
        tasks.append(_shield(self._start_bus_when_ready(), "bus_init"))
        tasks.append(_shield(self._fleet_queue_drain_loop(), "fleet_queue_drain"))

        # Subscribers run in their own threads with dedicated event loops.
        # The main asyncio event loop on Python 3.12 does not reliably
        # process ``call_soon_threadsafe`` callbacks while inside
        # ``asyncio.wait(FIRST_COMPLETED)``, which starves subscriber
        # tasks of ``asyncio.to_thread`` callback resumption and prevents
        # new tasks from being scheduled.
        if self.fleet_sub:
            threading.Thread(
                target=lambda: _run_subscriber_loop(self.fleet_sub),
                name="fleet-subscriber",
                daemon=True,
            ).start()
        if self.rule_sub:
            threading.Thread(
                target=lambda: _run_subscriber_loop(self.rule_sub),
                name="rule-subscriber",
                daemon=True,
            ).start()
        if self.config_sub:
            threading.Thread(
                target=lambda: _run_subscriber_loop(self.config_sub),
                name="config-subscriber",
                daemon=True,
            ).start()

        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        log.info("Vespid shutting down")
        self.logproc.stop()
        self.subs.stop()
        self.ctl.stop()
        if self.fleet_sub:
            self.fleet_sub.stop()
        if self.rule_sub:
            self.rule_sub.stop()
        if self.config_sub:
            self.config_sub.stop()
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        self.bus.stop()

    async def _fleet_queue_drain_loop(self) -> None:
        """Background task that periodically drains the fleet report queue.

        Waits for ``_credentials_ready`` before attempting the first drain.
        Uses exponential backoff: starts at 30s, doubles on each failed
        attempt up to 300s max. Resets to 30s on a successful drain.
        """
        await asyncio.to_thread(self._credentials_ready.wait)
        if self._stop.is_set():
            return

        initial_delay = 30.0
        max_delay = 300.0
        factor = 2.0
        current_delay = initial_delay

        fleet_queue = self.bus._fleet_queue

        while not self._stop.is_set():
            # Wait for the current backoff interval (or stop signal)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=current_delay)
                break  # stop was requested
            except asyncio.TimeoutError:
                pass  # delay elapsed — time to try draining

            if fleet_queue.is_empty():
                # Nothing to drain — reset backoff and wait again
                current_delay = initial_delay
                continue

            try:
                sent = await fleet_queue.drain_batch(
                    self._fleet_queue_send_batch,
                    batch_size=self.config.flush_batch_size,
                )
                if sent > 0:
                    log.info("Fleet queue drained %d report(s) successfully", sent)
                    current_delay = initial_delay  # reset backoff on success
                else:
                    # drain returned 0 — either queue was empty or first send failed
                    current_delay = min(current_delay * factor, max_delay)
            except Exception:
                log.exception("Unexpected error draining fleet queue")
                current_delay = min(current_delay * factor, max_delay)

    async def _fleet_queue_send_batch(self, reports: list[dict]) -> bool:
        """Attempt to send a batch of queued block reports in one request.

        Returns True when the reports should be removed from the queue:
        either the server accepted them (2xx) or rejected them permanently
        (a non-retryable 4xx such as 400/422). Returns False on connection
        errors, 5xx responses, and 429 throttling so the reports stay queued
        and are retried on a later drain cycle.
        """
        try:
            await asyncio.to_thread(
                request,
                self.config.API_KEY,
                self.config.node_id,
                "POST",
                self.config.SERVER_URL,
                json_data={"events": reports},
                verify=self.config.ssl_verify,
                cert=self.config.ssl_cert,
                key=self.config.ssl_key,
            )
            return True
        except HttpError as exc:
            if exc.is_retryable:
                log.warning(
                    "Fleet queue batch of %d report(s) deferred: %s",
                    len(reports),
                    exc,
                )
                return False
            # Permanent 4xx errors — discard so the queue cannot stall
            log.warning(
                "Fleet queue batch of %d report(s) rejected, discarding: %s",
                len(reports),
                exc,
            )
            return True

    async def _wait_stop(self) -> None:
        await self._stop.wait()

    def _request_stop(self) -> None:
        log.info("Stop requested")
        self._stop.set()

    async def _nft_health_loop(self) -> None:
        """Periodically verify the shield table is still in the kernel."""
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=30)
                break
            except asyncio.TimeoutError:
                pass
            try:
                ok = await self._nft_in_thread(self.nft.health_check)
                if not ok:
                    log.error("nft health check failed — will retry in 30 s")
            except Exception:
                log.exception("Unexpected error in nft health check")

    async def _expiry_reap_loop(self) -> None:
        """Periodically remove expired entries from the in-memory local block list."""
        interval = self.config.expiry_reap_interval
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass
            try:
                await self._nft_in_thread(self.nft.reap_expired)
            except Exception:
                log.exception("Unexpected error in expiry reaper")

    async def _gc_loop(self) -> None:
        """Periodic garbage collection of stale in-memory tracking data."""
        interval = 600
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass
            try:
                buckets_pruned = self.logproc.detector.prune_stale()
                correlation_pruned = self.logproc.correlation.prune_stale()
                recidive_pruned = await self._nft_in_thread(self.nft.prune_recidive)
                # Persist detector state to survive restarts
                self.logproc.detector.save()
                self.logproc.correlation.save()
                if buckets_pruned or correlation_pruned or recidive_pruned:
                    log.info(
                        "GC: pruned %d detector buckets, %d correlation entries, %d recidive entries",
                        buckets_pruned,
                        correlation_pruned,
                        recidive_pruned,
                    )
            except Exception:
                log.exception("Unexpected error in GC loop")

    async def _watch_for_credentials(self) -> None:
        """Watch for unvalidated credentials and retry until confirmed."""
        while not self._stop.is_set():
            if not self._api_key_is_valid():
                loop = asyncio.get_running_loop()
                try:
                    await loop.run_in_executor(None, self._credentials_received.wait, 60.0)
                except asyncio.CancelledError:
                    return
                self._credentials_received.clear()
            if self._stop.is_set():
                return
            if self._credentials_ready.is_set():
                await self._stop.wait()
                return
            if not self._api_key_is_valid():
                continue
            retry_delay = 30.0
            while not self._stop.is_set() and not self._credentials_ready.is_set():
                result = self._validate_api_key()
                if result == "valid":
                    log.info("Watcher: API key validated — entering operational state")
                    self._credentials_ready.set()
                    break  # credentials ready — exit inner retry loop,
                    # outer while will hit the "wait for stop" path
                if result == "invalid":
                    log.error("Watcher: API key rejected by server — re-enrolling")
                    self.config.API_KEY = ""
                    self._handle_enrollment()
                    break
                log.info("Watcher: verify endpoint unreachable, retrying in %.0fs", retry_delay)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=retry_delay)
                    return
                except asyncio.TimeoutError:
                    retry_delay = min(retry_delay * 2, 300.0)

    async def _start_bus_when_ready(self) -> None:
        """Wait for credentials, then start the databus and keep it alive."""
        await asyncio.to_thread(self._credentials_ready.wait)
        if self._stop.is_set():
            return
        log.info("Credentials ready — starting databus")
        self.bus.start()
        await self._stop.wait()
        self.bus.stop()


def main() -> int:
    import faulthandler

    faulthandler.enable()
    faulthandler.register(signal.SIGUSR2)

    parser = argparse.ArgumentParser(prog="vespid")
    parser.add_argument(
        "--check-config", action="store_true", help="validate configuration and exit"
    )
    args = parser.parse_args()

    if args.check_config:
        print(CONFIG.to_dict())
        return 0

    asyncio.run(Vespid().run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
