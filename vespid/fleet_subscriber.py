"""Fleet Block Subscriber.

Connects to the server's Fleet SSE channel and applies fleet-wide
block/unblock directives to the local nftables set.  Handles
reconnection with exponential backoff and ``Last-Event-ID`` replay.

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
from collections.abc import Callable

import httpx

from . import __version__
from .config import ShieldConfig
from .http_client import build_ssl_context
from .nftables_manager import NFTablesManager

log = logging.getLogger("vespid.fleet_sub")

# Reconnection backoff parameters
_BACKOFF_INITIAL = 5  # seconds
_BACKOFF_MAX = 300  # 5 minutes
_BACKOFF_FACTOR = 2
_BACKOFF_JITTER = 0.20  # ±20%

# Read timeout: if no data received for this many seconds, consider
# the connection dead and force a reconnect.  The server sends keepalive
# comments every 15s, so 60s gives 4 missed keepalives before triggering.
_KEEPALIVE_TIMEOUT = 60

# Periodic fallback sync interval: if the SSE connection silently fails or
# the reconnection fails to detect a disconnect, this ensures the node still
# catches fleet blocks by polling the active blocks endpoint directly.
_SYNC_INTERVAL = 300  # 5 minutes


class FleetBlockSubscriber:
    """Asyncio task that subscribes to the Fleet SSE channel.

    Parses incoming fleet block/unblock messages and applies them to
    the local nftables set after checking the local allow-list.
    """

    def __init__(
        self,
        config: ShieldConfig,
        nft: NFTablesManager,
        on_fleet_block=None,
        credentials_ready: threading.Event | None = None,
        on_auth_failure: Callable[[], bool] | None = None,
    ) -> None:
        self.config = config
        self.nft = nft
        self._on_fleet_block = on_fleet_block
        self._credentials_ready = credentials_ready
        self._on_auth_failure = on_auth_failure
        self._last_event_id: str | None = None
        self._stop = asyncio.Event()
        self._backoff = _BACKOFF_INITIAL
        # Pre-parse the local allow-list into network objects
        self._allow_networks = self._parse_allow_list(config.fleet_local_allow_list)
        # Track the source list so we can detect config changes at runtime
        self._allow_list_source = list(config.fleet_local_allow_list)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Main loop: connect to SSE stream, process messages, reconnect on failure."""
        self._stop.clear()
        log.info("Fleet block subscriber starting (server=%s)", self.config.SERVER_URL)

        # Wait for valid credentials before attempting connections
        if self._credentials_ready and not self._credentials_ready.is_set():
            log.info("Fleet subscriber waiting for credentials...")
            # Wait for either credentials or stop signal
            cred_task = asyncio.create_task(asyncio.to_thread(self._credentials_ready.wait))
            stop_task = asyncio.create_task(self._wait_event(self._stop))
            done, pending = await asyncio.wait(
                [cred_task, stop_task], return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()
            if self._stop.is_set():
                return
            log.info("Fleet subscriber credentials ready, connecting")

        # Start periodic sync as a concurrent background task.
        # This runs every _SYNC_INTERVAL seconds regardless of SSE connection
        # state, providing a fallback catch-up mechanism in case the SSE stream
        # silently drops events or fails to detect a disconnected socket.
        sync_task = asyncio.create_task(self._periodic_sync_loop())

        try:
            while not self._stop.is_set():
                try:
                    await self._connect_and_consume()
                    # If _connect_and_consume returns normally, the stream ended cleanly.
                    # Reset backoff and reconnect.
                    self._backoff = _BACKOFF_INITIAL
                except asyncio.CancelledError:
                    log.info("Fleet block subscriber cancelled")
                    return
                except Exception as exc:
                    log.warning("Fleet SSE connection error: %s", exc)

                if self._stop.is_set():
                    break

                # Exponential backoff with jitter before reconnecting
                delay = self._compute_backoff()
                log.info("Fleet SSE reconnecting in %.1fs (backoff=%.1fs)", delay, self._backoff)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                    break  # stop was signaled during wait
                except asyncio.TimeoutError:
                    pass  # timeout expired, reconnect

                # Increase backoff for next failure
                self._backoff = min(self._backoff * _BACKOFF_FACTOR, _BACKOFF_MAX)
        finally:
            sync_task.cancel()
            try:
                await sync_task
            except asyncio.CancelledError:
                pass

    async def _periodic_sync_loop(self) -> None:
        """Periodically poll active fleet blocks as a fallback to SSE.

        Runs every ``_SYNC_INTERVAL`` seconds, independent of SSE connection
        state.  Calls ``_initial_sync()`` which fetches all currently active
        fleet blocks from ``GET /api/v1/fleet/blocks/active`` and applies any
        that are not already blocked locally.

        Provides a safety net for scenarios where the SSE stream silently
        drops events or fails to detect a disconnected socket.
        """
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=_SYNC_INTERVAL)
                return
            except asyncio.TimeoutError:
                pass

            try:
                await self._initial_sync()
            except Exception as exc:
                log.warning("Periodic fleet sync failed: %s", exc)

    def stop(self) -> None:
        """Signal the subscriber to stop."""
        self._stop.set()

    @staticmethod
    async def _wait_event(event: asyncio.Event) -> None:
        """Await an asyncio.Event (helper for wait/race patterns)."""
        await event.wait()

    # ------------------------------------------------------------------
    # SSE Connection
    # ------------------------------------------------------------------

    async def _connect_and_consume(self) -> None:
        """Connect to the Fleet SSE stream and process messages.

        Always performs a bulk sync of active fleet blocks before
        subscribing to the SSE stream.  Ensures the node catches up on
        any blocks that were propagated while the connection was down.
        """
        await self._initial_sync()

        url = self._build_stream_url()
        headers = self._build_headers()

        await self._sse_read_async(url, headers)

    async def _initial_sync(self) -> None:
        """Bulk-fetch all active fleet blocks from the server.

        Called on first connection (before any SSE events have been received)
        to catch up on fleet blocks that were issued before this agent joined.
        Uses GET /api/v1/fleet/blocks/active which returns the same format as
        SSE block events.

        Skips IPs that are already blocked locally to avoid redundant
        nftables operations and log noise on reconnection.
        """
        url = self._build_active_blocks_url()
        headers = {
            "Authorization": f"Bearer {self.config.API_KEY}",
            "User-Agent": f"Vespid/{__version__} FleetSubscriber",
            "Accept": "application/json",
        }

        try:
            blocks = await self._fetch_active_async(url, headers)
        except Exception as exc:
            log.warning("Fleet initial sync failed: %s — will rely on SSE stream", exc)
            return

        if not blocks:
            log.info("Fleet initial sync: no active blocks to ingest")
            return

        # Pre-filter: skip IPs already blocked locally to avoid redundant
        # nftables syscalls and log noise on reconnection.
        already_blocked = self.nft.local_blocked_set()

        applied = 0
        skipped = 0
        with self.nft.defer_persist():
            for block in blocks:
                if not isinstance(block, dict) or "source_ip" not in block:
                    continue
                if block["source_ip"] in already_blocked:
                    skipped += 1
                    continue
                self._apply_block_sync(block)
                applied += 1

        # Reconcile: remove fleet-propagated blocks from shield_local that
        # are no longer on the server.  This catches remove events that were
        # lost during an SSE outage.
        server_ips = {b["source_ip"] for b in blocks if isinstance(b, dict) and "source_ip" in b}
        local_fleet_ips = self.nft.local_fleet_blocked_set()
        stale = local_fleet_ips - server_ips
        if stale:
            self.nft.unblock_local_bulk(stale)

        log.info(
            "Fleet initial sync complete: %d applied, %d already local, %d total from server",
            applied,
            skipped,
            len(blocks),
        )

    async def _fetch_active_async(self, url: str, headers: dict) -> list:
        """Fetch active fleet blocks (inline sync httpx — fast GET, avoids executor)."""
        ctx = build_ssl_context(self.config.ssl_verify, self.config.ssl_cert, self.config.ssl_key)
        with httpx.Client(verify=ctx, timeout=30.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 401:
                log.error("Fleet initial sync auth failed (401)")
                if self._on_auth_failure:
                    self._on_auth_failure()
            resp.raise_for_status()
            return resp.json().get("blocks", [])

    def _build_active_blocks_url(self) -> str:
        """Build the URL for the fleet blocks active endpoint."""
        base = self.config.SERVER_URL
        if "/api/v1/" in base:
            base = base[: base.index("/api/v1/") + len("/api/v1/")]
        elif base.endswith("/"):
            base = base + "api/v1/"
        else:
            base = base + "/api/v1/"
        return base + "fleet/blocks/active"

    async def _sse_read_async(self, url: str, headers: dict) -> None:
        """SSE reader in a daemon thread, polled via asyncio.sleep.

        Spawns a blocking SSE reader in a raw thread and polls a
        ``threading.Event`` for completion.  Avoids ``asyncio.to_thread``
        whose ``call_soon_threadsafe`` callback is not reliably processed
        inside ``asyncio.wait(FIRST_COMPLETED)`` on Python 3.12.
        """
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
                            log.error("Fleet SSE auth failed (401)")
                            if self._on_auth_failure:
                                self._on_auth_failure()
                            resp.raise_for_status()
                        elif resp.status_code == 403:
                            log.error("Fleet SSE forbidden (403)")
                            resp.raise_for_status()
                        elif resp.status_code >= 400:
                            log.warning("Fleet SSE HTTP error %d", resp.status_code)
                            resp.raise_for_status()

                        self._backoff = _BACKOFF_INITIAL
                        log.info("Connected to Fleet SSE stream at %s", url)

                        event_id = None
                        event_type = None
                        data_lines: list = []

                        for raw_line in resp.iter_lines():
                            if self._stop.is_set():
                                return

                            line = raw_line.rstrip("\n\r")

                            if line == "":
                                if data_lines:
                                    data = "\n".join(data_lines)
                                    self._handle_event(event_id, event_type, data)
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

        t = threading.Thread(target=_run, name="fleet-sse", daemon=True)
        t.start()

        # Poll until the thread completes or we're asked to stop
        while not done.is_set():
            if self._stop.is_set():
                return
            await asyncio.sleep(1.0)

        if error[0] is not None:
            raise error[0]

    def _handle_event(self, event_id: str | None, event_type: str | None, data: str) -> None:
        """Process a single SSE event."""
        # We only care about fleet_block events
        if event_type and event_type != "fleet_block":
            log.debug("Ignoring SSE event type: %s", event_type)
            return

        msg = self._parse_message(data)
        if msg is None:
            return

        action = msg.get("action")
        if action == "block":
            self._apply_block_sync(msg)
        elif action == "unblock":
            self._apply_unblock_sync(msg)
        elif action == "renew":
            self._apply_renew_sync(msg)
        else:
            log.warning(
                "Fleet SSE unknown action %r in message %s", action, msg.get("fleet_block_id", "?")
            )

    # ------------------------------------------------------------------
    # Message Parsing
    # ------------------------------------------------------------------

    def _parse_message(self, data: str) -> dict | None:
        """Parse JSON SSE data, validate required fields.

        Returns the parsed dict or None if the message is invalid.
        Required fields: action, source_ip, fleet_block_id.
        """
        try:
            msg = json.loads(data)
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("Fleet SSE malformed JSON: %s (data=%r)", exc, data[:200] if data else "")
            return None

        if not isinstance(msg, dict):
            log.warning("Fleet SSE message is not a JSON object: %r", type(msg).__name__)
            return None

        # Validate required fields
        required = ("action", "source_ip", "fleet_block_id")
        missing = [f for f in required if not msg.get(f)]
        if missing:
            log.warning(
                "Fleet SSE message missing required fields: %s (id=%s)",
                ", ".join(missing),
                msg.get("fleet_block_id", "?"),
            )
            return None

        # Validate action is recognized
        action = msg["action"]
        if action not in ("block", "unblock", "renew"):
            log.warning(
                "Fleet SSE unrecognized action %r (id=%s)", action, msg.get("fleet_block_id", "?")
            )
            return None

        return msg

    # ------------------------------------------------------------------
    # Local Allow-List
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_allow_list(entries: list) -> list:
        """Parse allow-list entries into ipaddress network objects."""
        networks = []
        for entry in entries:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except (ValueError, TypeError):
                log.warning("Invalid fleet local allow-list entry: %r", entry)
        return networks

    def _check_local_allowlist(self, ip: str) -> bool:
        """Check if an IP matches the local allow-list or the node allowlist.

        Returns True if the IP is allowed (should NOT be blocked).
        Checks both the fleet-specific local allow-list AND the node's
        main runtime allowlist (managed via config profiles and CLI).
        This ensures that allowlist additions from IP Rules Management
        are respected immediately by the fleet subscriber without
        requiring a daemon restart.

        The fleet local allow-list is re-parsed if the underlying config
        has been updated (e.g. via config profile sync from the server).
        """
        # Check the node's main allowlist first (includes runtime additions)
        if self.nft.is_allowlisted(ip):
            return True

        # Refresh parsed allow-list if config has changed since last parse
        current_source = self.config.fleet_local_allow_list
        if current_source != self._allow_list_source:
            self._allow_networks = self._parse_allow_list(current_source)
            self._allow_list_source = list(current_source)
            log.debug("Fleet local allow-list refreshed (%d entries)", len(self._allow_networks))

        if not self._allow_networks:
            return False

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        return any(addr in net for net in self._allow_networks)

    # ------------------------------------------------------------------
    # Block/Unblock Application
    # ------------------------------------------------------------------

    def _apply_block_sync(self, msg: dict) -> None:
        """Apply a fleet block directive (synchronous, called from thread)."""
        ip = msg["source_ip"]
        reason = msg.get("reason", "fleet_block")
        fleet_block_id = msg.get("fleet_block_id", "")
        ttl = msg.get("ttl_seconds", self.config.fleet_block_ttl_seconds)

        # Check local allow-list
        if self._check_local_allowlist(ip):
            log.info("Fleet block for %s rejected by local allow-list (id=%s)", ip, fleet_block_id)
            return

        # Apply the block via NFTablesManager with fleet TTL
        # Include detection info for intel tracking if available
        detection_rule_name = msg.get("detection_rule_name") or reason
        threat_tag = msg.get("threat_tag") or reason.lower().replace("_", "-")

        try:
            blocked = self.nft.block_local(
                ip,
                reason=f"fleet:{reason}",
                ttl=ttl,
                detection_rule_name=detection_rule_name,
                threat_tag=f"fleet:{threat_tag}",
            )
            if blocked:
                log.info(
                    "Fleet block applied: %s (id=%s, reason=%s, ttl=%ds)",
                    ip,
                    fleet_block_id,
                    reason,
                    ttl,
                )
                if self._on_fleet_block:
                    self._on_fleet_block()
            else:
                log.debug("Fleet block for %s not applied (allowlisted or already blocked)", ip)
        except Exception as exc:
            log.error("Failed to apply fleet block for %s: %s", ip, exc)

    def _apply_unblock_sync(self, msg: dict) -> None:
        """Apply a fleet unblock directive (synchronous, called from thread)."""
        ip = msg["source_ip"]
        reason = msg.get("reason", "fleet_unblock")
        fleet_block_id = msg.get("fleet_block_id", "")

        try:
            was_present = self.nft.unblock_local(ip, reason=f"fleet:{reason}")
            if was_present:
                log.info("Fleet unblock applied: %s (id=%s, reason=%s)", ip, fleet_block_id, reason)
            else:
                log.debug("Fleet unblock for %s — was not blocked locally", ip)
        except Exception as exc:
            log.error("Failed to apply fleet unblock for %s: %s", ip, exc)

    def _apply_renew_sync(self, msg: dict) -> None:
        """Apply a fleet TTL renewal (synchronous, called from thread).

        Resets the local TTL for an already-blocked IP. If the IP is not
        currently blocked locally (e.g. it already expired), falls back to
        applying a fresh block so the agent stays in sync with the server.
        """
        ip = msg["source_ip"]
        fleet_block_id = msg.get("fleet_block_id", "")
        ttl = msg.get("ttl_seconds", self.config.fleet_block_ttl_seconds)

        try:
            renewed = self.nft.renew_local(ip, ttl=ttl)
            if renewed:
                log.info("Fleet TTL renewed: %s (id=%s, new_ttl=%ds)", ip, fleet_block_id, ttl)
            else:
                # IP not present locally — apply as a fresh block to re-sync
                log.info("Fleet renew for %s — not blocked locally, applying fresh block", ip)
                self._apply_block_sync(msg)
        except Exception as exc:
            log.error("Failed to apply fleet TTL renewal for %s: %s", ip, exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_stream_url(self) -> str:
        """Build the Fleet SSE stream URL from config."""
        # The SERVER_URL typically points to /api/v1/events
        # We need /api/v1/fleet/blocks/stream
        base = self.config.SERVER_URL
        # Strip trailing path components to get the base API URL
        if "/api/v1/" in base:
            base = base[: base.index("/api/v1/") + len("/api/v1/")]
        elif base.endswith("/"):
            base = base + "api/v1/"
        else:
            base = base + "/api/v1/"
        return base + "fleet/blocks/stream"

    def _build_headers(self) -> dict:
        """Build HTTP headers for the SSE connection."""
        headers = {
            "Accept": "text/event-stream",
            "Authorization": f"Bearer {self.config.API_KEY}",
            "User-Agent": f"Vespid/{__version__} FleetSubscriber",
            "Cache-Control": "no-cache",
        }
        if self._last_event_id:
            headers["Last-Event-ID"] = self._last_event_id
        return headers

    def _compute_backoff(self) -> float:
        """Compute the next backoff delay with ±20% jitter."""
        jitter_factor = 1.0 + random.uniform(-_BACKOFF_JITTER, _BACKOFF_JITTER)
        return self._backoff * jitter_factor
