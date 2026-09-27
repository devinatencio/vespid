"""Event Telemetry Module - Producer/Consumer DataBus.

Producers (log processor, nftables manager, subscription manager) call
``DataBus.publish(...)``. A background worker (Consumer) drains the queue,
batches events and ships them as JSON. While the central management server
does not yet exist, the worker spools batches to disk and respects an
``upload_enabled`` flag so the wiring is ready for the future.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .config import CONFIG, STATE_DIR, ShieldConfig
from .fleet_queue import FleetReportQueue
from .geo import lookup as geo_lookup
from .host_info import collect as collect_host_info
from .http_client import HttpError, request

log = logging.getLogger("vespid.databus")


def _atomic_write_text(path: Path, text: str) -> None:
    """Write *text* to *path* atomically.

    Uses a sibling temporary file and ``os.replace()`` so readers never
    see a partially-written file. The temporary file is cleaned up on
    failure.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Event schema
# ---------------------------------------------------------------------------
@dataclass
class SecurityEvent:
    """Canonical event schema shared by every producer."""

    node_id: str
    timestamp: str  # ISO-8601 / RFC3339 UTC
    source_ip: str
    event_type: str  # e.g. SSH_BRUTE, BLOCKLIST_HIT, NFT_ACTION
    action_taken: str  # e.g. BLOCKED, UNBLOCKED, OBSERVED
    geo_data: dict[str, Any]
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Replace random event_id with a deterministic content-based hash.

        The hash covers node_id, source_ip, event_type, action_taken,
        detection_rule_name (if present in metadata), and a 60-second
        time bucket. Identical detections (same attacker, same rule,
        same 60s window) produce the same event_id, making the
        server-side INSERT OR IGNORE dedup effective on restart replay.
        """
        rule_name = ""
        if self.metadata and isinstance(self.metadata, dict):
            rule_name = self.metadata.get("detection_rule_name", "") or self.metadata.get(
                "rule", ""
            )
        # 60-second time bucket aligned to the epoch
        try:
            ts = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
            bucket = int(ts.timestamp() / 60)
        except (ValueError, AttributeError):
            bucket = 0
        raw = "|".join(
            [
                self.node_id,
                self.source_ip,
                self.event_type,
                self.action_taken,
                rule_name,
                str(bucket),
            ]
        )
        self.event_id = hashlib.sha256(raw.encode()).hexdigest()[:32]

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


# ---------------------------------------------------------------------------
# DataBus
# ---------------------------------------------------------------------------
class DataBus:
    """Thread-safe in-process bus that any producer can publish to."""

    def __init__(self, config: ShieldConfig | None = None) -> None:
        self.config = config or CONFIG
        self._queue: queue.Queue[SecurityEvent] = queue.Queue(maxsize=self.config.queue_max_size)
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._lock = threading.Lock()
        self._on_auth_failure: Callable[[], None] | None = None  # Callback for 401 handling
        self._get_blocks: Callable[[], list[dict[str, Any]]] | None = None
        self._last_block_hash: str | None = None
        self._get_feeds: Callable[[], list[dict[str, Any]]] | None = None
        self._get_counters_cb: Callable[[], list[dict[str, Any]]] | None = None
        self._exec_cmd: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None
        self._stats = {
            "published": 0,
            "dropped": 0,
            "shipped": 0,
            "spooled": 0,
            "failed": 0,
        }
        # Fleet report offline queue for block reports that fail to send
        self._fleet_queue = FleetReportQueue(
            queue_dir=self.config.fleet_queue_dir,
            max_size=self.config.fleet_queue_max_size,
        )
        # Fleet-wide active block count (updated from heartbeat response)
        self.fleet_active_blocks: int = 0

    _CREDENTIALS_PATH = STATE_DIR / "credentials.json"

    def _load_asset_id(self) -> str:
        """Read asset_id from credentials file, or empty string."""
        try:
            if self._CREDENTIALS_PATH.is_file():
                data = json.loads(self._CREDENTIALS_PATH.read_text(encoding="utf-8"))
                return data.get("asset_id", "") or ""
        except (OSError, json.JSONDecodeError):
            pass
        return ""

    # --- producer side -------------------------------------------------
    def publish(
        self,
        *,
        source_ip: str,
        event_type: str,
        action_taken: str,
        metadata: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> SecurityEvent:
        ts = (timestamp or datetime.now(timezone.utc)).astimezone(timezone.utc)
        event = SecurityEvent(
            node_id=self.config.node_id,
            timestamp=ts.isoformat().replace("+00:00", "Z"),
            source_ip=source_ip,
            event_type=event_type,
            action_taken=action_taken,
            geo_data=geo_lookup(source_ip),
            metadata=metadata or {},
        )
        try:
            self._queue.put_nowait(event)
            with self._lock:
                self._stats["published"] += 1
        except queue.Full:
            with self._lock:
                self._stats["spooled"] += 1
            log.warning("DataBus queue full - spooling event %s/%s", event_type, source_ip)
            self._spool_one(event)
        return event

    # --- consumer side -------------------------------------------------
    def start(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._run, name="vespid-databus", daemon=True)
        self._worker.start()

        # Start heartbeat thread if upload is enabled
        if self.config.upload_enabled:
            self._heartbeat_worker = threading.Thread(
                target=self._heartbeat_loop, name="vespid-heartbeat", daemon=True
            )
            self._heartbeat_worker.start()
            log.info(
                "Heartbeat thread started (interval=%ds)",
                getattr(self.config, "heartbeat_interval_seconds", 300),
            )

        log.info("DataBus worker started (node_id=%s)", self.config.node_id)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._worker:
            self._worker.join(timeout=timeout)
        if hasattr(self, "_heartbeat_worker") and self._heartbeat_worker:
            self._heartbeat_worker.join(timeout=timeout)

    def stats(self) -> dict[str, int]:
        with self._lock:
            snapshot = dict(self._stats)
        snapshot["queued"] = self._queue.qsize()
        return snapshot

    # --- internals -----------------------------------------------------
    def _run(self) -> None:
        Path(self.config.spool_path).parent.mkdir(parents=True, exist_ok=True)
        while not self._stop.is_set():
            batch = self._drain_batch(
                self.config.flush_batch_size,
                self.config.flush_interval_seconds,
            )
            if batch:
                self._handle_batch(batch)
        # final flush
        remaining = self._drain_batch(self._queue.qsize() or 1, 0.1)
        if remaining:
            self._handle_batch(remaining)

    def _drain_batch(self, max_items: int, max_wait: float) -> list[SecurityEvent]:
        deadline = time.monotonic() + max_wait
        batch: list[SecurityEvent] = []
        while len(batch) < max_items:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                item = self._queue.get(timeout=remaining if remaining > 0 else 0.05)
            except queue.Empty:
                break
            batch.append(item)
            if remaining == 0 and not batch:
                break
        return batch

    def _handle_batch(self, batch: list[SecurityEvent]) -> None:
        payload = [json.loads(e.to_json()) for e in batch]

        # Filter out fleet-originated block events — these are blocks applied
        # locally because another node reported the IP via the fleet blocklist.
        # They should not be reported back to the server as new intel events
        # since they are not independent observations.
        #
        # Also filter out LOG_MATCH observation events — every parsed log line
        # generates one of these for local activity tracking, but shipping them
        # would flood the server with noise.  Only meaningful events (detections,
        # blocks, escalations) should reach the server.
        # Also filter out DETECTED events — these are internal detection
        # signals that don't represent an action taken. Only events with
        # action_taken == BLOCKED, UNBLOCKED, OBSERVED etc. should reach
        # the server.
        intel_payload = [
            e
            for e in payload
            if e.get("event_type") != "LOG_MATCH"
            and e.get("action_taken") != "DETECTED"
            and not (e.get("metadata", {}).get("reason", "").startswith("fleet:"))
        ]

        # Collect fleet-originated events and tag them with event_kind="fleet_block"
        # so the server can store them for operational visibility without
        # incrementing intel counters.
        fleet_payload = []
        for e in payload:
            if e.get("metadata", {}).get("reason", "").startswith("fleet:"):
                fleet_event = dict(e)
                fleet_event["event_kind"] = "fleet_block"
                fleet_payload.append(fleet_event)

        if self.config.upload_enabled:
            # Ship only non-fleet events to the intel server
            if intel_payload:
                ok, is_connection_or_5xx = self._ship(intel_payload)
            else:
                ok = True
                is_connection_or_5xx = False
            if ok:
                with self._lock:
                    self._stats["shipped"] += len(intel_payload)
            else:
                with self._lock:
                    self._stats["failed"] += len(intel_payload)

                # If the failure was a connection error or 5xx, enqueue
                # qualifying block reports to the fleet offline queue.
                if is_connection_or_5xx:
                    self._enqueue_failed_block_reports(intel_payload)

            # Ship fleet_block events separately for operational visibility.
            # These are sent independently of the intel payload outcome.
            if fleet_payload:
                fleet_ok, _ = self._ship(fleet_payload)
                if fleet_ok:
                    with self._lock:
                        self._stats["shipped"] += len(fleet_payload)
                else:
                    log.warning("Failed to ship %d fleet_block event(s)", len(fleet_payload))

            if ok:
                return

        # Either upload disabled or it failed -> spool to disk for later.
        # Only spool non-fleet events (fleet blocks are not independent observations)
        if intel_payload:
            self._spool(intel_payload)
        with self._lock:
            self._stats["spooled"] += len(intel_payload)

    def _enforce_spool_bounds(self, lines: list[str]) -> list[str]:
        """Drop oldest spool lines until event count and byte size limits are met."""
        max_events = self.config.spool_max_events
        max_bytes = self.config.spool_max_size_bytes
        non_blank = [line for line in lines if line.strip()]

        dropped = 0
        while len(non_blank) > max_events:
            non_blank.pop(0)
            dropped += 1

        total = sum(len(line.encode("utf-8")) for line in non_blank)
        while non_blank and total > max_bytes:
            removed = non_blank.pop(0)
            total -= len(removed.encode("utf-8"))
            dropped += 1

        if dropped:
            log.warning("Spool bounds exceeded — dropped %d oldest event(s)", dropped)
            with self._lock:
                self._stats["dropped"] = self._stats.get("dropped", 0) + dropped

        return non_blank

    def _spool_one(self, event: SecurityEvent) -> None:
        try:
            with self._lock:
                spool = Path(self.config.spool_path)
                existing = spool.read_text(encoding="utf-8") if spool.exists() else ""
                lines = (existing + event.to_json() + "\n").splitlines(keepends=True)
                trimmed = self._enforce_spool_bounds(lines)
                _atomic_write_text(spool, "".join(trimmed))
        except OSError as exc:
            log.error("Failed to spool event: %s", exc)

    def _spool(self, payload: list[dict[str, Any]]) -> None:
        try:
            with self._lock:
                spool = Path(self.config.spool_path)
                existing = spool.read_text(encoding="utf-8") if spool.exists() else ""
                new_lines = "".join(
                    json.dumps(item, separators=(",", ":")) + "\n" for item in payload
                )
                lines = (existing + new_lines).splitlines(keepends=True)
                trimmed = self._enforce_spool_bounds(lines)
                _atomic_write_text(spool, "".join(trimmed))
        except OSError as exc:
            log.error("Failed to spool events: %s", exc)

    def _drain_spool(self) -> None:
        """Re-send spooled events to the server now that it's reachable.

        Reads the spool file in batches, ships each batch, and removes
        successfully sent lines. Stops on the first failed batch so we
        don't lose events. If all events are sent, the spool file is
        removed.

        Uses streaming to avoid loading entire file into memory.
        """
        spool = Path(self.config.spool_path)
        if not spool.exists():
            return

        try:
            # Stream the file line by line to avoid loading entire file into memory
            with open(spool, encoding="utf-8") as fh:
                lines = []
                batch_size = self.config.flush_batch_size
                sent_count = 0

                for line in fh:
                    line = line.rstrip("\n")
                    if not line:
                        sent_count += 1  # skip blank lines
                        continue
                    try:
                        lines.append(json.loads(line))
                    except json.JSONDecodeError:
                        log.warning("Skipping malformed spool line: %.80s", line)
                        sent_count += 1  # discard corrupt lines
                        continue

                    if len(lines) >= batch_size:
                        ok, _ = self._ship(lines)
                        if ok:
                            sent_count += len(lines)
                            with self._lock:
                                self._stats["shipped"] += len(lines)
                            log.debug("Spool drain: shipped batch of %d events", len(lines))
                            lines = []
                        else:
                            log.warning(
                                "Spool drain stopped: failed to ship batch at offset %d. %d event(s) remain.",
                                sent_count,
                                sent_count + len(lines),
                            )
                            # Rewrite spool with remaining lines
                            remaining_lines = [json.dumps(line) for line in lines]
                            self._rewrite_spool(fh, remaining_lines)
                            return
                # Process remaining lines
                if lines:
                    ok, _ = self._ship(lines)
                    if ok:
                        sent_count += len(lines)
                        with self._lock:
                            self._stats["shipped"] += len(lines)
                        log.debug("Spool drain: shipped final batch of %d events", len(lines))
                    else:
                        log.warning(
                            "Spool drain stopped: failed to ship final batch. %d event(s) remain.",
                            len(lines),
                        )
                        remaining_lines = [json.dumps(line) for line in lines]
                        self._rewrite_spool(fh, remaining_lines)
                        return

                # All events sent successfully - remove spool file
                try:
                    spool.unlink()
                    log.info("Spool fully drained and removed")
                except OSError:
                    pass

        except OSError as exc:
            log.error("Failed to read spool file for drain: %s", exc)
            return

    def _rewrite_spool(self, fh, remaining_lines: list[str]) -> None:
        """Rewrite the spool file with remaining lines atomically."""
        spool = Path(self.config.spool_path)
        try:
            # Read remaining lines from current position
            remaining_from_file = fh.readlines()
            all_remaining = remaining_lines + [line.rstrip("\n") for line in remaining_from_file]
            trimmed = self._enforce_spool_bounds(all_remaining)
            if trimmed:
                _atomic_write_text(spool, "\n".join(trimmed) + "\n")
                log.info("Spool partially drained: %d event(s) remain", len(trimmed))
            else:
                spool.unlink()
                log.info("Spool fully drained and removed")
        except OSError as exc:
            log.error("Failed to rewrite spool after partial drain: %s", exc)
            # Empty file, clean up
            try:
                spool.unlink()
            except OSError:
                pass

    def _ship(self, payload: list[dict[str, Any]]) -> tuple[bool, bool]:
        """POST the batch to the future central server.

        Returns a tuple (success: bool, is_connection_or_5xx: bool).
        The second element is True when the failure was due to a connection
        error or a 5xx server response — these are the cases where block
        reports should be enqueued for offline retry.
        """
        try:
            request(
                self.config.API_KEY,
                self.config.node_id,
                "POST",
                self.config.SERVER_URL,
                json_data={"events": payload},
                verify=self.config.ssl_verify,
                cert=self.config.ssl_cert,
                key=self.config.ssl_key,
            )
            return (True, False)
        except HttpError as exc:
            if exc.status == 401 and self._on_auth_failure:
                log.warning("Telemetry upload received 401, triggering auth failure handler")
                self._on_auth_failure()
                return (False, False)
            if exc.is_server_error:
                log.warning("Telemetry upload failed: %s", exc)
                return (False, True)
            log.warning("Telemetry upload failed: %s", exc)
            return (False, False)

    def _enqueue_failed_block_reports(self, payload: list[dict[str, Any]]) -> None:
        """Enqueue block reports from a failed batch to the fleet offline queue.

        Only events with action_taken == "BLOCKED" and detection_rule_name
        in metadata are considered fleet block reports worth queuing.
        """
        if not self.config.fleet_blocklist_report_enabled:
            return

        for event in payload:
            action = event.get("action_taken", "")
            metadata = event.get("metadata", {})
            if action == "BLOCKED" and "detection_rule_name" in metadata:
                self._fleet_queue.enqueue(event)
                log.debug(
                    "Enqueued failed block report for %s to fleet queue",
                    event.get("source_ip", "unknown"),
                )

    # --- heartbeat -----------------------------------------------------
    def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to the server to keep the node healthy.

        Runs every ``heartbeat_interval_seconds`` (default 300 = 5 minutes).
        The heartbeat updates the node's last_event_at on the server without
        creating any events, so the node stays 'healthy' even during quiet
        periods with no security events.

        The first heartbeat is delayed by a few seconds to allow the
        control socket to finish binding. Without this delay, the block
        list and allowlist queries fail because the socket doesn't exist
        yet, and the server receives empty lists until the next cycle.
        """
        interval = getattr(self.config, "heartbeat_interval_seconds", 300)
        # Wait briefly for the control socket to be ready before the
        # first heartbeat so that list_local / allowlist_list succeed.
        if not self._stop.wait(timeout=5):
            self._send_heartbeat()
        while not self._stop.wait(timeout=interval):
            self._send_heartbeat()

    def _get_api_base(self) -> str:
        """Derive the /api/v1 base URL from SERVER_URL.

        SERVER_URL is typically ``https://host:port/api/v1/events``.
        This strips the trailing path segment to get the base.
        """
        server_url = self.config.SERVER_URL
        if server_url.endswith("/events"):
            return server_url.rsplit("/events", 1)[0]
        base = server_url.rstrip("/")
        if "/api/v1" in base:
            return base.rsplit("/api/v1", 1)[0] + "/api/v1"
        return base + "/api/v1"

    def _send_heartbeat(self) -> None:
        """POST a heartbeat to the server's /api/v1/heartbeat endpoint.

        After a successful heartbeat, polls for pending commands and
        executes them via the local control socket.

        Retries up to 3 times with 15 seconds between attempts on
        connection errors or 5xx responses.
        """
        max_retries = 3
        retry_delay = 15  # seconds

        for attempt in range(1, max_retries + 1):
            success = self._attempt_heartbeat(attempt, max_retries)
            if success:
                return
            # Don't sleep after the last failed attempt
            if attempt < max_retries:
                log.info(
                    "Retrying heartbeat in %ds (attempt %d/%d)...",
                    retry_delay,
                    attempt + 1,
                    max_retries,
                )
                if self._stop.wait(timeout=retry_delay):
                    return  # Shutting down, bail out

        log.error("Heartbeat failed after %d attempts, giving up until next cycle", max_retries)

    def trigger_heartbeat(self) -> None:
        """Trigger an immediate heartbeat on a daemon thread.

        Non-blocking — used after config updates to push fresh state
        to the server without waiting for the next heartbeat cycle.
        """
        threading.Thread(target=self._send_heartbeat, daemon=True).start()

    def _attempt_heartbeat(self, attempt: int, max_retries: int) -> bool:
        """Single heartbeat attempt. Returns True on success, False on retryable failure.

        Raises nothing — all exceptions are handled internally.
        Non-retryable failures (e.g. 401) also return True to stop retrying.
        """
        api_base = self._get_api_base()
        heartbeat_url = api_base + "/heartbeat"

        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        payload: dict[str, Any] = {
            "node_id": self.config.node_id,
            "display_name": self.config.display_name,
            "asset_id": self._load_asset_id(),
            "timestamp": ts,
            "agent_version": __version__,
        }

        payload["allowlist"] = self._get_allowlist()
        payload["feeds"] = self._get_feed_list()
        payload["counters"] = self._get_counters()
        payload["host_info"] = collect_host_info()
        payload["host_info"]["fleet_enabled"] = (
            self.config.fleet_blocklist_report_enabled
            or self.config.fleet_blocklist_subscribe_enabled
        )
        payload["host_info"]["active_parsers"] = list(
            set(ls.parser for ls in self.config.log_sources)
            | (
                {"auditd"}
                if getattr(self.config, "auditd", None) and self.config.auditd.enabled
                else set()
            )
        )

        # Include auditd mode state if available (from persisted state file)
        auditd_cfg = getattr(self.config, "auditd", None)
        if auditd_cfg and auditd_cfg.enabled:
            auditd_state: dict[str, Any] = {"mode": "unknown"}
            state_path = STATE_DIR / "auditd_mode_state.json"
            try:
                if state_path.exists():
                    raw = state_path.read_text(encoding="utf-8")
                    state_data = json.loads(raw)
                    auditd_state["mode"] = state_data.get("mode", auditd_cfg.mode)
                    if state_data.get("learning_started_at"):
                        auditd_state["learning_started_at"] = state_data["learning_started_at"]
                    auditd_state["learning_duration_hours"] = auditd_cfg.learning_duration_hours
                else:
                    # No state file yet — use configured mode
                    auditd_state["mode"] = auditd_cfg.mode
                    auditd_state["learning_duration_hours"] = auditd_cfg.learning_duration_hours
            except (OSError, json.JSONDecodeError, TypeError):
                auditd_state["mode"] = auditd_cfg.mode
            payload["host_info"]["auditd"] = auditd_state

        log.debug(
            "Sending heartbeat to %s (attempt %d/%d, node_id=%s, ts=%s)",
            heartbeat_url,
            attempt,
            max_retries,
            self.config.node_id,
            ts,
        )

        try:
            resp = request(
                self.config.API_KEY,
                self.config.node_id,
                "POST",
                heartbeat_url,
                json_data=payload,
                verify=self.config.ssl_verify,
                cert=self.config.ssl_cert,
                key=self.config.ssl_key,
            )
            resp_body = resp.body.decode("utf-8", errors="replace").strip()
            feed_count = len(payload.get("feeds", []))
            parser_count = len(payload.get("host_info", {}).get("active_parsers", []))
            log.info(
                "Heartbeat OK (%d): %d feeds, %d parsers",
                resp.status,
                feed_count,
                parser_count,
            )

            # Parse response for fleet stats
            try:
                resp_data = json.loads(resp_body) if resp_body else {}
                if "fleet_active_blocks" in resp_data:
                    self.fleet_active_blocks = int(resp_data["fleet_active_blocks"])
                    log.debug("Fleet active blocks from server: %d", self.fleet_active_blocks)
            except (json.JSONDecodeError, ValueError, TypeError):
                pass

            # Heartbeat succeeded — poll for pending commands
            had_commands = self._poll_commands()
            # If commands were executed, send a follow-up heartbeat
            # so the server gets the updated state immediately
            # (e.g. newly added feeds, changed block list).
            if had_commands:
                self._send_state_update()
            # Drain any spooled events now that the server is reachable
            self._drain_spool()
            # Push block list if it changed since last push
            self._push_blocks()
            return True

        except HttpError as exc:
            body_text = exc.body.decode("utf-8", errors="replace")
            if exc.status == 401 and self._on_auth_failure:
                log.warning("Heartbeat received 401, triggering auth failure handler")
                self._on_auth_failure()
                return True
            if exc.is_server_error:
                log.warning(
                    "Heartbeat failed to %s (attempt %d/%d): %s",
                    heartbeat_url,
                    attempt,
                    max_retries,
                    exc,
                )
                return False
            log.warning(
                "Heartbeat HTTP error to %s (attempt %d/%d): %s",
                heartbeat_url,
                attempt,
                max_retries,
                body_text or exc,
            )
            return True

    # --- command polling -----------------------------------------------
    def _poll_commands(self) -> bool:
        """GET pending commands from the server and execute them locally.

        Called after each successful heartbeat. Commands are dispatched
        to the local control socket (same handlers the CLI uses), and
        results are reported back to the server.

        Returns True if any commands were executed, False otherwise.
        """
        api_base = self._get_api_base()
        node_id = self.config.node_id
        commands_url = f"{api_base}/nodes/{node_id}/commands"

        try:
            resp = request(
                self.config.API_KEY,
                node_id,
                "GET",
                commands_url,
                verify=self.config.ssl_verify,
                cert=self.config.ssl_cert,
                key=self.config.ssl_key,
            )
            data = resp.json()
        except HttpError as exc:
            log.warning("Command poll HTTP error %s: %s", exc.status or "connection", exc)
            return False
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Command poll failed: %s", exc)
            return False

        commands = data.get("commands", [])
        if not commands:
            log.debug("No pending commands")
            return False

        log.info("Received %d command(s) from server", len(commands))

        for cmd in commands:
            command_id = cmd.get("command_id", "")
            command_type = cmd.get("command_type", "")
            payload = cmd.get("payload", {})

            log.info("Executing command %s: %s %s", command_id, command_type, payload)

            result_status, result_msg = self._execute_command(command_type, payload)

            # Report result back to the server
            self._report_command_result(command_id, result_status, result_msg)

        return True

    def _execute_command(self, command_type: str, payload: dict[str, Any]) -> tuple:
        """Execute a command via the local control socket.

        Uses the direct callback if set (in-process), falling back to
        the control socket for legacy compatibility.
        """
        if self._exec_cmd:
            try:
                result = self._exec_cmd(command_type, payload)
                if result and result.get("ok"):
                    log.info("Command %s executed via callback", command_type)
                    return ("completed", json.dumps(result))
                error = (result or {}).get("error", "unknown error")
                log.warning("Command %s failed via callback: %s", command_type, error)
                return ("failed", error)
            except Exception as exc:
                log.error("Command %s callback error: %s", command_type, exc)
                return ("failed", str(exc))

        from .control_socket import send_command

        try:
            if command_type == "allowlist_add":
                entry = payload.get("entry", "")
                if not entry:
                    return ("failed", "missing entry in payload")
                result = send_command("allowlist_add", entry=entry)

            elif command_type == "allowlist_remove":
                entry = payload.get("entry", "")
                if not entry:
                    return ("failed", "missing entry in payload")
                result = send_command("allowlist_remove", entry=entry)

            elif command_type == "block":
                ip = payload.get("ip", "")
                reason = payload.get("reason", "server_command")
                if not ip:
                    return ("failed", "missing ip in payload")
                result = send_command("block", ip=ip, reason=reason)

            elif command_type == "unblock":
                ip = payload.get("ip", "")
                reason = payload.get("reason", "server_command")
                if not ip:
                    return ("failed", "missing ip in payload")
                result = send_command("unblock", ip=ip, reason=reason)

            elif command_type == "feed_enable":
                name = payload.get("name", "")
                if not name:
                    return ("failed", "missing feed name in payload")
                result = send_command("feed_enable", name=name)

            elif command_type == "feed_disable":
                name = payload.get("name", "")
                if not name:
                    return ("failed", "missing feed name in payload")
                result = send_command("feed_disable", name=name)

            elif command_type == "feed_add":
                name = payload.get("name", "")
                url = payload.get("url", "")
                if not name or not url:
                    return ("failed", "missing name or url in payload")
                result = send_command(
                    "feed_add",
                    name=name,
                    url=url,
                    format=payload.get("format", "plain"),
                    refresh_seconds=payload.get("refresh_seconds", 3600),
                )

            elif command_type == "feed_remove":
                name = payload.get("name", "")
                if not name:
                    return ("failed", "missing feed name in payload")
                result = send_command("feed_remove", name=name)

            else:
                log.warning("Unknown command type: %s", command_type)
                return ("failed", f"unknown command type: {command_type}")

            if result.get("ok"):
                log.info("Command %s executed successfully: %s", command_type, result)
                return ("completed", json.dumps(result))
            else:
                error = result.get("error", "unknown error")
                log.warning("Command %s failed: %s", command_type, error)
                return ("failed", error)

        except Exception as exc:
            log.error("Failed to execute command %s: %s", command_type, exc)
            return ("failed", str(exc))

    def _report_command_result(self, command_id: str, status: str, result_msg: str) -> None:
        """POST command execution result back to the server."""
        if not command_id:
            return

        api_base = self._get_api_base()
        node_id = self.config.node_id
        result_url = f"{api_base}/nodes/{node_id}/commands/{command_id}/result"

        try:
            request(
                self.config.API_KEY,
                node_id,
                "POST",
                result_url,
                json_data={"status": status, "result": result_msg},
                verify=self.config.ssl_verify,
                cert=self.config.ssl_cert,
                key=self.config.ssl_key,
            )
            log.debug("Reported result for command %s: %s", command_id, status)
        except HttpError:
            pass  # Best-effort

    # --- block list push ------------------------------------------------
    def _push_blocks(self) -> bool:
        """Push current block list to server if it changed since last push.

        POSTs to /api/v1/nodes/blocks/publish only when the block list
        content actually changed (SHA-256 hash comparison).
        """
        blocks = self._get_local_block_list()
        bl_hash = hashlib.sha256(json.dumps(blocks, sort_keys=True).encode()).hexdigest()
        if bl_hash == self._last_block_hash:
            return True
        api_base = self._get_api_base()
        url = api_base + "/nodes/blocks/publish"
        payload = {"node_id": self.config.node_id, "blocks": blocks}
        try:
            request(
                self.config.API_KEY,
                self.config.node_id,
                "POST",
                url,
                json_data=payload,
                verify=self.config.ssl_verify,
                cert=self.config.ssl_cert,
                key=self.config.ssl_key,
            )
            self._last_block_hash = bl_hash
            log.debug("Pushed %d block(s) to server", len(blocks))
            return True
        except HttpError as exc:
            log.warning("Failed to push blocks: %s", exc)
            return False

    # --- state update after commands -------------------------------------
    def _send_state_update(self) -> None:
        """Send a follow-up heartbeat with updated state after command execution.

        This ensures the server immediately sees changes (new feeds, updated
        block list, etc.) without waiting for the next heartbeat cycle.
        """
        api_base = self._get_api_base()
        heartbeat_url = api_base + "/heartbeat"

        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        host_info = collect_host_info()
        host_info["fleet_enabled"] = (
            self.config.fleet_blocklist_report_enabled
            or self.config.fleet_blocklist_subscribe_enabled
        )
        host_info["active_parsers"] = list(
            set(ls.parser for ls in self.config.log_sources)
            | (
                {"auditd"}
                if getattr(self.config, "auditd", None) and self.config.auditd.enabled
                else set()
            )
        )

        # Include auditd mode state if available
        auditd_cfg = getattr(self.config, "auditd", None)
        if auditd_cfg and auditd_cfg.enabled:
            auditd_state: dict[str, Any] = {"mode": "unknown"}
            state_path = STATE_DIR / "auditd_mode_state.json"
            try:
                if state_path.exists():
                    raw = state_path.read_text(encoding="utf-8")
                    state_data = json.loads(raw)
                    auditd_state["mode"] = state_data.get("mode", auditd_cfg.mode)
                    if state_data.get("learning_started_at"):
                        auditd_state["learning_started_at"] = state_data["learning_started_at"]
                    auditd_state["learning_duration_hours"] = auditd_cfg.learning_duration_hours
                else:
                    auditd_state["mode"] = auditd_cfg.mode
                    auditd_state["learning_duration_hours"] = auditd_cfg.learning_duration_hours
            except (OSError, json.JSONDecodeError, TypeError):
                auditd_state["mode"] = auditd_cfg.mode
            host_info["auditd"] = auditd_state

        payload = {
            "node_id": self.config.node_id,
            "timestamp": ts,
            "agent_version": __version__,
            "allowlist": self._get_allowlist(),
            "feeds": self._get_feed_list(),
            "counters": self._get_counters(),
            "host_info": host_info,
        }

        try:
            request(
                self.config.API_KEY,
                self.config.node_id,
                "POST",
                heartbeat_url,
                json_data=payload,
                verify=self.config.ssl_verify,
                cert=self.config.ssl_cert,
                key=self.config.ssl_key,
            )
            log.debug("State update sent after command execution")
            self._push_blocks()
        except HttpError:
            pass  # Best-effort

    # --- block list / allowlist gathering ------------------------------
    def _get_local_block_list(self) -> list[dict[str, Any]]:
        """Query the local daemon for its current block list.

        Uses the direct callback if set (in-process), falling back to
        the control socket for CLI or legacy compatibility.
        """
        if self._get_blocks:
            try:
                return self._get_blocks()
            except Exception as exc:
                log.debug("Could not fetch local block list via callback: %s", exc)
        try:
            from .control_socket import send_command

            result = send_command("list_local")
            if result.get("ok"):
                return result.get("entries", [])
        except Exception as exc:
            log.debug("Could not fetch local block list via socket: %s", exc)
        return []

    def _get_allowlist(self) -> list[dict[str, Any]]:
        """Query the local daemon for its current allowlist via control socket.

        Returns a list of allowlist entry dicts, or an empty list on failure.
        """
        try:
            from .control_socket import send_command

            result = send_command("allowlist_list")
            if result.get("ok"):
                return result.get("entries", [])
        except Exception as exc:
            log.debug("Could not fetch allowlist: %s", exc)
        return []

    def _get_feed_list(self) -> list[dict[str, Any]]:
        """Query the local daemon for its subscription feed status.

        Uses the direct callback if set (in-process), falling back to
        the control socket for CLI or legacy compatibility.
        """
        if self._get_feeds:
            try:
                return self._get_feeds()
            except Exception as exc:
                log.debug("Could not fetch feed list via callback: %s", exc)
        try:
            from .control_socket import send_command

            result = send_command("feed_list")
            if result.get("ok"):
                return result.get("feeds", [])
        except Exception as exc:
            log.debug("Could not fetch feed list: %s", exc)
        return []

    def _get_counters(self) -> list[dict[str, Any]]:
        """Query the local daemon for nftables packet/byte counters.

        Uses the direct callback if set (in-process), falling back to
        the control socket for CLI or legacy compatibility.
        """
        if self._get_counters_cb:
            try:
                return self._get_counters_cb()
            except Exception as exc:
                log.debug("Could not fetch counters via callback: %s", exc)
        try:
            from .control_socket import send_command

            result = send_command("counters")
            if result.get("ok"):
                return result.get("counters", [])
        except Exception as exc:
            log.debug("Could not fetch counters: %s", exc)
        return []


# A module-level singleton so producers can simply import and use it.
BUS = DataBus()
