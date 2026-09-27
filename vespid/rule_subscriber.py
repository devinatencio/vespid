"""Rule Subscriber — polls the server for detection rule updates.

Periodically fetches the current rule set from the server's distribution
endpoint, caches it locally for offline resilience, merges with local
config rules according to the configured strategy, and triggers a
hot-reload of the LogProcessor's detector.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from collections.abc import Callable
from pathlib import Path

import httpx

from . import __version__
from .config import BruteForceRule, CorrelationRule, CustomRule, ShieldConfig
from .http_client import build_ssl_context

log = logging.getLogger("vespid.rule_sub")

_STATE_DIR = Path(os.environ.get("VESPID_STATE_DIR", "/var/lib/vespid"))
_CACHE_FILENAME = "rules_cache.json"

# Backoff parameters for server unreachable
_BACKOFF_INITIAL = 30
_BACKOFF_FACTOR = 2
_BACKOFF_MAX = 300


class RuleSubscriber:
    """Polls the server for rule updates and triggers hot-reload.

    Args:
        config: The ShieldConfig instance.
        on_rules_updated: Callback invoked with (brute_force_rules, custom_rules, correlation_rules)
            when a new rule set is received and merged.
        credentials_ready: Optional asyncio.Event that, when set, indicates the
            API key has been validated and the agent is in operational state.
        on_auth_failure: Optional callback invoked when a 401 is received.
    """

    def __init__(
        self,
        config: ShieldConfig,
        on_rules_updated: Callable[
            [list[BruteForceRule], list[CustomRule], list[CorrelationRule]], None
        ],
        credentials_ready: threading.Event | None = None,
        on_auth_failure: Callable[[], bool] | None = None,
    ) -> None:
        self.config = config
        self._on_rules_updated = on_rules_updated
        self._credentials_ready = credentials_ready
        self._on_auth_failure = on_auth_failure
        self._revision: int | None = None
        self._last_custom_count: int | None = None
        self._cache_path = _STATE_DIR / _CACHE_FILENAME
        self._stop = asyncio.Event()
        self._backoff = _BACKOFF_INITIAL

    async def run(self) -> None:
        """Main polling loop."""
        self._stop.clear()
        log.info(
            "Rule subscriber starting (interval=%ds, strategy=%s)",
            self.config.rule_poll_interval_seconds,
            self.config.rule_merge_strategy,
        )

        # Wait for valid credentials before attempting authenticated polls
        if self._credentials_ready and not self._credentials_ready.is_set():
            log.info("Rule subscriber waiting for credentials...")
            cred_task = asyncio.create_task(asyncio.to_thread(self._credentials_ready.wait))
            stop_task = asyncio.create_task(self._wait_event(self._stop))
            done, pending = await asyncio.wait(
                [cred_task, stop_task], return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()
            if self._stop.is_set():
                return
            log.info("Rule subscriber credentials ready, starting polls")

        # Load from cache on startup
        cached = self._load_cache()
        if cached is not None:
            if "packs" not in cached:
                log.info("Cached rules missing 'packs' metadata — will force full re-fetch")
                self._revision = None
                self._apply_rules(cached)
            else:
                self._revision = cached.get("revision")
                self._last_custom_count = len(cached.get("custom_rules", []))
                self._apply_rules(cached)
                log.info("Loaded cached rules (revision=%s)", self._revision)

        interval = max(60, min(86400, self.config.rule_poll_interval_seconds))

        while not self._stop.is_set():
            try:
                updated = await self._poll()
                if updated:
                    self._backoff = _BACKOFF_INITIAL  # Reset backoff on success
            except asyncio.CancelledError:
                log.info("Rule subscriber cancelled")
                return
            except Exception as exc:
                log.warning("Rule poll error: %s", exc)
                # Use backoff delay instead of normal interval
                delay = min(self._backoff, _BACKOFF_MAX)
                self._backoff = min(self._backoff * _BACKOFF_FACTOR, _BACKOFF_MAX)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                    break
                except asyncio.TimeoutError:
                    pass
                continue

            # Wait for next poll cycle
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
                break  # stop was signaled
            except asyncio.TimeoutError:
                pass  # normal timeout, poll again

    def stop(self) -> None:
        """Signal the subscriber to stop."""
        self._stop.set()

    @staticmethod
    async def _wait_event(event: asyncio.Event) -> None:
        """Await an asyncio.Event (helper for wait/race patterns)."""
        await event.wait()

    def get_active_packs(self) -> list[str]:
        """Return the list of detection pack names currently active on this node.

        First checks the 'packs' metadata field from the distribution response.
        Falls back to deriving pack names from the custom_rules in the cache
        (for older cache formats that predate the packs field).
        """
        cached = self._load_cache()
        if cached is None:
            return []

        # Prefer the explicit packs field from the distribution response
        packs = cached.get("packs")
        if packs:
            return packs

        # Fall back: derive from custom_rules pack_name field
        custom_rules = cached.get("custom_rules", [])
        derived = sorted(set(r.get("pack_name", "") for r in custom_rules if r.get("pack_name")))
        return derived

    async def _poll(self) -> bool:
        """Poll the server for rule updates. Returns True if rules were updated."""
        url = self._build_url()
        headers = self._build_headers()

        response = await self._fetch_async(url, headers)

        if response is None:
            # Server unreachable — handled by caller
            return False

        status, body, etag = response

        if status == 304:
            log.debug("Rules unchanged (revision=%s)", self._revision)
            return False

        if status == 401 or status == 403:
            log.error("Rule distribution auth failed (HTTP %d)", status)
            if status == 401 and self._on_auth_failure:
                self._on_auth_failure()
            return False

        if status != 200:
            log.warning("Rule distribution unexpected status: %d", status)
            return False

        # Parse the rule set
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError) as exc:
            log.error("Rule distribution response is not valid JSON: %s", exc)
            return False

        if not isinstance(data, dict):
            log.error("Rule distribution response is not a JSON object")
            return False

        required_keys = ("revision", "brute_force_rules", "custom_rules")
        missing = [k for k in required_keys if k not in data]
        if missing:
            log.error("Rule distribution response missing keys: %s", missing)
            return False

        new_revision = data["revision"]
        new_custom_count = len(data.get("custom_rules", []))

        if self._revision is not None and new_revision == self._revision:
            # Same revision — but check if rule count changed (e.g. active_parsers
            # changed so server now returns a different filtered set for same revision)
            if self._last_custom_count is not None and self._last_custom_count == new_custom_count:
                return False
            log.info(
                "Rule count changed at same revision %d (%s → %d custom rules) — re-applying",
                new_revision,
                self._last_custom_count,
                new_custom_count,
            )

        self._revision = new_revision
        self._last_custom_count = new_custom_count
        self._save_cache(data)
        self._apply_rules(data)

        log.info(
            "Rules updated (revision=%d, brute_force=%d, custom=%d)",
            new_revision,
            len(data["brute_force_rules"]),
            len(data["custom_rules"]),
        )
        return True

    def _apply_rules(self, data: dict) -> None:
        """Merge server rules with local config and trigger hot-reload."""
        server_bf = self._parse_brute_force_rules(data.get("brute_force_rules", []))
        server_custom = self._parse_custom_rules(data.get("custom_rules", []))
        server_corr = self._parse_correlation_rules(data.get("correlation_rules", []))

        strategy = self.config.rule_merge_strategy
        if strategy not in ("layer", "replace"):
            log.warning(
                "Invalid rule_merge_strategy '%s', falling back to 'layer'",
                strategy,
            )
            strategy = "layer"

        if strategy == "replace":
            merged_bf = server_bf
            merged_custom = server_custom
            merged_corr = server_corr
        else:
            # "layer": server rules + local rules not shadowed by name
            merged_bf = self._merge_by_name(server_bf, self.config.brute_force_rules, "brute_force")
            merged_custom = self._merge_by_name(server_custom, self.config.custom_rules, "custom")
            merged_corr = self._merge_by_name(
                server_corr, self.config.correlation_rules, "correlation"
            )

        # Update correlation rules on the config so LogProcessor picks them up
        self.config.correlation_rules = merged_corr

        try:
            self._on_rules_updated(merged_bf, merged_custom, merged_corr)
        except Exception as exc:
            log.exception("on_rules_updated callback failed: %s", exc)

    def _merge_by_name(self, server_rules, local_rules, rule_type: str):
        """Merge server rules with local rules. Server wins on name conflict."""
        server_names = {r.name for r in server_rules}
        merged = list(server_rules)
        for local_rule in local_rules:
            if local_rule.name in server_names:
                log.warning(
                    "Rule name conflict (%s): '%s' — using server version",
                    rule_type,
                    local_rule.name,
                )
            else:
                merged.append(local_rule)
        return merged

    def _parse_brute_force_rules(self, rules_data: list) -> list[BruteForceRule]:
        """Parse JSON rule dicts into BruteForceRule dataclass instances."""
        result = []
        for r in rules_data:
            try:
                result.append(
                    BruteForceRule(
                        name=r["name"],
                        event_type=r["event_type"],
                        max_attempts=int(r["max_attempts"]),
                        window_seconds=int(r["window_seconds"]),
                        parser=r["parser"],
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                log.warning("Skipping invalid brute force rule: %s (%s)", r, exc)
        return result

    def _parse_custom_rules(self, rules_data: list) -> list[CustomRule]:
        """Parse JSON rule dicts into CustomRule dataclass instances."""
        result = []
        for r in rules_data:
            try:
                log_sources = r.get("log_sources", ["*"])
                if isinstance(log_sources, str):
                    log_sources = json.loads(log_sources)
                # Deserialize tags from API response
                tags = r.get("tags", [])
                if isinstance(tags, str):
                    tags = json.loads(tags)
                elif not isinstance(tags, list):
                    tags = []
                result.append(
                    CustomRule(
                        name=r["name"],
                        event_type=r["event_type"],
                        regex=r["regex"],
                        log_sources=log_sources,
                        max_attempts=int(r["max_attempts"]),
                        window_seconds=int(r["window_seconds"]),
                        enabled=r.get("enabled", True),
                        pack_name=r.get("pack_name", ""),
                        tags=tags,
                        sigma_id=r.get("sigma_id", ""),
                        sigma_status=r.get("sigma_status", ""),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                log.warning("Skipping invalid custom rule: %s (%s)", r, exc)
        return result

    def _parse_correlation_rules(self, rules_data: list) -> list[CorrelationRule]:
        """Parse JSON rule dicts into CorrelationRule dataclass instances."""
        result = []
        for r in rules_data:
            try:
                result.append(
                    CorrelationRule(
                        name=r["name"],
                        event_type=r["event_type"],
                        min_categories=int(r.get("min_categories", 3)),
                        window_seconds=int(r.get("window_seconds", 600)),
                        enabled=r.get("enabled", True),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                log.warning("Skipping invalid correlation rule: %s (%s)", r, exc)
        return result

    def _build_url(self) -> str:
        """Build the rule distribution endpoint URL."""
        base = self.config.SERVER_URL.rstrip("/")
        # SERVER_URL typically ends with /api/v1/events — strip to base
        if "/api/v1/" in base:
            base = base.split("/api/v1/")[0]
        return f"{base}/api/v1/rules/distribution"

    def _build_headers(self) -> dict:
        """Build request headers with auth and conditional fetch."""
        headers = {
            "Authorization": f"Bearer {self.config.API_KEY}",
            "Accept": "application/json",
            "User-Agent": f"Vespid/{__version__} RuleSubscriber",
        }
        if self._revision is not None:
            headers["If-None-Match"] = f'"{self._revision}"'
        return headers

    async def _fetch_async(self, url: str, headers: dict):
        """Fetch rules from server and return (status, body, etag)."""
        ctx = build_ssl_context(self.config.ssl_verify, self.config.ssl_cert, self.config.ssl_key)
        try:
            with httpx.Client(verify=ctx, timeout=30.0) as client:
                resp = client.get(url, headers=headers)
        except httpx.TimeoutException:
            raise ConnectionError("Server unreachable: timeout") from None
        except Exception as exc:
            raise ConnectionError(f"Server unreachable: {exc}") from exc
        body = resp.text
        etag = resp.headers.get("ETag", "")
        return (resp.status_code, body, etag)

    def _load_cache(self) -> dict | None:
        """Load cached rule set from disk."""
        try:
            if self._cache_path.exists():
                raw = self._cache_path.read_text(encoding="utf-8")
                data = json.loads(raw)
                if isinstance(data, dict) and "revision" in data:
                    return data
                log.warning("Cached rules file is malformed, ignoring")
                self._cache_path.unlink(missing_ok=True)
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Could not load cached rules: %s", exc)
            try:
                self._cache_path.unlink(missing_ok=True)
            except OSError:
                pass
        return None

    def _save_cache(self, data: dict) -> None:
        """Persist rule set to local cache file."""
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(self._cache_path)
        except OSError as exc:
            log.warning("Could not save rules cache: %s", exc)
