"""Subscription Manager.

Periodically downloads IP blocklists, deduplicates them against:

1. Anything already present in ``shield_local`` (avoid double-blocking).
2. The configured local allowlist (handled inside :class:`NFTablesManager`).

The merged, deduplicated set is then synchronized into ``shield_subscribed``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections.abc import Iterable

import httpx

from . import __version__
from .config import CONFIG, ShieldConfig, SubscriptionFeed
from .databus import BUS, DataBus
from .http_client import build_ssl_context
from .nftables_manager import NFTablesManager

log = logging.getLogger("vespid.subs")


class SubscriptionManager:
    def __init__(
        self,
        nft: NFTablesManager,
        config: ShieldConfig | None = None,
        bus: DataBus | None = None,
    ) -> None:
        self.config = config or CONFIG
        self.bus = bus or BUS
        self.nft = nft
        self._stop = asyncio.Event()
        self._last_sync: dict = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def run(self) -> None:
        self._stop.clear()
        self._loop = asyncio.get_running_loop()
        self._tasks: list[asyncio.Task] = []
        # Run an immediate sync, then schedule per-feed loops.
        await self.sync_now()
        # Snapshot the feed list to avoid races with config_subscriber
        # mutating config.subscriptions from another thread.
        feeds_snapshot = list(self.config.subscriptions)
        for feed in feeds_snapshot:
            self._tasks.append(asyncio.create_task(self._feed_loop(feed), name=f"feed-{feed.name}"))
        if not self._tasks:
            return
        await asyncio.gather(*self._tasks, return_exceptions=True)

    def start_feed_loop(self, feed: SubscriptionFeed) -> None:
        """Spawn a new _feed_loop task for a dynamically added feed.

        Called by the daemon's feed_add handler so that newly deployed
        feeds get their own periodic refresh loop, not just a one-shot sync.

        Uses ``run_coroutine_threadsafe`` because the caller may be in a
        different thread/event-loop than the main one.
        """
        loop = self._loop
        if loop is None or loop.is_closed():
            log.warning("Main event loop not available — cannot start feed loop for %s", feed.name)
            return
        asyncio.run_coroutine_threadsafe(self._feed_loop(feed), loop)
        log.info("Started feed loop for %s (refresh every %ds)", feed.name, feed.refresh_seconds)

    def stop(self) -> None:
        self._stop.set()

    async def sync_now(self) -> int:
        """Sync all enabled feeds, each into its own nftables set."""
        total = 0
        for feed in self.config.subscriptions:
            total += await self._sync_feed(feed)
        return total

    def status(self) -> dict:
        return {"feeds": dict(self._last_sync)}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    async def _sync_feed(self, feed: SubscriptionFeed) -> int:
        """Sync a single feed into its own nftables set. Returns entry count."""
        if not feed.enabled:
            log.info("FEED %s SKIPPED (disabled)", feed.name)
            self._last_sync[feed.name] = {
                "ts": time.time(),
                "count": 0,
                "enabled": False,
            }
            return 0

        entries = await self._fetch_feed(feed)

        if not entries:
            log.warning(
                "FEED %s fetch returned no entries — skipping sync to preserve existing set",
                feed.name,
            )
            return 0

        log.info("FEED %s url=%s entries=%d", feed.name, feed.url, len(entries))

        # Run sync_feed in a thread — it calls nft subprocess commands
        # that can block for seconds with large entry sets, and must not
        # block the event loop.
        count = await asyncio.to_thread(self.nft.sync_feed, feed.name, entries)

        self._last_sync[feed.name] = {
            "ts": time.time(),
            "count": count,
            "enabled": True,
        }
        return count

    async def _feed_loop(self, feed: SubscriptionFeed) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=feed.refresh_seconds)
                return  # stop signaled
            except asyncio.TimeoutError:
                pass
            if not feed.enabled:
                continue
            try:
                await self._sync_feed(feed)
            except Exception as exc:  # pragma: no cover
                log.exception("Feed %s sync failed: %s", feed.name, exc)

    async def _fetch_feed(self, feed: SubscriptionFeed) -> list[str]:
        ctx = build_ssl_context(self.config.ssl_verify, self.config.ssl_cert, self.config.ssl_key)
        try:
            async with httpx.AsyncClient(
                verify=ctx,
                timeout=httpx.Timeout(30.0),
                follow_redirects=True,
            ) as client:
                resp = await client.get(feed.url, headers={"User-Agent": f"Vespid/{__version__}"})
                resp.raise_for_status()
                text = resp.text
        except Exception as exc:
            log.warning("Failed to fetch %s: %s", feed.url, exc)
            self.bus.publish(
                source_ip="0.0.0.0",
                event_type="SUBSCRIPTION_FETCH",
                action_taken="FAILED",
                metadata={"feed": feed.name, "error": str(exc)},
            )
            return []

        return list(self._parse_feed(text, feed.format))

    @staticmethod
    def _parse_feed(text: str, fmt: str) -> Iterable[str]:
        for line in text.splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#") or entry.startswith(";"):
                continue
            # Some feeds have inline comments after a space.
            entry = entry.split()[0]
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            yield entry

    def _merge(self, raw_entries: Iterable[str]) -> list[str]:
        # First pass: dedup as networks.
        unique: set[str] = set()
        for entry in raw_entries:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            unique.add(str(net))

        # Drop any entry that overlaps the dynamic local set so the
        # subscription feed cannot stomp on (or duplicate) live decisions.
        local_nets = []
        for ip in list(self.nft.status()["local_sample"]):
            try:
                local_nets.append(ipaddress.ip_network(ip, strict=False))
            except ValueError:
                continue

        result = []
        for s in unique:
            net = ipaddress.ip_network(s, strict=False)
            if any(net.overlaps(local_net) for local_net in local_nets):
                continue
            result.append(s)
        return result
