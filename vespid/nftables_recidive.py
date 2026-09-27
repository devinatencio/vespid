"""Repeat-offender (recidive) tracking mixin for NFTablesManager.

Tracks strike counts per IP with configurable escalation tiers and decay.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

log = logging.getLogger("vespid.nft")


class RecidiveMixin:
    """Mixin providing repeat-offender tracking for NFTablesManager."""

    def _load_recidive(self) -> None:
        try:
            with open(self._recidive_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Failed to load recidive state from %s: %s", self._recidive_path, exc)
            return

        if not isinstance(data, dict):
            log.warning("Invalid recidive state format in %s", self._recidive_path)
            return

        now = time.time()
        decay = self.config.recidive_decay_seconds
        for ip, meta in data.items():
            last_seen = meta.get("last_seen", 0)
            if (now - last_seen) < decay:
                self._recidive[ip] = meta

        if self._recidive:
            log.info("Loaded %d recidive records from disk", len(self._recidive))

    def _save_recidive(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._recidive_path), exist_ok=True)
            tmp = self._recidive_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._recidive, fh, indent=2)
            os.replace(tmp, self._recidive_path)
        except OSError as exc:
            log.warning("Failed to persist recidive state to %s: %s", self._recidive_path, exc)

    def prune_recidive(self) -> int:
        now = time.time()
        decay = self.config.recidive_decay_seconds
        stale = [
            ip for ip, meta in self._recidive.items() if (now - meta.get("last_seen", 0)) >= decay
        ]
        for ip in stale:
            del self._recidive[ip]
        if stale:
            self._save_recidive()
            log.debug("Pruned %d decayed recidive entries", len(stale))
        return len(stale)

    def _record_offense(self, ip: str) -> int:
        now = time.time()
        decay = self.config.recidive_decay_seconds
        rec = self._recidive.get(ip)

        if rec is None or (now - rec.get("last_seen", 0)) >= decay:
            self._recidive[ip] = {
                "count": 1,
                "first_seen": now,
                "last_seen": now,
            }
            self._save_recidive()
            return 1

        rec["count"] = rec.get("count", 0) + 1
        rec["last_seen"] = now
        self._save_recidive()
        return rec["count"]

    def _ttl_for_offense(self, strike_count: int) -> int:
        tiers = self.config.recidive_tiers
        if not tiers:
            return self.config.nft_local_block_ttl
        idx = min(strike_count - 1, len(tiers) - 1)
        return tiers[idx]

    def recidive_info(self, ip: str) -> dict[str, Any]:
        with self._lock:
            rec = self._recidive.get(ip)
            if rec is None:
                return {"ip": ip, "offenses": 0}
            now = time.time()
            decay = self.config.recidive_decay_seconds
            if (now - rec.get("last_seen", 0)) >= decay:
                return {"ip": ip, "offenses": 0, "decayed": True}
            return {
                "ip": ip,
                "offenses": rec.get("count", 0),
                "first_seen": rec.get("first_seen"),
                "last_seen": rec.get("last_seen"),
                "next_ttl": self._ttl_for_offense(rec.get("count", 0) + 1),
            }
