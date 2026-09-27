"""Lightweight 24h activity tracker — bounded ring buffer of timestamps.

Persists to disk so stats survive daemon restarts.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque


class ActivityTracker:
    """Tracks event counts over a rolling 24-hour window.

    Uses a deque of timestamps per category. Prunes entries older than
    24h on each query. Memory is bounded: worst case is one entry per
    event in the last 24h, which for a busy host is ~10k entries total
    (a few hundred KB).
    """

    WINDOW = 86400  # 24 hours in seconds
    _SAVE_INTERVAL = 60.0

    def __init__(self, persist_path: str | None = None) -> None:
        self._observed: deque = deque()
        self._blocks: deque = deque()
        self._escalations: deque = deque()
        self._fleet_blocks: deque = deque()
        self._persist_path = persist_path or os.path.join(
            os.environ.get("VESPID_STATE_DIR", "/var/lib/vespid"),
            "activity.json",
        )
        self._dirty = False
        self._last_save = 0.0
        self._lock = threading.RLock()
        self._load()

    def record_observed(self) -> None:
        with self._lock:
            self._observed.append(time.time())
            self._maybe_save()

    def record_block(self, *, escalated: bool = False, fleet: bool = False) -> None:
        with self._lock:
            self._blocks.append(time.time())
            if escalated:
                self._escalations.append(time.time())
            if fleet:
                self._fleet_blocks.append(time.time())
            self._maybe_save()

    def _maybe_save(self) -> None:
        self._dirty = True
        now = time.time()
        if now - self._last_save >= self._SAVE_INTERVAL:
            self._save()
            self._last_save = now
            self._dirty = False

    def _prune(self, dq: deque) -> None:
        cutoff = time.time() - self.WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            self._prune(self._observed)
            self._prune(self._blocks)
            self._prune(self._escalations)
            self._prune(self._fleet_blocks)
            if self._dirty:
                self._save()
                self._dirty = False
                self._last_save = time.time()
            return {
                "observed_24h": len(self._observed),
                "blocks_24h": len(self._blocks),
                "escalations_24h": len(self._escalations),
                "fleet_blocks_24h": len(self._fleet_blocks),
            }

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._persist_path), exist_ok=True)
            with self._lock:
                data = {
                    "observed": list(self._observed),
                    "blocks": list(self._blocks),
                    "escalations": list(self._escalations),
                    "fleet_blocks": list(self._fleet_blocks),
                }
            tmp = self._persist_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh, separators=(",", ":"))
            os.replace(tmp, self._persist_path)
        except OSError:
            pass

    def _load(self) -> None:
        try:
            with open(self._persist_path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return

        cutoff = time.time() - self.WINDOW
        for ts in data.get("observed", []):
            if ts > cutoff:
                self._observed.append(ts)
        for ts in data.get("blocks", []):
            if ts > cutoff:
                self._blocks.append(ts)
        for ts in data.get("escalations", []):
            if ts > cutoff:
                self._escalations.append(ts)
        for ts in data.get("fleet_blocks", []):
            if ts > cutoff:
                self._fleet_blocks.append(ts)
