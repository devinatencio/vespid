"""Offset persistence — remembers per-file (inode, byte-offset) so the tailer
can resume after restart without re-reading the entire file.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger("vespid.logproc.offsets")


class OffsetStore:
    """Persist per-file (inode, byte-offset) so we can resume after restart."""

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._data: dict[str, dict[str, object]] = {}
        self._load()

    def _load(self) -> None:
        try:
            if self._path.exists():
                self._data = json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Could not load offsets from %s: %s", self._path, exc)
            self._data = {}

    def get(self, path: str) -> dict[str, object] | None:
        return self._data.get(path)

    def save(self, path: str, inode: int | None, offset: int) -> None:
        self._data[path] = {"inode": inode, "offset": offset}

    def flush(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=2))
            tmp.replace(self._path)
        except OSError as exc:
            log.warning("Could not persist offsets to %s: %s", self._path, exc)
