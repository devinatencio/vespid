"""Event-driven file change watcher with polling fallback.

On Linux, uses inotify via ``inotify_simple`` (optional dependency) so
tailers block at zero CPU until the file is written to.

On systems without inotify (macOS, Windows, or when ``inotify_simple`` is
not installed), gracefully falls back to a configurable polling interval.

Rotation detection is handled separately by the caller (stat-based inode
comparison), so this watcher only concerns itself with *new content*.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Any

log = logging.getLogger("vespid.file_watcher")

_HAS_INOTIFY = sys.platform == "linux"


class FileWatcher:
    """Watch *path* for new data and optionally detect rotation events.

    Usage::

        watcher = FileWatcher(path, parent_dir=os.path.dirname(path))
        while not stop_event.is_set():
            changed, rotation = await watcher.wait(stop_event)
            if rotation:
                # reopen the file
            if changed:
                # read new lines
    """

    def __init__(self, path: str, parent_dir: str | None = None) -> None:
        self._path = path
        self._parent_dir = parent_dir
        self._inotify: Any = None
        self._inotify_fd: int | None = None
        self._file_wd: int | None = None
        self._parent_wd: int | None = None
        self._use_inotify = False
        self._init_inotify()

    # ------------------------------------------------------------------
    # Inotify setup (Linux only, optional dep)
    # ------------------------------------------------------------------
    def _init_inotify(self) -> None:
        if not _HAS_INOTIFY:
            return
        try:
            import inotify_simple as _inotify

            inotify_instance = _inotify.INotify()
            self._inotify = inotify_instance
            self._inotify_fd = inotify_instance.fileno()
            self._flags = _inotify.flags
            self._use_inotify = True
            log.debug("file_watcher: using inotify for %s", self._path)
        except ImportError:
            log.debug("file_watcher: inotify_simple not installed, falling back to poll")
        except OSError as exc:
            log.debug("file_watcher: inotify init failed (%s), falling back to poll", exc)

    def _ensure_watches(self) -> None:
        if not self._use_inotify or self._inotify is None:
            return
        import inotify_simple as _inotify

        flags = _inotify.flags
        if self._file_wd is None and os.path.isfile(self._path):
            self._file_wd = self._inotify.add_watch(self._path, flags.MODIFY)
        if self._parent_wd is None and self._parent_dir and os.path.isdir(self._parent_dir):
            self._parent_wd = self._inotify.add_watch(
                self._parent_dir,
                flags.MOVED_TO | flags.CREATE | flags.DELETE_SELF,
            )

    def _drain_inotify(self) -> tuple[bool, bool]:
        """Read and classify all pending inotify events.
        Returns (file_modified, rotation_detected).
        """
        if not self._use_inotify or self._inotify is None:
            return False, False

        import inotify_simple as _inotify

        changed = False
        rotation = False
        try:
            for event in self._inotify.read(timeout=0):
                if event.wd == self._file_wd:
                    changed = True
                elif event.wd == self._parent_wd:
                    name = getattr(event, "name", "")
                    if name == os.path.basename(self._path):
                        rotation = True
                if event.mask & _inotify.flags.DELETE_SELF:
                    rotation = True
        except BlockingIOError:
            pass
        return changed, rotation

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def wait(
        self, stop_event: asyncio.Event, poll_interval: float = 0.5
    ) -> tuple[bool, bool]:
        """Wait until the file changes, rotates, or *stop_event* is set.

        Returns ``(content_changed, rotation_detected)``.
        When *stop_event* is set, returns ``(False, False)`` immediately.
        """
        if stop_event.is_set():
            return False, False

        if self._use_inotify and self._inotify_fd is not None:
            self._ensure_watches()
            return await self._wait_inotify(stop_event)

        return await self._wait_poll(stop_event, poll_interval)

    async def _wait_inotify(self, stop_event: asyncio.Event) -> tuple[bool, bool]:
        """Block on the inotify fd via ``loop.add_reader`` — zero CPU."""
        assert self._inotify_fd is not None  # Caller checks _use_inotify
        loop = asyncio.get_running_loop()
        event_occurred = asyncio.Event()

        def callback() -> None:
            event_occurred.set()

        loop.add_reader(self._inotify_fd, callback)

        stop_task = asyncio.ensure_future(stop_event.wait())
        event_task = asyncio.ensure_future(event_occurred.wait())

        try:
            await asyncio.wait(
                [stop_task, event_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            loop.remove_reader(self._inotify_fd)
            stop_task.cancel()
            event_task.cancel()

        if stop_event.is_set():
            return False, False

        return self._drain_inotify()

    async def _wait_poll(self, stop_event: asyncio.Event, interval: float) -> tuple[bool, bool]:
        """Fallback: poll every *interval* seconds."""
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
        except asyncio.CancelledError:
            pass
        return False, False

    def close(self) -> None:
        """Release inotify resources."""
        if self._inotify is not None:
            try:
                self._inotify.close()
            except OSError:
                pass
            self._inotify = None
            self._inotify_fd = None
