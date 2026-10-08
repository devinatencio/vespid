"""Async file tailer with catchup support.

Architecture: a dedicated reader thread handles ALL file I/O (open,
seek, readline, stat) and pushes raw lines into a thread-safe queue.
The async consumer pulls lines from the queue and dispatches them to
the provided callback.

This design avoids ``asyncio.to_thread()`` entirely — the reader
thread runs continuously and never depends on the event loop's
callback mechanism to resume it. The event loop only needs to drain
the queue, which uses ``call_soon_threadsafe`` for notification.

Supports:
- inotify-based wakeup on Linux (via FileWatcher)
- Polling fallback on other platforms
- Log rotation detection (stat-based inode comparison)
- Offset-based catchup replay on restart
"""

from __future__ import annotations

import asyncio
import logging
import os
import queue as thread_queue
import re
import threading
from collections.abc import Awaitable, Callable

from .config import LogSource
from .file_watcher import FileWatcher
from .log_offset_store import OffsetStore
from .log_parsers import ParsedLine, _get_parser

log = logging.getLogger("vespid.logproc.tailer")

# Signature of vespid's own human-readable log lines. Two variants:
#
# * The Python daemon uses the %(asctime)s %(levelname)-7s %(name)-22s format
#   from logging_setup (e.g. "2026-08-01T15:59:11+0000 INFO    vespid.logproc.tailer  ...").
# * The Rust agents (vespid-agent, vespid-sync-agent, vespid-worker) use the
#   tracing_subscriber fmt format (e.g. "2026-08-01T16:13:11.088555Z  INFO Sending batch ...").
#
# Both write to stdout, which journald mirrors into /var/log/messages and
# /var/log/syslog via rsyslog, prefixed by a syslog program tag such as
# "vespid: " or "vespid-agent[1388]: ". Since vespid tails those files, this
# pattern lets the tailer skip its own mirrored lines instead of counting them
# as parse failures — a self-tailing feedback loop.
_SELF_LOG_RE = re.compile(
    r"(?:"
    # Variant 1: syslog program tag (e.g. "vespid: " / "vespid-agent[1388]: ")
    # + ISO timestamp (either Z-suffixed fractional or numeric offset) + level.
    r"\bvespid(?:-[a-z]+)*(?:\[\d+\])?: "
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})"
    r"\s+(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL)(?=\s|$)"
    r")|(?:"
    # Variant 2: bare Python-format line (no tag) — ISO timestamp + level
    # followed by the vespid logger name.
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2}"
    r"\s+(?:DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+vespid(?:\.| )"
    r")"
)


def _is_self_log_line(line: str) -> bool:
    """Return True if *line* is one of vespid's own mirrored log lines."""
    return _SELF_LOG_RE.search(line) is not None


async def tail_file(
    source: LogSource,
    on_line: Callable[[ParsedLine], Awaitable[None]],
    stop_event: asyncio.Event,
    offsets: OffsetStore | None = None,
    catchup: bool = False,
) -> None:
    """Tail a file with rotation awareness and optional catchup replay.

    Args:
        source: The log source configuration (path + parser name).
        on_line: Async callback invoked for each successfully parsed line.
        stop_event: Asyncio event that signals shutdown.
        offsets: Optional offset store for persist/resume across restarts.
        catchup: If True, resume from saved offset (or beginning) on start.
    """
    parser = _get_parser(source)
    if parser is None:
        log.warning("Unknown parser %s for %s", source.parser, source.path)
        return

    log.info("Tailing %s (%s, catchup=%s)", source.path, source.parser, catchup)

    offset_key = f"{source.path}:{source.parser}"

    # Thread-safe queue with backpressure (bounded).
    line_queue: thread_queue.Queue = thread_queue.Queue(maxsize=500)
    loop = asyncio.get_running_loop()
    # Async event to wake the consumer when data is available.
    data_ready = asyncio.Event()
    # Threading event to signal the reader thread to stop (independent of
    # the shared asyncio stop_event so we don't affect other tailers).
    reader_stop = threading.Event()

    # Sentinels
    _SENTINEL_ROTATE = object()  # noqa: N806

    def _notify_async():
        """Thread-safe: wake the async consumer."""
        loop.call_soon_threadsafe(data_ready.set)

    # Shared mutable state (written by reader, read by consumer)
    current_inode: list = [None]
    current_pos: list = [0]
    reader_error: list = []
    reader_done = threading.Event()

    def _reader_thread():
        """Dedicated thread: reads the file and pushes lines to the queue."""
        catching_up = catchup
        watcher_local: FileWatcher | None = None

        def _is_stopped():
            return reader_stop.is_set() or stop_event.is_set()

        try:
            while not _is_stopped():
                # --- Open the file ---
                try:
                    fh = open(source.path, encoding="utf-8", errors="replace")
                except FileNotFoundError:
                    if _is_stopped():
                        return
                    reader_stop.wait(5)
                    continue
                except PermissionError as exc:
                    log.error("Cannot read %s: %s", source.path, exc)
                    return

                try:
                    inode = os.fstat(fh.fileno()).st_ino
                except OSError:
                    inode = None
                current_inode[0] = inode

                watcher_local = FileWatcher(source.path, parent_dir=os.path.dirname(source.path))

                log.info(
                    "Tailer opened: path=%s inode=%s catching_up=%s",
                    source.path,
                    inode,
                    catching_up,
                )

                # --- Determine seek position ---
                if catching_up and offsets is not None:
                    saved = offsets.get(offset_key)
                    if saved is not None:
                        saved_inode = saved.get("inode")
                        saved_offset = int(str(saved.get("offset") or 0))
                        file_size = os.fstat(fh.fileno()).st_size
                        if saved_inode == inode and 0 < saved_offset <= file_size:
                            fh.seek(saved_offset)
                            log.info("Resuming %s from offset %d", source.path, saved_offset)
                        elif saved_inode == inode and saved_offset > file_size:
                            # The file was truncated in place (e.g. logrotate
                            # `copytruncate`) after the offset was persisted.
                            # Seeking past EOF would stall the tailer forever,
                            # so replay from the beginning instead.
                            log.info(
                                "Saved offset %d for %s is past EOF (size %d) — "
                                "truncated, reading from beginning",
                                saved_offset,
                                source.path,
                                file_size,
                            )
                        else:
                            log.info(
                                "Reading %s from beginning (inode changed or no prior offset)",
                                source.path,
                            )
                    else:
                        log.info("Reading %s from beginning (no saved offset)", source.path)
                elif not catching_up:
                    fh.seek(0, os.SEEK_END)

                # --- Main read loop ---
                need_reopen = False
                while not _is_stopped():
                    line = fh.readline()
                    if line:
                        current_pos[0] = fh.tell()
                        # Put with timeout so we can check stop
                        while not _is_stopped():
                            try:
                                line_queue.put(line, timeout=0.5)
                                break
                            except thread_queue.Full:
                                continue
                        _notify_async()
                        continue

                    # No more data
                    current_pos[0] = fh.tell()

                    if catching_up:
                        catching_up = False
                        line_queue.put(("EOF", current_pos[0]))
                        _notify_async()

                    # In-place truncation check (logrotate `copytruncate` and
                    # similar): the file keeps its inode but shrinks below our
                    # read position, so the inode check below can't catch it.
                    # Rewind to the start rather than blocking forever at EOF.
                    try:
                        st = os.stat(source.path)
                        if st.st_size < current_pos[0]:
                            log.info(
                                "Log file %s truncated in place (%d -> %d bytes), "
                                "rewinding to start",
                                source.path,
                                current_pos[0],
                                st.st_size,
                            )
                            fh.seek(0)
                            current_pos[0] = 0
                            continue
                    except FileNotFoundError:
                        pass

                    # --- Wait for new data ---
                    truncated = False
                    if watcher_local._use_inotify and watcher_local._inotify_fd is not None:
                        import select

                        watcher_local._ensure_watches()
                        while not _is_stopped():
                            ready, _, _ = select.select([watcher_local._inotify_fd], [], [], 1.0)
                            if ready:
                                changed, rotated = watcher_local._drain_inotify()
                                if rotated:
                                    need_reopen = True
                                    break
                                if changed:
                                    break
                            # Stat-based rotation/truncation check
                            try:
                                st = os.stat(source.path)
                                if inode is not None and st.st_ino != inode:
                                    need_reopen = True
                                    break
                                if st.st_size < current_pos[0]:
                                    truncated = True
                                    break
                            except FileNotFoundError:
                                need_reopen = True
                                break
                    else:
                        # Polling fallback
                        reader_stop.wait(0.5)
                        if _is_stopped():
                            break
                        try:
                            st = os.stat(source.path)
                            if inode is not None and st.st_ino != inode:
                                need_reopen = True
                            elif st.st_size < current_pos[0]:
                                truncated = True
                        except FileNotFoundError:
                            need_reopen = True

                    if need_reopen:
                        log.info("Rotation detected on %s, reopening", source.path)
                        line_queue.put(_SENTINEL_ROTATE)
                        _notify_async()
                        break

                    if truncated:
                        log.info(
                            "Log file %s truncated in place (%d bytes now), rewinding to start",
                            source.path,
                            st.st_size,
                        )
                        fh.seek(0)
                        current_pos[0] = 0
                        continue

                # Close file and watcher for this iteration
                try:
                    fh.close()
                except OSError:
                    pass
                if watcher_local:
                    watcher_local.close()
                    watcher_local = None

        except Exception as exc:
            log.exception("Reader thread crashed for %s", source.path)
            reader_error.append(exc)
        finally:
            reader_done.set()
            try:
                line_queue.put_nowait(("EOF", current_pos[0]))
            except thread_queue.Full:
                pass
            _notify_async()
            if watcher_local:
                watcher_local.close()

    # --- Start the reader thread ---
    thread = threading.Thread(
        target=_reader_thread,
        name=f"tailer-{os.path.basename(source.path)}",
        daemon=True,
    )
    thread.start()

    # --- Async consumer loop ---
    lines_processed = 0
    parse_failures = 0
    catching_up_local = catchup
    try:
        while not stop_event.is_set():
            data_ready.clear()

            # Drain all available items from the queue
            batch_count = 0
            while True:
                try:
                    item = line_queue.get_nowait()
                except thread_queue.Empty:
                    break

                if isinstance(item, tuple) and item[0] == "EOF":
                    final_pos = item[1]
                    if catching_up_local:
                        log.info(
                            "Catchup complete for %s (%d lines replayed)",
                            source.path,
                            lines_processed,
                        )
                        catching_up_local = False
                        if offsets is not None:
                            try:
                                offsets.save(offset_key, current_inode[0], final_pos)
                            except OSError:
                                pass
                    continue

                if item is _SENTINEL_ROTATE:
                    if offsets is not None:
                        try:
                            offsets.save(offset_key, current_inode[0], current_pos[0])
                        except OSError:
                            pass
                    continue

                # Regular line
                lines_processed += 1
                batch_count += 1
                # Skip vespid's own mirrored log lines (journald -> rsyslog
                # -> the very file we are tailing) before parsing/counting.
                if _is_self_log_line(item):
                    continue
                try:
                    parsed = parser(item.rstrip("\n"))
                    if parsed:
                        parse_failures = 0
                        if lines_processed <= 5:
                            log.debug(
                                "Tailer line: path=%s parser=%s ip=%s lines=%d qsize=%d",
                                source.path,
                                parsed.parser,
                                parsed.source_ip,
                                lines_processed,
                                line_queue.qsize(),
                            )
                        await on_line(parsed)
                    else:
                        parse_failures += 1
                        if parse_failures == 1:
                            log.debug(
                                "Parse miss: path=%s line=%r",
                                source.path,
                                item.rstrip("\n")[:200],
                            )
                        elif parse_failures == 50:
                            log.info(
                                "Parser %s: 50 consecutive non-matching lines for %s "
                                "(expected if most lines aren't security events)",
                                source.parser,
                                source.path,
                            )
                        elif parse_failures % 1000 == 0:
                            log.info(
                                "Parser %s: %d consecutive non-matching lines for %s",
                                source.parser,
                                parse_failures,
                                source.path,
                            )
                except Exception:
                    log.exception("Failed to process line from %s", source.path)

                # Yield every 100 lines so other tasks can run
                if batch_count % 100 == 0:
                    if offsets is not None and lines_processed % 1000 == 0:
                        try:
                            offsets.save(offset_key, current_inode[0], current_pos[0])
                        except OSError:
                            pass
                    await asyncio.sleep(0)

            # Save offset after each drain cycle (live-tail mode)
            if batch_count > 0 and not catching_up_local and offsets is not None:
                try:
                    offsets.save(offset_key, current_inode[0], current_pos[0])
                except OSError:
                    pass

            if batch_count > 0 and catching_up_local:
                log.debug(
                    "Consumer drained %d lines for %s (total=%d)",
                    batch_count,
                    source.path,
                    lines_processed,
                )

            # Check if reader is done
            if reader_done.is_set() and line_queue.empty():
                if reader_error:
                    log.error("Reader thread for %s failed: %s", source.path, reader_error[0])
                break

            # Wait for more data
            try:
                await asyncio.wait_for(data_ready.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                pass

    finally:
        reader_stop.set()
        thread.join(timeout=5.0)
        if offsets is not None:
            try:
                offsets.save(offset_key, current_inode[0], current_pos[0])
            except OSError:
                pass
