"""Tests for vespid.file_tailer — self-log detection.

The daemon and agents write their human-readable log lines to stdout, which
systemd journald captures and rsyslog mirrors into /var/log/messages
(RHEL/SUSE) and /var/log/syslog (Debian). Since vespid tails those files,
_is_self_log_line() is used to skip its own mirrored lines instead of counting
them as parse failures (self-tailing feedback loop).
"""

from __future__ import annotations

import asyncio
import os

from vespid.config import LogSource
from vespid.file_tailer import _is_self_log_line, tail_file
from vespid.log_offset_store import OffsetStore


class TestIsSelfLogLine:
    def test_own_log_line_with_program_tag(self):
        line = (
            "Aug  1 15:59:11 myhost vespid: "
            "2026-08-01T15:59:11+0000 INFO    vespid.logproc.tailer  "
            "Parser messages: 204000 consecutive non-matching lines for "
            "/var/log/messages"
        )
        assert _is_self_log_line(line) is True

    def test_own_log_line_without_program_tag(self):
        line = (
            "2026-08-01T15:59:11+0000 INFO    vespid.logproc.tailer  "
            "Tailing /var/log/messages (messages, catchup=True)"
        )
        assert _is_self_log_line(line) is True

    def test_own_log_line_level_warning(self):
        line = (
            "Aug  1 15:59:12 myhost vespid: "
            "2026-08-01T15:59:12+0000 WARNING vespid.config  "
            "Ignoring unknown key foo"
        )
        assert _is_self_log_line(line) is True

    def test_root_logger_name(self):
        line = (
            "Aug  1 15:59:13 myhost vespid: "
            "2026-08-01T15:59:13+0000 INFO    vespid  "
            "Logging configured"
        )
        assert _is_self_log_line(line) is True

    def test_rust_agent_log_line(self):
        line = (
            "Aug  1 16:13:11 vps-43d4bac7 vespid-agent[1388]: "
            "2026-08-01T16:13:11.088555Z  INFO Sending batch  212 metrics, "
            "39643 bytes  \u2192 https://demo.vespid.app/api/v1/metrics/write"
        )
        assert _is_self_log_line(line) is True

    def test_rust_agent_shipped_log_line(self):
        line = (
            "Aug  1 16:13:11 vps-43d4bac7 vespid-agent[1388]: "
            "2026-08-01T16:13:11.107951Z  INFO Shipped 212 metrics "
            "(39643 bytes)  \u2713"
        )
        assert _is_self_log_line(line) is True

    def test_rust_sync_agent_log_line(self):
        line = (
            "Aug  1 16:13:12 vps-43d4bac7 vespid-sync-agent[1402]: "
            "2026-08-01T16:13:12.000123Z  WARN Sync failed, will retry"
        )
        assert _is_self_log_line(line) is True

    def test_real_security_event_not_skipped(self):
        line = (
            "Aug  1 16:00:01 myhost sshd[1234]: "
            "Failed password for invalid user root from 203.0.113.5 port "
            "53422 ssh2"
        )
        assert _is_self_log_line(line) is False

    def test_firewall_deny_not_skipped(self):
        line = (
            "Aug  1 16:00:02 myhost kernel: "
            "IN=eth0 OUT= MAC=.. SRC=198.51.100.9 DST=192.0.2.1 "
            "PROTO=TCP SPT=4444 DPT=22 DROP"
        )
        assert _is_self_log_line(line) is False

    def test_apache_line_not_skipped(self):
        line = (
            "192.0.2.7 - - [01/Aug/2026:15:59:11 +0000] "
            '"GET /wp-login.php HTTP/1.1" 404 489 "-" "-"'
        )
        assert _is_self_log_line(line) is False


def _firewall_line(i: int) -> str:
    return (
        f"Sep 21 12:00:{i:02d} host kernel: DROP IN=eth0 OUT= "
        f"SRC=198.51.100.{i} DST=192.0.2.1 PROTO=TCP SPT=4444 DPT=22 DROP\n"
    )


async def _wait_for(predicate, timeout: float = 5.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return False


class TestRotationAndTruncation:
    """The tailer must survive log rotation and in-place truncation.

    Covers `copytruncate` (same inode, shrunk), rename-style rotation (new
    inode, usually smaller) and stale saved offsets that point past EOF.
    """

    def test_truncation_in_place_is_followed(self, tmp_path):
        log_path = tmp_path / "app.log"
        # Seed larger than the replacement so the size shrink is observable.
        log_path.write_text("".join(_firewall_line(i) for i in range(1, 21)))

        seen: list[str] = []

        async def scenario():
            async def on_line(parsed):
                seen.append(parsed.raw)

            stop = asyncio.Event()
            source = LogSource(path=str(log_path), parser="messages")
            task = asyncio.create_task(tail_file(source, on_line, stop, offsets=None, catchup=True))
            try:
                assert await _wait_for(lambda: len(seen) >= 20), "initial read failed"

                # Simulate copytruncate: truncate in place then append new data.
                inode_before = os.stat(log_path).st_ino
                log_path.write_text(_firewall_line(99))
                assert os.stat(log_path).st_ino == inode_before, "inode must not change"

                assert await _wait_for(lambda: any("198.51.100.99" in raw for raw in seen)), (
                    "post-truncation line was not read"
                )
            finally:
                stop.set()
                await task

        asyncio.run(scenario())

    def test_rename_rotation_to_smaller_file_is_followed(self, tmp_path):
        """A rename-style rotation must not be read as in-place truncation.

        Regression test: the truncation check compares the stat size of
        ``source.path`` with the open handle's read position. After a rename
        rotation the path resolves to a different (usually smaller) inode than
        the open handle, so the check used to fire and rewind the *stale*
        handle forever — never following the rotated-in file.
        """
        log_path = tmp_path / "audit.log"
        rotated = tmp_path / "audit.log.1"

        # Large enough to overflow the reader's bounded queue so the tailer is
        # still mid-file (in the old inode) when the rotation happens.
        log_path.write_text("".join(_firewall_line(i) for i in range(1, 2001)))
        old_inode = os.stat(log_path).st_ino

        marker = "203.0.113.77"
        marker_line = (
            "Sep 21 12:59:59 host kernel: DROP IN=eth0 OUT= "
            f"SRC={marker} DST=192.0.2.1 PROTO=TCP SPT=4444 DPT=22 DROP\n"
        )

        seen: list[str] = []

        async def scenario():
            first_called = asyncio.Event()
            release = asyncio.Event()

            async def on_line(parsed):
                seen.append(parsed.raw)
                first_called.set()
                # Park the consumer so the reader fills its queue and blocks
                # mid-file; otherwise it can reach EOF (and the wait loop, which
                # detects rotation correctly) before we rotate.
                await release.wait()

            stop = asyncio.Event()
            source = LogSource(path=str(log_path), parser="messages")
            task = asyncio.create_task(tail_file(source, on_line, stop, offsets=None, catchup=True))
            try:
                assert await _wait_for(first_called.is_set), "consumer never started"

                # Rename-style rotation: old file -> .1, fresh file at path.
                os.rename(log_path, rotated)
                log_path.write_text("")
                assert os.stat(log_path).st_ino != old_inode

                release.set()

                # Keep appending to the new file until the tailer follows it.
                followed = False
                for _ in range(100):
                    with open(log_path, "a", encoding="utf-8") as fh:
                        fh.write(marker_line)
                    await asyncio.sleep(0.1)
                    if any(marker in raw for raw in seen):
                        followed = True
                        break
                assert followed, "tailer re-read the rotated-out file instead of the new one"
            finally:
                stop.set()
                await task

        asyncio.run(scenario())

    def test_saved_offset_past_eof_reads_from_beginning(self, tmp_path):
        log_path = tmp_path / "app.log"
        log_path.write_text(_firewall_line(1))
        inode = os.stat(log_path).st_ino

        offsets = OffsetStore(str(tmp_path / "offsets.json"))
        offsets.save(f"{log_path}:messages", inode, 10_000_000)

        seen: list[str] = []

        async def scenario():
            async def on_line(parsed):
                seen.append(parsed.raw)

            stop = asyncio.Event()
            source = LogSource(path=str(log_path), parser="messages")
            task = asyncio.create_task(
                tail_file(source, on_line, stop, offsets=offsets, catchup=True)
            )
            try:
                assert await _wait_for(lambda: any("198.51.100.1" in raw for raw in seen)), (
                    "tailer stalled on a stale past-EOF offset"
                )
            finally:
                stop.set()
                await task

        asyncio.run(scenario())
