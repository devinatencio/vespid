"""Tests for runtime log_sources reconciliation in the LogProcessor.

A config profile can add or remove log sources after the daemon has started.
Those changes must spawn/cancel tailers without a daemon restart.
"""

from __future__ import annotations

import asyncio
import sys
from unittest.mock import MagicMock

# Importing vespid.log_processor pulls in vespid.databus, whose module-level
# ``BUS = DataBus()`` creates the fleet queue directory under STATE_DIR at
# import time. Stub it so tests don't require a writable /var/lib/vespid.
sys.modules["vespid.databus"] = MagicMock()

from vespid.config import LogSource, ShieldConfig  # noqa: E402
from vespid.log_processor import LogProcessor  # noqa: E402


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


def _make_processor(tmp_path, sources) -> LogProcessor:
    cfg = ShieldConfig()
    cfg.auditd.enabled = False
    cfg.catchup_on_start = False
    cfg.offsets_path = str(tmp_path / "offsets.json")
    cfg.log_sources = list(sources)
    return LogProcessor(config=cfg)


class TestRuntimeLogSourceReconcile:
    def test_new_source_is_tailed_and_removed_source_stops(self, tmp_path):
        a = tmp_path / "a.log"
        a.write_text(_firewall_line(1))
        b = tmp_path / "b.log"
        b.write_text(_firewall_line(2))

        src_a = LogSource(path=str(a), parser="messages")
        src_b = LogSource(path=str(b), parser="messages")
        lp = _make_processor(tmp_path, [src_a])

        async def scenario():
            runner = asyncio.create_task(lp.run())
            try:
                assert await _wait_for(lambda: f"{a}:messages" in lp._source_tasks)

                # Profile adds a second source at runtime.
                lp.update_log_sources([src_a, src_b])
                assert await _wait_for(lambda: f"{b}:messages" in lp._source_tasks)
                assert not lp._source_tasks[f"{b}:messages"].done()

                # Profile removes a source.
                lp.update_log_sources([src_b])
                assert await _wait_for(lambda: f"{a}:messages" not in lp._source_tasks)
                assert f"{b}:messages" in lp._source_tasks
            finally:
                lp.stop()
                await runner

        asyncio.run(scenario())

    def test_reconcile_is_idempotent(self, tmp_path):
        a = tmp_path / "a.log"
        a.write_text(_firewall_line(1))
        src = LogSource(path=str(a), parser="messages")
        lp = _make_processor(tmp_path, [src])

        async def scenario():
            runner = asyncio.create_task(lp.run())
            try:
                assert await _wait_for(lambda: f"{a}:messages" in lp._source_tasks)
                first = lp._source_tasks[f"{a}:messages"]

                lp.update_log_sources([src])
                await asyncio.sleep(0.1)

                assert lp._source_tasks[f"{a}:messages"] is first
            finally:
                lp.stop()
                await runner

        asyncio.run(scenario())

    def test_update_before_run_stores_sources(self, tmp_path):
        a = tmp_path / "a.log"
        a.write_text(_firewall_line(1))
        src = LogSource(path=str(a), parser="messages")
        lp = _make_processor(tmp_path, [])

        # No loop yet — sources should simply be stored for run() to pick up.
        lp.update_log_sources([src])

        assert [s.path for s in lp.config.log_sources] == [str(a)]
