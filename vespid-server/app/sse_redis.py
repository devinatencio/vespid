"""Optional Redis/Valkey pub/sub bridge for cross-worker SSE fan-out.

When running gunicorn with multiple workers, each worker has its own
in-memory SSE manager.  Events published by one worker are invisible
to SSE clients connected to other workers.

This module provides a ``RedisSSEBridge`` that uses Redis pub/sub to
relay SSE messages across all workers.  Each worker subscribes to the
relevant channels and fans out received messages to its local clients.

Usage is **optional** — controlled by the ``SSE_REDIS_URL`` config key.
When not configured, SSE managers fall back to in-memory-only fan-out
and the agent's periodic check-in (60s) catches missed updates.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Callable
from typing import Any

log = logging.getLogger("vespid.sse_redis")

_CHANNEL_PREFIX = "vespid:sse:"


class RedisSSEBridge:
    """Lazy-connecting Redis pub/sub bridge for SSE managers.

    Connections are established on first use (after gunicorn fork) to
    avoid sharing TCP sockets across forked worker processes.
    """

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url
        self._pub_redis = None
        self._sub_redis = None
        self._thread = None
        self._handlers: dict[str, Callable[[dict], None]] = {}
        self._started = False
        self._lock = threading.Lock()
        self._worker_pid: int | None = None

    def _ensure_publisher(self) -> None:
        if self._pub_redis is not None and self._worker_pid == os.getpid():
            return
        try:
            import redis as _redis

            self._pub_redis = _redis.Redis.from_url(self._redis_url, decode_responses=True)
            self._pub_redis.ping()
            self._worker_pid = os.getpid()
        except Exception as exc:
            log.warning("Redis SSE bridge publisher connect failed: %s", exc)
            self._pub_redis = None

    def _start_subscriber(self) -> None:
        if self._started:
            return
        with self._lock:
            if self._started:
                return
            if not self._handlers:
                return
            try:
                import redis as _redis

                self._sub_redis = _redis.Redis.from_url(self._redis_url, decode_responses=True)
                pubsub = self._sub_redis.pubsub(ignore_subscribe_messages=True)
                channel_handlers = {}
                for channel, handler in self._handlers.items():

                    def _make_cb(h):
                        def _cb(message):
                            if message["type"] != "message":
                                return
                            try:
                                data = json.loads(message["data"])
                                h(data)
                            except Exception as exc:
                                log.warning("Redis SSE handler error: %s", exc)

                        return _cb

                    channel_handlers[channel] = _make_cb(handler)
                pubsub.subscribe(**channel_handlers)
                self._thread = pubsub.run_in_thread(sleep_time=0.01, daemon=True)
                self._started = True
                log.info(
                    "Redis SSE subscriber started (pid=%d, channels=%s)",
                    os.getpid(),
                    list(self._handlers.keys()),
                )
            except Exception as exc:
                log.warning("Redis SSE subscriber failed to start: %s", exc)

    def register(self, channel: str, handler: Callable[[dict], None]) -> None:
        self._handlers[channel] = handler

    def publish(self, channel: str, data: dict[str, Any]) -> None:
        self._ensure_publisher()
        if self._pub_redis is None:
            return
        try:
            self._pub_redis.publish(channel, json.dumps(data, separators=(",", ":")))
        except Exception as exc:
            log.warning("Redis SSE publish failed on %s: %s", channel, exc)

    def start(self) -> None:
        self._start_subscriber()

    def stop(self) -> None:
        if self._thread:
            try:
                self._thread.stop()
            except Exception:
                pass
