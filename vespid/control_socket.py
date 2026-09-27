"""UNIX-socket control plane used by the local CLI.

The running daemon listens on a small JSON-line protocol so that the CLI
(``vespid-cli``) can talk to it without any network exposure.

Uses a dedicated thread for socket I/O — completely independent of the
asyncio event loop.  Handler coroutines run in a fresh event loop on the
handler thread, so they never contend with the main event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import threading
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from .config import CONFIG, ShieldConfig

log = logging.getLogger("vespid.ctl")

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


def _run_async(coro: Awaitable[Any], timeout: float = 25.0) -> Any:
    """Run a coroutine in a fresh event loop on the current thread."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(asyncio.wait_for(coro, timeout=timeout))
    finally:
        loop.close()


class ControlServer:
    def __init__(
        self,
        handlers: dict[str, Handler],
        config: ShieldConfig | None = None,
    ) -> None:
        self.config = config or CONFIG
        self.handlers = handlers
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._path: str = ""

    def start(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        from .config import SOCKET_PATH

        path = Path(str(SOCKET_PATH))
        self._path = str(path)

        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self._path)
        sock.listen(8)
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            pass

        self._sock = sock
        self._stopping.clear()
        self._thread = threading.Thread(target=self._serve, name="vespid-ctl", daemon=True)
        self._thread.start()
        log.info("Control socket listening on %s", self._path)

    def _serve(self) -> None:
        sock = self._sock
        assert sock is not None
        while not self._stopping.is_set():
            try:
                sock.settimeout(1.0)
                client, _addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle,
                args=(client,),
                name="vespid-ctl-handler",
                daemon=True,
            ).start()

    def _handle(self, client: socket.socket) -> None:
        try:
            client.settimeout(10.0)
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = client.recv(4096)
                except TimeoutError:
                    return
                if not chunk:
                    return
                chunks.append(chunk)
                if b"\n" in chunk:
                    break

            if not chunks:
                return

            raw = b"".join(chunks)
            line_bytes = raw.split(b"\n", 1)[0]
            try:
                line = line_bytes.decode("utf-8", errors="replace")
            except Exception:
                return

            try:
                request = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                response: dict[str, Any] = {"ok": False, "error": "invalid_json"}
            else:
                if not isinstance(request, dict) or "cmd" not in request:
                    response = {"ok": False, "error": "bad_request"}
                else:
                    cmd = request["cmd"]
                    handler = self.handlers.get(cmd)
                    if not handler:
                        response = {"ok": False, "error": f"unknown_cmd:{cmd}"}
                    else:
                        try:
                            response = _run_async(handler(request))
                        except Exception as exc:
                            log.exception("Handler %s failed", cmd)
                            response = {"ok": False, "error": str(exc)}

            resp_bytes = (json.dumps(response) + "\n").encode("utf-8")
            client.sendall(resp_bytes)
        except (OSError, ConnectionError):
            pass
        except Exception:
            log.exception("Control socket handler error")
        finally:
            try:
                client.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stopping.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        if self._path:
            try:
                os.unlink(self._path)
            except OSError:
                pass


def send_command(cmd: str, **kwargs: Any) -> dict[str, Any]:
    """Synchronous helper used by the CLI."""
    import socket as _stdlib_socket

    from .config import SOCKET_PATH

    payload = json.dumps({"cmd": cmd, **kwargs}) + "\n"
    with _stdlib_socket.socket(_stdlib_socket.AF_UNIX, _stdlib_socket.SOCK_STREAM) as s:
        s.settimeout(15.0)
        s.connect(str(SOCKET_PATH))
        s.sendall(payload.encode("utf-8"))
        chunks: list[bytes] = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
    raw = b"".join(chunks).decode("utf-8").strip()
    if not raw:
        return {"ok": False, "error": "empty_response"}
    return json.loads(raw)
