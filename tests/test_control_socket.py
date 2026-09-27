"""Tests for vespid.control_socket.

Covers:
- Server start/stop lifecycle
- Handler dispatch (known and unknown commands)
- JSON-line protocol (request → response)
- Invalid input handling (bad JSON, missing cmd)
- send_command helper
- Handler exceptions are caught and return error responses
"""

from __future__ import annotations

import json
import os
import socket
import time
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Redirect state/config to tmp_path."""
    monkeypatch.setenv("VESPID_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_ID_FILE", str(tmp_path / "node_id"))
    monkeypatch.setenv("VESPID_SOCKET", str(tmp_path / "vespid.sock"))


@pytest.fixture
def socket_path(tmp_path):
    # Unix sockets have a 104-char path limit on macOS. Use /tmp directly.
    import tempfile

    path = tempfile.mktemp(prefix="vespid_test_", suffix=".sock", dir="/tmp")
    yield path
    # Cleanup
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def handlers():
    """Simple test handlers."""

    async def status_handler(request):
        return {"ok": True, "status": "running", "blocks": 42}

    async def echo_handler(request):
        return {"ok": True, "echo": request.get("data", "")}

    async def error_handler(request):
        raise RuntimeError("something broke")

    return {
        "status": status_handler,
        "echo": echo_handler,
        "error": error_handler,
    }


@pytest.fixture
def server(handlers, socket_path, tmp_path):
    """Create and start a ControlServer, yield it, then stop."""
    from vespid.config import ShieldConfig
    from vespid.control_socket import ControlServer

    config = ShieldConfig(
        node_id="test-node",
        spool_path=str(tmp_path / "spool.jsonl"),
        fleet_queue_dir=str(tmp_path / "fleet_queue"),
        subscriptions=[],
    )

    # Patch SOCKET_PATH to our test path (it's a module-level Path in vespid.config)
    from pathlib import Path

    with patch("vespid.config.SOCKET_PATH", Path(socket_path)):
        srv = ControlServer(handlers, config)
        srv.start()
        # Wait for socket to be ready
        for _ in range(50):
            if os.path.exists(socket_path):
                break
            time.sleep(0.02)
        yield srv
        srv.stop()


def _send_raw(socket_path: str, payload: str) -> str:
    """Send a raw string to the control socket and return the response."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect(socket_path)
    sock.sendall((payload + "\n").encode("utf-8"))
    chunks = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
        if b"\n" in chunk:
            break
    sock.close()
    return b"".join(chunks).decode("utf-8").strip()


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_socket_file_created(self, server, socket_path):
        assert os.path.exists(socket_path)

    def test_socket_permissions_0600(self, server, socket_path):
        import stat

        mode = stat.S_IMODE(os.stat(socket_path).st_mode)
        assert mode == 0o600

    def test_stop_removes_socket(self, server, socket_path):
        server.stop()
        assert not os.path.exists(socket_path)


# ---------------------------------------------------------------------------
# Handler dispatch
# ---------------------------------------------------------------------------


class TestDispatch:
    def test_known_command(self, server, socket_path):
        resp = _send_raw(socket_path, json.dumps({"cmd": "status"}))
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["status"] == "running"
        assert data["blocks"] == 42

    def test_echo_command_with_data(self, server, socket_path):
        resp = _send_raw(socket_path, json.dumps({"cmd": "echo", "data": "hello"}))
        data = json.loads(resp)
        assert data["ok"] is True
        assert data["echo"] == "hello"

    def test_unknown_command(self, server, socket_path):
        resp = _send_raw(socket_path, json.dumps({"cmd": "nonexistent"}))
        data = json.loads(resp)
        assert data["ok"] is False
        assert "unknown_cmd" in data["error"]

    def test_handler_exception_returns_error(self, server, socket_path):
        resp = _send_raw(socket_path, json.dumps({"cmd": "error"}))
        data = json.loads(resp)
        assert data["ok"] is False
        assert "something broke" in data["error"]


# ---------------------------------------------------------------------------
# Protocol handling
# ---------------------------------------------------------------------------


class TestProtocol:
    def test_invalid_json(self, server, socket_path):
        resp = _send_raw(socket_path, "not valid json{{{")
        data = json.loads(resp)
        assert data["ok"] is False
        assert "invalid_json" in data["error"]

    def test_missing_cmd_field(self, server, socket_path):
        resp = _send_raw(socket_path, json.dumps({"foo": "bar"}))
        data = json.loads(resp)
        assert data["ok"] is False
        assert "bad_request" in data["error"]

    def test_multiple_sequential_requests(self, server, socket_path):
        """Each request gets its own connection (no keep-alive)."""
        for i in range(5):
            resp = _send_raw(socket_path, json.dumps({"cmd": "echo", "data": str(i)}))
            data = json.loads(resp)
            assert data["echo"] == str(i)
