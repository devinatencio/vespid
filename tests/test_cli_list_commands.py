"""Command-level tests for the local list commands.

These cover the shared renderer introduced for ``list-local``,
``list-subscribed``, and ``allowlist-list``. In particular, mixed IPv4/IPv6
blocklists must render instead of raising the ``ipaddress`` version error.
"""

import importlib

import pytest
from typer.testing import CliRunner

cli_app = importlib.import_module("vespid.cli.app")

runner = CliRunner()


@pytest.fixture(autouse=True)
def _wide_console():
    """Keep long IPv6 entries from wrapping in captured output."""
    previous = cli_app.console.width
    cli_app.console.width = 200
    yield
    cli_app.console.width = previous


def _invoke(args, responses):
    def fake_safe(command, **kwargs):
        return responses[command]

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(cli_app, "_safe", fake_safe)
        return runner.invoke(cli_app.app, args)


def test_list_local_mixed_ip_versions():
    result = _invoke(
        ["list-local"],
        {
            "list_local": {
                "ok": True,
                "entries": [
                    {"ip": "2400:6180:10:200::e8e6:f000", "ttl_remaining": 60, "strike": 1},
                    {"ip": "121.31.210.125", "ttl_remaining": 120, "strike": 2},
                ],
            }
        },
    )

    assert result.exit_code == 0, result.output
    assert "121.31.210.125" in result.output
    assert "2400:6180:10:200::e8e6:f000" in result.output
    assert result.output.index("121.31.210.125") < result.output.index(
        "2400:6180:10:200::e8e6:f000"
    )


def test_list_local_empty_and_error():
    empty = _invoke(["list-local"], {"list_local": {"ok": True, "entries": []}})
    assert empty.exit_code == 0
    assert "shield_local is empty" in empty.output

    failed = _invoke(
        ["list-local"],
        {"list_local": {"ok": False, "error": "daemon_not_running (control socket missing)"}},
    )
    combined = failed.output + (failed.stderr or "")
    assert failed.exit_code == 1
    assert "daemon_not_running" in combined
    assert "systemctl start vespid" in combined


def test_list_subscribed_sorts_mixed_entries():
    result = _invoke(
        ["list-subscribed"],
        {
            "list_subscribed": {
                "ok": True,
                "entries": ["2001:db8::/32", "10.0.0.0/8", "192.0.2.0/24"],
                "count": 3,
                "returned": 3,
            }
        },
    )

    assert result.exit_code == 0, result.output
    assert result.output.index("10.0.0.0/8") < result.output.index("192.0.2.0/24")
    assert result.output.index("192.0.2.0/24") < result.output.index("2001:db8::/32")


def test_allowlist_list_sorts_mixed_entries():
    result = _invoke(
        ["allowlist-list"],
        {
            "allowlist_list": {
                "ok": True,
                "entries": [
                    {"entry": "2001:db8::1", "source": "config"},
                    {"entry": "192.0.2.1", "source": "runtime"},
                ],
            }
        },
    )

    assert result.exit_code == 0, result.output
    assert result.output.index("192.0.2.1") < result.output.index("2001:db8::1")


def test_list_local_json_still_works():
    result = _invoke(
        ["list-local", "--json"],
        {
            "list_local": {
                "ok": True,
                "entries": [{"ip": "121.31.210.125", "ttl_remaining": 60}],
            }
        },
    )

    assert result.exit_code == 0, result.output
    assert "121.31.210.125" in result.output
