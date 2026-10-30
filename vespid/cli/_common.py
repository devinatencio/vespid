"""Shared presentation and error-handling helpers for vespid-cli.

Keeping output, exit-code, and IP-sorting behavior in one place makes the
individual commands smaller and prevents issues like comparing an
``IPv4Address`` with an ``IPv6Address`` from breaking a whole command.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable
from typing import Any

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()
err_console = Console(stderr=True)

# Reusable --json option. Commands should import this instead of defining
# their own copy so the help text and behavior stay consistent.
JsonOption = typer.Option(False, "--json", help="Output raw JSON instead of pretty tables.")


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def dump_json(payload: dict[str, Any]) -> int:
    """Print *payload* as JSON and return an exit code."""
    console.print(JSON(json.dumps(payload, sort_keys=True)))
    return 0 if payload.get("ok") else 1


def print_error(resp: dict[str, Any] | str) -> int:
    """Print a user-friendly error panel and return exit code 1."""
    error = resp.get("error", "unknown error") if isinstance(resp, dict) else str(resp)

    hint = ""
    if "daemon_not_running" in error:
        hint = "Start the daemon with: [bold]sudo systemctl start vespid[/bold]"
    elif "daemon_unreachable" in error:
        hint = "The daemon may be overloaded or restarting. Try again in a moment."
    elif "permission_denied" in error:
        hint = "Try running with [bold]sudo[/bold] or check socket permissions."

    body = Text(error, style="red")
    if hint:
        body.append(f"\n\n💡 {hint}")

    err_console.print(Panel(body, title="[red]✖ Error[/red]", border_style="red", expand=False))
    return 1


def check_resp(resp: dict[str, Any], json_output: bool) -> bool:
    """If *resp* is an error, print it and return False."""
    if resp.get("ok"):
        return True
    if json_output:
        dump_json(resp)
    else:
        print_error(resp)
    return False


def print_empty(message: str) -> None:
    """Print the standard dim empty-state message."""
    console.print(f"[dim]({message})[/dim]")


def print_count(count: int, noun: str, total: int | None = None) -> None:
    """Print a result count, noting when a page is truncated."""
    if total is not None and total != count:
        console.print(f"[dim]showing {count} of {total} {noun}[/dim]")
    else:
        console.print(f"[dim]{count} {noun}[/dim]")


def make_table(
    title: str,
    border_style: str,
    *,
    row_styles: list[str] | None = None,
) -> Table:
    """Build a table with the CLI's standard chrome."""
    kwargs: dict[str, Any] = {
        "title": title,
        "border_style": border_style,
        "show_lines": False,
        "padding": (0, 1),
        "title_style": f"bold {border_style}",
        "header_style": "bold",
    }
    if row_styles is not None:
        kwargs["row_styles"] = row_styles
    return Table(**kwargs)


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------
def ip_sort_key(value: str) -> tuple:
    """Return a sort key that safely handles IPv4, IPv6, CIDRs, and junk.

    ``ipaddress.ip_address()`` raises ``TypeError`` when Python compares an
    IPv4 object with an IPv6 object. Including the address family in the key
    keeps mixed lists sortable and puts unparseable entries last.
    """
    text = str(value or "").strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
        return (0, net.version, int(net.network_address), net.prefixlen)
    except ValueError:
        return (1, 0, 0, text)


def sort_entries_by_ip(
    entries: Iterable[Any],
    key: str | None = "ip",
) -> list[Any]:
    """Sort *entries* by IP, where entries are dicts or plain strings.

    Args:
        entries: Dicts containing an address field, or plain address strings.
        key: Dict key to read. Pass ``None`` when *entries* are strings.
    """

    def _value(entry: Any) -> str:
        if key is None:
            return str(entry or "")
        if isinstance(entry, dict):
            return str(entry.get(key, "") or "")
        return str(getattr(entry, key, "") or "")

    return sorted(entries, key=lambda entry: ip_sort_key(_value(entry)))
