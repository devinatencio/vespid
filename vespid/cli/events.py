"""Events sub-commands for vespid-cli.

Provides CLI access to search and export events from the central server,
giving operators the same event visibility as the web dashboard.
"""

from __future__ import annotations

import json as _json
from typing import Any

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..server_client import ServerClient, ServerClientError, get_client

events_app = typer.Typer(
    name="events",
    help="Event search and export (requires server connection).",
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)

JsonOption = typer.Option(False, "--json", help="Output raw JSON instead of pretty tables.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_client() -> ServerClient:
    try:
        return get_client()
    except (ValueError, ImportError) as exc:
        err_console.print(f"[red]✖ Server connection error:[/red] {exc}")
        raise typer.Exit(1) from exc


def _handle_error(exc: ServerClientError) -> None:
    err_console.print(
        Panel(
            f"[red]{exc.detail}[/red]\n\n[dim]HTTP {exc.status_code}[/dim]",
            title="[red]✖ Server Error[/red]",
            border_style="red",
            expand=False,
        )
    )


def _dump_json(data: Any) -> None:
    console.print(JSON(_json.dumps(data, default=str, sort_keys=True)))


def _load_node_map(client: ServerClient) -> dict[str, str]:
    """Build a UUID → hostname map from all enrolled nodes."""
    try:
        result = client.nodes_list()
    except ServerClientError:
        return {}
    nodes = result if isinstance(result, list) else result.get("nodes", [])
    mapping: dict[str, str] = {}
    for n in nodes:
        nid = n.get("node_id", "")
        if not nid:
            continue
        hi = n.get("last_host_info", {})
        if isinstance(hi, str):
            try:
                hi = _json.loads(hi)
            except (ValueError, TypeError):
                hi = {}
        hostname = (
            n.get("display_name", "")
            or n.get("node_display", "")
            or hi.get("hostname", "")
            or hi.get("host_name", "")
        )
        if hostname:
            mapping[nid] = hostname
    return mapping


def _action_style(action: str) -> str:
    a = action.lower()
    if a in ("block", "blocked"):
        return "bold red"
    if a in ("unblock", "unblocked"):
        return "bold green"
    if a in ("observed", "detect", "detected"):
        return "yellow"
    return "white"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@events_app.command("search")
def events_search(
    source_ip: str | None = typer.Option(None, "--ip", help="Filter by source IP."),
    event_type: str | None = typer.Option(None, "--type", help="Filter by event type."),
    node_id: str | None = typer.Option(None, "--node", help="Filter by node ID."),
    action_taken: str | None = typer.Option(
        None, "--action", help="Filter by action (BLOCKED, OBSERVED, etc)."
    ),
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    per_page: int = typer.Option(50, "--per-page", help="Results per page."),
    json_output: bool = JsonOption,
) -> None:
    """Search events on the central server."""
    client = _get_client()
    try:
        result = client.events_search(
            page=page,
            per_page=per_page,
            source_ip=source_ip,
            event_type=event_type,
            node_id=node_id,
            action_taken=action_taken,
        )
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    events = result.get("events", result.get("results", []))
    total = result.get("total", len(events))

    if not events:
        console.print("[dim](no events found)[/dim]")
        return

    node_map = _load_node_map(client)

    table = Table(
        title="Events",
        border_style="blue",
        show_lines=False,
        padding=(0, 1),
        title_style="bold blue",
        header_style="bold",
        row_styles=["", "dim"],
    )
    table.add_column("Time", style="dim")
    table.add_column("Type", style="bold")
    table.add_column("Action")
    table.add_column("IP", style="bold white", min_width=16)
    table.add_column("Node", style="dim")
    table.add_column("Country")

    for ev in events:
        action = ev.get("action_taken", "-")
        geo = ev.get("geo_data", {})
        if isinstance(geo, str):
            try:
                geo = _json.loads(geo)
            except (ValueError, TypeError):
                geo = {}
        country = geo.get("country", "-") if isinstance(geo, dict) else "-"
        raw_node = ev.get("node_id", "-")
        display_node = node_map.get(raw_node, raw_node)

        table.add_row(
            ev.get("timestamp", "-"),
            ev.get("event_type", "-"),
            Text(action, style=_action_style(action)),
            ev.get("source_ip", "-"),
            display_node,
            country,
        )

    console.print(table)
    console.print(f"[dim]Page {page} — {total} total events[/dim]")


@events_app.command("export")
def events_export(
    format: str = typer.Option("json", "--format", "-f", help="Export format: json or csv."),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Output file path (stdout if omitted)."
    ),
    source_ip: str | None = typer.Option(None, "--ip", help="Filter by source IP."),
    event_type: str | None = typer.Option(None, "--type", help="Filter by event type."),
    node_id: str | None = typer.Option(None, "--node", help="Filter by node ID."),
    action_taken: str | None = typer.Option(None, "--action", help="Filter by action."),
) -> None:
    """Export events from the central server."""
    client = _get_client()
    try:
        result = client.events_export(
            format=format,
            source_ip=source_ip,
            event_type=event_type,
            node_id=node_id,
            action_taken=action_taken,
        )
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if isinstance(result, (dict, list)):
        content = _json.dumps(result, indent=2, default=str)
    else:
        content = str(result)

    if output:
        with open(output, "w") as f:
            f.write(content)
        console.print(f"[bold green]✅ Exported to {output}[/bold green]")
    else:
        console.print(content)
