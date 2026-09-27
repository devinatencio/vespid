"""Node management sub-commands for vespid-cli.

Provides CLI access to view enrolled nodes, their health status,
and send remote commands via the central server API.
"""

from __future__ import annotations

import json as _json
import re as _re
from typing import Any

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..server_client import ServerClient, ServerClientError, get_client

nodes_app = typer.Typer(
    name="nodes",
    help="Node management and visibility (requires server connection).",
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


_UUID_RE = _re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    _re.IGNORECASE,
)


def _resolve_node(client: ServerClient, ident: str) -> str | None:
    """Resolve a node ID or hostname to a node ID UUID."""
    if _UUID_RE.match(ident):
        return ident
    try:
        result = client.nodes_list()
    except ServerClientError:
        return None
    nodes = result if isinstance(result, list) else result.get("nodes", [])
    for n in nodes:
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
        if ident.lower() == hostname.lower():
            return n.get("node_id")
    return None


def _health_style(health: str) -> str:
    h = health.lower()
    if h == "healthy":
        return "bold green"
    if h == "degraded":
        return "bold yellow"
    if h in ("offline", "dead", "unknown"):
        return "bold red"
    return "white"


def _health_icon(health: str) -> str:
    h = health.lower()
    if h == "healthy":
        return "🟢"
    if h == "degraded":
        return "🟡"
    return "🔴"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@nodes_app.command("list")
def nodes_list(
    json_output: bool = JsonOption,
) -> None:
    """List all enrolled nodes with health status."""
    client = _get_client()
    try:
        result = client.nodes_list()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    nodes = result if isinstance(result, list) else result.get("nodes", [])

    if not nodes:
        console.print("[dim](no nodes enrolled)[/dim]")
        return

    table = Table(
        title="Enrolled Nodes",
        border_style="cyan",
        show_lines=False,
        padding=(0, 1),
        title_style="bold cyan",
        header_style="bold",
        row_styles=["", "dim"],
    )
    table.add_column("", width=2)  # health icon
    table.add_column("Health")
    table.add_column("Hostname", style="bold")
    table.add_column("Node ID", style="bold white", min_width=36)
    table.add_column("IP", style="dim")
    table.add_column("OS", style="dim")
    table.add_column("Last Event")
    table.add_column("Blocks", justify="right")

    for n in nodes:
        health = n.get("health", "unknown")

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

        os_name = n.get("os_name", "") or hi.get("os", "")

        ifaces = hi.get("interfaces") if isinstance(hi, dict) else []
        ip_addr = "-"
        for iface in ifaces if isinstance(ifaces, list) else []:
            ips = iface.get("ipv4", [])
            if ips:
                ip_addr = ips[0]
                break

        block_count = "-"
        bl = n.get("last_block_list", "")
        if isinstance(bl, str) and bl:
            try:
                parsed = _json.loads(bl)
                block_count = str(len(parsed)) if isinstance(parsed, list) else "-"
            except (ValueError, TypeError):
                pass
        elif isinstance(bl, list):
            block_count = str(len(bl))

        table.add_row(
            _health_icon(health),
            Text(health, style=_health_style(health)),
            hostname or "-",
            n.get("node_id", "-"),
            ip_addr,
            os_name or "-",
            n.get("last_event_at", "-"),
            block_count,
        )

    console.print(table)
    console.print(f"[dim]{len(nodes)} nodes[/dim]")


@nodes_app.command("show")
def nodes_show(
    node_id: str = typer.Argument(..., help="Node ID or hostname to inspect."),
    json_output: bool = JsonOption,
) -> None:
    """Show detailed information for a specific node. Accepts node ID or hostname."""
    client = _get_client()

    resolved = _resolve_node(client, node_id)
    if resolved is None:
        err_console.print(f"[red]Node '{node_id}' not found.[/red]")
        raise typer.Exit(1)
    node_id = resolved

    try:
        result = client.nodes_get(node_id)
    except ServerClientError as exc:
        if exc.status_code == 404:
            err_console.print(f"[red]Node '{node_id}' not found.[/red]")
            raise typer.Exit(1) from exc
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    node = result.get("node", result)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    grid.add_row("node_id", node.get("node_id", node_id))
    health = node.get("health", "unknown")
    grid.add_row("health", Text(f"{_health_icon(health)} {health}", style=_health_style(health)))
    grid.add_row("version", str(node.get("agent_version", node.get("version", "-"))))
    grid.add_row("", "")

    # Host info
    hi = node.get("last_host_info", {})
    if isinstance(hi, str):
        try:
            hi = _json.loads(hi)
        except (ValueError, TypeError):
            hi = {}
    if isinstance(hi, dict) and hi:
        grid.add_row("os", hi.get("os", "-"))
        grid.add_row("hostname", hi.get("hostname", "-"))
        grid.add_row("kernel", hi.get("kernel", "-"))
        if hi.get("fleet_enabled"):
            grid.add_row("fleet", Text("enabled", style="green"))
        grid.add_row("", "")

    # Geo
    geo = node.get("last_geo_data", {})
    if isinstance(geo, str):
        try:
            geo = _json.loads(geo)
        except (ValueError, TypeError):
            geo = {}
    if isinstance(geo, dict) and geo:
        parts = []
        if geo.get("city"):
            parts.append(geo["city"])
        if geo.get("country"):
            parts.append(geo["country"])
        if parts:
            grid.add_row("location", ", ".join(parts))
        if geo.get("asn"):
            grid.add_row("asn", str(geo["asn"]))
        if geo.get("org"):
            grid.add_row("isp", geo["org"])
        grid.add_row("", "")

    # Stats
    grid.add_row("last_event_at", node.get("last_event_at", "-"))
    grid.add_row("total_events", str(node.get("total_events", "-")))

    # Block count from last_block_list
    block_count = "-"
    bl = node.get("last_block_list", "")
    if isinstance(bl, str) and bl:
        try:
            parsed = _json.loads(bl)
            block_count = str(len(parsed)) if isinstance(parsed, list) else "-"
        except (ValueError, TypeError):
            pass
    elif isinstance(bl, list):
        block_count = str(len(bl))
    grid.add_row("local_blocks", block_count)

    # Profile
    profile = node.get("effective_profile", node.get("profile"))
    if profile:
        pname = profile.get("name", str(profile)) if isinstance(profile, dict) else str(profile)
        grid.add_row("config_profile", pname)

    console.print(
        Panel(grid, title=f"[bold]Node: {node_id}[/bold]", border_style="cyan", expand=False)
    )


@nodes_app.command("blocks")
def nodes_blocks(
    node_id: str = typer.Argument(..., help="Node ID or hostname."),
    json_output: bool = JsonOption,
) -> None:
    """Show a node's active block list."""
    client = _get_client()
    resolved = _resolve_node(client, node_id)
    if resolved is None:
        err_console.print(f"[red]Node '{node_id}' not found.[/red]")
        raise typer.Exit(1)
    node_id = resolved

    try:
        result = client.nodes_get(node_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    node = result.get("node", result)
    bl_raw = node.get("last_block_list", "[]")
    blocks: list = []
    if isinstance(bl_raw, str):
        try:
            blocks = _json.loads(bl_raw)
        except (ValueError, TypeError):
            blocks = []
    elif isinstance(bl_raw, list):
        blocks = bl_raw

    if json_output:
        _dump_json({"blocks": blocks})
        return

    if not blocks:
        console.print("[dim](no active blocks)[/dim]")
        return

    hi = node.get("last_host_info", {})
    if isinstance(hi, str):
        try:
            hi = _json.loads(hi)
        except (ValueError, TypeError):
            hi = {}
    hostname = hi.get("hostname", node_id)

    table = Table(
        title=f"Active Blocks — {hostname}",
        border_style="red",
        show_lines=False,
        header_style="bold",
    )
    table.add_column("IP", style="bold white")
    table.add_column("Reason", style="dim")
    table.add_column("TTL Remaining", justify="right")
    table.add_column("Blocked At")
    for b in blocks:
        if isinstance(b, dict):
            table.add_row(
                b.get("ip", "-"),
                b.get("reason", "-"),
                str(b.get("ttl_remaining", "-")),
                b.get("blocked_at", "-"),
            )
        else:
            table.add_row(str(b), "-", "-", "-")
    console.print(table)
    console.print(f"[dim]Total: {len(blocks)} blocks[/dim]")


@nodes_app.command("command")
def nodes_command(
    node_id: str = typer.Argument(..., help="Target node ID or hostname."),
    command_type: str = typer.Argument(
        ..., help="Command type (e.g. unblock, allowlist_add, sync_feeds)."
    ),
    payload: str | None = typer.Option(None, "--payload", help="JSON payload for the command."),
    json_output: bool = JsonOption,
) -> None:
    """Send a remote command to a node."""
    parsed_payload = None
    if payload:
        try:
            parsed_payload = _json.loads(payload)
        except _json.JSONDecodeError as exc:
            err_console.print("[red]Invalid JSON payload.[/red]")
            raise typer.Exit(1) from exc

    client = _get_client()
    resolved = _resolve_node(client, node_id)
    if resolved is None:
        err_console.print(f"[red]Node '{node_id}' not found.[/red]")
        raise typer.Exit(1)
    node_id = resolved
    try:
        result = client.nodes_send_command(node_id, command_type, payload=parsed_payload)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(
        f"[bold green]✅ Command sent[/bold green] → [white]{node_id}[/white]  type=[dim]{command_type}[/dim]"
    )
    cmd_id = result.get("command_id", result.get("id"))
    if cmd_id:
        console.print(f"   [dim]command_id: {cmd_id}[/dim]")


@nodes_app.command("assign-profile")
def nodes_assign_profile(
    node_id: str = typer.Argument(..., help="Target node ID or hostname."),
    profile_id: int = typer.Argument(..., help="Config profile ID to assign."),
    json_output: bool = JsonOption,
) -> None:
    """Assign a configuration profile to a node."""
    client = _get_client()
    resolved = _resolve_node(client, node_id)
    if resolved is None:
        err_console.print(f"[red]Node '{node_id}' not found.[/red]")
        raise typer.Exit(1)
    node_id = resolved
    try:
        result = client.config_create_assignment(profile_id=profile_id, node_id=node_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(
        f"[bold green]✅ Profile #{profile_id} assigned[/bold green] → [white]{node_id}[/white]"
    )
