"""Fleet management sub-commands for vespid-cli.

Provides CLI access to the fleet-wide blocklist, allow-list, and
propagation configuration via the central server API.
"""

from __future__ import annotations

from typing import Any

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..server_client import ServerClient, ServerClientError, get_client
from ._resolve import build_node_map

fleet_app = typer.Typer(
    name="fleet",
    help="Fleet-wide blocklist and propagation management (requires server connection).",
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)

JsonOption = typer.Option(False, "--json", help="Output raw JSON instead of pretty tables.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_client() -> ServerClient:
    """Create a server client, handling configuration errors gracefully."""
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
    import json

    console.print(JSON(json.dumps(data, default=str, sort_keys=True)))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@fleet_app.command("blocks")
def fleet_blocks(
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    per_page: int = typer.Option(50, "--per-page", help="Results per page."),
    source_ip: str | None = typer.Option(None, "--ip", help="Filter by source IP."),
    event_type: str | None = typer.Option(None, "--type", help="Filter by event type."),
    status: str | None = typer.Option(None, "--status", help="Filter by status (active/expired)."),
    json_output: bool = JsonOption,
) -> None:
    """List fleet-wide blocks."""
    client = _get_client()
    try:
        result = client.fleet_list_blocks(
            page=page,
            per_page=per_page,
            source_ip=source_ip,
            event_type=event_type,
            status=status,
        )
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    blocks = result.get("blocks", result.get("items", []))
    total = result.get("total", len(blocks))

    if not blocks:
        console.print("[dim](no fleet blocks)[/dim]")
        return

    table = Table(
        title="Fleet Blocks",
        border_style="magenta",
        show_lines=False,
        padding=(0, 1),
        title_style="bold magenta",
        header_style="bold",
        row_styles=["", "dim"],
    )
    table.add_column("IP", style="bold white", min_width=18)
    table.add_column("Event Type", style="yellow")
    table.add_column("Status")
    table.add_column("Nodes", justify="right")
    table.add_column("First Reported")
    table.add_column("TTL", justify="right")

    for b in blocks:
        st = b.get("status", "active")
        st_style = "green" if st == "active" else "dim"
        nodes = b.get("reporting_nodes", b.get("node_count", "-"))
        table.add_row(
            b.get("source_ip", "-"),
            b.get("event_type", "-"),
            Text(st, style=st_style),
            str(nodes),
            b.get("first_reported_at", b.get("approved_at", "-")),
            str(b.get("ttl_remaining", b.get("ttl_seconds", "-"))),
        )

    console.print(table)
    console.print(f"[dim]Page {page} — {total} total blocks[/dim]")


@fleet_app.command("block")
def fleet_block(
    ip: str = typer.Argument(..., help="IP address to block fleet-wide."),
    reason: str = typer.Option("cli", "--reason", "-r", help="Reason for the block."),
    ttl: int | None = typer.Option(
        None, "--ttl", help="TTL in seconds (uses server default if omitted)."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Add a manual fleet-wide block."""
    client = _get_client()
    try:
        result = client.fleet_add_block(ip, reason=reason, ttl=ttl)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(
        f"[bold red]🚫 Fleet-blocked[/bold red] [white]{ip}[/white]  reason=[dim]{reason}[/dim]"
    )


@fleet_app.command("unblock")
def fleet_unblock(
    ip: str = typer.Argument(..., help="IP address to remove from fleet blocklist."),
    json_output: bool = JsonOption,
) -> None:
    """Remove an IP from the fleet-wide blocklist."""
    client = _get_client()
    try:
        result = client.fleet_remove_block(ip)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]✅ Fleet-unblocked[/bold green] [white]{ip}[/white]")


@fleet_app.command("history")
def fleet_history(
    ip: str = typer.Argument(..., help="IP address to look up reporting history."),
    json_output: bool = JsonOption,
) -> None:
    """Show reporting history for a fleet-blocked IP."""
    client = _get_client()
    try:
        result = client.fleet_block_history(ip)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    reports = result.get("reports", [])
    if not reports:
        console.print(f"[dim]No reporting history for {ip}[/dim]")
        return

    table = Table(
        title=f"Fleet Reports: {ip}",
        border_style="cyan",
        show_lines=False,
        padding=(0, 1),
        title_style="bold cyan",
        header_style="bold",
        row_styles=["", "dim"],
    )
    table.add_column("Node", style="bold")
    table.add_column("Event Type")
    table.add_column("Reported At")
    table.add_column("Detection Rule", style="dim")

    node_map = build_node_map(client)
    for r in reports:
        nid = r.get("node_id", "-")
        table.add_row(
            node_map.get(nid, nid),
            r.get("event_type", "-"),
            r.get("reported_at", "-"),
            r.get("detection_rule", "-"),
        )

    console.print(table)


@fleet_app.command("allowlist")
def fleet_allowlist(
    json_output: bool = JsonOption,
) -> None:
    """List the fleet-wide allow-list."""
    client = _get_client()
    try:
        result = client.fleet_list_allowlist()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    entries = result if isinstance(result, list) else result.get("entries", result.get("items", []))
    if not entries:
        console.print("[dim](fleet allowlist is empty)[/dim]")
        return

    table = Table(
        title="Fleet Allow-list",
        border_style="green",
        show_lines=False,
        padding=(0, 1),
        title_style="bold green",
        header_style="bold",
        row_styles=["", "dim"],
    )
    table.add_column("ID", style="dim")
    table.add_column("IP / CIDR", style="bold white", min_width=20)
    table.add_column("Reason", style="dim")
    table.add_column("Created At")
    table.add_column("Created By", style="cyan")

    for e in entries:
        table.add_row(
            str(e.get("id", "-")),
            e.get("ip", e.get("entry", "-")),
            e.get("reason", "-"),
            e.get("created_at", "-"),
            e.get("created_by", "-"),
        )

    console.print(table)
    console.print(f"[dim]{len(entries)} entries[/dim]")


@fleet_app.command("allow")
def fleet_allow(
    ip: str = typer.Argument(..., help="IP or CIDR to add to fleet allow-list."),
    reason: str = typer.Option("cli", "--reason", "-r", help="Reason for allow-listing."),
    json_output: bool = JsonOption,
) -> None:
    """Add an entry to the fleet-wide allow-list."""
    client = _get_client()
    try:
        result = client.fleet_add_allowlist(ip, reason=reason)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]✅ Fleet allow-listed[/bold green] [white]{ip}[/white]")


@fleet_app.command("deny")
def fleet_deny(
    entry_id: int = typer.Argument(..., help="Allow-list entry ID to remove."),
    json_output: bool = JsonOption,
) -> None:
    """Remove an entry from the fleet-wide allow-list."""
    client = _get_client()
    try:
        result = client.fleet_remove_allowlist(entry_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(
        f"[bold yellow]🗑  Removed[/bold yellow] allow-list entry [white]#{entry_id}[/white]"
    )


@fleet_app.command("config")
def fleet_config(
    json_output: bool = JsonOption,
) -> None:
    """Show current fleet propagation configuration."""
    client = _get_client()
    try:
        result = client.fleet_get_config()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    config = result.get("config", result)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    for key, value in sorted(config.items()):
        if key.startswith("_"):
            continue
        style = "green" if value not in (False, 0, None, "") else "dim"
        grid.add_row(key, Text(str(value), style=style))

    console.print(
        Panel(
            grid,
            title="[bold]Fleet Propagation Config[/bold]",
            border_style="magenta",
            expand=False,
        )
    )


@fleet_app.command("config-set")
def fleet_config_set(
    key: str = typer.Argument(..., help="Config key to update."),
    value: str = typer.Argument(..., help="New value."),
    json_output: bool = JsonOption,
) -> None:
    """Update a fleet propagation config value."""
    # Try to parse value as int/bool/float
    parsed_value: Any = value
    if value.lower() in ("true", "false"):
        parsed_value = value.lower() == "true"
    else:
        try:
            parsed_value = int(value)
        except ValueError:
            try:
                parsed_value = float(value)
            except ValueError:
                pass

    client = _get_client()
    try:
        result = client.fleet_update_config({key: parsed_value})
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(
        f"[bold green]✅ Updated[/bold green] [cyan]{key}[/cyan] = [white]{parsed_value}[/white]"
    )


@fleet_app.command("pause")
def fleet_pause(
    json_output: bool = JsonOption,
) -> None:
    """Toggle fleet propagation pause state."""
    client = _get_client()
    try:
        result = client.fleet_toggle_pause()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    paused = result.get("propagation_paused", result.get("paused"))
    if paused:
        console.print("[bold yellow]⏸  Fleet propagation PAUSED[/bold yellow]")
    else:
        console.print("[bold green]▶  Fleet propagation RESUMED[/bold green]")


@fleet_app.command("reenable")
def fleet_reenable(
    ip: str = typer.Argument(..., help="IP address to re-enable."),
    json_output: bool = JsonOption,
) -> None:
    """Re-enable a previously disabled block."""
    client = _get_client()
    try:
        result = client.fleet_reenable_block(ip)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]✅ Re-enabled block for[/bold green] [white]{ip}[/white]")


@fleet_app.command("active")
def fleet_active(
    json_output: bool = JsonOption,
) -> None:
    """Show currently active fleet-wide blocks."""
    client = _get_client()
    try:
        result = client.fleet_active_blocks()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    blocks = result.get("blocks", result.get("active_blocks", []))
    if not blocks:
        console.print("[dim]No active blocks[/dim]")
        return

    table = Table(title="Active Blocks", border_style="red", show_lines=False)
    table.add_column("IP", style="bold white")
    table.add_column("Reason", style="dim")
    table.add_column("Remaining", justify="right")
    table.add_column("Source", style="dim")

    for b in blocks:
        remaining = b.get("remaining_ttl", b.get("ttl", "-"))
        table.add_row(
            b.get("source_ip", b.get("ip", "-")),
            b.get("reason", "-"),
            str(remaining),
            b.get("source", "-"),
        )

    console.print(table)
    console.print(f"[dim]Total: {len(blocks)} active blocks[/dim]")


@fleet_app.command("reap")
def fleet_reap(
    json_output: bool = JsonOption,
) -> None:
    """Manually trigger a fleet block reap + purge cycle."""
    client = _get_client()
    try:
        result = client.fleet_reap()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    expired = result.get("expired", 0)
    purged = result.get("purged", 0)
    if expired or purged:
        console.print(
            f"[bold green]Reap complete[/bold green]  "
            f"expired=[cyan]{expired}[/cyan]  "
            f"purged=[cyan]{purged}[/cyan]"
        )
    else:
        console.print("[dim]Reap complete — nothing to expire or purge[/dim]")
