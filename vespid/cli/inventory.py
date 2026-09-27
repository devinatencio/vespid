"""Inventory sub-commands for vespid-cli.

Provides CLI access to asset inventory querying, graph views,
and admin management (merge, purge, delete).
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

inventory_app = typer.Typer(
    name="inventory",
    help="Asset inventory queries and management (requires server connection).",
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)

JsonOption = typer.Option(False, "--json", help="Output raw JSON instead of pretty tables.")


def _get_client() -> ServerClient:
    try:
        return get_client()
    except (ValueError, ImportError) as exc:
        err_console.print(f"[red]Server connection error:[/red] {exc}")
        raise typer.Exit(1) from exc


def _handle_error(exc: ServerClientError) -> None:
    err_console.print(
        Panel(
            f"[red]{exc.detail}[/red]\n\n[dim]HTTP {exc.status_code}[/dim]",
            title="[red]Server Error[/red]",
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


def _resolve_asset(client: ServerClient, ident: str) -> str | None:
    """Resolve an asset ID or display_name/hostname to an asset UUID."""
    if _UUID_RE.match(ident):
        return ident
    try:
        result: Any = client.inventory_query(limit=500)
    except ServerClientError:
        return None
    assets = result if isinstance(result, list) else result.get("results", result.get("assets", []))
    for a in assets:
        name = a.get("display_name") or a.get("name") or ""
        aid = str(a.get("asset_id") or a.get("id") or "")
        if ident.lower() == name.lower() or ident.lower() == aid.lower():
            return aid
    return None


# ---------------------------------------------------------------------------
# Query / List
# ---------------------------------------------------------------------------


@inventory_app.command("list")
def inventory_list(
    q: str | None = typer.Option(None, "--query", "-q", help="Search query."),
    asset_type: str | None = typer.Option(None, "--type", "-t", help="Asset type filter."),
    source: str | None = typer.Option(None, "--source", "-s", help="Source filter."),
    status: str | None = typer.Option(None, "--status", "-S", help="Status filter."),
    label: str | None = typer.Option(None, "--label", "-l", help="Label filter (key=value)."),
    parent: str | None = typer.Option(None, "--parent", "-p", help="Parent asset ID."),
    limit: int = typer.Option(100, "--limit", "-L", help="Max results."),
    offset: int = typer.Option(0, "--offset", "-O", help="Result offset."),
    json_output: bool = JsonOption,
) -> None:
    """Query the asset inventory."""
    client = _get_client()
    try:
        result: Any = client.inventory_query(
            q=q,
            asset_type=asset_type,
            source=source,
            status=status,
            label=label,
            parent=parent,
            limit=limit,
            offset=offset,
        )
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    assets = result if isinstance(result, list) else result.get("results", result.get("assets", []))
    total = result.get("total", len(assets))

    if not assets:
        console.print("[dim](no matching assets)[/dim]")
        return

    table = Table(
        title=f"Assets (showing {len(assets)} of {total})", border_style="green", show_lines=False
    )
    table.add_column("ID", style="bold white", no_wrap=True)
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Source")
    table.add_column("Labels")

    for a in assets:
        labels = a.get("labels", {}) or {}
        if isinstance(labels, str):
            try:
                labels = _json.loads(labels)
            except (ValueError, TypeError):
                labels = {}
        label_str = ", ".join(f"{k}={v}" for k, v in labels.items()) if labels else ""
        table.add_row(
            str(a.get("asset_id") or a.get("id") or "-"),
            str(a.get("display_name") or a.get("name") or "-"),
            a.get("asset_type", a.get("type", "-")),
            Text(a.get("status", "-"), style="green" if a.get("status") == "active" else "yellow"),
            a.get("created_by_source") or a.get("source") or "-",
            label_str[:60] or "[dim]—[/dim]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Get asset detail
# ---------------------------------------------------------------------------


@inventory_app.command("get")
def inventory_get(
    asset_id: str = typer.Argument(..., help="Asset ID or hostname."),
    json_output: bool = JsonOption,
) -> None:
    """Show detailed information for a single asset."""
    client = _get_client()
    resolved = _resolve_asset(client, asset_id)
    if resolved is None:
        err_console.print(f"[red]Asset '{asset_id}' not found.[/red]")
        raise typer.Exit(1)
    asset_id = resolved
    try:
        result = client.inventory_asset(asset_id)
    except ServerClientError as exc:
        if exc.status_code == 404:
            err_console.print(f"[red]Asset '{asset_id}' not found.[/red]")
            raise typer.Exit(1) from exc
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    asset = (
        result
        if isinstance(result, dict) and ("id" in result or "asset_id" in result)
        else result.get("asset", result)
    )
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    for key in (
        "asset_id",
        "id",
        "display_name",
        "name",
        "asset_type",
        "type",
        "status",
        "source",
        "created_at",
        "updated_at",
    ):
        val = asset.get(key)
        if val is not None:
            grid.add_row(key.replace("_", " "), str(val))

    labels = asset.get("labels", {}) or {}
    if isinstance(labels, str):
        try:
            labels = _json.loads(labels)
        except (ValueError, TypeError):
            labels = {}
    if labels:
        grid.add_row("labels", ", ".join(f"{k}={v}" for k, v in labels.items()))

    props = asset.get("properties", {}) or {}
    if props:
        grid.add_row("properties", _json.dumps(props, default=str))

    console.print(Panel(grid, title=f"Asset: {asset_id}", border_style="green", expand=False))


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


@inventory_app.command("export")
def inventory_export(
    json_output: bool = JsonOption,
) -> None:
    """Export the full asset inventory."""
    client = _get_client()
    try:
        result = client.inventory_export()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(JSON(_json.dumps(result, default=str, sort_keys=True)))


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


@inventory_app.command("graph")
def inventory_graph(
    json_output: bool = JsonOption,
) -> None:
    """View inventory graph data (nodes and edges)."""
    client = _get_client()
    try:
        result = client.inventory_graph()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    nodes = result.get("nodes", [])
    edges = result.get("edges", [])

    console.print(
        f"[bold]Graph[/bold]  [cyan]{len(nodes)}[/cyan] nodes, [cyan]{len(edges)}[/cyan] edges"
    )

    if nodes:
        nt = Table(title="Nodes", border_style="blue", show_lines=False)
        nt.add_column("ID", style="bold white")
        nt.add_column("Name")
        nt.add_column("Type")
        for n in nodes:
            nt.add_row(
                str(n.get("asset_id") or n.get("id") or "-"),
                n.get("label") or n.get("display_name") or n.get("name") or "-",
                n.get("asset_type", n.get("type", "-")),
            )
        console.print(nt)

    if edges:
        et = Table(title="Edges", border_style="dim", show_lines=False)
        et.add_column("Source", style="bold")
        et.add_column("Target", style="bold")
        et.add_column("Relation")
        for e in edges:
            et.add_row(str(e.get("source", "-")), str(e.get("target", "-")), e.get("relation", "-"))
        console.print(et)


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------


@inventory_app.command("relationships")
def inventory_relationships(
    asset_id: str = typer.Argument(..., help="Asset ID or hostname."),
    json_output: bool = JsonOption,
) -> None:
    """View relationships for an asset."""
    client = _get_client()
    resolved = _resolve_asset(client, asset_id)
    if resolved is None:
        err_console.print(f"[red]Asset '{asset_id}' not found.[/red]")
        raise typer.Exit(1)
    asset_id = resolved
    try:
        result = client.inventory_relationships(asset_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    rels = result if isinstance(result, list) else result.get("relationships", [])
    if not rels:
        console.print("[dim](no relationships)[/dim]")
        return

    table = Table(title=f"Relationships: {asset_id}", border_style="blue", show_lines=False)
    table.add_column("Relationship", style="bold")
    table.add_column("Source", style="bold white")
    table.add_column("Target", style="bold white")
    for r in rels:
        table.add_row(
            r.get("relationship", r.get("type", "-")),
            r.get("source_name", r.get("source_asset_id", "-")),
            r.get("target_name", r.get("target_asset_id", "-")),
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Admin: Status
# ---------------------------------------------------------------------------


@inventory_app.command("status")
def inventory_status(
    json_output: bool = JsonOption,
) -> None:
    """Show admin inventory status (counts, health)."""
    client = _get_client()
    try:
        result = client.admin_inventory_status()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    for key, val in sorted(result.items()):
        grid.add_row(key.replace("_", " "), str(val))

    console.print(Panel(grid, title="Inventory Admin Status", border_style="green", expand=False))


# ---------------------------------------------------------------------------
# Admin: Purge stale
# ---------------------------------------------------------------------------


@inventory_app.command("purge-stale")
def inventory_purge_stale(
    json_output: bool = JsonOption,
) -> None:
    """Purge stale assets from the inventory."""
    client = _get_client()
    try:
        result = client.admin_inventory_purge_stale()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(JSON(_json.dumps(result, default=str, sort_keys=True)))


# ---------------------------------------------------------------------------
# Admin: Merge
# ---------------------------------------------------------------------------


@inventory_app.command("merge")
def inventory_merge(
    keep_id: str = typer.Argument(..., help="Asset ID to keep."),
    discard_id: str = typer.Argument(..., help="Asset ID to discard/merge from."),
    json_output: bool = JsonOption,
) -> None:
    """Merge two duplicate assets into one."""
    client = _get_client()
    try:
        result = client.admin_inventory_merge(keep_id, discard_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(
        f"[bold green]Merged[/bold green] [white]{discard_id}[/white] → [white]{keep_id}[/white]"
    )


# ---------------------------------------------------------------------------
# Admin: Delete
# ---------------------------------------------------------------------------


@inventory_app.command("delete")
def inventory_delete(
    asset_id: str = typer.Argument(..., help="Asset ID to delete."),
    json_output: bool = JsonOption,
) -> None:
    """Delete an asset from the inventory."""
    client = _get_client()
    try:
        result = client.admin_inventory_delete_asset(asset_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]Deleted[/bold yellow] asset [white]{asset_id}[/white]")
