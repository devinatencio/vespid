"""Metrics sub-commands for vespid-cli.

Provides CLI access to agent metrics summary, PromQL queries, saved queries,
and logfile watch management.
"""

from __future__ import annotations

import json as _json
from datetime import datetime, timezone
from typing import Any

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..server_client import ServerClient, ServerClientError, get_client
from ._resolve import resolve_node

metrics_app = typer.Typer(
    name="metrics",
    help="Agent metrics and PromQL queries (requires server connection).",
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


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


@metrics_app.command("summary")
def metrics_summary(
    json_output: bool = JsonOption,
) -> None:
    """Show agent metrics summary."""
    client = _get_client()
    try:
        result = client.metrics_summary()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    summary = result.get("summary", {})
    agent_count = summary.get("agent_count", 0)
    responding = summary.get("responding", 0)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()
    grid.add_row("agent_count", str(agent_count))
    grid.add_row("responding", Text(str(responding), style="green" if responding else "red"))
    if responding:
        grid.add_row("avg_cpu", f"{summary.get('avg_cpu_pct', 0):.1f}%")
        grid.add_row("avg_mem", f"{summary.get('avg_mem_pct', 0):.1f}%")
    console.print(Panel(grid, title="Metrics Summary", border_style="green", expand=False))

    agents = result.get("agents", [])
    if agents:
        atable = Table(border_style="green", show_lines=False)
        atable.add_column("Agent ID", style="bold white")
        atable.add_column("Hostname")
        atable.add_column("CPU", justify="right")
        atable.add_column("Memory", justify="right")
        atable.add_column("Disk", justify="right")
        atable.add_column("Responding")

        for a in agents:
            cpu = a.get("cpu_pct")
            mem = a.get("memory_pct", a.get("mem_pct"))
            disk = a.get("disk_max_pct", a.get("disk_pct"))
            responding = cpu is not None or mem is not None
            atable.add_row(
                a.get("agent_id", "-"),
                a.get("hostname", "-"),
                f"{cpu:.1f}%" if cpu is not None else "[dim]—[/dim]",
                f"{mem:.1f}%" if mem is not None else "[dim]—[/dim]",
                f"{disk:.1f}%" if disk is not None else "[dim]—[/dim]",
                Text("yes" if responding else "no", style="green" if responding else "red"),
            )
        console.print(atable)


# ---------------------------------------------------------------------------
# Agent detail
# ---------------------------------------------------------------------------


@metrics_app.command("agent")
def metrics_agent(
    agent_id: str = typer.Argument(..., help="Agent ID or hostname."),
    range: str = typer.Option("1h", "--range", "-r", help="Time range: 1h, 6h, 24h, 3d, 7d."),
    json_output: bool = JsonOption,
) -> None:
    """Show detailed metrics for a specific agent."""
    client = _get_client()
    resolved = resolve_node(client, agent_id)
    if resolved is None:
        err_console.print(f"[red]Agent '{agent_id}' not found.[/red]")
        raise typer.Exit(1)
    agent_id = resolved
    try:
        result = client.metrics_agent_range(agent_id, range=range)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    series = result.get("series", {})

    has_data = any(points for points in series.values())

    if not has_data:
        console.print("[dim](no metrics data — agent may not be reporting)[/dim]")
        return

    console.print(
        f"[bold]Agent: {agent_id}[/bold]  range=[cyan]{result.get('range', range)}[/cyan]"
    )

    table = Table(border_style="green", show_lines=False, header_style="bold")
    table.add_column("Metric", style="bold white")
    table.add_column("Value", justify="right")
    table.add_column("Time")

    for metric_name, points in sorted(series.items()):
        if not points:
            continue
        latest = points[-1]
        raw = latest.get("v")
        ts = latest.get("t", "")

        if isinstance(ts, (int, float)):
            time_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
        else:
            time_str = str(ts)

        if metric_name in (
            "cpu_usage",
            "memory_used_percent",
            "disk_used_percent",
            "swap_used_percent",
        ):
            val = f"{raw:.1f}%" if raw is not None else "-"
        elif metric_name in ("process_count_total", "process_running", "process_zombies_count"):
            val = f"{int(raw)}" if raw is not None else "-"
        elif metric_name in ("network_bytes_recv", "network_bytes_sent"):
            val = _fmt_bytes(raw) + "/s" if raw is not None else "-"
        else:
            val = f"{raw:.2f}" if isinstance(raw, float) else str(raw or "-")

        table.add_row(metric_name, val, time_str)

    console.print(table)


# ---------------------------------------------------------------------------
# PromQL query
# ---------------------------------------------------------------------------


@metrics_app.command("query")
def metrics_query(
    query: str = typer.Argument(..., help="PromQL query string."),
    json_output: bool = JsonOption,
) -> None:
    """Execute an instant PromQL query."""
    client = _get_client()
    try:
        result = client.metrics_query(query)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(JSON(_json.dumps(result, default=str, sort_keys=True)))


@metrics_app.command("query-range")
def metrics_query_range(
    query: str = typer.Argument(..., help="PromQL query string."),
    start: str = typer.Option("-1h", "--start", "-s", help="Start time."),
    end: str | None = typer.Option(None, "--end", "-e", help="End time."),
    step: str = typer.Option("60s", "--step", help="Step interval."),
    json_output: bool = JsonOption,
) -> None:
    """Execute a range PromQL query."""
    client = _get_client()
    try:
        result = client.metrics_query_range(query, start=start, step=step, end=end)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(JSON(_json.dumps(result, default=str, sort_keys=True)))


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


@metrics_app.command("labels")
def metrics_labels(
    label_name: str = typer.Argument(..., help="Label name (e.g. agent_id, hostname)."),
    json_output: bool = JsonOption,
) -> None:
    """Show distinct values for a metric label."""
    client = _get_client()
    try:
        result = client.metrics_labels(label_name)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    values = result.get("data", result.get("values", []))
    if not values:
        console.print("[dim](no values)[/dim]")
        return

    for v in values:
        console.print(v)
    console.print(f"[dim]{len(values)} values[/dim]")


# ---------------------------------------------------------------------------
# Saved queries
# ---------------------------------------------------------------------------


@metrics_app.command("saved-queries")
def metrics_saved_queries(
    action: str = typer.Argument("list", help="Action: list, create, update, delete."),
    query_id: int | None = typer.Option(None, "--id", help="Query ID (update/delete)."),
    name: str | None = typer.Option(None, "--name", "-n", help="Query name."),
    query: str | None = typer.Option(None, "--query", "-q", help="PromQL query."),
    json_output: bool = JsonOption,
) -> None:
    """Manage saved PromQL queries."""
    client = _get_client()

    if action == "list":
        try:
            result = client.metrics_saved_queries_list()
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc

        if json_output:
            _dump_json(result)
            return

        queries = result if isinstance(result, list) else result.get("queries", [])
        if not queries:
            console.print("[dim](no saved queries)[/dim]")
            return

        table = Table(title="Saved Queries", border_style="blue", show_lines=False)
        table.add_column("ID", style="dim", justify="right")
        table.add_column("Name", style="bold white")
        table.add_column("Query", style="dim")
        for q in queries:
            table.add_row(str(q.get("id", "-")), q.get("name", "-"), q.get("query", "-"))
        console.print(table)

    elif action == "create":
        if not name or not query:
            err_console.print("[red]--name and --query are required for create.[/red]")
            raise typer.Exit(1)
        try:
            result = client.metrics_saved_queries_create(name, query)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        qid = result.get("query", result).get("id", "?")
        console.print(f"[bold green]Query saved[/bold green]  id=[white]{qid}[/white]")

    elif action == "update":
        if not query_id:
            err_console.print("[red]--id is required for update.[/red]")
            raise typer.Exit(1)
        data: dict[str, Any] = {}
        if name:
            data["name"] = name
        if query:
            data["query"] = query
        if not data:
            err_console.print("[red]At least --name or --query is required.[/red]")
            raise typer.Exit(1)
        try:
            result = client.metrics_saved_queries_update(query_id, name or "", query or "")
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        console.print(f"[bold green]Query #{query_id} updated[/bold green]")

    elif action == "delete":
        if not query_id:
            err_console.print("[red]--id is required for delete.[/red]")
            raise typer.Exit(1)
        try:
            result = client.metrics_saved_queries_delete(query_id)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        console.print(f"[bold yellow]Query #{query_id} deleted[/bold yellow]")

    else:
        err_console.print(f"[red]Unknown action: {action}[/red]")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Logfile watches
# ---------------------------------------------------------------------------


@metrics_app.command("logfile-watches")
def metrics_logfile_watches(
    action: str = typer.Argument("list", help="Action: list, create, update, delete."),
    agent_id: str | None = typer.Option(None, "--agent", "-a", help="Agent ID."),
    watch_id: int | None = typer.Option(None, "--id", help="Watch ID (update/delete)."),
    name: str | None = typer.Option(None, "--name", "-n", help="Watch name (create/update)."),
    path: str | None = typer.Option(None, "--path", "-p", help="Log file path (create/update)."),
    pattern: str | None = typer.Option(None, "--pattern", help="Match pattern (create/update)."),
    enabled: bool | None = typer.Option(None, "--enabled/--disabled", help="Enable or disable."),
    json_output: bool = JsonOption,
) -> None:
    """Manage logfile watches."""
    client = _get_client()

    if action == "list":
        try:
            result = client.logfile_watches_list(agent_id=agent_id)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc

        if json_output:
            _dump_json(result)
            return

        watches = result if isinstance(result, list) else result.get("watches", [])
        if not watches:
            console.print("[dim](no logfile watches)[/dim]")
            return

        table = Table(title="Logfile Watches", border_style="blue", show_lines=False)
        table.add_column("ID", style="dim", justify="right")
        table.add_column("Name", style="bold white")
        table.add_column("Agent ID")
        table.add_column("Path", style="dim")
        table.add_column("Enabled")

        for w in watches:
            en = w.get("enabled", False)
            table.add_row(
                str(w.get("id", "-")),
                w.get("name", "-"),
                w.get("agent_id") or "(all)",
                w.get("path", "-"),
                Text("on" if en else "off", style="green" if en else "dim"),
            )
        console.print(table)

    elif action == "create":
        if not name or not path or not agent_id:
            err_console.print("[red]--name, --path, and --agent are required for create.[/red]")
            raise typer.Exit(1)
        watch: dict[str, Any] = {
            "name": name,
            "path": path,
            "agent_id": agent_id,
        }
        if pattern:
            watch["pattern"] = pattern
        if enabled is not None:
            watch["enabled"] = enabled
        try:
            result = client.logfile_watches_create(watch)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        wid = result.get("id", "?")
        console.print(f"[bold green]Logfile watch created[/bold green]  id=[white]{wid}[/white]")

    elif action == "update":
        if not watch_id:
            err_console.print("[red]--id is required for update.[/red]")
            raise typer.Exit(1)
        update: dict[str, Any] = {}
        if name is not None:
            update["name"] = name
        if path is not None:
            update["path"] = path
        if pattern is not None:
            update["pattern"] = pattern
        if enabled is not None:
            update["enabled"] = enabled
        if not update:
            err_console.print("[red]At least one field to update is required.[/red]")
            raise typer.Exit(1)
        try:
            result = client.logfile_watches_update(watch_id, update)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        console.print(f"[bold green]Logfile watch #{watch_id} updated[/bold green]")

    elif action == "delete":
        if not watch_id:
            err_console.print("[red]--id is required for delete.[/red]")
            raise typer.Exit(1)
        try:
            result = client.logfile_watches_delete(watch_id)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        console.print(f"[bold yellow]Logfile watch #{watch_id} deleted[/bold yellow]")

    else:
        err_console.print(f"[red]Unknown action: {action}[/red]")
        raise typer.Exit(1)
