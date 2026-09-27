"""Alert management sub-commands for vespid-cli.

Provides CLI access to alert rules, active alerts, notification channels,
silences, monitoring groups, and hosts via the central server API.
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
from ._resolve import resolve_node

alerts_app = typer.Typer(
    name="alerts",
    help="Alert and monitoring management (requires server connection).",
    no_args_is_help=True,
)

# Sub-groups
rules_app = typer.Typer(name="rules", help="Manage alert rules.", no_args_is_help=True)
active_app = typer.Typer(name="active", help="View and manage active alerts.", no_args_is_help=True)
channels_app = typer.Typer(
    name="channels", help="Manage notification channels.", no_args_is_help=True
)
silences_app = typer.Typer(name="silences", help="Manage alert silences.", no_args_is_help=True)
groups_app = typer.Typer(name="groups", help="Manage monitoring groups.", no_args_is_help=True)
conditions_app = typer.Typer(
    name="conditions", help="Manage group alert conditions.", no_args_is_help=True
)

alerts_app.add_typer(rules_app)
alerts_app.add_typer(active_app)
alerts_app.add_typer(channels_app)
alerts_app.add_typer(silences_app)
alerts_app.add_typer(groups_app)
alerts_app.add_typer(conditions_app)

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


def _severity_style(severity: str) -> str:
    return {"critical": "red", "warning": "yellow", "ok": "green"}.get(severity, "dim")


def _state_style(state: str) -> str:
    return {"firing": "red", "acknowledged": "yellow", "resolved": "green"}.get(state, "dim")


# ---------------------------------------------------------------------------
# Alert Rules
# ---------------------------------------------------------------------------


@rules_app.command("list")
def rules_list(
    json_output: bool = JsonOption,
) -> None:
    """List all alert rules."""
    client = _get_client()
    try:
        result = client.alerts_rules_list()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    rules = result if isinstance(result, list) else result.get("rules", [])
    if not rules:
        console.print("[dim](no alert rules)[/dim]")
        return

    table = Table(title="Alert Rules", border_style="red", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Name", style="bold white")
    table.add_column("Severity")
    table.add_column("Enabled")
    table.add_column("Type", style="dim")
    table.add_column("Threshold")
    table.add_column("Interval", justify="right")

    for r in rules:
        sev = r.get("severity", "-")
        enabled = r.get("enabled", False)
        enabled_text = Text("on" if enabled else "off", style="green" if enabled else "dim")
        metric_type = "promql" if r.get("query") else r.get("check_name", "-")

        table.add_row(
            str(r.get("id", "-")),
            r.get("name", "-"),
            Text(sev, style=_severity_style(sev)),
            enabled_text,
            metric_type,
            str(r.get("operator", "")) + " " + str(r.get("threshold", "")),
            str(r.get("interval_secs", "-")) + "s",
        )

    console.print(table)
    console.print(f"[dim]Total: {len(rules)} rules[/dim]")


@rules_app.command("show")
def rules_show(
    rule_id: int = typer.Argument(..., help="Rule ID to inspect."),
    json_output: bool = JsonOption,
) -> None:
    """Show detailed alert rule."""
    client = _get_client()
    try:
        result = client.alerts_rules_list()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    rules = result if isinstance(result, list) else result.get("rules", [])
    rule = None
    for r in rules:
        if r.get("id") == rule_id:
            rule = r
            break

    if rule is None:
        err_console.print(f"[red]Rule #{rule_id} not found[/red]")
        raise typer.Exit(1)

    if json_output:
        _dump_json(rule)
        return

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    grid.add_row("id", str(rule.get("id", "-")))
    grid.add_row("name", rule.get("name", "-"))
    grid.add_row(
        "severity", Text(rule.get("severity", "-"), style=_severity_style(rule.get("severity", "")))
    )
    enabled = rule.get("enabled", False)
    grid.add_row("enabled", Text("yes" if enabled else "no", style="green" if enabled else "dim"))

    if rule.get("query"):
        grid.add_row("query", rule["query"])
    if rule.get("check_name"):
        grid.add_row("check", rule["check_name"])

    grid.add_row("operator", rule.get("operator", "-"))
    grid.add_row("threshold", str(rule.get("threshold", "-")))
    grid.add_row("resolve_threshold", str(rule.get("resolve_threshold", "-")))
    grid.add_row("for_duration", str(rule.get("for_duration", "-")) + "s")
    grid.add_row("cooldown", str(rule.get("cooldown_secs", "-")))
    grid.add_row("interval", str(rule.get("interval_secs", "-")) + "s")
    grid.add_row("created", rule.get("created_at", "-"))
    grid.add_row("updated", rule.get("updated_at", "-"))

    tags = rule.get("tags", {})
    if tags:
        grid.add_row("tags", str(tags))

    channels = rule.get("channel_ids", [])
    if channels:
        grid.add_row("channels", str(channels))

    console.print(
        Panel(
            grid,
            title=f"[bold]Alert Rule: {rule.get('name', rule_id)}[/bold]",
            border_style="red",
            expand=False,
        )
    )


@rules_app.command("create")
def rules_create(
    name: str = typer.Argument(..., help="Rule name."),
    severity: str = typer.Option("warning", "--severity", "-s", help="warning or critical."),
    operator: str = typer.Option(">", "--operator", "-o", help="Comparison operator."),
    threshold: float = typer.Option(..., "--threshold", "-t", help="Threshold value."),
    query: str | None = typer.Option(None, "--query", "-q", help="PromQL query."),
    check_name: str | None = typer.Option(
        None, "--check", "-c", help="Check name (mutual excl. with query)."
    ),
    for_duration: int = typer.Option(0, "--for", help="For duration in seconds."),
    interval: int = typer.Option(60, "--interval", help="Evaluation interval in seconds."),
    enabled: bool = typer.Option(True, "--enabled/--disabled", help="Enable rule."),
    json_output: bool = JsonOption,
) -> None:
    """Create a new alert rule."""
    rule: dict[str, Any] = {
        "name": name,
        "severity": severity,
        "operator": operator,
        "threshold": threshold,
        "for_duration": for_duration,
        "interval_secs": interval,
        "enabled": enabled,
    }
    if query:
        rule["query"] = query
    if check_name:
        rule["check_name"] = check_name

    client = _get_client()
    try:
        result = client.alerts_rules_create(rule)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    rid = result.get("rule", result).get("id", "?")
    console.print(
        f"[bold green]Alert rule created[/bold green]  id=[white]{rid}[/white]  name=[cyan]{name}[/cyan]"
    )


@rules_app.command("update")
def rules_update(
    rule_id: int = typer.Argument(..., help="Rule ID to update."),
    name: str | None = typer.Option(None, "--name", "-n", help="New name."),
    severity: str | None = typer.Option(None, "--severity", "-s", help="warning or critical."),
    operator: str | None = typer.Option(None, "--operator", "-o", help="Comparison operator."),
    threshold: float | None = typer.Option(None, "--threshold", "-t", help="Threshold value."),
    enabled: bool | None = typer.Option(
        None, "--enabled/--disabled", help="Enable or disable rule."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Update an alert rule."""
    rule: dict[str, Any] = {}
    if name is not None:
        rule["name"] = name
    if severity is not None:
        rule["severity"] = severity
    if operator is not None:
        rule["operator"] = operator
    if threshold is not None:
        rule["threshold"] = threshold
    if enabled is not None:
        rule["enabled"] = enabled

    if not rule:
        err_console.print("[red]At least one field to update is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.alerts_rules_update(rule_id, rule)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Rule #{rule_id} updated[/bold green]")


@rules_app.command("delete")
def rules_delete(
    rule_id: int = typer.Argument(..., help="Rule ID to delete."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
    json_output: bool = JsonOption,
) -> None:
    """Delete an alert rule."""
    if not force and not json_output:
        confirm = typer.confirm(f"Delete rule #{rule_id}?")
        if not confirm:
            raise typer.Abort()

    client = _get_client()
    try:
        result = client.alerts_rules_delete(rule_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]Rule #{rule_id} deleted[/bold yellow]")


@rules_app.command("toggle")
def rules_toggle(
    rule_id: int = typer.Argument(..., help="Rule ID to toggle."),
    enabled: bool = typer.Option(True, "--on/--off", help="Enable or disable."),
    json_output: bool = JsonOption,
) -> None:
    """Enable or disable an alert rule."""
    client = _get_client()
    try:
        result = client.alerts_rules_update(rule_id, {"enabled": enabled})
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    state = "enabled" if enabled else "disabled"
    console.print(f"[bold green]Rule #{rule_id} {state}[/bold green]")


# ---------------------------------------------------------------------------
# Active Alerts
# ---------------------------------------------------------------------------


@active_app.command("list")
def active_list(
    json_output: bool = JsonOption,
) -> None:
    """Show currently firing/acknowledged alerts."""
    client = _get_client()
    try:
        result = client.alerts_active_list()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    alerts = result if isinstance(result, list) else result.get("alerts", [])
    if not alerts:
        console.print("[dim]No active alerts[/dim]")
        return

    table = Table(title="Active Alerts", border_style="red", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("State")
    table.add_column("Severity")
    table.add_column("Rule", style="bold white")
    table.add_column("Value", justify="right")
    table.add_column("Fired At", style="dim")

    for a in alerts:
        state = a.get("state", "-")
        sev = a.get("severity", "-")
        table.add_row(
            str(a.get("id", "-")),
            Text(state, style=_state_style(state)),
            Text(sev, style=_severity_style(sev)),
            a.get("rule_name", "-"),
            str(a.get("value", "-")),
            a.get("fired_at", "-"),
        )

    console.print(table)
    console.print(f"[dim]Total: {len(alerts)} active alerts[/dim]")


@active_app.command("count")
def active_count(
    severity: str | None = typer.Option(None, "--severity", help="Filter by severity."),
    json_output: bool = JsonOption,
) -> None:
    """Count active alerts."""
    client = _get_client()
    try:
        result = client.alerts_active_count(severity=severity)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    count = result.get("count", 0)
    console.print(f"[bold]Active alerts:[/bold] [white]{count}[/white]")


@active_app.command("ack")
def active_ack(
    event_id: int = typer.Argument(..., help="Alert event ID to acknowledge."),
    json_output: bool = JsonOption,
) -> None:
    """Acknowledge an active alert."""
    client = _get_client()
    try:
        result = client.alerts_event_ack(event_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]Alert #{event_id} acknowledged[/bold yellow]")


@active_app.command("resolve")
def active_resolve(
    event_id: int = typer.Argument(..., help="Alert event ID to resolve."),
    json_output: bool = JsonOption,
) -> None:
    """Manually resolve an active alert."""
    client = _get_client()
    try:
        result = client.alerts_event_resolve(event_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Alert #{event_id} resolved[/bold green]")


# ---------------------------------------------------------------------------
# Alert History
# ---------------------------------------------------------------------------


@alerts_app.command("history")
def alerts_history(
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    per_page: int = typer.Option(50, "--per-page", help="Results per page."),
    filter: str = typer.Option("all", "--filter", "-f", help="Time filter: all, 24h, 7d, 30d."),
    search: str | None = typer.Option(None, "--search", "-s", help="Search query."),
    json_output: bool = JsonOption,
) -> None:
    """Show resolved/acknowledged alert history."""
    client = _get_client()
    try:
        result = client.alerts_history(page=page, per_page=per_page, filter=filter, q=search)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    events = result.get("events", [])
    if not events:
        console.print("[dim](no alert history)[/dim]")
        return

    table = Table(title="Alert History", border_style="blue", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("State")
    table.add_column("Severity")
    table.add_column("Rule", style="bold white")
    table.add_column("Fired", style="dim")
    table.add_column("Resolved", style="dim")

    for e in events:
        state = e.get("state", "-")
        sev = e.get("severity", "-")
        table.add_row(
            str(e.get("id", "-")),
            Text(state, style=_state_style(state)),
            Text(sev, style=_severity_style(sev)),
            e.get("rule_name", "-"),
            e.get("fired_at", "-"),
            e.get("resolved_at", "-"),
        )

    console.print(table)
    total = result.get("total", len(events))
    console.print(f"[dim]Page {page} — {total} total events[/dim]")


# ---------------------------------------------------------------------------
# Notification Channels
# ---------------------------------------------------------------------------


@channels_app.command("list")
def channels_list(
    json_output: bool = JsonOption,
) -> None:
    """List notification channels."""
    client = _get_client()
    try:
        result = client.alerts_channels_list()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    channels = result if isinstance(result, list) else result.get("channels", [])
    if not channels:
        console.print("[dim](no notification channels)[/dim]")
        return

    table = Table(title="Notification Channels", border_style="blue", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Name", style="bold white")
    table.add_column("Type")
    table.add_column("Enabled")
    table.add_column("Created", style="dim")

    for c in channels:
        enabled = c.get("enabled", False)
        table.add_row(
            str(c.get("id", "-")),
            c.get("name", "-"),
            c.get("type", "-"),
            Text("on" if enabled else "off", style="green" if enabled else "dim"),
            c.get("created_at", "-"),
        )

    console.print(table)


@channels_app.command("create")
def channels_create(
    name: str = typer.Argument(..., help="Channel name."),
    type: str = typer.Argument(
        ..., help="Channel type: email, slack, webhook, pagerduty, discord."
    ),
    config_json: str | None = typer.Option(
        None, "--config", "-c", help="JSON config string or @file path."
    ),
    enabled: bool = typer.Option(True, "--enabled/--disabled", help="Enable channel."),
    json_output: bool = JsonOption,
) -> None:
    """Create a notification channel."""
    config: dict[str, Any] = {}
    if config_json:
        raw = config_json
        if config_json.startswith("@"):
            try:
                raw = open(config_json[1:]).read()
            except OSError as exc:
                err_console.print(f"[red]Failed to read file:[/red] {exc}")
                raise typer.Exit(1) from exc
        try:
            config = _json.loads(raw)
        except _json.JSONDecodeError as exc:
            err_console.print(f"[red]Invalid JSON:[/red] {exc}")
            raise typer.Exit(1) from exc

    channel: dict[str, Any] = {"name": name, "type": type, "config": config, "enabled": enabled}

    client = _get_client()
    try:
        result = client.alerts_channels_create(channel)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    cid = result.get("channel", result).get("id", "?")
    console.print(
        f"[bold green]Channel created[/bold green]  id=[white]{cid}[/white]  name=[cyan]{name}[/cyan]"
    )


@channels_app.command("update")
def channels_update(
    channel_id: int = typer.Argument(..., help="Channel ID to update."),
    name: str | None = typer.Option(None, "--name", "-n", help="New name."),
    enabled: bool | None = typer.Option(None, "--enabled/--disabled", help="Enable or disable."),
    json_output: bool = JsonOption,
) -> None:
    """Update a notification channel."""
    channel: dict[str, Any] = {}
    if name is not None:
        channel["name"] = name
    if enabled is not None:
        channel["enabled"] = enabled

    if not channel:
        err_console.print("[red]At least one field to update is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.alerts_channels_update(channel_id, channel)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Channel #{channel_id} updated[/bold green]")


@channels_app.command("delete")
def channels_delete(
    channel_id: int = typer.Argument(..., help="Channel ID to delete."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
    json_output: bool = JsonOption,
) -> None:
    """Delete a notification channel."""
    if not force and not json_output:
        confirm = typer.confirm(f"Delete channel #{channel_id}?")
        if not confirm:
            raise typer.Abort()

    client = _get_client()
    try:
        result = client.alerts_channels_delete(channel_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]Channel #{channel_id} deleted[/bold yellow]")


@channels_app.command("test")
def channels_test(
    channel_id: int = typer.Argument(..., help="Channel ID to test."),
    json_output: bool = JsonOption,
) -> None:
    """Send a test notification to a channel."""
    client = _get_client()
    try:
        result = client.alerts_channels_test(channel_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Test sent to channel #{channel_id}[/bold green]")


# ---------------------------------------------------------------------------
# Silences
# ---------------------------------------------------------------------------


@silences_app.command("list")
def silences_list(
    include_expired: bool = typer.Option(
        False, "--expired", "-e", help="Include expired silences."
    ),
    json_output: bool = JsonOption,
) -> None:
    """List alert silences."""
    client = _get_client()
    try:
        result = client.alerts_silences_list(include_expired=include_expired)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    silences = result if isinstance(result, list) else result.get("silences", [])
    if not silences:
        console.print("[dim](no silences)[/dim]")
        return

    table = Table(title="Silences", border_style="cyan", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Reason", style="bold white")
    table.add_column("Rule ID")
    table.add_column("Starts", style="dim")
    table.add_column("Ends", style="dim")

    for s in silences:
        table.add_row(
            str(s.get("id", "-")),
            (s.get("reason", "") or "")[:40],
            str(s.get("rule_id", "-")),
            s.get("starts_at", "-"),
            s.get("ends_at", "-"),
        )

    console.print(table)


@silences_app.command("show")
def silences_show(
    silence_id: int = typer.Argument(..., help="Silence ID to inspect."),
    json_output: bool = JsonOption,
) -> None:
    """Show detailed alert silence."""
    client = _get_client()
    try:
        result = client.alerts_silences_get(silence_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    silence = result.get("silence", result)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    grid.add_row("id", str(silence.get("id", "-")))
    grid.add_row("reason", silence.get("reason", "-"))
    grid.add_row("rule_id", str(silence.get("rule_id", "-")))
    grid.add_row("starts_at", silence.get("starts_at", "-"))
    grid.add_row("ends_at", silence.get("ends_at", "-"))

    matchers = silence.get("matchers", [])
    if matchers:
        grid.add_row("matchers", str(matchers))

    console.print(
        Panel(grid, title=f"[bold]Silence #{silence_id}[/bold]", border_style="cyan", expand=False)
    )


@silences_app.command("create")
def silences_create(
    starts_at: str = typer.Argument(..., help="Start time (ISO-8601)."),
    ends_at: str = typer.Argument(..., help="End time (ISO-8601)."),
    reason: str = typer.Argument(..., help="Reason for silence."),
    rule_id: int | None = typer.Option(None, "--rule", "-r", help="Rule ID to silence."),
    json_output: bool = JsonOption,
) -> None:
    """Create an alert silence."""
    silence: dict[str, Any] = {
        "starts_at": starts_at,
        "ends_at": ends_at,
        "reason": reason,
        "matchers": [],
    }
    if rule_id is not None:
        silence["rule_id"] = rule_id

    client = _get_client()
    try:
        result = client.alerts_silences_create(silence)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    sid = result.get("silence", result).get("id", "?")
    console.print(f"[bold green]Silence created[/bold green]  id=[white]{sid}[/white]")


@silences_app.command("delete")
def silences_delete(
    silence_id: int = typer.Argument(..., help="Silence ID to delete."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
    json_output: bool = JsonOption,
) -> None:
    """Delete an alert silence."""
    if not force and not json_output:
        confirm = typer.confirm(f"Delete silence #{silence_id}?")
        if not confirm:
            raise typer.Abort()

    client = _get_client()
    try:
        result = client.alerts_silences_delete(silence_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]Silence #{silence_id} deleted[/bold yellow]")


@silences_app.command("update")
def silences_update(
    silence_id: int = typer.Argument(..., help="Silence ID."),
    starts_at: str | None = typer.Option(None, "--start", help="New start time (ISO-8601)."),
    ends_at: str | None = typer.Option(None, "--end", help="New end time (ISO-8601)."),
    reason: str | None = typer.Option(None, "--reason", "-r", help="New reason."),
    json_output: bool = JsonOption,
) -> None:
    """Update an alert silence."""
    silence: dict[str, Any] = {}
    if starts_at is not None:
        silence["starts_at"] = starts_at
    if ends_at is not None:
        silence["ends_at"] = ends_at
    if reason is not None:
        silence["reason"] = reason
    if not silence:
        err_console.print("[red]At least one field to update is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.alerts_silences_update(silence_id, silence)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Silence #{silence_id} updated[/bold green]")


# ---------------------------------------------------------------------------
# Monitoring Groups
# ---------------------------------------------------------------------------


@groups_app.command("list")
def groups_list(
    json_output: bool = JsonOption,
) -> None:
    """List monitoring groups."""
    client = _get_client()
    try:
        result = client.alerts_groups_list()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    groups = result if isinstance(result, list) else result.get("groups", [])
    if not groups:
        console.print("[dim](no monitoring groups)[/dim]")
        return

    table = Table(title="Monitoring Groups", border_style="green", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Name", style="bold white")
    table.add_column("Enabled")
    table.add_column("Conditions")
    table.add_column("Active")
    table.add_column("Instances")
    table.add_column("Description", style="dim")

    for g in groups:
        enabled = g.get("enabled", False)
        table.add_row(
            str(g.get("id", "-")),
            g.get("name", "-"),
            Text("on" if enabled else "off", style="green" if enabled else "dim"),
            str(g.get("condition_count", 0)),
            str(g.get("active_count", 0)),
            str(g.get("instance_count", 0)),
            (g.get("description", "") or "")[:30],
        )

    console.print(table)


@groups_app.command("show")
def groups_show(
    group_id: int = typer.Argument(..., help="Group ID to inspect."),
    json_output: bool = JsonOption,
) -> None:
    """Show detailed monitoring group with conditions."""
    client = _get_client()
    try:
        result = client.alerts_groups_get(group_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    group = result.get("group", result)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    grid.add_row("id", str(group.get("id", "-")))
    grid.add_row("name", group.get("name", "-"))
    grid.add_row("description", group.get("description", "-") or "-")
    enabled = group.get("enabled", False)
    grid.add_row("enabled", Text("yes" if enabled else "no", style="green" if enabled else "dim"))
    grid.add_row("created", group.get("created_at", "-"))
    grid.add_row("updated", group.get("updated_at", "-"))

    console.print(
        Panel(
            grid,
            title=f"[bold]Group: {group.get('name', group_id)}[/bold]",
            border_style="green",
            expand=False,
        )
    )

    conditions = group.get("conditions", [])
    if conditions:
        console.print("\n[bold]Conditions:[/bold]")
        ctable = Table(border_style="green", show_lines=False)
        ctable.add_column("ID", style="dim", justify="right")
        ctable.add_column("Name", style="bold white")
        ctable.add_column("Type", style="dim")
        ctable.add_column("Severity")
        ctable.add_column("Enabled")
        ctable.add_column("Threshold")
        ctable.add_column("Interval", justify="right")

        for c in conditions:
            sev = c.get("severity", "-")
            en = c.get("enabled", False)
            ctable.add_row(
                str(c.get("id", "-")),
                c.get("name", "-"),
                c.get("metric_type", "-"),
                Text(sev, style=_severity_style(sev)),
                Text("on" if en else "off", style="green" if en else "dim"),
                str(c.get("operator", "")) + " " + str(c.get("threshold", "")),
                str(c.get("interval_secs", "-")) + "s",
            )

        console.print(ctable)


@groups_app.command("create")
def groups_create(
    name: str = typer.Argument(..., help="Group name."),
    description: str = typer.Option("", "--description", "-d", help="Group description."),
    enabled: bool = typer.Option(True, "--enabled/--disabled", help="Enable group."),
    json_output: bool = JsonOption,
) -> None:
    """Create a monitoring group."""
    group: dict[str, Any] = {
        "name": name,
        "description": description,
        "enabled": enabled,
        "match_labels": [],
    }

    client = _get_client()
    try:
        result = client.alerts_groups_create(group)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    gid = result.get("group", result).get("id", "?")
    console.print(
        f"[bold green]Group created[/bold green]  id=[white]{gid}[/white]  name=[cyan]{name}[/cyan]"
    )


@groups_app.command("update")
def groups_update(
    group_id: int = typer.Argument(..., help="Group ID to update."),
    name: str | None = typer.Option(None, "--name", "-n", help="New name."),
    enabled: bool | None = typer.Option(None, "--enabled/--disabled", help="Enable or disable."),
    json_output: bool = JsonOption,
) -> None:
    """Update a monitoring group."""
    group: dict[str, Any] = {}
    if name is not None:
        group["name"] = name
    if enabled is not None:
        group["enabled"] = enabled

    if not group:
        err_console.print("[red]At least one field to update is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.alerts_groups_update(group_id, group)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Group #{group_id} updated[/bold green]")


@groups_app.command("delete")
def groups_delete(
    group_id: int = typer.Argument(..., help="Group ID to delete."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
    json_output: bool = JsonOption,
) -> None:
    """Delete a monitoring group."""
    if not force and not json_output:
        confirm = typer.confirm(f"Delete group #{group_id}?")
        if not confirm:
            raise typer.Abort()

    client = _get_client()
    try:
        result = client.alerts_groups_delete(group_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]Group #{group_id} deleted[/bold yellow]")


@groups_app.command("instances")
def groups_instances(
    group_id: int = typer.Argument(..., help="Group ID."),
    json_output: bool = JsonOption,
) -> None:
    """List instances in a monitoring group."""
    client = _get_client()
    try:
        result = client.alerts_groups_instances(group_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    instances = result.get("instances", [])
    if not instances:
        console.print("[dim](no instances)[/dim]")
        return

    table = Table(title=f"Group #{group_id} Instances", border_style="green", show_lines=False)
    table.add_column("Agent ID", style="bold white")
    table.add_column("Hostname")

    for inst in instances:
        table.add_row(
            inst.get("agent_id", "-"),
            inst.get("hostname", "-"),
        )

    console.print(table)
    console.print(f"[dim]Total: {len(instances)} instances[/dim]")


@groups_app.command("active")
def groups_active(
    group_id: int = typer.Argument(..., help="Group ID."),
    json_output: bool = JsonOption,
) -> None:
    """Show active alerts for a monitoring group."""
    client = _get_client()
    try:
        result = client.alerts_groups_active(group_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    alerts = result if isinstance(result, list) else result.get("alerts", [])
    if not alerts:
        console.print("[dim](no active alerts for this group)[/dim]")
        return

    table = Table(title=f"Group #{group_id} Active Alerts", border_style="red", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Severity")
    table.add_column("Condition", style="bold white")
    table.add_column("Agent ID", style="dim")
    table.add_column("Started At")
    for a in alerts:
        sev = a.get("severity", "info")
        table.add_row(
            str(a.get("id", "-")),
            Text(sev, style=_severity_style(sev)),
            a.get("condition_name", "-"),
            a.get("agent_id", "-"),
            a.get("started_at", "-"),
        )
    console.print(table)


@groups_app.command("status")
def groups_status(
    group_id: int = typer.Argument(..., help="Group ID."),
    json_output: bool = JsonOption,
) -> None:
    """Show status matrix for a monitoring group."""
    client = _get_client()
    try:
        result = client.alerts_groups_status(group_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    conditions = result.get("conditions", [])
    rows = result.get("rows", [])

    if not conditions:
        console.print("[dim](no conditions)[/dim]")
        return

    table = Table(title=f"Group #{group_id} Status Matrix", border_style="green", show_lines=False)
    table.add_column("Agent ID", style="bold white")
    table.add_column("Hostname", style="dim")

    for c in conditions:
        table.add_column(c.get("name", f"cond_{c['id']}"), style="dim")

    for row in rows:
        cells = row.get("cells", {})
        row_data = [row.get("agent_id", "-"), row.get("hostname", "-")]
        for c in conditions:
            cell = cells.get(str(c["id"]), {})
            status = cell.get("status", "unknown")
            row_data.append(Text(status, style=_severity_style(status)))
        table.add_row(*row_data)

    console.print(table)
    console.print(f"[dim]Total: {len(rows)} instances[/dim]")


# ---------------------------------------------------------------------------
# Alert Conditions
# ---------------------------------------------------------------------------


@conditions_app.command("create")
def conditions_create(
    group_id: int = typer.Argument(..., help="Group ID."),
    name: str = typer.Argument(..., help="Condition name."),
    check_type: str = typer.Option(
        "promql", "--check-type", help="Check type (promql, http, tcp, exec)."
    ),
    query: str | None = typer.Option(None, "--query", "-q", help="PromQL or check query."),
    severity: str = typer.Option("warning", "--severity", "-s", help="Alert severity."),
    threshold: float | None = typer.Option(None, "--threshold", "-t", help="Threshold value."),
    json_output: bool = JsonOption,
) -> None:
    """Create an alert condition in a monitoring group."""
    condition: dict[str, Any] = {
        "name": name,
        "check_type": check_type,
        "severity": severity,
    }
    if query:
        condition["query"] = query
    if threshold is not None:
        condition["threshold"] = threshold

    client = _get_client()
    try:
        result = client.alerts_conditions_create(group_id, condition)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    cid = result.get("condition", result).get("id", "?")
    console.print(f"[bold green]Condition created[/bold green]  id=[white]{cid}[/white]")


@conditions_app.command("update")
def conditions_update(
    group_id: int = typer.Argument(..., help="Group ID."),
    condition_id: int = typer.Argument(..., help="Condition ID."),
    name: str | None = typer.Option(None, "--name", "-n", help="New name."),
    query: str | None = typer.Option(None, "--query", "-q", help="New query."),
    severity: str | None = typer.Option(None, "--severity", "-s", help="New severity."),
    threshold: float | None = typer.Option(None, "--threshold", "-t", help="New threshold."),
    json_output: bool = JsonOption,
) -> None:
    """Update an alert condition."""
    condition: dict[str, Any] = {}
    if name is not None:
        condition["name"] = name
    if query is not None:
        condition["query"] = query
    if severity is not None:
        condition["severity"] = severity
    if threshold is not None:
        condition["threshold"] = threshold
    if not condition:
        err_console.print("[red]At least one field to update is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.alerts_conditions_update(group_id, condition_id, condition)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Condition #{condition_id} updated[/bold green]")


@conditions_app.command("delete")
def conditions_delete(
    group_id: int = typer.Argument(..., help="Group ID."),
    condition_id: int = typer.Argument(..., help="Condition ID."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
    json_output: bool = JsonOption,
) -> None:
    """Delete an alert condition."""
    if not force and not json_output:
        confirm = typer.confirm(f"Delete condition #{condition_id} from group #{group_id}?")
        if not confirm:
            raise typer.Abort()

    client = _get_client()
    try:
        result = client.alerts_conditions_delete(group_id, condition_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]Condition #{condition_id} deleted[/bold yellow]")


@conditions_app.command("set-channels")
def conditions_set_channels(
    group_id: int = typer.Argument(..., help="Group ID."),
    condition_id: int = typer.Argument(..., help="Condition ID."),
    channel_ids: str = typer.Argument(..., help="Comma-separated channel IDs."),
    json_output: bool = JsonOption,
) -> None:
    """Set notification channels on a condition."""
    ids = [int(x.strip()) for x in channel_ids.split(",") if x.strip()]
    if not ids:
        err_console.print("[red]At least one channel ID is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.alerts_conditions_set_channels(group_id, condition_id, ids)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(
        f"[bold green]Channels set[/bold green] condition #{condition_id} → "
        f"[white]{', '.join(str(i) for i in ids)}[/white]"
    )


# ---------------------------------------------------------------------------
# Agent detail
# ---------------------------------------------------------------------------


@alerts_app.command("agent")
def alerts_agent(
    agent_id: str = typer.Argument(..., help="Agent ID or hostname."),
    json_output: bool = JsonOption,
) -> None:
    """Show alert agent details."""
    client = _get_client()
    resolved = resolve_node(client, agent_id)
    if resolved is None:
        err_console.print(f"[red]Agent '{agent_id}' not found.[/red]")
        raise typer.Exit(1)
    agent_id = resolved
    try:
        result = client.alerts_agent(agent_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(JSON(_json.dumps(result, default=str, sort_keys=True)))


@alerts_app.command("check-history")
def alerts_check_history(
    agent_id: str = typer.Argument(..., help="Agent ID or hostname."),
    condition_id: int = typer.Argument(..., help="Condition ID."),
    range: str = typer.Option("24h", "--range", "-r", help="Time range."),
    step: str = typer.Option("60s", "--step", help="Step interval."),
    json_output: bool = JsonOption,
) -> None:
    """Show check history for a specific agent/condition."""
    client = _get_client()
    resolved = resolve_node(client, agent_id)
    if resolved is None:
        err_console.print(f"[red]Agent '{agent_id}' not found.[/red]")
        raise typer.Exit(1)
    agent_id = resolved
    try:
        result = client.alerts_agent_check_history(agent_id, condition_id, range=range, step=step)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(JSON(_json.dumps(result, default=str, sort_keys=True)))


# ---------------------------------------------------------------------------
# Hosts overview
# ---------------------------------------------------------------------------


@alerts_app.command("hosts")
def alerts_hosts(
    json_output: bool = JsonOption,
) -> None:
    """Show monitored hosts overview."""
    client = _get_client()
    try:
        result = client.alerts_hosts()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    hosts = result if isinstance(result, list) else result.get("hosts", [])
    if not hosts:
        console.print("[dim](no monitored hosts)[/dim]")
        return

    table = Table(title="Monitored Hosts", border_style="green", show_lines=False)
    table.add_column("Agent ID", style="bold white")
    table.add_column("Hostname")
    table.add_column("OK")
    table.add_column("Warnings")
    table.add_column("Critical")
    table.add_column("Pending")
    table.add_column("Groups", style="dim")

    for h in hosts:
        table.add_row(
            h.get("agent_id", "-"),
            h.get("hostname", "-"),
            Text(str(h.get("ok_count", 0)), style="green"),
            Text(str(h.get("warning_count", 0)), style="yellow"),
            Text(str(h.get("critical_count", 0)), style="red"),
            str(h.get("pending_count", 0)),
            h.get("groups", "-"),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@alerts_app.command("health")
def alerts_health(
    json_output: bool = JsonOption,
) -> None:
    """Show alert evaluation engine health."""
    client = _get_client()
    try:
        result = client.alerts_health()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    healthy = result.get("healthy", False)
    style = "green" if healthy else "red"
    status = "Healthy" if healthy else "Unhealthy"
    console.print(f"[bold {style}]Alert Engine: {status}[/]")
    if result.get("last_eval_at"):
        console.print(f"  Last eval: [dim]{result['last_eval_at']}[/dim]")
    if result.get("message"):
        console.print(f"  Message: {result['message']}")
