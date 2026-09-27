"""Synthetic checks sub-commands for vespid-cli.

Provides CLI access to synthetic checks, synthetic alerts, and
synthetic alert policies via the central server API.
"""

from __future__ import annotations

import json as _json
from typing import Any

import typer
from rich.console import Console
from rich.json import JSON
from rich.table import Table
from rich.text import Text

from ..server_client import ServerClient, ServerClientError, get_client

synthetic_checks_app = typer.Typer(
    name="synthetic-checks",
    help="Synthetic monitoring checks (requires server connection).",
    no_args_is_help=True,
)

# Sub-groups
checks_app = typer.Typer(name="checks", help="Manage synthetic checks.", no_args_is_help=True)
synth_alerts_app = typer.Typer(name="alerts", help="Manage synthetic alerts.", no_args_is_help=True)
policies_app = typer.Typer(
    name="policies", help="Manage synthetic alert policies.", no_args_is_help=True
)

synthetic_checks_app.add_typer(checks_app)
synthetic_checks_app.add_typer(synth_alerts_app)
synthetic_checks_app.add_typer(policies_app)

console = Console()
err_console = Console(stderr=True)

JsonOption = typer.Option(False, "--json", "-j", help="Output raw JSON.")


def _get_client() -> ServerClient:
    try:
        return get_client()
    except (ValueError, ImportError) as exc:
        err_console.print(f"[red]Server connection error:[/red] {exc}")
        raise typer.Exit(1) from exc


def _handle_error(exc: ServerClientError) -> None:
    err_console.print(f"[red]Error:[/red] {exc}")


def _dump_json(data: Any) -> None:
    console.print(JSON(_json.dumps(data, default=str, sort_keys=True)))


# ---------------------------------------------------------------------------
# Synthetic Checks CRUD
# ---------------------------------------------------------------------------


@checks_app.command("list")
def checks_list(
    json_output: bool = JsonOption,
) -> None:
    """List synthetic checks."""
    client = _get_client()
    try:
        result = client.synth_checks_list()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    checks = result if isinstance(result, list) else result.get("checks", [])
    if not checks:
        console.print("[dim](no synthetic checks)[/dim]")
        return

    table = Table(title="Synthetic Checks", border_style="blue", show_lines=False)
    table.add_column("ID", justify="right", style="dim")
    table.add_column("Name", style="bold white")
    table.add_column("Type")
    table.add_column("Target")
    table.add_column("Interval")
    table.add_column("Enabled")
    table.add_column("Last Run")

    for c in checks:
        table.add_row(
            str(c.get("id", "-")),
            c.get("name", "-"),
            c.get("check_type", "-"),
            (c.get("target", "") or ""),
            str(c.get("interval_seconds", "") or ""),
            Text(
                "yes" if c.get("enabled", False) else "no",
                style="green" if c.get("enabled", False) else "red",
            ),
            c.get("last_run_at", "-"),
        )
    console.print(table)
    console.print(f"[dim]Total: {len(checks)} checks[/dim]")


@checks_app.command("create")
def checks_create(
    name: str = typer.Argument(..., help="Check name."),
    check_type: str = typer.Option(
        "http", "--type", "-t", help="Check type (http, tcp, icmp, dns, script)."
    ),
    target: str = typer.Option(..., "--target", help="Check target (URL, hostname, script path)."),
    interval: int = typer.Option(60, "--interval", "-i", help="Interval in seconds."),
    enabled: bool = typer.Option(True, "--enabled/--disabled", help="Enable immediately."),
    timeout: int = typer.Option(30, "--timeout", help="Timeout in seconds."),
    json_output: bool = JsonOption,
) -> None:
    """Create a synthetic check."""
    check: dict[str, Any] = {
        "name": name,
        "check_type": check_type,
        "target": target,
        "interval_seconds": interval,
        "enabled": enabled,
        "timeout": timeout,
    }

    client = _get_client()
    try:
        result = client.synth_checks_create(check)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    cid = result.get("check", result).get("id", "?")
    console.print(f"[bold green]Synthetic check created[/bold green]  id=[white]{cid}[/white]")


@checks_app.command("show")
def checks_show(
    check_id: int = typer.Argument(..., help="Check ID."),
    json_output: bool = JsonOption,
) -> None:
    """Show synthetic check details."""
    client = _get_client()
    try:
        result = client.synth_checks_get(check_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(JSON(_json.dumps(result, default=str, sort_keys=True)))


@checks_app.command("update")
def checks_update(
    check_id: int = typer.Argument(..., help="Check ID."),
    name: str | None = typer.Option(None, "--name", "-n", help="New name."),
    target: str | None = typer.Option(None, "--target", help="New target."),
    interval: int | None = typer.Option(None, "--interval", "-i", help="New interval in seconds."),
    enabled: bool | None = typer.Option(None, "--enabled/--disabled", help="Enable/disable."),
    timeout: int | None = typer.Option(None, "--timeout", help="New timeout."),
    json_output: bool = JsonOption,
) -> None:
    """Update a synthetic check."""
    check: dict[str, Any] = {}
    if name is not None:
        check["name"] = name
    if target is not None:
        check["target"] = target
    if interval is not None:
        check["interval_seconds"] = interval
    if enabled is not None:
        check["enabled"] = enabled
    if timeout is not None:
        check["timeout"] = timeout
    if not check:
        err_console.print("[red]At least one field to update is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.synth_checks_update(check_id, check)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Check #{check_id} updated[/bold green]")


@checks_app.command("delete")
def checks_delete(
    check_id: int = typer.Argument(..., help="Check ID."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
    json_output: bool = JsonOption,
) -> None:
    """Delete a synthetic check."""
    if not force and not json_output:
        confirm = typer.confirm(f"Delete synthetic check #{check_id}?")
        if not confirm:
            raise typer.Abort()

    client = _get_client()
    try:
        result = client.synth_checks_delete(check_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]Check #{check_id} deleted[/bold yellow]")


@checks_app.command("history")
def checks_history(
    check_id: int = typer.Argument(..., help="Check ID."),
    json_output: bool = JsonOption,
) -> None:
    """Show check run history."""
    client = _get_client()
    try:
        result = client.synth_checks_history(check_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    entries = result if isinstance(result, list) else result.get("history", [])
    if not entries:
        console.print("[dim](no history)[/dim]")
        return

    table = Table(title=f"Check #{check_id} History", border_style="blue", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Status")
    table.add_column("Response Time")
    table.add_column("Status Code")
    table.add_column("Error")
    table.add_column("Run At")

    for e in entries:
        status = e.get("status", "-")
        status_style = "green" if status == "ok" else "red" if status == "error" else "yellow"
        table.add_row(
            str(e.get("id", "-")),
            Text(status, style=status_style),
            f"{e.get('response_time_ms', '-')} ms",
            str(e.get("status_code", "-")),
            (e.get("error", "") or "")[:40] or "-",
            e.get("run_at", "-"),
        )
    console.print(table)


# ---------------------------------------------------------------------------
# Synthetic Alerts
# ---------------------------------------------------------------------------


@synth_alerts_app.command("list")
def synth_alerts_list(
    json_output: bool = JsonOption,
) -> None:
    """List synthetic alerts."""
    client = _get_client()
    try:
        result = client.synth_alerts_list()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    alerts = result if isinstance(result, list) else result.get("alerts", [])
    if not alerts:
        console.print("[dim](no synthetic alerts)[/dim]")
        return

    table = Table(title="Synthetic Alerts", border_style="red", show_lines=False)
    table.add_column("ID", justify="right", style="dim")
    table.add_column("Check ID", justify="right")
    table.add_column("Check Name", style="bold white")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Message")
    table.add_column("Created At")

    for a in alerts:
        status = a.get("status", "open")
        sev = a.get("severity", "warning")
        table.add_row(
            str(a.get("id", "-")),
            str(a.get("check_id", "-")),
            a.get("check_name", "-"),
            Text(
                sev, style="red" if sev == "critical" else "yellow" if sev == "warning" else "dim"
            ),
            Text(
                status,
                style="red" if status == "open" else "green" if status == "resolved" else "yellow",
            ),
            (a.get("message", "") or "")[:50],
            a.get("created_at", "-"),
        )
    console.print(table)
    console.print(f"[dim]Total: {len(alerts)} alerts[/dim]")


@synth_alerts_app.command("show")
def synth_alerts_show(
    alert_id: int = typer.Argument(..., help="Alert ID."),
    json_output: bool = JsonOption,
) -> None:
    """Show synthetic alert details."""
    client = _get_client()
    try:
        result = client.synth_alerts_get(alert_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(JSON(_json.dumps(result, default=str, sort_keys=True)))


@synth_alerts_app.command("create")
def synth_alerts_create(
    check_id: int = typer.Argument(..., help="Check ID."),
    severity: str = typer.Option(
        "warning", "--severity", "-s", help="Severity (info, warning, critical)."
    ),
    message: str = typer.Option(..., "--message", "-m", help="Alert message."),
    json_output: bool = JsonOption,
) -> None:
    """Create a synthetic alert."""
    alert: dict[str, Any] = {
        "check_id": check_id,
        "severity": severity,
        "message": message,
    }

    client = _get_client()
    try:
        result = client.synth_alerts_create(alert)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    aid = result.get("alert", result).get("id", "?")
    console.print(f"[bold green]Synthetic alert created[/bold green]  id=[white]{aid}[/white]")


@synth_alerts_app.command("update")
def synth_alerts_update(
    alert_id: int = typer.Argument(..., help="Alert ID."),
    severity: str | None = typer.Option(None, "--severity", "-s", help="New severity."),
    message: str | None = typer.Option(None, "--message", "-m", help="New message."),
    status: str | None = typer.Option(
        None, "--status", help="New status (open, acknowledged, resolved)."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Update a synthetic alert."""
    alert: dict[str, Any] = {}
    if severity is not None:
        alert["severity"] = severity
    if message is not None:
        alert["message"] = message
    if status is not None:
        alert["status"] = status
    if not alert:
        err_console.print("[red]At least one field to update is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.synth_alerts_update(alert_id, alert)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Synthetic alert #{alert_id} updated[/bold green]")


@synth_alerts_app.command("delete")
def synth_alerts_delete(
    alert_id: int = typer.Argument(..., help="Alert ID."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
    json_output: bool = JsonOption,
) -> None:
    """Delete a synthetic alert."""
    if not force and not json_output:
        confirm = typer.confirm(f"Delete synthetic alert #{alert_id}?")
        if not confirm:
            raise typer.Abort()

    client = _get_client()
    try:
        result = client.synth_alerts_delete(alert_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]Synthetic alert #{alert_id} deleted[/bold yellow]")


@synth_alerts_app.command("resolve")
def synth_alerts_resolve(
    alert_id: int = typer.Argument(..., help="Alert ID to resolve."),
    json_output: bool = JsonOption,
) -> None:
    """Resolve a synthetic alert."""
    client = _get_client()
    try:
        result = client.synth_alerts_resolve(alert_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Synthetic alert #{alert_id} resolved[/bold green]")


# ---------------------------------------------------------------------------
# Synthetic Alert Policies
# ---------------------------------------------------------------------------


@policies_app.command("list")
def policies_list(
    json_output: bool = JsonOption,
) -> None:
    """List synthetic alert policies."""
    client = _get_client()
    try:
        result = client.synth_policies_list()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    policies = result if isinstance(result, list) else result.get("policies", [])
    if not policies:
        console.print("[dim](no alert policies)[/dim]")
        return

    table = Table(title="Synthetic Alert Policies", border_style="cyan", show_lines=False)
    table.add_column("ID", justify="right", style="dim")
    table.add_column("Name", style="bold white")
    table.add_column("Check ID", justify="right")
    table.add_column("Condition")
    table.add_column("Threshold")
    table.add_column("Severity")
    table.add_column("Enabled")

    for p in policies:
        table.add_row(
            str(p.get("id", "-")),
            p.get("name", "-"),
            str(p.get("check_id", "-")),
            p.get("condition_type", "-"),
            str(p.get("threshold", "-")),
            p.get("severity", "warning"),
            Text(
                "yes" if p.get("enabled", False) else "no",
                style="green" if p.get("enabled", False) else "red",
            ),
        )
    console.print(table)
    console.print(f"[dim]Total: {len(policies)} policies[/dim]")


@policies_app.command("update")
def policies_update(
    policy_id: int = typer.Argument(..., help="Policy ID."),
    name: str | None = typer.Option(None, "--name", "-n", help="New name."),
    condition_type: str | None = typer.Option(
        None, "--condition", help="Condition type (threshold, pattern, etc.)."
    ),
    threshold: float | None = typer.Option(None, "--threshold", "-t", help="New threshold."),
    severity: str | None = typer.Option(None, "--severity", "-s", help="New severity."),
    enabled: bool | None = typer.Option(None, "--enabled/--disabled", help="Enable/disable."),
    json_output: bool = JsonOption,
) -> None:
    """Update a synthetic alert policy."""
    policy: dict[str, Any] = {}
    if name is not None:
        policy["name"] = name
    if condition_type is not None:
        policy["condition_type"] = condition_type
    if threshold is not None:
        policy["threshold"] = threshold
    if severity is not None:
        policy["severity"] = severity
    if enabled is not None:
        policy["enabled"] = enabled
    if not policy:
        err_console.print("[red]At least one field to update is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.synth_policies_update(policy_id, policy)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Policy #{policy_id} updated[/bold green]")


@policies_app.command("reconcile")
def policies_reconcile(
    policy_id: int = typer.Argument(..., help="Policy ID."),
    json_output: bool = JsonOption,
) -> None:
    """Reconcile alerts for a specific policy."""
    client = _get_client()
    try:
        result = client.synth_policies_reconcile(policy_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Policy #{policy_id} reconciled[/bold green]")


@policies_app.command("reconcile-all")
def policies_reconcile_all(
    json_output: bool = JsonOption,
) -> None:
    """Reconcile alerts for all policies."""
    client = _get_client()
    try:
        result = client.synth_policies_reconcile_all()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print("[bold green]All policies reconciled[/bold green]")
