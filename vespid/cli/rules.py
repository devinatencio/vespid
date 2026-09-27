"""Detection rules sub-commands for vespid-cli.

Provides CLI access to brute-force, custom, and correlation detection rules,
rule pack templates, and sigma rule synchronization.
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

rules_app = typer.Typer(
    name="rules",
    help="Detection rules management (requires server connection + admin role).",
    no_args_is_help=True,
)

# Sub-groups
bruteforce_app = typer.Typer(
    name="brute-force", help="Manage brute-force detection rules.", no_args_is_help=True
)
custom_app = typer.Typer(name="custom", help="Manage custom detection rules.", no_args_is_help=True)
correlation_app = typer.Typer(
    name="correlation", help="Manage correlation rules.", no_args_is_help=True
)
templates_app = typer.Typer(
    name="templates", help="Manage rule pack templates.", no_args_is_help=True
)

rules_app.add_typer(bruteforce_app)
rules_app.add_typer(custom_app)
rules_app.add_typer(correlation_app)
rules_app.add_typer(templates_app)

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


def _show_rule_table(rules: list[dict], title: str, border_style: str) -> None:
    if not rules:
        console.print(f"[dim](no {title.lower()})[/dim]")
        return

    table = Table(title=title, border_style=border_style, show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Name", style="bold white")
    table.add_column("Type", style="dim")
    table.add_column("Enabled")
    table.add_column("Event Type", style="dim")
    table.add_column("Threshold")
    table.add_column("Window")

    for r in rules:
        enabled = r.get("enabled", False)
        threshold = ""
        window = ""

        if "max_attempts" in r:
            threshold = str(r.get("max_attempts", "-"))
            window = str(r.get("window_seconds", "-")) + "s"
        elif "min_categories" in r:
            threshold = str(r.get("min_categories", "-"))
            window = str(r.get("window_seconds", "-")) + "s"

        table.add_row(
            str(r.get("id", "-")),
            r.get("name", "-"),
            r.get("parser", r.get("event_type", "-")),
            Text("on" if enabled else "off", style="green" if enabled else "dim"),
            r.get("event_type", "-"),
            threshold,
            window,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# List all rules
# ---------------------------------------------------------------------------


@rules_app.command("list")
def rules_list(
    json_output: bool = JsonOption,
) -> None:
    """List all detection rules (brute-force, custom, correlation)."""
    client = _get_client()
    try:
        result = client.rules_list()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    bf = result.get("brute_force_rules", [])
    cu = result.get("custom_rules", [])
    co = result.get("correlation_rules", [])

    _show_rule_table(bf, "Brute-Force Rules", "yellow")
    _show_rule_table(cu, "Custom Rules", "cyan")
    _show_rule_table(co, "Correlation Rules", "magenta")

    console.print(
        f"[dim]Revision: {result.get('revision', '?')} — Total: {result.get('total', 0)}[/dim]"
    )


# ---------------------------------------------------------------------------
# Brute-force rules
# ---------------------------------------------------------------------------


@bruteforce_app.command("create")
def bf_create(
    name: str = typer.Argument(..., help="Rule name."),
    event_type: str = typer.Option("ssh", "--event-type", "-e", help="Event type to match."),
    max_attempts: int = typer.Option(
        5, "--max-attempts", "-m", help="Max attempts before alerting."
    ),
    window_seconds: int = typer.Option(60, "--window", "-w", help="Time window in seconds."),
    parser: str = typer.Option("ssh", "--parser", "-p", help="Log parser to use."),
    enabled: bool = typer.Option(True, "--enabled/--disabled", help="Enable rule."),
    json_output: bool = JsonOption,
) -> None:
    """Create a brute-force detection rule."""
    rule: dict[str, Any] = {
        "name": name,
        "event_type": event_type,
        "max_attempts": max_attempts,
        "window_seconds": window_seconds,
        "parser": parser,
        "enabled": enabled,
    }
    client = _get_client()
    try:
        result = client.rules_create_brute_force(rule)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    rid = result.get("id", "?")
    console.print(f"[bold green]Brute-force rule created[/bold green]  id=[white]{rid}[/white]")


@bruteforce_app.command("update")
def bf_update(
    rule_id: int = typer.Argument(..., help="Rule ID to update."),
    name: str | None = typer.Option(None, "--name", "-n", help="New name."),
    max_attempts: int | None = typer.Option(None, "--max-attempts", "-m", help="Max attempts."),
    window_seconds: int | None = typer.Option(
        None, "--window", "-w", help="Time window in seconds."
    ),
    enabled: bool | None = typer.Option(None, "--enabled/--disabled", help="Enable or disable."),
    json_output: bool = JsonOption,
) -> None:
    """Update a brute-force detection rule."""
    rule: dict[str, Any] = {}
    if name is not None:
        rule["name"] = name
    if max_attempts is not None:
        rule["max_attempts"] = max_attempts
    if window_seconds is not None:
        rule["window_seconds"] = window_seconds
    if enabled is not None:
        rule["enabled"] = enabled

    if not rule:
        err_console.print("[red]At least one field to update is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.rules_update_brute_force(rule_id, rule)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Brute-force rule #{rule_id} updated[/bold green]")


@bruteforce_app.command("delete")
def bf_delete(
    rule_id: int = typer.Argument(..., help="Rule ID to delete."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
    json_output: bool = JsonOption,
) -> None:
    """Delete (disable) a brute-force rule."""
    if not force and not json_output:
        confirm = typer.confirm(f"Delete brute-force rule #{rule_id}?")
        if not confirm:
            raise typer.Abort()

    client = _get_client()
    try:
        result = client.rules_delete_brute_force(rule_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]Brute-force rule #{rule_id} deleted[/bold yellow]")


# ---------------------------------------------------------------------------
# Custom rules
# ---------------------------------------------------------------------------


@custom_app.command("create")
def custom_create(
    name: str = typer.Argument(..., help="Rule name."),
    event_type: str = typer.Option("ssh", "--event-type", "-e", help="Event type to match."),
    regex: str = typer.Option("", "--regex", "-r", help="Regex pattern to match."),
    max_attempts: int = typer.Option(5, "--max-attempts", "-m", help="Max attempts."),
    window_seconds: int = typer.Option(60, "--window", "-w", help="Time window in seconds."),
    enabled: bool = typer.Option(True, "--enabled/--disabled", help="Enable rule."),
    json_output: bool = JsonOption,
) -> None:
    """Create a custom detection rule."""
    rule: dict[str, Any] = {
        "name": name,
        "event_type": event_type,
        "max_attempts": max_attempts,
        "window_seconds": window_seconds,
        "enabled": enabled,
    }
    if regex:
        rule["regex"] = regex

    client = _get_client()
    try:
        result = client.rules_create_custom(rule)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    rid = result.get("id", "?")
    console.print(f"[bold green]Custom rule created[/bold green]  id=[white]{rid}[/white]")


@custom_app.command("update")
def custom_update(
    rule_id: int = typer.Argument(..., help="Rule ID to update."),
    name: str | None = typer.Option(None, "--name", "-n", help="New name."),
    max_attempts: int | None = typer.Option(None, "--max-attempts", "-m", help="Max attempts."),
    window_seconds: int | None = typer.Option(None, "--window", "-w", help="Time window."),
    enabled: bool | None = typer.Option(None, "--enabled/--disabled", help="Enable or disable."),
    json_output: bool = JsonOption,
) -> None:
    """Update a custom detection rule."""
    rule: dict[str, Any] = {}
    if name is not None:
        rule["name"] = name
    if max_attempts is not None:
        rule["max_attempts"] = max_attempts
    if window_seconds is not None:
        rule["window_seconds"] = window_seconds
    if enabled is not None:
        rule["enabled"] = enabled

    if not rule:
        err_console.print("[red]At least one field to update is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.rules_update_custom(rule_id, rule)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Custom rule #{rule_id} updated[/bold green]")


@custom_app.command("delete")
def custom_delete(
    rule_id: int = typer.Argument(..., help="Rule ID to delete."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
    json_output: bool = JsonOption,
) -> None:
    """Delete (disable) a custom rule."""
    if not force and not json_output:
        confirm = typer.confirm(f"Delete custom rule #{rule_id}?")
        if not confirm:
            raise typer.Abort()

    client = _get_client()
    try:
        result = client.rules_delete_custom(rule_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]Custom rule #{rule_id} deleted[/bold yellow]")


# ---------------------------------------------------------------------------
# Correlation rules
# ---------------------------------------------------------------------------


@correlation_app.command("create")
def corr_create(
    name: str = typer.Argument(..., help="Rule name."),
    event_type: str = typer.Option("ssh", "--event-type", "-e", help="Event type to match."),
    min_categories: int = typer.Option(2, "--min-categories", "-m", help="Min categories (2-20)."),
    window_seconds: int = typer.Option(60, "--window", "-w", help="Time window in seconds."),
    enabled: bool = typer.Option(True, "--enabled/--disabled", help="Enable rule."),
    json_output: bool = JsonOption,
) -> None:
    """Create a correlation rule."""
    rule: dict[str, Any] = {
        "name": name,
        "event_type": event_type,
        "min_categories": min_categories,
        "window_seconds": window_seconds,
        "enabled": enabled,
    }
    client = _get_client()
    try:
        result = client.rules_create_correlation(rule)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    rid = result.get("id", "?")
    console.print(f"[bold green]Correlation rule created[/bold green]  id=[white]{rid}[/white]")


@correlation_app.command("update")
def corr_update(
    rule_id: int = typer.Argument(..., help="Rule ID to update."),
    name: str | None = typer.Option(None, "--name", "-n", help="New name."),
    min_categories: int | None = typer.Option(
        None, "--min-categories", "-m", help="Min categories."
    ),
    window_seconds: int | None = typer.Option(None, "--window", "-w", help="Time window."),
    enabled: bool | None = typer.Option(None, "--enabled/--disabled", help="Enable or disable."),
    json_output: bool = JsonOption,
) -> None:
    """Update a correlation rule."""
    rule: dict[str, Any] = {}
    if name is not None:
        rule["name"] = name
    if min_categories is not None:
        rule["min_categories"] = min_categories
    if window_seconds is not None:
        rule["window_seconds"] = window_seconds
    if enabled is not None:
        rule["enabled"] = enabled

    if not rule:
        err_console.print("[red]At least one field to update is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.rules_update_correlation(rule_id, rule)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Correlation rule #{rule_id} updated[/bold green]")


@correlation_app.command("delete")
def corr_delete(
    rule_id: int = typer.Argument(..., help="Rule ID to delete."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
    json_output: bool = JsonOption,
) -> None:
    """Delete (disable) a correlation rule."""
    if not force and not json_output:
        confirm = typer.confirm(f"Delete correlation rule #{rule_id}?")
        if not confirm:
            raise typer.Abort()

    client = _get_client()
    try:
        result = client.rules_delete_correlation(rule_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]Correlation rule #{rule_id} deleted[/bold yellow]")


# ---------------------------------------------------------------------------
# Rule pack templates
# ---------------------------------------------------------------------------


@templates_app.command("list")
def templates_list(
    pack_name: str | None = typer.Argument(
        None, help="Pack name (e.g. sigma-web-attacks). Omit to list available packs."
    ),
    json_output: bool = JsonOption,
) -> None:
    """List templates in a rule pack, or list available packs if no pack given."""
    client = _get_client()

    if not pack_name:
        try:
            result = client.rules_packs_list()
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc

        packs = result.get("packs", [])
        if not packs:
            console.print("[dim](no rule packs available)[/dim]")
            return

        if json_output:
            _dump_json({"packs": [p["pack_name"] for p in packs]})
            return

        table = Table(title="Available Rule Packs", border_style="green", show_lines=False)
        table.add_column("Pack Name", style="bold white")
        table.add_column("Description", style="dim")
        table.add_column("Rules")
        table.add_column("Type")
        for p in packs:
            table.add_row(
                p["pack_name"],
                p.get("description", ""),
                str(p.get("rule_count", "-")),
                "sigma" if "sigma" in p["pack_name"] else "custom",
            )
        console.print(table)
        console.print(
            "\n[yellow]Usage:[/yellow] [bold]vespid-cli rules templates list <pack-name>[/bold]"
        )
        return

    try:
        result = client.rules_templates_list(pack_name)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    templates = result.get("templates", [])
    if not templates:
        console.print(f"[dim](no templates in pack '{pack_name}')[/dim]")
        return

    table = Table(title=f"Pack: {pack_name}", border_style="green", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Name", style="bold white")
    table.add_column("Enabled")
    table.add_column("Event Type", style="dim")

    for t in templates:
        enabled = t.get("enabled", False)
        table.add_row(
            str(t.get("id", "-")),
            t.get("name", "-"),
            Text("on" if enabled else "off", style="green" if enabled else "dim"),
            t.get("event_type", "-"),
        )

    console.print(table)


@templates_app.command("enable-all")
def templates_enable_all(
    pack_name: str = typer.Argument(..., help="Pack name."),
    json_output: bool = JsonOption,
) -> None:
    """Enable all templates in a rule pack."""
    client = _get_client()
    try:
        result = client.rules_templates_enable_all(pack_name)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]All templates in '{pack_name}' enabled[/bold green]")


@templates_app.command("disable-all")
def templates_disable_all(
    pack_name: str = typer.Argument(..., help="Pack name."),
    json_output: bool = JsonOption,
) -> None:
    """Disable all templates in a rule pack."""
    client = _get_client()
    try:
        result = client.rules_templates_disable_all(pack_name)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]All templates in '{pack_name}' disabled[/bold yellow]")


@templates_app.command("toggle")
def templates_toggle(
    pack_name: str = typer.Argument(..., help="Pack name."),
    rule_id: int = typer.Argument(..., help="Template rule ID."),
    json_output: bool = JsonOption,
) -> None:
    """Toggle a single template in a pack."""
    client = _get_client()
    try:
        result = client.rules_templates_toggle(pack_name, rule_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    state = "enabled" if result.get("enabled") else "disabled"
    console.print(f"[bold green]Template rule #{rule_id} {state}[/bold green]")


# ---------------------------------------------------------------------------
# Sigma sync
# ---------------------------------------------------------------------------


@rules_app.command("sigma-sync")
def rules_sigma_sync(
    json_output: bool = JsonOption,
) -> None:
    """Trigger Sigma rule synchronization."""
    client = _get_client()
    try:
        result = client.rules_sigma_sync()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print("[bold green]Sigma sync complete[/bold green]")
    for key in ("inserted", "updated", "returncode"):
        if key in result:
            console.print(f"  {key}: {result[key]}")
