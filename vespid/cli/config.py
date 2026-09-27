"""Config management sub-commands for vespid-cli.

Provides CLI access to centralized configuration profiles, agent groups,
assignments, and rollouts via the central server API.
"""

from __future__ import annotations

import json as _json
from typing import Any

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table

from ..server_client import ServerClient, ServerClientError, get_client
from ._resolve import resolve_node

config_app = typer.Typer(
    name="config",
    help="Centralized configuration management (requires server connection).",
    no_args_is_help=True,
)

# Sub-groups
profiles_app = typer.Typer(
    name="profiles", help="Manage configuration profiles.", no_args_is_help=True
)
groups_app = typer.Typer(name="groups", help="Manage agent groups.", no_args_is_help=True)
assignments_app = typer.Typer(
    name="assign", help="Manage profile assignments.", no_args_is_help=True
)

config_app.add_typer(profiles_app)
config_app.add_typer(groups_app)
config_app.add_typer(assignments_app)

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


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------


@profiles_app.command("list")
def profiles_list(
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    per_page: int = typer.Option(50, "--per-page", help="Results per page."),
    json_output: bool = JsonOption,
) -> None:
    """List configuration profiles."""
    client = _get_client()
    try:
        result = client.config_list_profiles(page=page, per_page=per_page)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    profiles = result.get("profiles", [])
    if not profiles:
        console.print("[dim](no profiles)[/dim]")
        return

    table = Table(title="Configuration Profiles", border_style="green", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Name", style="bold white")
    table.add_column("Version", justify="right")
    table.add_column("Description", style="dim")
    table.add_column("Created", style="dim")
    table.add_column("Updated", style="dim")

    for p in profiles:
        table.add_row(
            str(p.get("id", "-")),
            p.get("name", "-"),
            str(p.get("version", 1)),
            (p.get("description", "") or "")[:40],
            p.get("created_at", "-"),
            p.get("updated_at", "-"),
        )

    console.print(table)
    total = result.get("total", len(profiles))
    console.print(f"[dim]Page {page} — {total} total profiles[/dim]")


@profiles_app.command("show")
def profiles_show(
    profile_id: int = typer.Argument(..., help="Profile ID to inspect."),
    json_output: bool = JsonOption,
) -> None:
    """Show detailed configuration profile."""
    client = _get_client()
    try:
        result = client.config_get_profile(profile_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    profile = result.get("profile", result)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    grid.add_row("id", str(profile.get("id", "-")))
    grid.add_row("name", profile.get("name", "-"))
    grid.add_row("version", str(profile.get("version", 1)))
    grid.add_row("description", profile.get("description", "-") or "-")
    grid.add_row("created_at", profile.get("created_at", "-"))
    grid.add_row("updated_at", profile.get("updated_at", "-"))
    grid.add_row("created_by", profile.get("created_by", "-"))

    console.print(
        Panel(
            grid,
            title=f"[bold]Profile: {profile.get('name', profile_id)}[/bold]",
            border_style="green",
            expand=False,
        )
    )

    # Settings
    settings = profile.get("settings", {})
    if isinstance(settings, str):
        try:
            settings = _json.loads(settings)
        except (ValueError, TypeError):
            settings = {}

    if settings:
        console.print("\n[bold]Settings:[/bold]")
        console.print(JSON(_json.dumps(settings, indent=2, default=str)))


@profiles_app.command("create")
def profiles_create(
    name: str = typer.Argument(..., help="Profile name."),
    settings_file: str | None = typer.Option(
        None, "--settings", "-s", help="Path to JSON/YAML settings file."
    ),
    description: str = typer.Option("", "--description", "-d", help="Profile description."),
    json_output: bool = JsonOption,
) -> None:
    """Create a new configuration profile."""
    settings: dict[str, Any] = {}
    if settings_file:
        try:
            raw = open(settings_file).read()
            if settings_file.endswith((".yaml", ".yml")):
                try:
                    import yaml

                    settings = yaml.safe_load(raw) or {}
                except ImportError as exc:
                    err_console.print("[red]PyYAML required for YAML files.[/red]")
                    raise typer.Exit(1) from exc
            else:
                settings = _json.loads(raw)
        except (OSError, _json.JSONDecodeError) as exc:
            err_console.print(f"[red]Failed to read settings file:[/red] {exc}")
            raise typer.Exit(1) from exc

    client = _get_client()
    try:
        result = client.config_create_profile(name=name, settings=settings, description=description)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    pid = result.get("id", result.get("profile", {}).get("id", "?"))
    console.print(
        f"[bold green]✅ Profile created[/bold green]  id=[white]{pid}[/white]  name=[cyan]{name}[/cyan]"
    )


@profiles_app.command("update")
def profiles_update(
    profile_id: int = typer.Argument(..., help="Profile ID to update."),
    settings_file: str | None = typer.Option(
        None, "--settings", "-s", help="Path to JSON/YAML settings file."
    ),
    description: str | None = typer.Option(
        None, "--description", "-d", help="Updated description."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Update an existing configuration profile (creates new version)."""
    settings: dict[str, Any] = {}
    if settings_file:
        try:
            raw = open(settings_file).read()
            if settings_file.endswith((".yaml", ".yml")):
                try:
                    import yaml

                    settings = yaml.safe_load(raw) or {}
                except ImportError as exc:
                    err_console.print("[red]PyYAML required for YAML files.[/red]")
                    raise typer.Exit(1) from exc
            else:
                settings = _json.loads(raw)
        except (OSError, _json.JSONDecodeError) as exc:
            err_console.print(f"[red]Failed to read settings file:[/red] {exc}")
            raise typer.Exit(1) from exc

    client = _get_client()
    try:
        result = client.config_update_profile(
            profile_id, settings=settings, description=description
        )
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    new_version = result.get("version", result.get("profile", {}).get("version", "?"))
    console.print(
        f"[bold green]✅ Profile #{profile_id} updated[/bold green]  version=[white]{new_version}[/white]"
    )


@profiles_app.command("delete")
def profiles_delete(
    profile_id: int = typer.Argument(..., help="Profile ID to delete."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
    json_output: bool = JsonOption,
) -> None:
    """Delete a configuration profile (soft-delete)."""
    if not force and not json_output:
        confirm = typer.confirm(f"Delete profile #{profile_id}?")
        if not confirm:
            raise typer.Abort()

    client = _get_client()
    try:
        result = client.config_delete_profile(profile_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]🗑  Profile #{profile_id} deleted[/bold yellow]")


@profiles_app.command("history")
def profiles_history(
    profile_id: int = typer.Argument(..., help="Profile ID."),
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    json_output: bool = JsonOption,
) -> None:
    """Show version history for a configuration profile."""
    client = _get_client()
    try:
        result = client.config_profile_history(profile_id, page=page)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    versions = result.get("versions", result.get("history", []))
    if not versions:
        console.print("[dim](no history)[/dim]")
        return

    table = Table(
        title=f"Profile #{profile_id} Version History",
        border_style="green",
        show_lines=False,
    )
    table.add_column("Version", justify="right", style="bold")
    table.add_column("Changed By", style="cyan")
    table.add_column("Reason", style="dim")
    table.add_column("Timestamp", style="dim")

    for v in versions:
        table.add_row(
            str(v.get("version", "-")),
            v.get("changed_by", "-"),
            (v.get("reason", v.get("change_reason", "")) or "-")[:40],
            v.get("created_at", v.get("timestamp", "-")),
        )

    console.print(table)
    total = result.get("total", len(versions))
    console.print(f"[dim]Page {page} — {total} total versions[/dim]")


@profiles_app.command("version")
def profiles_version(
    profile_id: int = typer.Argument(..., help="Profile ID."),
    version: int = typer.Argument(..., help="Version number to inspect."),
    json_output: bool = JsonOption,
) -> None:
    """Show the full settings for a specific historical version."""
    client = _get_client()
    try:
        result = client.config_profile_version(profile_id, version)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    settings = result.get("settings", {})
    if isinstance(settings, str):
        try:
            settings = _json.loads(settings)
        except (ValueError, TypeError):
            settings = {}

    console.print(
        Panel(
            f"[bold]Version {version}[/bold] of [bold]Profile #{profile_id}[/bold]",
            border_style="green",
            expand=False,
        )
    )
    console.print(JSON(_json.dumps(settings, indent=2, default=str)))


@profiles_app.command("diff")
def profiles_diff(
    profile_id: int = typer.Argument(..., help="Profile ID."),
    from_version: int = typer.Argument(..., help="Source version."),
    to_version: int = typer.Argument(..., help="Target version."),
    json_output: bool = JsonOption,
) -> None:
    """Show a diff between two profile versions."""
    client = _get_client()
    try:
        result = client.config_profile_diff(profile_id, from_version, to_version)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    diff = result.get("diff", [])
    if not diff:
        console.print("[dim]No differences between versions[/dim]")
        return

    table = Table(
        title=f"Profile #{profile_id} v{from_version} → v{to_version}",
        border_style="yellow",
        show_lines=False,
    )
    table.add_column("Op", style="bold")
    table.add_column("Key", style="cyan")
    table.add_column("From", style="red")
    table.add_column("To", style="green")

    for entry in diff:
        op = entry.get("op", entry.get("operation", "?"))
        op_style = {"add": "green", "remove": "red", "replace": "yellow"}.get(op, "dim")
        from_val = entry.get("from", entry.get("old_value", "-"))
        to_val = entry.get("to", entry.get("new_value", "-"))
        if isinstance(from_val, (dict, list)):
            from_val = _json.dumps(from_val, default=str)
        if isinstance(to_val, (dict, list)):
            to_val = _json.dumps(to_val, default=str)

        table.add_row(
            f"[{op_style}]{op}[/{op_style}]",
            entry.get("path", entry.get("key", "-")),
            str(from_val)[:60],
            str(to_val)[:60],
        )

    console.print(table)


@profiles_app.command("rollback")
def profiles_rollback(
    profile_id: int = typer.Argument(..., help="Profile ID."),
    target_version: int = typer.Argument(..., help="Version to roll back to."),
    reason: str = typer.Option("cli rollback", "--reason", "-r", help="Reason for rollback."),
    json_output: bool = JsonOption,
) -> None:
    """Roll back a profile to a previous version."""
    client = _get_client()
    try:
        result = client.config_profile_rollback(
            profile_id, target_version=target_version, reason=reason
        )
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    new_version = result.get("new_version", result.get("version", "?"))
    console.print(
        f"[bold yellow]↩ Profile #{profile_id} rolled back[/bold yellow] "
        f"to v{target_version} → new version [white]{new_version}[/white]"
    )


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------


@groups_app.command("list")
def groups_list(
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    per_page: int = typer.Option(50, "--per-page", help="Results per page."),
    json_output: bool = JsonOption,
) -> None:
    """List agent groups."""
    client = _get_client()
    try:
        result = client.config_list_groups(page=page, per_page=per_page)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    groups = result.get("groups", [])
    if not groups:
        console.print("[dim](no groups)[/dim]")
        return

    table = Table(title="Agent Groups", border_style="blue", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Name", style="bold white")
    table.add_column("Members", justify="right")
    table.add_column("Description", style="dim")
    table.add_column("Created", style="dim")

    for g in groups:
        table.add_row(
            str(g.get("id", "-")),
            g.get("name", "-"),
            str(g.get("member_count", g.get("members", "-"))),
            (g.get("description", "") or "")[:40],
            g.get("created_at", "-"),
        )

    console.print(table)


@groups_app.command("create")
def groups_create(
    name: str = typer.Argument(..., help="Group name."),
    description: str = typer.Option("", "--description", "-d", help="Group description."),
    json_output: bool = JsonOption,
) -> None:
    """Create a new agent group."""
    client = _get_client()
    try:
        result = client.config_create_group(name=name, description=description)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    gid = result.get("id", result.get("group", {}).get("id", "?"))
    console.print(
        f"[bold green]✅ Group created[/bold green]  id=[white]{gid}[/white]  name=[cyan]{name}[/cyan]"
    )


@groups_app.command("delete")
def groups_delete(
    group_id: int = typer.Argument(..., help="Group ID to delete."),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation."),
    json_output: bool = JsonOption,
) -> None:
    """Delete an agent group."""
    if not force and not json_output:
        confirm = typer.confirm(f"Delete group #{group_id}?")
        if not confirm:
            raise typer.Abort()

    client = _get_client()
    try:
        result = client.config_delete_group(group_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]🗑  Group #{group_id} deleted[/bold yellow]")


@groups_app.command("add-member")
def groups_add_member(
    group_id: int = typer.Argument(..., help="Group ID."),
    node_id: str = typer.Argument(..., help="Node ID or hostname to add."),
    json_output: bool = JsonOption,
) -> None:
    """Add a node to an agent group."""
    client = _get_client()
    resolved = resolve_node(client, node_id)
    if resolved is None:
        err_console.print(f"[red]Node '{node_id}' not found.[/red]")
        raise typer.Exit(1)
    node_id = resolved
    try:
        result = client.config_add_group_member(group_id, node_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]Added[/bold green] [white]{node_id}[/white] → group #{group_id}")


@groups_app.command("remove-member")
def groups_remove_member(
    group_id: int = typer.Argument(..., help="Group ID."),
    node_id: str = typer.Argument(..., help="Node ID or hostname to remove."),
    json_output: bool = JsonOption,
) -> None:
    """Remove a node from an agent group."""
    client = _get_client()
    resolved = resolve_node(client, node_id)
    if resolved is None:
        err_console.print(f"[red]Node '{node_id}' not found.[/red]")
        raise typer.Exit(1)
    node_id = resolved
    try:
        result = client.config_remove_group_member(group_id, node_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(
        f"[bold yellow]Removed[/bold yellow] [white]{node_id}[/white] from group #{group_id}"
    )


# ---------------------------------------------------------------------------
# Assignments
# ---------------------------------------------------------------------------


@assignments_app.command("create")
def assign_create(
    profile_id: int = typer.Argument(..., help="Profile ID to assign."),
    node_id: str | None = typer.Option(None, "--node", "-n", help="Target node ID."),
    group_id: int | None = typer.Option(None, "--group", "-g", help="Target group ID."),
    json_output: bool = JsonOption,
) -> None:
    """Assign a profile to a node or group."""
    if not node_id and not group_id:
        err_console.print("[red]Specify --node or --group.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.config_create_assignment(
            profile_id=profile_id, node_id=node_id, group_id=group_id
        )
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    target = node_id or f"group #{group_id}"
    console.print(
        f"[bold green]✅ Profile #{profile_id} assigned[/bold green] → [white]{target}[/white]"
    )


@assignments_app.command("delete")
def assign_delete(
    assignment_id: int = typer.Argument(..., help="Assignment ID to remove."),
    json_output: bool = JsonOption,
) -> None:
    """Remove a profile assignment."""
    client = _get_client()
    try:
        result = client.config_delete_assignment(assignment_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]🗑  Assignment #{assignment_id} removed[/bold yellow]")
