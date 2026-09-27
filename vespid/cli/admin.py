"""Admin sub-commands for vespid-cli.

Provides CLI access to user management, API key management, audit log,
and enrollment operations via the central server API.
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

admin_app = typer.Typer(
    name="admin",
    help="Server administration (requires server connection + admin role).",
    no_args_is_help=True,
)

# Sub-groups
users_app = typer.Typer(name="users", help="Manage operators/users.", no_args_is_help=True)
keys_app = typer.Typer(name="keys", help="Manage API keys.", no_args_is_help=True)
enrollment_app = typer.Typer(
    name="enrollment", help="Manage node enrollments.", no_args_is_help=True
)

admin_app.add_typer(users_app)
admin_app.add_typer(keys_app)
admin_app.add_typer(enrollment_app)

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


def _role_style(role: str) -> str:
    r = role.lower()
    if r == "admin":
        return "bold red"
    if r == "analyst":
        return "bold yellow"
    if r == "agent":
        return "bold cyan"
    return "dim"


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@users_app.command("list")
def users_list(
    json_output: bool = JsonOption,
) -> None:
    """List all operators."""
    client = _get_client()
    try:
        result = client.admin_list_users()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    users = result if isinstance(result, list) else result.get("users", [])
    if not users:
        console.print("[dim](no users)[/dim]")
        return

    table = Table(title="Operators", border_style="cyan", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Username", style="bold white")
    table.add_column("Role")
    table.add_column("Created", style="dim")
    table.add_column("Last Login", style="dim")

    for u in users:
        role = u.get("role", "-")
        table.add_row(
            str(u.get("id", "-")),
            u.get("username", "-"),
            Text(role, style=_role_style(role)),
            u.get("created_at", "-"),
            u.get("last_login_at", u.get("last_login", "-")),
        )

    console.print(table)


@users_app.command("create")
def users_create(
    username: str = typer.Argument(..., help="Username for the new operator."),
    role: str = typer.Option("viewer", "--role", "-r", help="Role: admin, analyst, viewer."),
    password: str | None = typer.Option(
        None, "--password", help="Password (prompted if not provided)."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Create a new operator."""
    if not password:
        password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)

    client = _get_client()
    try:
        result = client.admin_create_user(username=username, password=password, role=role)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(
        f"[bold green]✅ User created[/bold green]  username=[white]{username}[/white]  role=[cyan]{role}[/cyan]"
    )


@users_app.command("change-role")
def users_change_role(
    user_id: int = typer.Argument(..., help="User ID."),
    role: str = typer.Argument(..., help="New role: admin, analyst, viewer."),
    json_output: bool = JsonOption,
) -> None:
    """Change a user's role."""
    client = _get_client()
    try:
        result = client.admin_change_user_role(user_id, role)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]✅ User #{user_id} role changed[/bold green] → [cyan]{role}[/cyan]")


@users_app.command("change-password")
def users_change_password(
    user_id: int = typer.Argument(..., help="User ID."),
    password: str | None = typer.Option(
        None, "--password", help="New password (prompted if not provided)."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Change a user's password."""
    if not password:
        password = typer.prompt("New password", hide_input=True, confirmation_prompt=True)

    client = _get_client()
    try:
        result = client.admin_change_user_password(user_id, password)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]✅ Password changed for user #{user_id}[/bold green]")


# ---------------------------------------------------------------------------
# API Keys
# ---------------------------------------------------------------------------


@keys_app.command("list")
def keys_list(
    json_output: bool = JsonOption,
) -> None:
    """List all API keys."""
    client = _get_client()
    try:
        result = client.admin_list_keys()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    keys = result if isinstance(result, list) else result.get("keys", [])
    if not keys:
        console.print("[dim](no API keys)[/dim]")
        return

    table = Table(title="API Keys", border_style="yellow", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Name", style="bold white")
    table.add_column("Role")
    table.add_column("Active")
    table.add_column("Created", style="dim")
    table.add_column("Last Used", style="dim")

    for k in keys:
        active = k.get("is_active", True)
        active_text = Text("✓" if active else "✗", style="green" if active else "red")
        role = k.get("role", "-")
        table.add_row(
            str(k.get("id", "-")),
            k.get("name", k.get("description", "-")),
            Text(role, style=_role_style(role)),
            active_text,
            k.get("created_at", "-"),
            k.get("last_used_at", k.get("last_used", "-")),
        )

    console.print(table)


@keys_app.command("create")
def keys_create(
    name: str = typer.Argument(..., help="Descriptive name for the key."),
    role: str = typer.Option("agent", "--role", "-r", help="Role: admin, analyst, agent."),
    json_output: bool = JsonOption,
) -> None:
    """Create a new API key."""
    client = _get_client()
    try:
        result = client.admin_create_key(name=name, role=role)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    key_value = result.get("key", result.get("api_key", result.get("token", "")))
    console.print(
        f"[bold green]✅ API key created[/bold green]  name=[white]{name}[/white]  role=[cyan]{role}[/cyan]"
    )
    if key_value:
        console.print("\n[bold yellow]⚠  Save this key — it won't be shown again:[/bold yellow]")
        console.print(f"   [bold white]{key_value}[/bold white]\n")


@keys_app.command("revoke")
def keys_revoke(
    key_id: int = typer.Argument(..., help="API key ID to revoke."),
    json_output: bool = JsonOption,
) -> None:
    """Revoke an API key."""
    client = _get_client()
    try:
        result = client.admin_revoke_key(key_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold red]🚫 API key #{key_id} revoked[/bold red]")


@keys_app.command("delete")
def keys_delete(
    key_id: int = typer.Argument(..., help="API key ID to permanently delete."),
    json_output: bool = JsonOption,
) -> None:
    """Permanently delete a revoked API key."""
    client = _get_client()
    try:
        result = client.admin_delete_key(key_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]🗑  API key #{key_id} permanently deleted[/bold yellow]")


@keys_app.command("set-node-restriction")
def keys_set_node_restriction(
    key_id: int = typer.Argument(..., help="API key ID."),
    node_id: str | None = typer.Argument(
        None, help="Node ID or hostname to restrict to (omit to clear restriction)."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Set or clear the node restriction on an API key."""
    client = _get_client()
    if node_id:
        resolved = resolve_node(client, node_id)
        if resolved is None:
            err_console.print(f"[red]Node '{node_id}' not found.[/red]")
            raise typer.Exit(1)
        node_id = resolved
    try:
        result = client.admin_update_key_node_restriction(key_id, node_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    if node_id:
        console.print(
            f"[bold green]✅ Key #{key_id} restricted[/bold green] → node [white]{node_id}[/white]"
        )
    else:
        console.print(f"[bold green]✅ Node restriction cleared for key #{key_id}[/bold green]")


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------


@admin_app.command("audit")
def audit_log(
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    per_page: int = typer.Option(50, "--per-page", help="Results per page."),
    actor: str | None = typer.Option(None, "--actor", help="Filter by actor."),
    action_type: str | None = typer.Option(None, "--action", help="Filter by action type."),
    json_output: bool = JsonOption,
) -> None:
    """View the server audit log."""
    client = _get_client()
    try:
        result = client.admin_audit_log(
            page=page, per_page=per_page, actor=actor, action_type=action_type
        )
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    entries = result.get("entries", result.get("audit_log", []))
    if not entries:
        console.print("[dim](no audit entries)[/dim]")
        return

    table = Table(title="Audit Log", border_style="yellow", show_lines=False)
    table.add_column("Time", style="dim")
    table.add_column("Actor", style="cyan")
    table.add_column("Action", style="bold")
    table.add_column("Target", style="white")
    table.add_column("IP", style="dim")

    for e in entries:
        table.add_row(
            e.get("timestamp", "-"),
            e.get("actor", "-"),
            e.get("action_type", "-"),
            e.get("target", "-"),
            e.get("actor_ip", "-"),
        )

    console.print(table)
    total = result.get("total", len(entries))
    console.print(f"[dim]Page {page} — {total} total entries[/dim]")


# ---------------------------------------------------------------------------
# Enrollment
# ---------------------------------------------------------------------------


@enrollment_app.command("list")
def enrollment_list(
    json_output: bool = JsonOption,
) -> None:
    """List enrollment requests."""
    client = _get_client()
    try:
        result = client.admin_list_enrollments()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    enrollments = result if isinstance(result, list) else result.get("enrollments", [])
    if not enrollments:
        console.print("[dim](no enrollment requests)[/dim]")
        return

    table = Table(title="Enrollment Requests", border_style="cyan", show_lines=False)
    table.add_column("ID", style="dim", justify="right")
    table.add_column("Node ID", style="bold white")
    table.add_column("Status")
    table.add_column("Hostname", style="dim")
    table.add_column("Requested At")

    for e in enrollments:
        status = e.get("status", "-")
        if status == "pending":
            st_style = "yellow"
        elif status == "approved":
            st_style = "green"
        elif status in ("rejected", "revoked"):
            st_style = "red"
        else:
            st_style = "dim"

        table.add_row(
            str(e.get("id", "-")),
            e.get("node_id", e.get("hostname", "-")),
            Text(status, style=st_style),
            e.get("hostname", "-"),
            e.get("requested_at", e.get("created_at", "-")),
        )

    console.print(table)


@enrollment_app.command("approve")
def enrollment_approve(
    enrollment_id: int = typer.Argument(..., help="Enrollment request ID to approve."),
    json_output: bool = JsonOption,
) -> None:
    """Approve a pending enrollment request."""
    client = _get_client()
    try:
        result = client.admin_approve_enrollment(enrollment_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold green]✅ Enrollment #{enrollment_id} approved[/bold green]")


@enrollment_app.command("reject")
def enrollment_reject(
    enrollment_id: int = typer.Argument(..., help="Enrollment request ID to reject."),
    json_output: bool = JsonOption,
) -> None:
    """Reject a pending enrollment request."""
    client = _get_client()
    try:
        result = client.admin_reject_enrollment(enrollment_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold red]🚫 Enrollment #{enrollment_id} rejected[/bold red]")


@enrollment_app.command("revoke")
def enrollment_revoke(
    enrollment_id: int = typer.Argument(..., help="Enrollment ID to revoke."),
    json_output: bool = JsonOption,
) -> None:
    """Revoke an approved enrollment."""
    client = _get_client()
    try:
        result = client.admin_revoke_enrollment(enrollment_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold red]🚫 Enrollment #{enrollment_id} revoked[/bold red]")


@enrollment_app.command("settings")
def enrollment_settings(
    json_output: bool = JsonOption,
) -> None:
    """Show current enrollment settings."""
    client = _get_client()
    try:
        result = client.admin_enrollment_settings()
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    grid.add_row("enabled", str(result.get("enrollment_enabled", "-")))
    grid.add_row("mode", str(result.get("enrollment_mode", "-")))
    grid.add_row("allow_unrestricted", str(result.get("allow_unrestricted_api_keys", "-")))
    token = result.get("enrollment_token", "")
    grid.add_row("token", token if token else "(not set)")

    console.print(Panel(grid, title="Enrollment Settings", border_style="cyan", expand=False))


@enrollment_app.command("set-settings")
def enrollment_set_settings(
    enabled: str | None = typer.Option(None, "--enabled", help="Enable enrollment (true/false)."),
    mode: str | None = typer.Option(
        None,
        "--mode",
        help="Enrollment mode: open, manual_approval, restricted.",
    ),
    allow_unrestricted: str | None = typer.Option(
        None, "--allow-unrestricted", help="Allow unrestricted API keys (true/false)."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Update enrollment settings."""
    settings: dict[str, str] = {}
    if enabled is not None:
        settings["enrollment_enabled"] = enabled
    if mode is not None:
        settings["enrollment_mode"] = mode
    if allow_unrestricted is not None:
        settings["allow_unrestricted_api_keys"] = allow_unrestricted

    if not settings:
        err_console.print("[red]At least one setting option is required.[/red]")
        raise typer.Exit(1)

    client = _get_client()
    try:
        result = client.admin_update_enrollment_settings(settings)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print("[bold green]✅ Enrollment settings updated[/bold green]")


@enrollment_app.command("rotate")
def enrollment_rotate(
    enrollment_id: int = typer.Argument(..., help="Enrollment ID to rotate credentials for."),
    json_output: bool = JsonOption,
) -> None:
    """Rotate credentials for an approved enrollment."""
    client = _get_client()
    try:
        result = client.admin_rotate_enrollment(enrollment_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(
        f"[bold green]✅ Credentials rotated for enrollment #{enrollment_id}[/bold green]"
    )


@enrollment_app.command("delete")
def enrollment_delete(
    enrollment_id: int = typer.Argument(..., help="Enrollment ID to delete."),
    json_output: bool = JsonOption,
) -> None:
    """Delete a revoked or rejected enrollment record."""
    client = _get_client()
    try:
        result = client.admin_delete_enrollment_record(enrollment_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(f"[bold yellow]🗑  Enrollment #{enrollment_id} deleted[/bold yellow]")


@enrollment_app.command("reissue")
def enrollment_reissue(
    enrollment_id: int = typer.Argument(..., help="Enrollment ID to re-issue credentials for."),
    json_output: bool = JsonOption,
) -> None:
    """Re-issue credentials for a revoked enrollment."""
    client = _get_client()
    try:
        result = client.admin_reissue_enrollment(enrollment_id)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    console.print(
        f"[bold green]✅ Credentials re-issued for enrollment #{enrollment_id}[/bold green]"
    )


# ---------------------------------------------------------------------------
# Cleanup / Retention
# ---------------------------------------------------------------------------


@admin_app.command("cleanup")
def admin_cleanup(
    action: str = typer.Argument("status", help="Action: status, save-retention, purge."),
    retention_days: int = typer.Option(
        90, "--days", "-d", help="Retention days (for save-retention)."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Manage event data retention and cleanup."""
    client = _get_client()

    if action == "status":
        try:
            result = client.admin_cleanup_status()
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc

        if json_output:
            _dump_json(result)
            return

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold cyan", justify="right")
        grid.add_column()
        grid.add_row("retention_days", str(result.get("retention_days", "-")))
        grid.add_row("total_events", str(result.get("total_events", 0)))
        grid.add_row("purgeable", str(result.get("purgeable", 0)))
        grid.add_row("oldest", result.get("oldest_event", "-"))
        grid.add_row("newest", result.get("newest_event", "-"))
        console.print(Panel(grid, title="Cleanup Status", border_style="yellow", expand=False))

    elif action == "save-retention":
        try:
            result = client.admin_cleanup_save_retention(retention_days)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        console.print(f"[bold green]Retention set to {retention_days} days[/bold green]")

    elif action == "purge":
        try:
            result = client.admin_cleanup_purge()
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        purged = result.get("purged", {})
        total = sum(purged.values()) if isinstance(purged, dict) else purged
        console.print(f"[bold yellow]Purged {total} events[/bold yellow]")

    else:
        err_console.print(
            f"[red]Unknown action: {action}. Use: status, save-retention, purge.[/red]"
        )
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Command Queue
# ---------------------------------------------------------------------------


@admin_app.command("commands")
def admin_commands(
    action: str = typer.Argument(
        "list", help="Action: list, delete, expire-pending, purge-old, settings."
    ),
    status: str = typer.Option("", "--status", "-s", help="Filter by status (list)."),
    node_id: str = typer.Option("", "--node", "-n", help="Filter by node (list)."),
    command_id: str | None = typer.Option(None, "--command-id", "-c", help="Command ID (delete)."),
    hours: int = typer.Option(24, "--hours", help="Hours for expire-pending."),
    days: int = typer.Option(30, "--days", "-d", help="Days for purge-old."),
    expiry_hours: int = typer.Option(24, "--expiry-hours", help="Pending expiry (settings)."),
    retention_days: int = typer.Option(30, "--retention-days", help="Retention days (settings)."),
    json_output: bool = JsonOption,
) -> None:
    """Manage the command queue."""
    client = _get_client()

    if action == "list":
        try:
            result = client.admin_commands_list(status=status, node_id=node_id)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc

        if json_output:
            _dump_json(result)
            return

        cmds = result.get("commands", [])
        if not cmds:
            console.print("[dim](no commands)[/dim]")
            return

        table = Table(title="Command Queue", border_style="blue", show_lines=False)
        table.add_column("ID", style="dim")
        table.add_column("Node", style="bold white")
        table.add_column("Type")
        table.add_column("Status")
        table.add_column("Created", style="dim")

        for c in cmds:
            table.add_row(
                str(c.get("command_id", "-")),
                c.get("node_id", "-"),
                c.get("command_type", "-"),
                c.get("status", "-"),
                c.get("created_at", "-"),
            )
        console.print(table)

    elif action == "delete":
        if not command_id:
            err_console.print("[red]--command-id is required for delete action.[/red]")
            raise typer.Exit(1)
        try:
            result = client.admin_commands_delete(command_id)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        console.print("[bold yellow]Command deleted[/bold yellow]")

    elif action == "expire-pending":
        try:
            result = client.admin_commands_expire_pending(hours)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        console.print(
            f"[bold yellow]Expired {result.get('expired', 0)} pending commands[/bold yellow]"
        )

    elif action == "purge-old":
        try:
            result = client.admin_commands_purge_old(days)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        console.print(f"[bold yellow]Purged {result.get('purged', 0)} old commands[/bold yellow]")

    elif action == "settings":
        try:
            result = client.admin_commands_save_settings(expiry_hours, retention_days)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        console.print("[bold green]Command queue settings saved[/bold green]")

    else:
        err_console.print(f"[red]Unknown action: {action}[/red]")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------


@admin_app.command("backups")
def admin_backups(
    action: str = typer.Argument("list", help="Action: list, run, delete, settings."),
    filename: str | None = typer.Option(None, "--filename", "-f", help="Backup filename (delete)."),
    enabled: str = typer.Option("false", "--enabled", help="Enable backups (settings)."),
    interval_hours: int = typer.Option(24, "--interval", help="Backup interval hours."),
    retention_days: int = typer.Option(30, "--retention-days", help="Backup retention days."),
    json_output: bool = JsonOption,
) -> None:
    """Manage database backups."""
    client = _get_client()

    if action == "list":
        try:
            result = client.admin_backups_list()
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc

        if json_output:
            _dump_json(result)
            return

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold cyan", justify="right")
        grid.add_column()
        grid.add_row("enabled", str(result.get("enabled", False)))
        grid.add_row("interval", f"{result.get('interval_hours', '-')}h")
        grid.add_row("retention", f"{result.get('retention_days', '-')}d")
        grid.add_row("last_run", result.get("last_run", "-"))
        grid.add_row("next_run", result.get("next_run", "-"))
        grid.add_row("total_size", str(result.get("total_size", 0)) + " bytes")
        console.print(Panel(grid, title="Backup Settings", border_style="green", expand=False))

        files = result.get("backup_files", [])
        if files:
            ftable = Table(title="Backup Files", border_style="green", show_lines=False)
            ftable.add_column("Filename", style="bold white")
            ftable.add_column("Size", justify="right")
            ftable.add_column("Modified", style="dim")
            for f in files:
                ftable.add_row(f.get("name", "-"), str(f.get("size", 0)), f.get("ts", "-"))
            console.print(ftable)

    elif action == "run":
        try:
            result = client.admin_backups_run()
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        console.print(f"[bold green]Backup created: {result.get('filename', '')}[/bold green]")

    elif action == "delete":
        if not filename:
            err_console.print("[red]--filename is required for delete action.[/red]")
            raise typer.Exit(1)
        try:
            result = client.admin_backups_delete(filename)
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        console.print(f"[bold yellow]Backup deleted: {filename}[/bold yellow]")

    elif action == "settings":
        try:
            result = client.admin_backups_save_settings(
                enabled=enabled, interval_hours=interval_hours, retention_days=retention_days
            )
        except ServerClientError as exc:
            _handle_error(exc)
            raise typer.Exit(1) from exc
        if json_output:
            _dump_json(result)
            return
        console.print("[bold green]Backup settings updated[/bold green]")

    else:
        err_console.print(f"[red]Unknown action: {action}[/red]")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Server Logs
# ---------------------------------------------------------------------------


@admin_app.command("logs")
def admin_logs(
    lines: int = typer.Option(200, "--lines", "-n", help="Number of lines to show."),
    follow: bool = typer.Option(
        False, "--follow", "-f", help="Follow log output (shows full tail)."
    ),
    json_output: bool = JsonOption,
) -> None:
    """View server log files."""
    client = _get_client()
    try:
        result = client.admin_logs(lines=lines)
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    log_files = result.get("log_files", {})
    for name, info in log_files.items():
        log_lines = info.get("lines", [])
        if log_lines:
            console.print(
                f"\n[bold cyan]── {name} ({info.get('total', 0)} total, showing {len(log_lines)})[/bold cyan]"
            )
            for line in log_lines:
                console.print(line.rstrip())
