"""Server connection management sub-commands for vespid-cli.

Provides login/logout, connection testing, and credential management
for the central vespid-server.
"""

from __future__ import annotations

import json as _json
import os

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..server_client import CLI_CONFIG_PATH, ServerClient, ServerClientError, get_client

server_app = typer.Typer(
    name="server",
    help="Server connection management.",
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)

JsonOption = typer.Option(False, "--json", help="Output raw JSON instead of pretty tables.")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@server_app.command("login")
def server_login(
    url: str | None = typer.Option(
        None, "--url", "-u", help="Server URL (e.g. https://vespid.example.com)."
    ),
    api_key: str | None = typer.Option(
        None, "--key", "-k", help="API key (prompted if not provided)."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Configure server connection credentials.

    Stores credentials in ~/.config/vespid/cli.yaml for use by all
    server-dependent commands (fleet, intel, nodes, config, admin).
    """
    if not url:
        url = typer.prompt("Server URL")
    if not api_key:
        api_key = typer.prompt("API Key", hide_input=True)

    # Validate connection
    try:
        client = ServerClient(base_url=url, api_key=api_key)
        # Try a lightweight request to verify credentials
        # The fleet blocks list endpoint requires analyst role (most keys have this)
        client.get("/api/v1/fleet/blocks", params={"page": 1, "per_page": 1})
        client.close()
    except ServerClientError as exc:
        if exc.status_code == 401:
            err_console.print("[red]✖ Authentication failed — invalid API key.[/red]")
            raise typer.Exit(1) from exc
        elif exc.status_code == 403:
            # Auth worked but role is insufficient for this endpoint — that's fine
            console.print("[dim]Connected (key valid, but limited role).[/dim]")
        else:
            err_console.print(
                f"[yellow]⚠  Server responded with HTTP {exc.status_code}:[/yellow] {exc.detail}"
            )
            if not typer.confirm("Save credentials anyway?"):
                raise typer.Exit(1) from exc
    except Exception as exc:
        err_console.print(f"[red]✖ Connection failed:[/red] {exc}")
        if not typer.confirm("Save credentials anyway?"):
            raise typer.Exit(1) from exc

    # Save credentials
    CLI_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

    config_data: dict = {}
    if CLI_CONFIG_PATH.exists():
        try:
            import yaml

            config_data = yaml.safe_load(CLI_CONFIG_PATH.read_text()) or {}
        except ImportError:
            try:
                config_data = _json.loads(CLI_CONFIG_PATH.read_text())
            except Exception:
                pass
        except Exception:
            pass

    config_data["server_url"] = url
    config_data["api_key"] = api_key

    # Write as YAML if possible, otherwise JSON
    try:
        import yaml

        CLI_CONFIG_PATH.write_text(yaml.dump(config_data, default_flow_style=False))
    except ImportError:
        CLI_CONFIG_PATH.write_text(_json.dumps(config_data, indent=2))

    # Restrict permissions
    os.chmod(str(CLI_CONFIG_PATH), 0o600)

    if json_output:
        console.print(_json.dumps({"ok": True, "server_url": url}))
        return

    console.print(f"[bold green]✅ Logged in[/bold green] to [white]{url}[/white]")
    console.print(f"   [dim]Credentials saved to {CLI_CONFIG_PATH}[/dim]")


@server_app.command("logout")
def server_logout(
    json_output: bool = JsonOption,
) -> None:
    """Remove stored server credentials."""
    if CLI_CONFIG_PATH.exists():
        CLI_CONFIG_PATH.unlink()
        if json_output:
            console.print(_json.dumps({"ok": True}))
        else:
            console.print("[bold yellow]🗑  Credentials removed.[/bold yellow]")
    else:
        if json_output:
            console.print(_json.dumps({"ok": True, "message": "no credentials stored"}))
        else:
            console.print("[dim]No stored credentials to remove.[/dim]")


@server_app.command("status")
def server_status(
    json_output: bool = JsonOption,
) -> None:
    """Test the server connection and show current config."""
    # Show where credentials come from
    url_source = "not configured"
    key_source = "not configured"
    url_value = None
    key_masked = None

    # Check env vars
    env_url = os.environ.get("VESPID_SERVER_URL")
    env_key = os.environ.get("VESPID_API_KEY")
    if env_url:
        url_source = "environment (VESPID_SERVER_URL)"
        url_value = env_url
    if env_key:
        key_source = "environment (VESPID_API_KEY)"
        key_masked = env_key[:8] + "..." + env_key[-4:] if len(env_key) > 12 else "***"

    # Check CLI config
    if CLI_CONFIG_PATH.exists():
        try:
            try:
                import yaml

                data = yaml.safe_load(CLI_CONFIG_PATH.read_text()) or {}
            except ImportError:
                data = _json.loads(CLI_CONFIG_PATH.read_text())

            if not url_value and data.get("server_url"):
                url_source = f"cli config ({CLI_CONFIG_PATH})"
                url_value = data["server_url"]
            if not key_masked and data.get("api_key"):
                key_source = f"cli config ({CLI_CONFIG_PATH})"
                k = data["api_key"]
                key_masked = k[:8] + "..." + k[-4:] if len(k) > 12 else "***"
        except Exception:
            pass

    # Check agent config
    if not url_value or not key_masked:
        try:
            from ..config import CONFIG

            if not url_value and CONFIG.SERVER_URL and "example.invalid" not in CONFIG.SERVER_URL:
                url_source = "agent config (vespid.yaml)"
                srv = CONFIG.SERVER_URL
                if "/api/" in srv:
                    srv = srv[: srv.index("/api/")]
                url_value = srv
            if not key_masked and CONFIG.API_KEY and not CONFIG.API_KEY.startswith("REPLACE_ME"):
                key_source = "agent config (vespid.yaml)"
                k = CONFIG.API_KEY
                key_masked = k[:8] + "..." + k[-4:] if len(k) > 12 else "***"
        except Exception:
            pass

    # Test connection
    connected = False
    error_msg = None
    if url_value and key_masked:
        try:
            client = get_client()
            client.get("/api/v1/fleet/blocks", params={"page": 1, "per_page": 1})
            client.close()
            connected = True
        except ServerClientError as exc:
            if exc.status_code == 401:
                error_msg = "authentication failed (invalid key)"
            elif exc.status_code == 403:
                connected = True  # Auth works, just insufficient role for this endpoint
            else:
                error_msg = f"HTTP {exc.status_code}: {exc.detail}"
        except Exception as exc:
            error_msg = str(exc)

    if json_output:
        console.print(
            _json.dumps(
                {
                    "server_url": url_value,
                    "url_source": url_source,
                    "key_source": key_source,
                    "connected": connected,
                    "error": error_msg,
                }
            )
        )
        return

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    grid.add_row("server_url", url_value or Text("not configured", style="red"))
    grid.add_row("  source", Text(url_source, style="dim"))
    grid.add_row("api_key", key_masked or Text("not configured", style="red"))
    grid.add_row("  source", Text(key_source, style="dim"))
    grid.add_row("", "")

    if connected:
        grid.add_row("connection", Text("✓ connected", style="bold green"))
    elif error_msg:
        grid.add_row("connection", Text(f"✗ {error_msg}", style="bold red"))
    else:
        grid.add_row("connection", Text("✗ not configured", style="dim"))

    console.print(
        Panel(grid, title="[bold]Server Connection[/bold]", border_style="cyan", expand=False)
    )
