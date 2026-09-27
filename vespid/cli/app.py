"""vespid-cli – local management and inspection CLI (Rich + Typer edition)."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..control_socket import send_command

app = typer.Typer(
    name="vespid-cli",
    help="Local management and inspection CLI for Vespid.",
    add_completion=True,
    no_args_is_help=False,
    invoke_without_command=True,
    rich_markup_mode="rich",
    pretty_exceptions_enable=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)

# ---------------------------------------------------------------------------
# Register server-side sub-apps (alphabetical, grouped in help)
# ---------------------------------------------------------------------------
# Import order matters to avoid circular dependencies
# app.py must be imported first, then the others
from . import (  # noqa: E402
    admin,
    alerts,
    config,
    events,
    fleet,
    intel,
    inventory,
    metrics,
    nodes,
    rules,
    server,
    synthetic_checks,
)

app.add_typer(admin.admin_app, name="admin", rich_help_panel="Server Commands")
app.add_typer(alerts.alerts_app, name="alerts", rich_help_panel="Server Commands")
app.add_typer(config.config_app, name="config", rich_help_panel="Server Commands")
app.add_typer(events.events_app, name="events", rich_help_panel="Server Commands")
app.add_typer(fleet.fleet_app, name="fleet", rich_help_panel="Server Commands")
app.add_typer(intel.intel_app, name="intel", rich_help_panel="Server Commands")
app.add_typer(inventory.inventory_app, name="inventory", rich_help_panel="Server Commands")
app.add_typer(metrics.metrics_app, name="metrics", rich_help_panel="Server Commands")
app.add_typer(nodes.nodes_app, name="nodes", rich_help_panel="Server Commands")
app.add_typer(rules.rules_app, name="rules", rich_help_panel="Server Commands")
app.add_typer(server.server_app, name="server", rich_help_panel="Server Commands")
app.add_typer(
    synthetic_checks.synthetic_checks_app,
    name="synthetic-checks",
    rich_help_panel="Server Commands",
)

console = Console()
err_console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Reusable --json option
# ---------------------------------------------------------------------------
JsonOption = typer.Option(False, "--json", help="Output raw JSON instead of pretty tables.")


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def _fmt_ts(ts: float) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _fmt_ttl(seconds: int) -> str:
    if seconds <= 0:
        return "expired"
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def _ttl_style(seconds: int) -> str:
    """Return a Rich style string based on remaining TTL."""
    if seconds <= 0:
        return "dim"
    if seconds < 300:
        return "yellow"
    return "green"


def _action_style(action: str) -> str:
    a = action.lower()
    if a in ("block", "blocked"):
        return "bold red"
    if a in ("unblock", "unblocked"):
        return "bold green"
    return "white"


def _fmt_country(geo: dict[str, Any]) -> str:
    """Format country as 'HK (Hong Kong)' when name is available."""
    from ..country_codes import country_name

    code = geo.get("country") or "??"
    name = geo.get("country_name")
    if name and code != "??":
        return f"{code} ({name})"
    # Fall back to the static lookup for old events missing country_name
    return country_name(code)


# ---------------------------------------------------------------------------
# Daemon communication
# ---------------------------------------------------------------------------
def _safe(cmd: str, **kwargs: Any) -> dict[str, Any]:
    try:
        return send_command(cmd, **kwargs)
    except FileNotFoundError:
        return {"ok": False, "error": "daemon_not_running (control socket missing)"}
    except (TimeoutError, ConnectionRefusedError) as exc:
        return {"ok": False, "error": f"daemon_unreachable: {exc}"}
    except PermissionError as exc:
        return {"ok": False, "error": f"permission_denied: {exc}"}


def _dump_json(payload: dict[str, Any]) -> int:
    console.print(JSON(json.dumps(payload, sort_keys=True)))
    return 0 if payload.get("ok") else 1


def _print_error(resp: dict[str, Any]) -> int:
    """Print a user-friendly error panel and return exit code 1."""
    error = resp.get("error", "unknown error")
    hint = ""
    if "daemon_not_running" in error:
        hint = "Start the daemon with: [bold]sudo systemctl start vespid[/bold]"
    elif "daemon_unreachable" in error:
        hint = "The daemon may be overloaded or restarting. Try again in a moment."
    elif "permission_denied" in error:
        hint = "Try running with [bold]sudo[/bold] or check socket permissions."

    body = Text(error, style="red")
    if hint:
        body.append(f"\n\n💡 {hint}")

    err_console.print(Panel(body, title="[red]✖ Error[/red]", border_style="red", expand=False))
    return 1


def _check_resp(resp: dict[str, Any], json_output: bool) -> bool:
    """If response is an error, print it and return False."""
    if resp.get("ok"):
        return True
    if json_output:
        _dump_json(resp)
    else:
        _print_error(resp)
    return False


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context) -> None:
    """Vespid local management CLI."""
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit(0)


@app.command(rich_help_panel="Local Commands")
def status(
    json_output: bool = JsonOption,
) -> None:
    """Show daemon status overview."""

    resp = _safe("status")
    if not _check_resp(resp, json_output):
        raise typer.Exit(1)
    if json_output:
        _dump_json(resp)
        return

    nft = resp.get("nft", {})
    bus = resp.get("bus", {})
    activity = resp.get("activity", {})

    nft_avail = nft.get("nft_available", False)
    nft_color = "green" if nft_avail else "red"
    upload = resp.get("upload_enabled", False)
    upload_color = "green" if upload else "yellow"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    grid.add_row("node_id", str(resp.get("node_id", "-")))
    grid.add_row("version", str(resp.get("version", "-")))
    grid.add_row("nft table", f"{nft.get('table', '-')}  [{nft_color}]available={nft_avail}[/]")
    grid.add_row("shield_local", f"{nft.get('local_count', 0)} entries")
    grid.add_row("shield_subscribed", f"{nft.get('subscribed_count', 0)} entries")
    grid.add_row(
        "upload",
        f"[{upload_color}]{'enabled' if upload else 'disabled'}[/]  url={resp.get('server_url', '-')}",
    )
    grid.add_row(
        "bus",
        f"published={bus.get('published', 0)}  shipped={bus.get('shipped', 0)}  "
        f"spooled={bus.get('spooled', 0)}  dropped={bus.get('dropped', 0)}  "
        f"queued={bus.get('queued', 0)}",
    )

    # Feeds section
    feeds = (resp.get("subs") or {}).get("feeds", {})
    fleet_block_count = nft.get("fleet_block_count", 0)
    fleet_info = resp.get("fleet", {})
    server_active_blocks = fleet_info.get("server_active_blocks", 0)
    fleet_enabled = fleet_info.get("report_enabled", False) or fleet_info.get(
        "subscribe_enabled", False
    )

    if feeds or fleet_enabled:
        grid.add_row("", "")  # spacer
        for name in sorted(feeds):
            info = feeds[name]
            grid.add_row(
                name,
                f"{info.get('count', 0)} entries  synced {_fmt_ts(info.get('ts', 0))}",
            )
        if fleet_enabled:
            parts = []
            parts.append(f"{server_active_blocks} fleet-wide")
            parts.append(f"{fleet_block_count} ingested locally")
            grid.add_row(
                Text("fleet blocks", style="magenta"),
                "  ".join(parts),
            )

    # 24h activity section
    observed = activity.get("observed_24h", 0)
    blocks = activity.get("blocks_24h", 0)
    escalations = activity.get("escalations_24h", 0)
    fleet_blocks = activity.get("fleet_blocks_24h", 0)

    grid.add_row("", "")  # spacer
    grid.add_row(Text("Last 24h", style="bold yellow"), "")
    grid.add_row("  Observed", f"{observed:,}")
    grid.add_row("  Blocks", f"{blocks:,}")
    if escalations:
        grid.add_row("  Repeat offenders", f"{escalations} (escalated)")
    if fleet_blocks:
        grid.add_row("  Fleet blocks", f"{fleet_blocks}")

    # Fleet section
    fleet = resp.get("fleet", {})
    report_on = fleet.get("report_enabled", False)
    subscribe_on = fleet.get("subscribe_enabled", False)

    grid.add_row("", "")  # spacer
    grid.add_row(Text("Fleet", style="bold magenta"), "")

    if not report_on and not subscribe_on:
        grid.add_row("  mode", "[dim]disabled[/dim]")
    else:
        parts = []
        if report_on:
            parts.append("report")
        if subscribe_on:
            parts.append("subscribe")
        mode_str = " + ".join(parts)
        grid.add_row("  mode", f"[green]{mode_str}[/green]")

        ttl = fleet.get("block_ttl_seconds", 0)
        grid.add_row("  fleet block TTL", _fmt_ttl(ttl))

        queue_pending = fleet.get("queue_pending", 0)
        queue_style = "yellow" if queue_pending > 0 else "dim"
        grid.add_row("  queue pending", f"[{queue_style}]{queue_pending}[/]")

        allow_count = fleet.get("allow_list_count", 0)
        if allow_count:
            grid.add_row("  local allow-list", f"{allow_count} entries")

    # Detection Packs section inside the main panel
    packs = resp.get("detection_packs", [])
    grid.add_row("", "")  # spacer
    grid.add_row(Text("Detection Packs", style="bold green"), "")
    if packs:
        for pack in packs:
            grid.add_row("  📦", f"[green]{pack}[/green]")
    elif resp.get("upload_enabled"):
        grid.add_row("", "[dim]no packs active (rules unfiltered)[/dim]")

    console.print(
        Panel(grid, title="[bold]Vespid Status[/bold]", border_style="cyan", expand=False)
    )


@app.command("stats", hidden=True, rich_help_panel="Local Commands")
def stats(
    json_output: bool = JsonOption,
) -> None:
    """Alias for status."""
    status(json_output=json_output)


@app.command(rich_help_panel="Local Commands")
def counters(
    watch: int = typer.Option(0, "--watch", "-w", help="Refresh every N seconds (0 = one-shot)."),
    chain: str = typer.Option(
        "", "--chain", "-c", help="Filter by chain name (e.g. shield_prerouting)."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Show nftables packet/byte counters per set.

    Displays which feeds and local blocks are actively dropping traffic.
    Use --watch to see live rates (packets/sec, bytes/sec).
    """
    import time as _time

    prev_snapshot: dict[str, dict[str, int]] = {}
    prev_time = 0.0
    first = True

    while True:
        resp = _safe("counters")
        if not _check_resp(resp, json_output):
            raise typer.Exit(1)

        raw_counters = resp.get("counters", [])

        # Filter by chain if requested
        if chain:
            raw_counters = [c for c in raw_counters if chain in c.get("chain", "")]

        if json_output:
            _dump_json({"counters": raw_counters})
            if watch <= 0:
                return
            _time.sleep(watch)
            continue

        # Aggregate by set name (sum across chains for the overview)
        aggregated: dict[str, dict[str, int]] = {}
        for entry in raw_counters:
            set_name = entry["set"]
            if set_name not in aggregated:
                aggregated[set_name] = {"packets": 0, "bytes": 0}
            aggregated[set_name]["packets"] += entry["packets"]
            aggregated[set_name]["bytes"] += entry["bytes"]

        now = _time.time()

        # Build the table
        if watch > 0 and not first:
            # Clear screen for watch mode
            console.clear()

        title = "nftables Counters"
        if watch > 0:
            title += f"  (refreshing every {watch}s — Ctrl+C to stop)"

        table = Table(title=title, border_style="cyan", show_lines=False)
        table.add_column("Set", style="bold white", min_width=30)
        table.add_column("Packets", justify="right", style="bold")
        table.add_column("Bytes", justify="right")
        if watch > 0 and not first:
            table.add_column("Pkts/s", justify="right", style="green")
            table.add_column("Bytes/s", justify="right", style="green")

        # Sort by packets descending, then by set name ascending for ties
        sorted_sets = sorted(aggregated.items(), key=lambda x: (-x[1]["packets"], x[0]))
        elapsed = now - prev_time if prev_time > 0 else 1.0

        for set_name, totals in sorted_sets:
            pkts = totals["packets"]
            bts = totals["bytes"]

            # Friendly set name
            display_name = set_name
            if display_name.startswith("shield_feed_"):
                display_name = "📋 " + display_name.replace("shield_feed_", "")
            elif display_name.startswith("shield_local"):
                display_name = "🔒 " + display_name

            # Color by activity
            if pkts == 0:
                pkt_style = "dim"
            elif pkts > 10000:
                pkt_style = "bold red"
            elif pkts > 1000:
                pkt_style = "bold yellow"
            else:
                pkt_style = "bold green"

            row = [
                display_name,
                Text(f"{pkts:,}", style=pkt_style),
                _fmt_bytes(bts),
            ]

            if watch > 0 and not first:
                prev = prev_snapshot.get(set_name, {"packets": 0, "bytes": 0})
                dpkts = max(0, pkts - prev["packets"])
                dbytes = max(0, bts - prev["bytes"])
                rate_pkts = dpkts / elapsed if elapsed > 0 else 0
                rate_bytes = dbytes / elapsed if elapsed > 0 else 0

                rate_style = "green" if rate_pkts > 0 else "dim"
                row.append(Text(f"{rate_pkts:.1f}", style=rate_style))
                row.append(
                    Text(
                        f"{_fmt_bytes(int(rate_bytes))}/s" if rate_bytes > 0 else "—",
                        style=rate_style,
                    )
                )

            table.add_row(*row)

        console.print(table)

        # Show totals
        total_pkts = sum(t["packets"] for t in aggregated.values())
        total_bytes = sum(t["bytes"] for t in aggregated.values())
        console.print(f"  [dim]Total: {total_pkts:,} packets, {_fmt_bytes(total_bytes)}[/dim]")

        if watch <= 0:
            return

        prev_snapshot = aggregated
        prev_time = now
        first = False

        try:
            _time.sleep(watch)
        except KeyboardInterrupt:
            console.print("\n[dim]Stopped.[/dim]")
            return


@app.command(rich_help_panel="Local Commands")
def block(
    ip: str = typer.Argument(..., help="IP address to block."),
    reason: str = typer.Option("cli", help="Reason for the block."),
    json_output: bool = JsonOption,
) -> None:
    """Manually block an IP in shield_local."""
    resp = _safe("block", ip=ip, reason=reason)
    if not _check_resp(resp, json_output):
        raise typer.Exit(1)
    if json_output:
        _dump_json(resp)
        return
    console.print(
        f"[bold red]🚫 Blocked[/bold red] [white]{ip}[/white]  reason=[dim]{reason}[/dim]"
    )


@app.command(rich_help_panel="Local Commands")
def unblock(
    ip: str = typer.Argument(..., help="IP address to unblock."),
    reason: str = typer.Option("cli", help="Reason for the unblock."),
    json_output: bool = JsonOption,
) -> None:
    """Manually unblock an IP."""
    resp = _safe("unblock", ip=ip, reason=reason)
    if not _check_resp(resp, json_output):
        raise typer.Exit(1)
    if json_output:
        _dump_json(resp)
        return
    console.print(
        f"[bold green]✅ Unblocked[/bold green] [white]{ip}[/white]  reason=[dim]{reason}[/dim]"
    )


@app.command("sync-feeds", rich_help_panel="Local Commands")
def sync_feeds(
    json_output: bool = JsonOption,
) -> None:
    """Force a subscription feed sync."""
    with console.status("[bold cyan]Syncing feeds…[/bold cyan]", spinner="dots"):
        resp = _safe("sync_feeds")
    if not _check_resp(resp, json_output):
        raise typer.Exit(1)
    if json_output:
        _dump_json(resp)
        return
    console.print("[bold green]✅ Feed sync complete.[/bold green]")


@app.command("list-local", rich_help_panel="Local Commands")
def list_local(
    json_output: bool = JsonOption,
) -> None:
    """List every IP currently in shield_local with TTL and reason."""
    resp = _safe("list_local")
    if not _check_resp(resp, json_output):
        raise typer.Exit(1)
    if json_output:
        _dump_json(resp)
        return

    rows = resp.get("entries", [])
    if not rows:
        console.print("[dim](shield_local is empty)[/dim]")
        return

    # Sort by IP address numerically
    import ipaddress

    def _sort_key(entry: dict[str, Any]) -> tuple:
        try:
            return (0, ipaddress.ip_address(entry["ip"].split("/")[0]))
        except (ValueError, KeyError):
            return (1, entry.get("ip", ""))

    rows.sort(key=_sort_key)

    table = Table(
        title="shield_local",
        border_style="red",
        show_lines=False,
        padding=(0, 1),
        title_style="bold red",
        header_style="bold",
        row_styles=["", "dim"],
    )
    table.add_column("IP", style="bold white", min_width=20)
    table.add_column("TTL", justify="right")
    table.add_column("Strike", justify="center")
    table.add_column("Blocked At")
    table.add_column("Reason", style="dim")

    for r in rows:
        ttl = r.get("ttl_remaining", 0)
        strike = r.get("strike", 1)
        strike_style = "bold red" if strike >= 3 else ("yellow" if strike >= 2 else "dim")
        table.add_row(
            r["ip"],
            Text(_fmt_ttl(ttl), style=_ttl_style(ttl)),
            Text(str(strike), style=strike_style),
            _fmt_ts(r.get("blocked_at", 0)),
            r.get("reason", "-"),
        )

    console.print(table)
    console.print(f"[dim]{len(rows)} entries[/dim]")


@app.command("list-subscribed", rich_help_panel="Local Commands")
def list_subscribed(
    limit: int = typer.Option(50, help="Max entries to show (0 = all)."),
    json_output: bool = JsonOption,
) -> None:
    """List entries in shield_subscribed."""
    resp = _safe("list_subscribed", limit=None if limit == 0 else limit)
    if not _check_resp(resp, json_output):
        raise typer.Exit(1)
    if json_output:
        _dump_json(resp)
        return

    entries = resp.get("entries", [])
    total = resp.get("count", len(entries))
    returned = resp.get("returned", len(entries))

    if not entries:
        console.print("[dim](shield_subscribed is empty)[/dim]")
        return

    table = Table(
        title="shield_subscribed",
        border_style="blue",
        show_lines=False,
        padding=(0, 1),
        title_style="bold blue",
        header_style="bold",
    )
    table.add_column("Entry", style="white")
    for e in entries:
        table.add_row(str(e))

    console.print(table)
    console.print(f"[dim]showing {returned} of {total} entries[/dim]")


@app.command(rich_help_panel="Local Commands")
def check(
    ip: str = typer.Argument(..., help="IP address to look up."),
    json_output: bool = JsonOption,
) -> None:
    """Check whether an IP is blocked and why."""
    resp = _safe("check", ip=ip)
    if not _check_resp(resp, json_output):
        raise typer.Exit(1)
    if json_output:
        _dump_json(resp)
        return

    r = resp.get("result", {})
    if r.get("error"):
        err_console.print(f"[red]error:[/red] {r['error']}")
        raise typer.Exit(1)

    in_local = r.get("in_local", False)
    in_sub = r.get("in_subscribed", False)
    allowlisted = r.get("allowlisted", False)

    if allowlisted:
        verdict_text = "allowlisted"
        verdict_style = "bold white"
    elif in_local or in_sub:
        verdict_text = "BLOCKED"
        verdict_style = "bold red"
    else:
        verdict_text = "clean"
        verdict_style = "bold green"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    grid.add_row("ip", r["ip"])
    grid.add_row("verdict", Text(verdict_text, style=verdict_style))
    grid.add_row("allowlisted", str(allowlisted))
    grid.add_row("in shield_local", str(in_local))

    if r.get("local"):
        meta = r["local"]
        grid.add_row("  reason", meta.get("reason", "-"))
        grid.add_row("  blocked_at", _fmt_ts(meta.get("blocked_at", 0)))
        grid.add_row("  expires_at", _fmt_ts(meta.get("expires_at", 0)))

    grid.add_row("in shield_subscribed", str(in_sub))
    for cidr in r.get("matching_subscribed", []):
        grid.add_row("  matched CIDR", cidr)

    console.print(Panel(grid, title=f"[bold]Check: {ip}[/bold]", border_style="cyan", expand=False))


@app.command(rich_help_panel="Local Commands")
def recidive(
    ip: str = typer.Argument(..., help="IP address to look up repeat-offender history."),
    json_output: bool = JsonOption,
) -> None:
    """Show repeat-offender (recidive) history for an IP.

    Displays how many times the IP has been blocked, when it was first/last
    seen, and what TTL it would receive on its next offense.
    """
    resp = _safe("recidive_info", ip=ip)
    if not _check_resp(resp, json_output):
        raise typer.Exit(1)
    if json_output:
        _dump_json(resp)
        return

    r = resp.get("result", {})
    offenses = r.get("offenses", 0)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    grid.add_row("ip", r.get("ip", ip))
    grid.add_row("offenses", str(offenses))

    if offenses > 0:
        grid.add_row("first_seen", _fmt_ts(r.get("first_seen", 0)))
        grid.add_row("last_seen", _fmt_ts(r.get("last_seen", 0)))
        next_ttl = r.get("next_ttl", 0)
        grid.add_row("next_ban_ttl", _fmt_ttl(next_ttl))
    elif r.get("decayed"):
        grid.add_row("status", Text("decayed (clean slate)", style="green"))
    else:
        grid.add_row("status", Text("no history", style="dim"))

    style = "red" if offenses >= 3 else ("yellow" if offenses >= 2 else "cyan")
    console.print(
        Panel(grid, title=f"[bold]Recidive: {ip}[/bold]", border_style=style, expand=False)
    )


@app.command(rich_help_panel="Local Commands")
def recent(
    limit: int = typer.Option(20, help="Number of recent decisions to show."),
    json_output: bool = JsonOption,
) -> None:
    """Show recent block/unblock decisions."""
    resp = _safe("recent", limit=limit)
    if not _check_resp(resp, json_output):
        raise typer.Exit(1)
    if json_output:
        _dump_json(resp)
        return

    entries = resp.get("entries", [])
    if not entries:
        console.print("[dim](no recent decisions)[/dim]")
        return

    table = Table(
        title="Recent Decisions",
        border_style="magenta",
        show_lines=False,
        padding=(0, 1),
        title_style="bold magenta",
        header_style="bold",
        row_styles=["", "dim"],
    )
    table.add_column("Time")
    table.add_column("Action")
    table.add_column("IP", style="bold white", min_width=20)
    table.add_column("Reason", style="dim")

    for e in entries:
        action = e.get("action", "-")
        table.add_row(
            _fmt_ts(e.get("ts", 0)),
            Text(action, style=_action_style(action)),
            e.get("ip", "-"),
            e.get("reason", "-"),
        )

    console.print(table)


@app.command("allowlist-add", rich_help_panel="Local Commands")
def allowlist_add(
    entry: str = typer.Argument(
        ..., help="IP address or CIDR to allowlist (e.g. 24.217.104.111 or 10.0.0.0/8)."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Add an IP or CIDR to the allowlist (hot, no restart needed).

    Also auto-unblocks the IP from shield_local if it was blocked.
    """
    resp = _safe("allowlist_add", entry=entry)
    if not _check_resp(resp, json_output):
        raise typer.Exit(1)
    if json_output:
        _dump_json(resp)
        return

    normalized = resp.get("entry", entry)
    if resp.get("already"):
        source = resp.get("source", "unknown")
        console.print(f"[dim]{normalized} is already allowlisted (source: {source})[/dim]")
        return

    unblocked = resp.get("unblocked", [])
    console.print(f"[bold green]✅ Allowlisted[/bold green] [white]{normalized}[/white]")
    if unblocked:
        for ip in unblocked:
            console.print(f"   [yellow]↳ auto-unblocked {ip} from shield_local[/yellow]")


@app.command("allowlist-remove", rich_help_panel="Local Commands")
def allowlist_remove(
    entry: str = typer.Argument(..., help="IP address or CIDR to remove from the allowlist."),
    json_output: bool = JsonOption,
) -> None:
    """Remove an IP or CIDR from the runtime allowlist.

    Only entries added via 'allowlist-add' can be removed this way.
    Config-file entries require editing the config and restarting.
    """
    resp = _safe("allowlist_remove", entry=entry)
    if not _check_resp(resp, json_output):
        raise typer.Exit(1)
    if json_output:
        _dump_json(resp)
        return

    console.print(
        f"[bold yellow]🗑  Removed[/bold yellow] [white]{resp.get('entry', entry)}[/white] from allowlist"
    )


@app.command("allowlist-list", rich_help_panel="Local Commands")
def allowlist_list(
    json_output: bool = JsonOption,
) -> None:
    """Show all allowlisted IPs/CIDRs with their source."""
    resp = _safe("allowlist_list")
    if not _check_resp(resp, json_output):
        raise typer.Exit(1)
    if json_output:
        _dump_json(resp)
        return

    entries = resp.get("entries", [])
    if not entries:
        console.print("[dim](allowlist is empty)[/dim]")
        return

    table = Table(
        title="Allowlist",
        border_style="green",
        show_lines=False,
        padding=(0, 1),
        title_style="bold green",
        header_style="bold",
        row_styles=["", "dim"],
    )
    table.add_column("Entry", style="bold white", min_width=20)
    table.add_column("Source")

    for e in entries:
        source = e.get("source", "unknown")
        style = "dim cyan" if source == "config" else "green"
        table.add_row(e["entry"], Text(source, style=style))

    console.print(table)
    console.print(f"[dim]{len(entries)} entries[/dim]")


@app.command("tail-log", rich_help_panel="Local Commands")
def tail_log(
    follow: bool = typer.Option(False, "-f", "--follow", help="Follow the log in real time."),
    decisions: bool = typer.Option(
        False, "--decisions", help="Tail the decisions audit log instead."
    ),
    lines_count: int = typer.Option(
        200, "-n", "--lines", help="Number of lines to show (non-follow mode)."
    ),
) -> None:
    """Tail the human-readable vespid log."""
    from ..logging_setup import DECISIONS_LOG_NAME, DEFAULT_LOG_DIR, HUMAN_LOG_NAME

    name = DECISIONS_LOG_NAME if decisions else HUMAN_LOG_NAME
    path = str(DEFAULT_LOG_DIR / name)

    if not os.path.exists(path):
        err_console.print(f"[red]log file not found:[/red] {path}")
        raise typer.Exit(1)

    formatter = _format_decision_line if decisions else _format_human_line

    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            if follow:
                import time

                fh.seek(0, os.SEEK_END)
                while True:
                    line = fh.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    console.print(formatter(line.rstrip("\n")), highlight=False)
            else:
                tail = fh.readlines()[-lines_count:]
                for line in tail:
                    console.print(formatter(line.rstrip("\n")), highlight=False)
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# Log line formatters
# ---------------------------------------------------------------------------
_LEVEL_STYLES: dict[str, str] = {
    "DEBUG": "dim",
    "INFO": "green",
    "WARNING": "yellow",
    "ERROR": "bold red",
    "CRITICAL": "bold white on red",
}

_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b")
_KV_RE = re.compile(r"\b(\w+)=([\w./:\-]+)")
_NUM_RE = re.compile(r"\b(\d+)\b")

_ACTION_WORDS: dict[str, str] = {
    "BLOCK": "bold red",
    "BLOCKED": "bold red",
    "UNBLOCK": "bold green",
    "UNBLOCKED": "bold green",
    "DETECT": "bold yellow",
    "DENY": "bold red",
    "DENIED": "bold red",
    "ALLOW": "bold green",
    "ALLOWED": "bold green",
    "SYNC": "bold cyan",
    "FEED": "bold cyan",
    "REPLACED": "bold cyan",
    "CATCHUP": "bold magenta",
}


def _format_human_line(line: str) -> Text:
    """Colorize a human log line: TIMESTAMP LEVEL LOGGER MESSAGE."""
    parts = line.split(None, 3)
    if len(parts) < 4:
        return Text(line)

    ts, level, logger, message = parts[0], parts[1], parts[2], parts[3]
    level_style = _LEVEL_STYLES.get(level.upper(), "white")

    result = Text()
    result.append(ts, style="dim cyan")
    result.append(" ")
    result.append(f"{level:<7}", style=level_style)
    result.append(" ")
    result.append(f"{logger:<22}", style="blue")
    result.append(" ")
    _colorize_message(result, message, level.upper())
    return result


def _colorize_message(result: Text, message: str, level: str) -> None:
    """Parse structured content out of a log message and apply colors."""
    pos = 0
    combined = re.compile(
        r"(?P<ip>\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)"
        r"|(?P<kv>\b(\w+)=([\w./:\-]+))"
        r"|(?P<arrow>->)"
        r"|(?P<word>\b[A-Z_]{3,}\b)"
    )
    for m in combined.finditer(message):
        if m.start() > pos:
            result.append(message[pos : m.start()])

        if m.group("ip"):
            result.append(m.group(), style="bold white")
        elif m.group("kv"):
            key = m.group(3)
            val = m.group(4)
            result.append(key, style="dim")
            result.append("=", style="dim")
            result.append(val, style="bold white")
        elif m.group("arrow"):
            result.append("->", style="bold yellow")
        elif m.group("word"):
            word = m.group("word")
            style = _ACTION_WORDS.get(word)
            if style:
                result.append(word, style=style)
            else:
                result.append(word)
        pos = m.end()

    if pos < len(message):
        result.append(message[pos:])


def _format_decision_line(line: str) -> Text:
    """Colorize a decisions.jsonl line."""
    try:
        rec = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return Text(line)

    ts = rec.get("ts", "")
    event = rec.get("event", "")
    level = rec.get("level", "INFO")
    msg = rec.get("msg", "")
    ip = rec.get("source_ip", "")
    action = rec.get("action_taken", "")

    level_style = _LEVEL_STYLES.get(level.upper(), "white")
    action_s = _action_style(action) if action else "white"

    result = Text()
    result.append(ts, style="dim cyan")
    result.append(" ")
    result.append(f"{level:<7}", style=level_style)
    if event:
        result.append(f" [{event}]", style="bold magenta")
    if action:
        result.append(f" {action}", style=action_s)
    if ip:
        result.append(f" {ip}", style="bold white")
    if msg and msg != event:
        result.append(f"  {msg}", style="dim")
    return result


# ---------------------------------------------------------------------------
# Spool helpers (stream from end to avoid loading huge files into memory)
# ---------------------------------------------------------------------------
def _tail_lines(path: str, n: int) -> list[str]:
    """Read the last *n* lines from a file efficiently."""
    buf_size = 8192
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        remaining = fh.tell()
        blocks: list[bytes] = []
        newline_count = 0
        while remaining > 0 and newline_count <= n:
            read_size = min(buf_size, remaining)
            remaining -= read_size
            fh.seek(remaining)
            chunk = fh.read(read_size)
            blocks.append(chunk)
            newline_count += chunk.count(b"\n")
        data = b"".join(reversed(blocks))
        all_lines = data.split(b"\n")
        non_empty = [line for line in all_lines if line]
        return [line.decode("utf-8", errors="replace") for line in non_empty[-n:]]


def _parse_spool_line(raw: str) -> dict[str, Any] | None:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None


def _spool_summary(path: str) -> dict[str, Any]:
    """Stream through the spool file once and collect summary stats."""
    from collections import Counter

    count = 0
    oldest: str | None = None
    newest: str | None = None
    by_event_type: Counter[str] = Counter()
    by_action: Counter[str] = Counter()
    by_country: Counter[str] = Counter()

    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ev = _parse_spool_line(line)
            if ev is None:
                continue
            count += 1
            ts = ev.get("timestamp", "")
            if oldest is None:
                oldest = ts
            newest = ts
            by_event_type[ev.get("event_type", "unknown")] += 1
            by_action[ev.get("action_taken", "unknown")] += 1
            country = _fmt_country(ev.get("geo_data") or {})
            by_country[country] += 1

    size = os.path.getsize(path)
    return {
        "path": path,
        "size_bytes": size,
        "event_count": count,
        "oldest": oldest,
        "newest": newest,
        "by_event_type": dict(by_event_type.most_common()),
        "by_action": dict(by_action.most_common()),
        "top_countries": dict(by_country.most_common(10)),
    }


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} TB"


@app.command("spool", rich_help_panel="Local Commands")
def spool(
    tail: int | None = typer.Option(None, "--tail", "-n", help="Show the last N spooled events."),
    purge: bool = typer.Option(
        False, "--purge", help="Truncate the spool file (asks for confirmation)."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Inspect or manage the local event spool.

    With no flags, shows a summary of the spool file (size, event counts,
    breakdown by type). Use --tail to see recent events, or --purge to
    clear stale data.
    """
    from ..config import CONFIG

    path = CONFIG.spool_path

    if not os.path.exists(path):
        if json_output:
            _dump_json({"ok": True, "spool": "empty", "path": path})
        else:
            console.print(f"[dim]Spool file does not exist yet:[/dim] {path}")
        return

    # --- purge ---------------------------------------------------------
    if purge:
        size_before = os.path.getsize(path)
        if not json_output:
            confirm = typer.confirm(f"Truncate {path} ({_fmt_bytes(size_before)})?")
            if not confirm:
                raise typer.Abort()
        with open(path, "w") as fh:
            fh.truncate(0)
        if json_output:
            _dump_json({"ok": True, "purged_bytes": size_before, "path": path})
        else:
            console.print(f"[bold green]Purged[/bold green] {_fmt_bytes(size_before)} from {path}")
        return

    # --- tail ----------------------------------------------------------
    if tail is not None:
        count = max(tail, 1)
        raw_lines = _tail_lines(path, count)
        events = [e for line in raw_lines if (e := _parse_spool_line(line)) is not None]

        if json_output:
            _dump_json({"ok": True, "count": len(events), "events": events})
            return

        if not events:
            console.print("[dim](spool is empty)[/dim]")
            return

        table = Table(
            title=f"Last {len(events)} Spooled Events",
            border_style="yellow",
            show_lines=False,
            padding=(0, 1),
            title_style="bold yellow",
            header_style="bold",
            row_styles=["", "dim"],
        )
        table.add_column("Time")
        table.add_column("Event Type", style="bold")
        table.add_column("Action")
        table.add_column("IP", style="bold white", min_width=16)
        table.add_column("Country")
        table.add_column("Node", style="dim")

        for ev in events:
            action = ev.get("action_taken", "-")
            geo = ev.get("geo_data") or {}
            table.add_row(
                ev.get("timestamp", "-"),
                ev.get("event_type", "-"),
                Text(action, style=_action_style(action)),
                ev.get("source_ip", "-"),
                _fmt_country(geo),
                ev.get("node_id", "-"),
            )

        console.print(table)
        return

    # --- summary (default) ---------------------------------------------
    with console.status("[bold cyan]Scanning spool…[/bold cyan]", spinner="dots"):
        summary = _spool_summary(path)

    if json_output:
        _dump_json({"ok": True, **summary})
        return

    if summary["event_count"] == 0:
        console.print(f"[dim]Spool file exists but is empty:[/dim] {path}")
        return

    upload_status = "enabled" if CONFIG.upload_enabled else "disabled"
    upload_color = "green" if CONFIG.upload_enabled else "yellow"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    grid.add_row("path", summary["path"])
    grid.add_row("size", _fmt_bytes(summary["size_bytes"]))
    grid.add_row("events", f"{summary['event_count']:,}")
    grid.add_row("oldest", summary["oldest"] or "-")
    grid.add_row("newest", summary["newest"] or "-")
    grid.add_row("upload", Text(upload_status, style=upload_color))

    console.print(
        Panel(grid, title="[bold]Spool Summary[/bold]", border_style="yellow", expand=False)
    )

    # Event type breakdown
    if summary["by_event_type"]:
        et = Table(title="By Event Type", border_style="dim", show_lines=False)
        et.add_column("Event Type", style="bold")
        et.add_column("Count", justify="right")
        for name, cnt in summary["by_event_type"].items():
            et.add_row(name, f"{cnt:,}")
        console.print(et)

    # Action breakdown
    if summary["by_action"]:
        at = Table(title="By Action", border_style="dim", show_lines=False)
        at.add_column("Action", style="bold")
        at.add_column("Count", justify="right")
        for name, cnt in summary["by_action"].items():
            at.add_row(Text(name, style=_action_style(name)), f"{cnt:,}")
        console.print(at)

    # Top countries
    if summary["top_countries"]:
        ct = Table(title="Top Countries", border_style="dim", show_lines=False)
        ct.add_column("Country", style="bold")
        ct.add_column("Count", justify="right")
        for code, cnt in summary["top_countries"].items():
            ct.add_row(code, f"{cnt:,}")
        console.print(ct)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    """Entry point kept for backward compatibility with pyproject console_scripts."""
    try:
        app(standalone_mode=True, args=argv)
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
