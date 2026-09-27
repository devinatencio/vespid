"""Intelligence sub-commands for vespid-cli.

Provides CLI access to the IP intelligence database — search, detail
views, and analytics queries via the central server API.
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

intel_app = typer.Typer(
    name="intel",
    help="IP intelligence database queries (requires server connection).",
    no_args_is_help=True,
)

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
    import json

    console.print(JSON(json.dumps(data, default=str, sort_keys=True)))


def _threat_score_style(score: int) -> str:
    if score >= 80:
        return "bold red"
    if score >= 50:
        return "bold yellow"
    if score >= 20:
        return "yellow"
    return "dim"


def _s(value: Any, default: str = "-") -> str:
    """Safely convert any value to a display string for Rich tables."""
    if value is None:
        return default
    if isinstance(value, list):
        return ", ".join(str(v) for v in value) if value else default
    if isinstance(value, dict):
        return ", ".join(f"{k}: {v}" for k, v in value.items()) if value else default
    return str(value) or default


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@intel_app.command("search")
def intel_search(
    query: str | None = typer.Argument(None, help="IP, CIDR prefix, or threat tag to search."),
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    per_page: int = typer.Option(30, "--per-page", help="Results per page."),
    min_score: int | None = typer.Option(None, "--min-score", help="Minimum threat score filter."),
    threat_tag: str | None = typer.Option(None, "--tag", help="Filter by threat tag."),
    json_output: bool = JsonOption,
) -> None:
    """Search the IP intelligence database."""
    client = _get_client()
    try:
        result = client.intel_search(
            query=query,
            page=page,
            per_page=per_page,
            min_score=min_score,
            threat_tag=threat_tag,
        )
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    records = result.get("records", result.get("results", result.get("ips", [])))
    total = result.get("total_count", result.get("total", len(records)))
    total_pages = result.get("total_pages", 1)

    if not records:
        console.print("[dim](no results)[/dim]")
        return

    table = Table(
        title="Intelligence Records",
        border_style="cyan",
        show_lines=False,
        padding=(0, 1),
        title_style="bold cyan",
        header_style="bold",
        row_styles=["", "dim"],
    )
    table.add_column("IP", style="bold white", min_width=18)
    table.add_column("Score", justify="right")
    table.add_column("Blocks", justify="right")
    table.add_column("Sightings", justify="right")
    table.add_column("Country")
    table.add_column("ASN", style="dim")
    table.add_column("Tags", style="yellow")
    table.add_column("Last Seen")

    for r in records:
        score = r.get("threat_score", r.get("reputation_score", r.get("score", 0))) or 0
        table.add_row(
            r.get("ip_address", r.get("ip", "-")),
            Text(str(score), style=_threat_score_style(score)),
            str(r.get("total_blocks", r.get("block_count", 0))),
            str(r.get("total_sightings", r.get("sighting_count", 0))),
            r.get("last_country", r.get("country", "-")),
            str(r.get("last_asn", r.get("asn", "-"))),
            _s(r.get("threat_tags", r.get("tags"))),
            r.get("last_seen_at", r.get("last_seen", "-")),
        )

    console.print(table)
    if total_pages > 1:
        console.print(
            f"[dim]Page {page} of {total_pages} ({total} records) — "
            f"use --page {page + 1} for next page[/dim]"
        )
    elif total > len(records):
        console.print(f"[dim]{total} records — use --per-page to show more[/dim]")


@intel_app.command("ip")
def intel_ip(
    ip: str = typer.Argument(..., help="IP address to look up."),
    json_output: bool = JsonOption,
) -> None:
    """Get detailed intelligence for a specific IP."""
    client = _get_client()
    try:
        result = client.intel_get_ip(ip)
    except ServerClientError as exc:
        if exc.status_code == 404:
            console.print(f"[dim]No intelligence record for {ip}[/dim]")
            raise typer.Exit(0) from exc
        _handle_error(exc)
        raise typer.Exit(1) from exc

    if json_output:
        _dump_json(result)
        return

    record = result.get("record", result)

    # Header with threat score
    score = record.get("threat_score", record.get("reputation_score", record.get("score"))) or 0
    score_style = _threat_score_style(score)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()

    grid.add_row("ip", record.get("ip_address", record.get("ip", ip)) or ip)
    grid.add_row("threat_score", Text(str(score), style=score_style))
    grid.add_row("", "")

    # Counters
    grid.add_row(
        "total_blocks", str(record.get("total_times_blocked", record.get("total_blocks", 0)) or 0)
    )
    grid.add_row(
        "total_sightings",
        str(record.get("total_times_seen", record.get("total_sightings", 0)) or 0),
    )
    grid.add_row(
        "seen_24h", str(record.get("times_seen_last_24h", record.get("blocks_24h", 0)) or 0)
    )
    grid.add_row("seen_7d", str(record.get("times_seen_last_7d", record.get("blocks_7d", 0)) or 0))
    grid.add_row(
        "seen_30d", str(record.get("times_seen_last_30d", record.get("blocks_30d", 0)) or 0)
    )
    grid.add_row("repeat_offender", str(record.get("repeat_offender", False)))
    grid.add_row("", "")

    # Geo / Network
    grid.add_row(
        "country",
        str(record.get("last_country", record.get("geo_country", record.get("country"))) or "-"),
    )
    grid.add_row("asn", str(record.get("last_asn", record.get("asn")) or "-"))
    grid.add_row(
        "isp",
        str(record.get("last_isp_org", record.get("isp_organization", record.get("isp"))) or "-"),
    )
    grid.add_row("", "")

    # Metadata
    grid.add_row("first_seen", str(record.get("first_seen_at", record.get("first_seen")) or "-"))
    grid.add_row("last_seen", str(record.get("last_seen_at", record.get("last_seen")) or "-"))
    nodes_val = record.get(
        "distinct_nodes", record.get("total_reporting_nodes", record.get("node_count"))
    )
    grid.add_row("reporting_nodes", str(nodes_val) if nodes_val is not None else "-")

    # Handle threat_tags as list or string
    tags = record.get("threat_tags", record.get("tags"))
    if isinstance(tags, list):
        tags_str = ", ".join(tags) if tags else "-"
    else:
        tags_str = str(tags) if tags else "-"
    grid.add_row("threat_tags", tags_str)

    # Reporting nodes list
    node_list = record.get("reporting_node_list", [])
    if isinstance(node_list, list) and node_list:
        grid.add_row("", "")
        for n in node_list:
            grid.add_row("  node", str(n))

    border_style = "red" if score >= 80 else ("yellow" if score >= 50 else "cyan")
    console.print(
        Panel(grid, title=f"[bold]Intel: {ip}[/bold]", border_style=border_style, expand=False)
    )

    # Event types breakdown if available
    event_types = record.get("event_types", record.get("event_type_breakdown", {}))
    if event_types and isinstance(event_types, dict):
        et_table = Table(title="Event Types", border_style="dim", show_lines=False)
        et_table.add_column("Type", style="bold")
        et_table.add_column("Count", justify="right")
        for etype, count in sorted(event_types.items(), key=lambda x: -x[1]):
            et_table.add_row(etype, str(count))
        console.print(et_table)


@intel_app.command("blocklist")
def intel_blocklist(
    min_score: int | None = typer.Option(
        None, "--min-score", help="Minimum reputation score (0-100)."
    ),
    min_sightings: int | None = typer.Option(None, "--min-sightings", help="Minimum times seen."),
    threat_tag: str | None = typer.Option(None, "--tag", help="Filter by threat tag."),
    geo_country: str | None = typer.Option(
        None, "--country", help="Filter by country code (e.g. CN, RU)."
    ),
    repeat_offender: bool = typer.Option(
        False, "--repeat-offender", help="Only show repeat offenders."
    ),
    json_output: bool = JsonOption,
) -> None:
    """Export the intel blocklist — all IPs seen by the intelligence database.

    Outputs one IP per line by default (suitable for piping to files or
    other tools). Use --json for structured output with count.
    """
    client = _get_client()
    try:
        result = client.intel_blocklist(
            min_score=min_score,
            min_sightings=min_sightings,
            threat_tag=threat_tag,
            geo_country=geo_country,
            repeat_offender=repeat_offender if repeat_offender else None,
            output_format="json",
        )
    except ServerClientError as exc:
        _handle_error(exc)
        raise typer.Exit(1) from exc

    ips = result.get("ips", [])
    count = result.get("count", len(ips))

    if json_output:
        _dump_json(result)
        return

    if not ips:
        console.print("[dim](no IPs in blocklist matching filters)[/dim]")
        return

    # Summary header
    console.print(f"[bold cyan]Intel Blocklist[/bold cyan] — [dim]{count} IPs[/dim]\n")

    # Print IPs one per line (easy to pipe to file)
    for ip in ips:
        console.print(ip)

    console.print(f"\n[dim]Total: {count} IPs[/dim]")
