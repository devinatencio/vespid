"""vespid-cli — local management and inspection CLI (Rich + Typer edition).

This package organizes the CLI into sub-modules:

    cli/app.py          — Main Typer app, local daemon commands, log tailing
    cli/fleet.py        — Fleet-wide blocklist management (server)
    cli/intel.py        — IP intelligence queries (server)
    cli/nodes.py        — Node management and visibility (server)
    cli/config.py       — Centralized config management (server)
    cli/admin.py        — User/key/enrollment administration (server)
    cli/server.py       — Server connection management (login/logout/status)
    cli/events.py       — Event search and export (server)

The entry point imports `app` from this package.
"""

from .app import app, main

__all__ = ["app", "main"]
