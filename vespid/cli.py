"""Backward-compatibility shim — imports from the new cli/ subpackage.

The CLI has been reorganized into vespid/cli/ for cleaner separation.
This module re-exports `app` and `main` so existing entry points
(entry_vespid_cli.py, pyproject.toml console_scripts) continue to work.
"""

from vespid.cli import app, main  # noqa: F401

__all__ = ["app", "main"]
