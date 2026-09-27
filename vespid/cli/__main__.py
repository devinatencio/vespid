"""Allow running the CLI as `python -m vespid.cli`."""

import sys

from .app import app


def main() -> int:
    try:
        app(standalone_mode=True)
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        from rich.console import Console

        Console(stderr=True).print(f"[red]error:[/red] {exc}")
        return 1


sys.exit(main())
