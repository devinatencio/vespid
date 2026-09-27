# Nuitka Build Guide — Vespid

Compile `vespid` (daemon + CLI) and `vespid-server` (Flask dashboard) into standalone native binaries using [Nuitka](https://nuitka.net/).

---

## Prerequisites

| Requirement | Install |
|-------------|---------|
| Python 3.10+ | Already required by both projects |
| Nuitka | `pip install nuitka ordered-set` |
| C compiler | `xcode-select --install` (macOS) or `apt install gcc` (Linux) |
| zstandard (optional, faster cache) | `pip install zstandard` |

---

## What Gets Built

| Binary | Source | Entry Point |
|--------|--------|-------------|
| `vespid` | `vespid/daemon.py` | `Vespid` daemon (asyncio) |
| `vespid-cli` | `vespid/cli.py` | Typer-based management CLI |
| `vespid-server` | `vespid-server/vespid_server.py` | Flask app + CLI (init-db, create-admin) |

---

## Quick Start

```bash
./build_nuitka.sh
```

Output lands in `dist/nuitka/` at the workspace root.

---

## Build Modes

The script defaults to `--onefile` (single portable executable). To get a folder-based standalone build instead (faster startup, easier debugging):

```bash
./build_nuitka.sh --standalone
```

| Mode | Pros | Cons |
|------|------|------|
| `--onefile` | Single file, easy to deploy/copy | Slightly slower cold start (extracts to tmpdir) |
| `--standalone` | Fast startup, inspectable | Produces a directory per binary |

---

## Troubleshooting

### Missing modules at runtime

Flask, Jinja2, and Rich use dynamic imports. If you see `ModuleNotFoundError`, add the module to the relevant `EXTRA_INCLUDES` array in `build_nuitka.sh`:

```bash
EXTRA_INCLUDES_SERVER+=(--include-module=some_missing_module)
```

Common culprits:
- `jinja2.ext`
- `markupsafe`
- `rich.traceback`
- `email.mime.text` (Flask internals)

### Rich unicode data

Rich dynamically loads unicode width tables at runtime using `importlib.import_module()` with module names containing hyphens (e.g., `rich._unicode_data.unicode17-0-0`). Nuitka cannot compile these as normal modules. The build script handles this by including the `rich/_unicode_data/` directory as data files so Python's import system can find them at runtime.

### Data files not found

Templates and static assets are bundled via `--include-data-dir`. If you add new template directories or static folders, update the `--include-data-dir` flags in the script.

### gunicorn + Nuitka

You cannot easily compile gunicorn into the binary. For production deployments behind gunicorn, compile the `app` package as a Nuitka extension module instead:

```bash
python -m nuitka --module app --include-package=app
```

Then point gunicorn at the compiled `.so`:

```bash
gunicorn -w 4 "app:create_app()"
```

---

## Output Structure

```
dist/nuitka/
├── vespid          # daemon binary
├── vespid-cli          # CLI binary
├── vespid-server   # server binary
└── build.log           # full compilation log
```

---

## Notes

- Binaries are platform-specific. Build on the target OS/arch.
- The build can take several minutes per binary (Nuitka does full C compilation).
- First build is slowest; subsequent builds use Nuitka's cache.
