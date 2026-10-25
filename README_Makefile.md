# Makefile Reference

Two Makefiles exist — one in the project root (agent builds) and one in
`vespid-server/` (server builds).  Both follow the same conventions.

## Root Makefile

```bash
make help         # Show all targets
```

| Target | Description |
|--------|-------------|
| `install-deps` | Install runtime dependencies (typer, rich, pyyaml, requests, httpx) |
| `test-deps` | Install test/dev dependencies (pytest, ruff) |
| `test` | Run pytest test suite (`PYTHONPATH=. pytest tests/ -v`) |
| `syntax-check` | Run `ast.parse()` syntax validation on all source files |
| `lint` | Run ruff linter + formatter check on `vespid/` and `tests/` |
| `rpm` | Build agent RPM package → `rpmbuild/RPMS/` |
| `deb` | Build Debian/Ubuntu `.deb` packages via `build_deb.sh` |
| `docs` | Build MkDocs documentation site → `website/docs/` |
| `docs-serve` | Serve built docs locally at `http://localhost:8000` |
| `clean` | Remove build artifacts (rpmbuild/, build/, dist/, `.pytest_cache`, `site/`, `website/docs/`) |

### Variables

```bash
PYTHON=python3.12 make test          # Override Python version
PYTEST="pytest -x" make test         # Pass custom pytest flags
```

| Variable | Default | Purpose |
|----------|---------|---------|
| `PYTHON` | `python3` | Python interpreter |
| `PYTEST` | `python3 -m pytest` | Test runner |
| `PIP` | `pip3` | Package installer |
| `NAME` | `vespid` | Package name for RPM |
| `VERSION` | `1.0.3` | Package version for RPM |

## Server Makefile (`vespid-server/`)

```bash
cd vespid-server/
make help         # Show all targets
```

| Target | Description |
|--------|-------------|
| `venv` | Create `.venv/` and install dependencies from `requirements.txt` |
| `test` | Run pytest test suite (`tests/ -v`) |
| `test-props` | Run only property-based tests |
| `dev` | Start Flask development server |
| `rpm` | Build server RPM package → `rpmbuild/RPMS/` |
| `lint` | Run ruff linter + formatter on `app/` and source files |
| `clean` | Remove `rpmbuild/`, `__pycache__`, `.pytest_cache`, `.hypothesis` |

### Variables

```bash
PYTHON=.venv/bin/python make dev     # Use venv Python
```

| Variable | Default | Purpose |
|----------|---------|---------|
| `PYTHON` | `.venv/bin/python` | Python interpreter (venv expected) |
| `PYTEST` | `.venv/bin/pytest` | Test runner |
| `PIP` | `.venv/bin/pip` | Package installer |
| `FLASK` | `.venv/bin/flask` | Flask CLI |
| `NAME` | `vespid-server` | Package name for RPM |
| `VERSION` | `1.0.3` | Package version for RPM |

## Common workflows

### Development

```bash
# First-time setup
make install-deps test-deps

# Run all checks
make syntax-check lint test

# Build docs and preview
make docs
python3 -m http.server -d site/ 8000
```

### Packaging

```bash
# One-shot: build every component in the host's native format (rpm or deb).
# Installs any missing packaging toolchain first, then compiles.
make package

# Force a format for all components
make package-rpm
make package-deb

# No local toolchain (e.g. macOS)? Build both formats in containers.
make package-docker

# Per-component builds
make rpm
cd vespid-server && make rpm
make deb
```

`make package*` depends on `make package-deps`, which installs the host's
packaging toolchain (RPM/DEB build tools, `protobuf-compiler`, and a rustup
Rust toolchain) before building. It is idempotent, so it is cheap to re-run.

### CI / pre-commit

```bash
make syntax-check lint test    # Agent
cd vespid-server && make lint test   # Server
```
