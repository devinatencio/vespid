# Contributing to Vespid

Thanks for your interest in contributing. This document covers the basics for
each component in the repository.

## Repository components

| Path            | Component                        | Language |
| --------------- | -------------------------------- | -------- |
| `vespid/`       | Security daemon + CLI (node)     | Python   |
| `vespid-server/`| Dashboard / management server    | Python   |
| `vespid-agent/` | Monitoring agent                 | Rust     |
| `tests/`        | Agent test suite                 | Python   |
| `docs/`         | MkDocs documentation source      | Markdown |

## Development setup

### Agent

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test,dev]"

pytest tests                 # test
ruff check vespid tests      # lint
ruff format vespid tests     # format
mypy                         # type check
```

### Server

The server has its own environment (its dependencies conflict with the agent's).

```bash
python3 -m venv vespid-server/.venv
vespid-server/.venv/bin/pip install -r vespid-server/requirements-dev.txt

cd vespid-server
.venv/bin/pytest server_tests
.venv/bin/ruff check app vespid_server.py gunicorn.conf.py
.venv/bin/ruff format app vespid_server.py gunicorn.conf.py
```

### Rust agent

```bash
cd vespid-agent
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Building the Rust agent requires `protoc` (`protobuf-compiler`).

## Pull requests

- Keep changes focused; one logical change per pull request.
- Add or update tests for behavioral changes.
- Ensure lint, format, type checks, and tests pass for the affected component
  (see the commands above; CI runs the same checks).
- Update the documentation under `docs/` and the relevant `README.md` when
  behavior or configuration changes.
- Add an entry to `CHANGELOG.md` under the `Unreleased` section for
  user-visible changes.

## Coding conventions

- Python: formatted with Ruff, line length 100, target 3.10+ (agent) / 3.11+
  (server).
- Rust: rustfmt defaults; Clippy clean with `-D warnings`.
- Do not commit secrets, credentials, generated build output, or cache
  directories (see `.gitignore`).

## License

By contributing you agree that your contributions are licensed under the
project's license (GPL-3.0-or-later, see `LICENSE`).
