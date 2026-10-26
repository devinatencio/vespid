#!/usr/bin/env python3
"""Bump every version reference in the Vespid tree.

The canonical version lives in ``vespid-server/VERSION``. This tool updates
the build metadata, package manifests, changelogs, and build-doc examples in
one pass, and can verify that nothing has drifted.

Usage::

    python3 packaging/bump_version.py 1.0.4
    python3 packaging/bump_version.py --dry-run 1.0.4
    python3 packaging/bump_version.py --check

``make bump-version NEW_VERSION=1.0.4`` and ``make version-check`` wrap these
commands.
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = Path("vespid-server/VERSION")
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")

# Files whose version examples should follow the current release.
DOC_FILES = (
    "build_readme.md",
    "docs/building.md",
    "docs/quickstart.md",
    "vespid-server/README.md",
    "README_Makefile.md",
)

# (relative path, pattern with one capture group containing the version)
CHECK_PATTERNS = (
    ("Makefile", re.compile(r"(?m)^VERSION\s*:=\s*(\S+)")),
    ("pyproject.toml", re.compile(r'(?m)^version\s*=\s*"([^"]+)"')),
    ("vespid/__init__.py", re.compile(r'(?m)^__version__\s*=\s*"([^"]+)"')),
    ("vespid-server/app/__init__.py", re.compile(r'(?m)^__version__\s*=\s*"([^"]+)"')),
    (
        "vespid-server/app/geo_updater.py",
        re.compile(r"Vespid-Server/([0-9]+\.[0-9]+\.[0-9]+)"),
    ),
    ("build_freeze.py", re.compile(r"version='([0-9]+\.[0-9]+\.[0-9]+)'")),
    ("vespid-agent/Cargo.toml", re.compile(r'(?m)^version\s*=\s*"([^"]+)"')),
    ("vespid-agent/vespid-sync/setup.py", re.compile(r'version="([^"]+)"')),
    (
        "vespid-agent/packaging/vespid-agent.spec",
        re.compile(r"(?m)^Version:\s+([0-9]+\.[0-9]+\.[0-9]+)"),
    ),
    (
        "vespid-agent/packaging/vespid-sync.spec",
        re.compile(r"(?m)^Version:\s+([0-9]+\.[0-9]+\.[0-9]+)"),
    ),
    (
        "vespid-server/vespid-server.spec",
        re.compile(r"%\{!\?version:%define version ([0-9]+\.[0-9]+\.[0-9]+)"),
    ),
    ("vespid.spec", re.compile(r"(?m)^%define version\s+([0-9]+\.[0-9]+\.[0-9]+)")),
    ("debian/vespid/DEBIAN/control", re.compile(r"(?m)^Version:\s+(\S+)")),
    ("debian/vespid-server/DEBIAN/control", re.compile(r"(?m)^Version:\s+(\S+)")),
    ("build_deb.sh", re.compile(r"echo ([0-9]+\.[0-9]+\.[0-9]+)")),
)

# (relative path, pattern, replacement)
SIMPLE_REPLACEMENTS = (
    (
        "Makefile",
        re.compile(r"(?m)^(VERSION\s*:=\s*)\S+"),
        lambda m, v: m.group(1) + v,
    ),
    (
        "pyproject.toml",
        re.compile(r'(?m)^(version\s*=\s*")[^"]+(")'),
        lambda m, v: m.group(1) + v + m.group(2),
    ),
    (
        "vespid/__init__.py",
        re.compile(r'(?m)^(__version__\s*=\s*")[^"]+(")'),
        lambda m, v: m.group(1) + v + m.group(2),
    ),
    (
        "vespid-server/app/__init__.py",
        re.compile(r'(?m)^(__version__\s*=\s*")[^"]+(")'),
        lambda m, v: m.group(1) + v + m.group(2),
    ),
    (
        "vespid-server/app/geo_updater.py",
        re.compile(r"(Vespid-Server/)[0-9]+\.[0-9]+\.[0-9]+"),
        lambda m, v: m.group(1) + v,
    ),
    (
        "build_freeze.py",
        re.compile(r"(version=')[0-9]+\.[0-9]+\.[0-9]+(')"),
        lambda m, v: m.group(1) + v + m.group(2),
    ),
    (
        "vespid-agent/Cargo.toml",
        re.compile(r'(?m)^(version\s*=\s*")[^"]+(")'),
        lambda m, v: m.group(1) + v + m.group(2),
    ),
    (
        "vespid-agent/vespid-sync/setup.py",
        re.compile(r'(version=")[^"]+(")'),
        lambda m, v: m.group(1) + v + m.group(2),
    ),
    (
        "vespid-agent/packaging/vespid-agent.spec",
        re.compile(r"(?m)^(Version:\s+)\S+"),
        lambda m, v: m.group(1) + v,
    ),
    (
        "vespid-agent/packaging/vespid-sync.spec",
        re.compile(r"(?m)^(Version:\s+)\S+"),
        lambda m, v: m.group(1) + v,
    ),
    (
        "vespid-server/vespid-server.spec",
        re.compile(r"(%\{!\?version:%define version )\S+"),
        lambda m, v: m.group(1) + v,
    ),
    (
        "vespid.spec",
        re.compile(r"(?m)^(%define version\s+)\S+"),
        lambda m, v: m.group(1) + v,
    ),
    (
        "debian/vespid/DEBIAN/control",
        re.compile(r"(?m)^(Version:\s+)\S+"),
        lambda m, v: m.group(1) + v,
    ),
    (
        "debian/vespid-server/DEBIAN/control",
        re.compile(r"(?m)^(Version:\s+)\S+"),
        lambda m, v: m.group(1) + v,
    ),
    (
        "build_deb.sh",
        re.compile(r"(echo )[0-9]+\.[0-9]+\.[0-9]+"),
        lambda m, v: m.group(1) + v,
    ),
)

# Root package entries in Cargo.lock that share the release version. Other
# crates in the lock file keep their own versions.
CARGO_ROOT_PACKAGES = ("vespid-agent", "vespid-agent-common", "vespid-agent-enroll")

RPM_SPECS = (
    ("vespid.spec", "Vespid Team <team@vespid.dev>"),
    ("vespid-server/vespid-server.spec", "Vespid Team <team@vespid.dev>"),
    ("vespid-agent/packaging/vespid-agent.spec", "Vespid Team <dev@vespid.io>"),
    ("vespid-agent/packaging/vespid-sync.spec", "Vespid Team <dev@vespid.io>"),
)


def _read(root: Path, rel: str) -> str:
    return (root / rel).read_text(encoding="utf-8")


def _stage(pending: dict[Path, tuple[str, str]], root: Path, rel: str, new: str) -> None:
    path = root / rel
    if path in pending:
        old, current = pending[path]
        if new != current:
            pending[path] = (old, new)
        return
    old = path.read_text(encoding="utf-8")
    if new != old:
        pending[path] = (old, new)


def _pending_text(pending: dict[Path, tuple[str, str]], root: Path, rel: str) -> str:
    """Return staged text if the file was already changed, else disk text."""
    path = root / rel
    if path in pending:
        return pending[path][1]
    return path.read_text(encoding="utf-8")


def _replace_required(
    pending: dict[Path, tuple[str, str]],
    root: Path,
    rel: str,
    pattern: re.Pattern[str],
    replacement,
    version: str,
) -> None:
    old = _read(root, rel)
    new, count = pattern.subn(lambda m: replacement(m, version), old)
    if count == 0:
        raise SystemExit(f"{rel}: could not find the version field to update")
    _stage(pending, root, rel, new)


def _replace_cargo_lock(pending: dict[Path, tuple[str, str]], root: Path, version: str) -> None:
    rel = "vespid-agent/Cargo.lock"
    old = _read(root, rel)
    new = old
    for package in CARGO_ROOT_PACKAGES:
        pattern = re.compile(rf'(?ms)(name = "{re.escape(package)}"\s*\nversion = ")[^"]+(")')
        new, count = pattern.subn(
            lambda m: m.group(1) + version + m.group(2),
            new,
        )
        if count != 1:
            raise SystemExit(f"{rel}: expected one version entry for {package}, found {count}")
    _stage(pending, root, rel, new)


def _insert_markdown_section(
    text: str,
    version: str,
    date: str,
    heading: str,
    message: str,
) -> str:
    if re.search(rf"(?m)^## \[?{re.escape(version)}\]?(?:\s|$)", text):
        return text

    section = f"{heading}\n\n### Changed\n\n- {message}\n\n"

    unreleased = re.search(r"(?m)^## (?:\[Unreleased\]|Unreleased)\s*$", text)
    if unreleased:
        next_section = re.search(r"(?m)^## ", text[unreleased.end() :])
        insert_at = unreleased.end() + next_section.start() if next_section else len(text)
    else:
        first_section = re.search(r"(?m)^## ", text)
        insert_at = first_section.start() if first_section else len(text)

    return text[:insert_at].rstrip() + "\n\n" + section + text[insert_at:]


def _insert_rpm_changelog(
    text: str,
    version: str,
    maintainer: str,
    message: str,
) -> str:
    if re.search(rf"(?m)^\* .+ - {re.escape(version)}-1$", text):
        return text

    marker = "%changelog"
    marker_at = text.find(marker)
    if marker_at < 0:
        raise SystemExit("RPM spec is missing %changelog")

    date = dt.date.today().strftime("%a %b %d %Y")
    remainder = text[marker_at + len(marker) :].lstrip("\n")
    entry = f"{marker}\n* {date} {maintainer} - {version}-1\n- {message}\n"
    return text[:marker_at] + entry + remainder


def _update_changelogs(
    pending: dict[Path, tuple[str, str]],
    root: Path,
    version: str,
    message: str,
) -> None:
    today = dt.date.today().isoformat()

    root_changelog = _pending_text(pending, root, "CHANGELOG.md")
    root_changelog = _insert_markdown_section(
        root_changelog,
        version,
        today,
        f"## [{version}] - {today}",
        message,
    )
    link = f"[{version}]: https://github.com/vespid/vespid/releases/tag/v{version}"
    if link not in root_changelog:
        first_link = re.search(
            r"(?m)^\[[0-9]+\.[0-9]+\.[0-9]+\]: ",
            root_changelog,
        )
        if first_link:
            root_changelog = (
                root_changelog[: first_link.start()]
                + link
                + "\n"
                + root_changelog[first_link.start() :]
            )
        else:
            root_changelog = root_changelog.rstrip() + "\n" + link + "\n"
    _stage(pending, root, "CHANGELOG.md", root_changelog)

    server_changelog = _pending_text(pending, root, "vespid-server/CHANGELOG.md")
    server_changelog = _insert_markdown_section(
        server_changelog,
        version,
        today,
        f"## {version} — {today}",
        message,
    )
    _stage(pending, root, "vespid-server/CHANGELOG.md", server_changelog)

    for rel, maintainer in RPM_SPECS:
        old = _pending_text(pending, root, rel)
        new = _insert_rpm_changelog(old, version, maintainer, message)
        _stage(pending, root, rel, new)


def _bump(root: Path, version: str, message: str) -> dict[Path, tuple[str, str]]:
    pending: dict[Path, tuple[str, str]] = {}
    old_version = _read(root, str(VERSION_FILE)).strip()
    if old_version == version:
        print(f"Already at {version}; no version changes needed.")
        return pending

    _stage(pending, root, str(VERSION_FILE), version + "\n")

    for rel, pattern, replacement in SIMPLE_REPLACEMENTS:
        _replace_required(pending, root, rel, pattern, replacement, version)

    _replace_cargo_lock(pending, root, version)

    # Keep current-version examples in the build docs in sync.
    for rel in DOC_FILES:
        old = _read(root, rel)
        if old_version not in old:
            print(
                f"warning: {rel} does not contain {old_version}; skipping doc example",
                file=sys.stderr,
            )
            continue
        _stage(pending, root, rel, old.replace(old_version, version))

    _update_changelogs(pending, root, version, message)
    return pending


def _check(root: Path) -> int:
    canonical = _read(root, str(VERSION_FILE)).strip()
    if not SEMVER_RE.match(canonical):
        print(f"{VERSION_FILE}: invalid version {canonical!r}", file=sys.stderr)
        return 1

    errors: list[str] = []

    def check(rel: str, pattern: re.Pattern[str]) -> None:
        path = root / rel
        if not path.exists():
            errors.append(f"{rel}: missing")
            return
        found = pattern.findall(path.read_text(encoding="utf-8"))
        if not found:
            errors.append(f"{rel}: version field not found")
            return
        for value in found:
            if value != canonical:
                errors.append(f"{rel}: expected {canonical}, found {value}")

    for rel, pattern in CHECK_PATTERNS:
        check(rel, pattern)

    cargo_lock = _read(root, "vespid-agent/Cargo.lock")
    for package in CARGO_ROOT_PACKAGES:
        match = re.search(
            rf'(?ms)name = "{re.escape(package)}"\s*\nversion = "([^"]+)"',
            cargo_lock,
        )
        if not match:
            errors.append(f"vespid-agent/Cargo.lock: missing {package}")
        elif match.group(1) != canonical:
            errors.append(
                f"vespid-agent/Cargo.lock: {package} is {match.group(1)}, expected {canonical}"
            )

    root_changelog = _read(root, "CHANGELOG.md")
    root_match = re.search(
        r"(?m)^## \[([0-9]+\.[0-9]+\.[0-9]+)\] - ",
        root_changelog,
    )
    if not root_match or root_match.group(1) != canonical:
        found = root_match.group(1) if root_match else "none"
        errors.append(f"CHANGELOG.md: top release is {found}, expected {canonical}")
    if f"[{canonical}]:" not in root_changelog:
        errors.append(f"CHANGELOG.md: missing release link for {canonical}")

    server_changelog = _read(root, "vespid-server/CHANGELOG.md")
    server_match = re.search(
        r"(?m)^## ([0-9]+\.[0-9]+\.[0-9]+) [—-] ",
        server_changelog,
    )
    if not server_match or server_match.group(1) != canonical:
        found = server_match.group(1) if server_match else "none"
        errors.append(f"vespid-server/CHANGELOG.md: top release is {found}, expected {canonical}")

    for rel, _maintainer in RPM_SPECS:
        text = _read(root, rel)
        match = re.search(
            r"(?m)^%changelog\s*\n\*\s+[^\n]*\s-\s+([0-9]+\.[0-9]+\.[0-9]+)-1",
            text,
        )
        if not match:
            errors.append(f"{rel}: missing RPM changelog entry")
        elif match.group(1) != canonical:
            errors.append(f"{rel}: top RPM changelog is {match.group(1)}, expected {canonical}")

    for rel in DOC_FILES:
        if canonical not in _read(root, rel):
            errors.append(f"{rel}: does not mention {canonical}")

    if errors:
        print(f"Version check failed for {canonical}:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"All version references match {canonical}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="new x.y.z version")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify all references match vespid-server/VERSION",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show the changes without writing them",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root (default: parent of packaging/)",
    )
    parser.add_argument(
        "--message",
        default=None,
        help="changelog/RPM bullet text (default: Version bump to x.y.z)",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()

    if args.check:
        if args.version or args.dry_run:
            parser.error("--check cannot be combined with a version or --dry-run")
        return _check(root)

    if not args.version:
        parser.error("a new x.y.z version is required (or use --check)")
    if not SEMVER_RE.match(args.version):
        parser.error(f"invalid version {args.version!r}; expected x.y.z")

    message = args.message or f"Version bump to {args.version}"
    pending = _bump(root, args.version, message)

    if not pending:
        return 0

    if args.dry_run:
        for path, (old, new) in pending.items():
            rel = path.relative_to(root)
            sys.stdout.writelines(
                difflib.unified_diff(
                    old.splitlines(keepends=True),
                    new.splitlines(keepends=True),
                    fromfile=str(rel),
                    tofile=str(rel),
                )
            )
        print(f"\nDry run: {len(pending)} file(s) would change.")
        return 0

    for path, (_old, new) in pending.items():
        path.write_text(new, encoding="utf-8")

    print(f"Bumped to {args.version}; updated {len(pending)} file(s).")
    print("Review the generated changelog/RPM placeholders, then run:")
    print("  make version-check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
