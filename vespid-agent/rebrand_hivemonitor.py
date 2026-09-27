#!/usr/bin/env python3
"""Rebrand hivemonitor workspace → Vespid Agent.

Transforms crate names, binaries, Cargo.toml references, systemd units,
packaging, docs, and source content.

Usage:
    python3 rebrand_hivemonitor.py [--dry-run]
"""

import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent

DRY_RUN = "--dry-run" in sys.argv

REPLACE = [
    # Longest first (most specific) to avoid partial matches
    ("hivelogic-monitor-agent", "vespid-agent"),
    ("hivelogic-monitor-common", "vespid-agent-common"),
    ("hivelogic-monitor-enroll", "vespid-agent-enroll"),
    ("hivelogic-monitor-worker", "vespid-worker"),
    ("hivelogic-sync", "vespid-sync"),
    ("hivelogic-monitor", "vespid-agent"),
    ("HiveLogic Monitor Agent", "Vespid Agent"),
    ("HiveLogic Monitor Worker", "Vespid Worker"),
    ("HiveLogic Sync", "Vespid Sync"),
    ("HIVELOGIC_MONITOR", "VESPID_AGENT"),
    # Snake-case crate references in Rust source (must come before plain hivelogic)
    ("hivelogic_monitor_common", "vespid_agent_common"),
    ("hivelogic_monitor_enroll", "vespid_agent_enroll"),
    ("HiveLogic", "Vespid"),
    ("hivelogic", "vespid"),
    ("HIVELOGIC", "VESPID"),
]

DIR_RENAMES = [
    ("crates/hivelogic-monitor-agent", "crates/vespid-agent"),
    ("crates/hivelogic-monitor-common", "crates/vespid-agent-common"),
    ("crates/hivelogic-monitor-enroll", "crates/vespid-agent-enroll"),
    ("hivelogic-sync", "vespid-sync"),
]

FILE_RENAMES = [
    ("systemd/hivelogic-monitor-agent.service", "systemd/vespid-agent.service"),
    ("systemd/hivelogic-monitor-worker.service", "systemd/vespid-worker.service"),
    ("systemd/hivelogic-sync-agent.service", "systemd/vespid-sync-agent.service"),
    ("systemd/hivelogic-sync-agent.timer", "systemd/vespid-sync-agent.timer"),
    ("packaging/hivelogic-monitor-agent.spec", "packaging/vespid-agent.spec"),
    ("packaging/hivelogic-sync.spec", "packaging/vespid-sync.spec"),
    ("packaging/build-hivelogic-sync-deb.sh", "packaging/build-vespid-sync-deb.sh"),
    ("packaging/build-hivelogic-sync-rpm.sh", "packaging/build-vespid-sync-rpm.sh"),
]

EXTENSIONS = {".rs", ".toml", ".md", ".sh", ".yml", ".yaml", ".json", ".html", ".css", ".js", ".service", ".spec", ".timer", ".cfg", ".ini", ".template"}
EXCLUDE_PATHS = {".git", "target", "site", ".venv", "venv", "__pycache__", ".github"}


def log(msg):
    print(f"  {'[dry-run]' if DRY_RUN else '[apply]'} {msg}")


def rename_dir(src: Path, dst: Path):
    if not src.exists():
        log(f"SKIP directory not found: {src}")
        return
    if dst.exists():
        log(f"SKIP destination already exists: {dst}")
        return
    if DRY_RUN:
        log(f"Would rename directory {src} -> {dst}")
    else:
        src.rename(dst)
        log(f"Renamed directory {src} -> {dst}")


def rename_file(src: Path, dst: Path):
    if not src.exists():
        log(f"SKIP file not found: {src}")
        return
    if dst.exists():
        log(f"SKIP destination already exists: {dst}")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    if DRY_RUN:
        log(f"Would rename file {src} -> {dst}")
    else:
        src.rename(dst)
        log(f"Renamed file {src} -> {dst}")


def replace_in_file(path: Path):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    new_text = text
    count = 0
    for old, new in REPLACE:
        if old in new_text:
            new_text = new_text.replace(old, new)
            count += new_text.count(new) - text.count(new)
    if new_text != text:
        if DRY_RUN:
            log(f"Would modify {path.relative_to(REPO)} ({count} replacements)")
        else:
            path.write_text(new_text, encoding="utf-8")
            log(f"Modified {path.relative_to(REPO)} ({count} replacements)")
    return count


def collect_files(root: Path) -> list[Path]:
    files = []
    for p in root.rglob("*"):
        if any(ex in p.parts for ex in EXCLUDE_PATHS):
            continue
        if p.is_file() and p.suffix in EXTENSIONS:
            files.append(p)
    # Also include files without extensions (Makefile, etc.)
    for p in root.rglob("*"):
        if any(ex in p.parts for ex in EXCLUDE_PATHS):
            continue
        if p.is_file() and p.suffix == "" and p.name in ("Makefile", "Dockerfile", "install.sh"):
            files.append(p)
    return sorted(files)


def main():
    print("=" * 60)
    print("  Hivemonitor → Vespid Agent Rebrand")
    print("=" * 60)
    if DRY_RUN:
        print("  DRY RUN — no changes will be made\n")

    # Phase 1: Rename directories
    print("\n[Phase 1] Renaming directories...")
    for src_rel, dst_rel in DIR_RENAMES:
        rename_dir(REPO / src_rel, REPO / dst_rel)

    # Phase 2: Rename files
    print("\n[Phase 2] Renaming files...")
    for src_rel, dst_rel in FILE_RENAMES:
        rename_file(REPO / src_rel, REPO / dst_rel)

    # Phase 3: Content transformations
    print("\n[Phase 3] Applying content transformations...")
    files = collect_files(REPO)
    total = 0
    for f in files:
        total += replace_in_file(f)

    # Phase 4: Update Cargo.toml workspace members
    cargo = REPO / "Cargo.toml"
    if cargo.exists():
        text = cargo.read_text(encoding="utf-8")
        new_text = text
        for old, new in [
            ('"crates/hivelogic-monitor-agent"', '"crates/vespid-agent"'),
            ('"crates/hivelogic-monitor-common"', '"crates/vespid-agent-common"'),
            ('"crates/hivelogic-monitor-enroll"', '"crates/vespid-agent-enroll"'),
        ]:
            new_text = new_text.replace(old, new)
        if new_text != text:
            if DRY_RUN:
                log(f"Would update Cargo.toml workspace members")
            else:
                cargo.write_text(new_text, encoding="utf-8")
                log("Updated Cargo.toml workspace members")

    # Summary
    print(f"\n{'=' * 60}")
    if DRY_RUN:
        print("  Dry run complete. Run without --dry-run to apply.")
    else:
        print("  Rebrand complete!")
        print("  Next: review changes, then cargo build --all")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
