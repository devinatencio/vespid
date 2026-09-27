#!/usr/bin/env python3
"""Sigma Rule Importer — CLI for importing SigmaHQ detection rules into Vespid.

Usage:
    sigma_import.py --init       Clone Sigma repo + convert + generate packs
    sigma_import.py --check      Check for upstream changes (exit code 0=none, 1=updates)
    sigma_import.py --sync       Pull latest rules + re-convert + regenerate packs
    sigma_import.py --report     Show current sync status and rule counts

The converted rules are written as YAML pack files into:
    vespid-server/packs/sigma-web-attacks.yaml
    vespid-server/packs/sigma-ssh-attacks.yaml

Sync state is stored in:
    ~/.cache/vespid/sigma_state.json
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add the converter module to the path
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR.parent) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR.parent))

from scripts.sigma_converter import (  # noqa: E402
    ConvertedRule,
    convert_rules,
    generate_pack_yaml,
    parse_sigma_rule,
)

log = logging.getLogger("sigma_import")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ── Constants ───────────────────────────────────────────────────────────

SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
CACHE_DIR = Path.home() / ".cache" / "vespid"
SIGMA_CLONE_DIR = CACHE_DIR / "sigma"
STATE_FILE = CACHE_DIR / "sigma_state.json"

# Sigma rule directories to scan (relative to repo root)
RULE_DIRS = [
    "rules/web",
    "rules/linux/builtin/sshd",
    "rules/linux/process_creation",
    "rules/linux/builtin",
]

# Output pack definitions
PACKS = {
    "sigma-web-attacks": {
        "display_name": "Sigma Web Attack Detection",
        "icon": "🌐",
        "description": (
            "Web application attack detection rules imported from SigmaHQ/sigma. "
            "Covers SQL injection, XSS, path traversal, JNDI/Log4Shell exploits, "
            "SSTI, webshells, suspicious user agents, scanner tools, and "
            "source code enumeration. Auto-generated from the Sigma community "
            "rule repository."
        ),
        "prerequisite": "Requires web server access logs in Combined Log Format (Apache/Nginx).",
        "dirs": ["rules/web"],
    },
    "sigma-ssh-attacks": {
        "display_name": "Sigma SSH Attack Detection",
        "icon": "🔐",
        "description": (
            "SSH attack detection rules imported from SigmaHQ/sigma. "
            "Covers suspicious SSHD error messages indicating exploitation "
            "attempts. Auto-generated from the Sigma community rule repository."
        ),
        "prerequisite": "Requires SSH daemon logs (secure/auth log).",
        "dirs": ["rules/linux/builtin/sshd"],
    },
    "sigma-host-threats": {
        "display_name": "Sigma Host Threat Detection (Auditd)",
        "icon": "🐧",
        "description": (
            "Host-based process creation detection rules imported from SigmaHQ/sigma. "
            "Covers reverse shells, privilege escalation, persistence, defense evasion, "
            "credential dumping, lateral movement, C2, and exfiltration via Linux auditd "
            "process monitoring. Auto-generated from the Sigma community rule repository."
        ),
        "prerequisite": "Requires auditd configured with execve audit rules.",
        "dirs": ["rules/linux/process_creation", "rules/linux/builtin"],
    },
}

# Where to write output packs (relative to project root)
PACKS_OUTPUT_DIR = Path(__file__).resolve().parent.parent.parent / "vespid-server" / "packs"


# ── Git helpers ─────────────────────────────────────────────────────────


def _ensure_sigma_repo() -> Path | None:
    """Ensure the Sigma repo is cloned locally. Returns the repo path or None."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if not SIGMA_CLONE_DIR.exists():
        log.info("Cloning SigmaHQ/sigma (depth=1)...")
        try:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--no-checkout",
                    SIGMA_REPO_URL,
                    str(SIGMA_CLONE_DIR),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.CalledProcessError as exc:
            log.error("Failed to clone Sigma repo: %s", exc.stderr)
            return None

        # Configure sparse checkout for the directories we need
        try:
            subprocess.run(
                ["git", "-C", str(SIGMA_CLONE_DIR), "sparse-checkout", "init", "--cone"],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            # Set all directories in a single call (cone mode accepts multiple dirs)
            subprocess.run(
                ["git", "-C", str(SIGMA_CLONE_DIR), "sparse-checkout", "set"] + RULE_DIRS,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            subprocess.run(
                ["git", "-C", str(SIGMA_CLONE_DIR), "checkout", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.CalledProcessError as exc:
            log.error("Failed to configure sparse checkout: %s", exc.stderr)
            return None

    return SIGMA_CLONE_DIR


def _git_pull(repo_dir: Path) -> bool:
    """Pull latest changes. Returns True if updates were pulled."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "pull", "--ff-only"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            log.warning("Git pull failed: %s", result.stderr.strip())
            return False
        output = result.stdout + result.stderr
        if "Already up to date" in output:
            return False
        return True
    except subprocess.CalledProcessError as exc:
        log.error("Git pull error: %s", exc)
        return False


def _git_head_commit(repo_dir: Path) -> str:
    """Return the current HEAD commit hash."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""


# ── Rule discovery ──────────────────────────────────────────────────────


def discover_rules(repo_dir: Path, dirs: list[str]) -> list[dict]:
    """Discover and parse all Sigma YAML rules in the given directories."""
    rules: list[dict] = []
    for rule_dir in dirs:
        target = repo_dir / rule_dir
        if not target.exists():
            log.warning("Rule directory not found: %s", target)
            continue
        for yaml_file in sorted(target.rglob("*.yml")):
            try:
                text = yaml_file.read_text(encoding="utf-8")
                rule = parse_sigma_rule(text)
                if rule is not None:
                    rules.append(rule)
                else:
                    log.debug("Skipping non-rule file: %s", yaml_file)
            except Exception as exc:
                log.warning("Failed to read %s: %s", yaml_file.name, exc)
    return rules


# ── State management ───────────────────────────────────────────────────


def _load_state() -> dict:
    """Load sync state from disk."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "last_commit": "",
        "last_sync": "",
        "rules_imported": 0,
        "sigma_ids": {},
    }


def _save_state(state: dict) -> None:
    """Save sync state to disk."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


# ── Commands ────────────────────────────────────────────────────────────


def cmd_init() -> int:
    """Initial import: clone + convert + generate packs."""
    repo_dir = _ensure_sigma_repo()
    if not repo_dir:
        return 1

    commit = _git_head_commit(repo_dir)
    log.info("Sigma repo at commit: %s", commit[:12])

    all_rules = discover_rules(repo_dir, RULE_DIRS)
    log.info("Discovered %d Sigma rules", len(all_rules))

    converted, report = convert_rules(all_rules)
    log.info(
        "Converted %d / %d rules (skipped: %d complex, %d platform, %d unsupported)",
        report.converted,
        report.total,
        report.skipped_complex,
        report.skipped_platform,
        report.skipped_unsupported,
    )

    _write_packs(converted)

    state = {
        "last_commit": commit,
        "last_sync": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rules_imported": report.converted,
        "sigma_ids": {cr.sigma_id: cr.name for cr in converted if cr.sigma_id},
    }
    _save_state(state)
    log.info("State saved to %s", STATE_FILE)

    return 0


def cmd_check() -> int:
    """Check if upstream Sigma repo has new commits. Exit 0=up to date, 1=updates."""
    repo_dir = _ensure_sigma_repo()
    if not repo_dir:
        return 2

    state = _load_state()
    last_commit = state.get("last_commit", "")

    # Try fetching
    try:
        subprocess.run(
            ["git", "-C", str(repo_dir), "fetch", "--depth", "1", "origin", "master"],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
    except subprocess.CalledProcessError:
        log.error("Failed to fetch from Sigma remote")
        return 2

    current = _git_head_commit(repo_dir)
    if not current:
        return 2

    remote_commit = _git_remote_head(repo_dir)
    if remote_commit and remote_commit != current:
        _git_pull(repo_dir)

    current = _git_head_commit(repo_dir)
    if last_commit and current == last_commit:
        log.info("Sigma rules are up to date (commit %s)", current[:12])
        return 0
    elif last_commit:
        log.info("Updates available (was %s, now %s)", last_commit[:12], current[:12])
        return 1
    else:
        log.info("No previous sync state found. Run --init first.")
        return 1


def cmd_sync() -> int:
    """Pull latest Sigma rules + re-convert + regenerate packs."""
    repo_dir = _ensure_sigma_repo()
    if not repo_dir:
        return 1

    state = _load_state()
    old_commit = state.get("last_commit", "")
    old_ids = state.get("sigma_ids", {})

    # Pull latest
    _git_pull(repo_dir)
    new_commit = _git_head_commit(repo_dir)

    if old_commit and new_commit == old_commit:
        log.info("No changes detected. Rules are up to date.")
        return 0

    # Re-convert
    all_rules = discover_rules(repo_dir, RULE_DIRS)
    log.info("Discovered %d Sigma rules", len(all_rules))

    converted, report = convert_rules(all_rules)
    log.info(
        "Converted %d / %d rules (skipped: %d complex, %d platform, %d unsupported)",
        report.converted,
        report.total,
        report.skipped_complex,
        report.skipped_platform,
        report.skipped_unsupported,
    )

    # Show diff
    new_ids = {cr.sigma_id: cr.name for cr in converted if cr.sigma_id}
    added = set(new_ids) - set(old_ids)
    removed = set(old_ids) - set(new_ids)
    if added:
        log.info("New rules: %d (%s)", len(added), ", ".join(added))
    if removed:
        log.info("Removed rules: %d (%s)", len(removed), ", ".join(removed))

    _write_packs(converted)

    new_state = {
        "last_commit": new_commit,
        "last_sync": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rules_imported": report.converted,
        "sigma_ids": new_ids,
    }
    _save_state(new_state)
    log.info("State updated. %d rule(s) imported.", report.converted)

    return 0


def cmd_report() -> int:
    """Show current sync status."""
    state = _load_state()
    if not state.get("last_sync"):
        print("No sync performed yet. Run --init first.")
        return 0

    print(f"Last sync:     {state['last_sync']}")
    print(f"Sigma commit:  {state.get('last_commit', 'unknown')[:12]}")
    print(f"Rules imported: {state['rules_imported']}")

    # Check if packs exist
    for pack_name in PACKS:
        pack_file = PACKS_OUTPUT_DIR / f"{pack_name}.yaml"
        if pack_file.exists():
            # Count rules in the pack
            rule_count = 0
            text = pack_file.read_text(encoding="utf-8")
            for line in text.splitlines():
                if line.strip().startswith("- name: sigma_"):
                    rule_count += 1
            print(f"  {pack_name}: {rule_count} rules ({pack_file})")
        else:
            print(f"  {pack_name}: not generated")

    # Check for updates
    repo_dir = _ensure_sigma_repo()
    if repo_dir:
        try:
            subprocess.run(
                ["git", "-C", str(repo_dir), "fetch", "--depth", "1", "origin", "master"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.CalledProcessError:
            pass
        current = _git_head_commit(repo_dir)
        last = state.get("last_commit", "")
        if current and last and current != last:
            print(f"\nUpdates available! Current HEAD: {current[:12]}")
            print("Run --sync to update.")
        elif current and last:
            print(f"\nUp to date (HEAD: {current[:12]})")

    return 0


# ── Pack output ─────────────────────────────────────────────────────────


def _write_packs(rules: list[ConvertedRule]) -> None:
    """Write converted rules to pack YAML files, organized by category."""
    # Group rules by their target pack
    packs_rules: dict[str, list[ConvertedRule]] = {name: [] for name in PACKS}

    for cr in rules:
        # Route to pack based on log_sources
        if "auditd" in cr.log_sources:
            packs_rules["sigma-host-threats"].append(cr)
        elif "secure" in cr.log_sources:
            packs_rules["sigma-ssh-attacks"].append(cr)
        else:
            packs_rules["sigma-web-attacks"].append(cr)

    PACKS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for pack_name, pack_rules in packs_rules.items():
        if not pack_rules:
            log.info("No rules for pack '%s', skipping", pack_name)
            continue

        pack = PACKS[pack_name]
        yaml_content = generate_pack_yaml(
            rules=pack_rules,
            pack_name=pack_name,
            display_name=pack["display_name"],
            icon=pack["icon"],
            description=pack["description"],
            prerequisite=pack.get("prerequisite", ""),
        )

        output_path = PACKS_OUTPUT_DIR / f"{pack_name}.yaml"
        output_path.write_text(yaml_content, encoding="utf-8")
        log.info(
            "Wrote %d rules to %s",
            len(pack_rules),
            output_path,
        )


def _git_remote_head(repo_dir: Path) -> str:
    """Return the remote HEAD commit hash."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "origin/master"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""


# ── CLI ─────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import SigmaHQ detection rules into Vespid pack format.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--init",
        action="store_true",
        help="Clone Sigma repo, convert rules, and generate pack YAMLs",
    )
    group.add_argument(
        "--check",
        action="store_true",
        help="Check for upstream changes without modifying anything",
    )
    group.add_argument(
        "--sync",
        action="store_true",
        help="Pull latest rules, re-convert, and regenerate packs",
    )
    group.add_argument(
        "--report",
        action="store_true",
        help="Show current sync status and rule counts",
    )

    args = parser.parse_args()

    if args.init:
        return cmd_init()
    elif args.check:
        return cmd_check()
    elif args.sync:
        return cmd_sync()
    elif args.report:
        return cmd_report()

    return 0


if __name__ == "__main__":
    sys.exit(main())
