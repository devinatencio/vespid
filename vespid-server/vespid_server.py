#!/usr/bin/env python3
"""Vespid Server entry point.

Provides CLI commands for database initialization and admin user creation,
and starts the Flask development server when run without a subcommand.

Usage:
    python vespid_server.py [--config CONFIG] init-db
    python vespid_server.py [--config CONFIG] create-admin
    python vespid_server.py [--config CONFIG]
"""

import argparse
import getpass
import logging
import os
import sys
import tempfile
from datetime import UTC

from app import create_app
from app.config import load_config
from app.models import create_user, get_db, init_db

# Configure logging so that logger.info() calls in create_app and blueprints
# are visible in the console/error log.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)


def _build_mysql_config(config):
    """Build a MySQL/MariaDB configuration dictionary from loaded config."""
    return {
        "DATABASE_TYPE": config["DATABASE_TYPE"],
        "DATABASE_HOST": config["DATABASE_HOST"],
        "DATABASE_PORT": config["DATABASE_PORT"],
        "DATABASE_NAME": config["DATABASE_NAME"],
        "DATABASE_USER": config["DATABASE_USER"],
        "DATABASE_PASSWORD": config["DATABASE_PASSWORD"],
    }


def _resolve_db_config(config):
    """Return ``(db_type, db_config)`` — a path for SQLite, a dict for MySQL."""
    db_type = config.get("DATABASE_TYPE", "sqlite").lower()
    if db_type == "sqlite":
        return db_type, config["DATABASE_PATH"]
    return db_type, _build_mysql_config(config)


def cmd_init_db(args):
    """Create or reset database tables."""
    config = load_config(args.config)
    db_type = config.get("DATABASE_TYPE", "sqlite").lower()

    if db_type == "sqlite":
        db_path = config["DATABASE_PATH"]
        print(f"Initializing SQLite database at: {db_path}")
        try:
            init_db(db_path)
        except ConnectionError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        # mysql or mariadb
        host = config["DATABASE_HOST"]
        port = config["DATABASE_PORT"]
        database = config["DATABASE_NAME"]
        print(f"Initializing MySQL database at: {host}:{port}/{database}")
        db_config = _build_mysql_config(config)
        try:
            init_db(db_config)
        except ConnectionError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

    print("Database initialized successfully.")


def cmd_create_admin(args):
    """Create the initial admin user."""
    import secrets

    config = load_config(args.config)
    db_type = config.get("DATABASE_TYPE", "sqlite").lower()

    if db_type == "sqlite":
        db_path = config["DATABASE_PATH"]
        if not getattr(args, "non_interactive", False):
            print(f"Database: SQLite at {db_path}")
        db_config_arg = db_path
    else:
        host = config["DATABASE_HOST"]
        port = config["DATABASE_PORT"]
        database = config["DATABASE_NAME"]
        if not getattr(args, "non_interactive", False):
            print(f"Database: MySQL at {host}:{port}/{database}")
        db_config_arg = _build_mysql_config(config)

    if getattr(args, "non_interactive", False):
        username = args.username
        password = secrets.token_urlsafe(16)
    else:
        username = input("Admin username: ").strip()
        if not username:
            print("Error: username cannot be empty.", file=sys.stderr)
            sys.exit(1)

        password = getpass.getpass("Admin password: ")
        if not password:
            print("Error: password cannot be empty.", file=sys.stderr)
            sys.exit(1)

        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Error: passwords do not match.", file=sys.stderr)
            sys.exit(1)

    try:
        conn = get_db(db_config_arg)
    except ConnectionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        create_user(conn, username, password, "admin")
    finally:
        conn.close()

    if getattr(args, "non_interactive", False):
        config_dir = (
            os.path.dirname(os.path.abspath(args.config)) if args.config else "/etc/vespid-server"
        )
        password_file = os.path.join(config_dir, ".admin-password")
        with open(password_file, "w") as f:
            f.write(password + "\n")
        os.chmod(password_file, 0o600)
        print(f"Admin user '{username}' created successfully.")
        logger.info("Bootstrap admin password written to %s", password_file)
    else:
        print(f"Admin user '{username}' created successfully.")


def cmd_run_server(args):
    """Start the Flask development server."""
    app = create_app(args.config)
    host = app.config.get("HOST", "0.0.0.0")
    port = app.config.get("PORT", 8000)
    debug = app.config.get("DEBUG", False)
    app.run(host=host, port=port, debug=debug)


def _packs_dir() -> "os.PathLike[str]":
    """Return the installed packs directory for this server install."""
    from pathlib import Path

    return Path(__file__).resolve().parent / "packs"


def cmd_rules(args):
    """Dispatch rule-pack subcommands."""
    if args.rules_command == "status":
        _rules_status()
    elif args.rules_command == "export":
        _rules_export(args)
    elif args.rules_command == "update":
        config = load_config(args.config)
        db_type, db_config = _resolve_db_config(config)
        _rules_update(args, db_type, db_config)
    else:
        print("No rules subcommand given. Use 'update', 'export' or 'status'.", file=sys.stderr)
        sys.exit(2)


def _rules_status():
    """Print installed packs, their rule counts, and bundle provenance."""
    from app.pack_loader import get_pack_metadata, load_packs
    from app.pack_update import manifest_sigma_commit, read_manifest

    packs_dir = _packs_dir()
    packs = load_packs(str(packs_dir))
    if not packs:
        print(f"No packs found in {packs_dir}")
        return
    print(f"Installed packs in {packs_dir}:")
    for meta in get_pack_metadata(packs):
        print(f"  {meta['pack_name']:<24} {meta['rule_count']:>4} rules")
    print(f"  {'TOTAL':<24} {sum(m['rule_count'] for m in get_pack_metadata(packs)):>4} rules")

    manifest = read_manifest(packs_dir)
    if manifest:
        commit = manifest_sigma_commit(manifest)
        print("\nBundle provenance:")
        if commit:
            print(f"  source commit: {commit}")
        if manifest.get("generated_at"):
            print(f"  generated:     {manifest['generated_at']}")


def _rules_export(args):
    """Create a distributable pack bundle from installed (or given) packs."""
    from pathlib import Path

    from app.pack_update import export_bundle

    packs_dir = Path(args.from_dir) if getattr(args, "from_dir", None) else _packs_dir()
    pack_names = args.packs.split(",") if getattr(args, "packs", None) else None

    try:
        exported = export_bundle(packs_dir, args.to, pack_names)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Exported {len(exported)} pack(s) from {packs_dir} to {args.to}")
    for name in exported:
        print(f"  {name}")


def _print_diff(diff):
    """Render a pack diff report to stdout."""
    print(
        f"Rules: {diff['current_rule_count']} installed -> {diff['incoming_rule_count']} in bundle"
    )
    for label, key, sym in (
        ("Added", "added", "+"),
        ("Removed", "removed", "-"),
        ("Changed", "changed", "~"),
    ):
        names = diff[key]
        print(f"  {label}: {len(names)}")
        for name in names:
            print(f"    {sym} {name}")


def _rules_update(args, db_type, db_config):
    """Validate, diff and apply a rule pack bundle.

    ``--from`` accepts a directory, a local ``.tar.gz``/``.zip`` archive, or an
    ``http(s)://`` URL pointing at such an archive.
    """
    from app.models import get_db
    from app.pack_loader import get_pack_rules, load_packs
    from app.pack_update import (
        apply_bundle,
        diff_packs,
        manifest_sigma_commit,
        read_manifest,
        resolve_bundle,
        validate_packs,
    )

    packs_dir = _packs_dir()
    installed_manifest = read_manifest(packs_dir)

    with tempfile.TemporaryDirectory(prefix="vespid-bundle-") as tmp:
        try:
            bundle_dir = resolve_bundle(args.source, tmp)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

        incoming = load_packs(str(bundle_dir))
        if not incoming:
            print(f"Error: no pack YAML files found in {args.source}", file=sys.stderr)
            sys.exit(1)

        errors = validate_packs(incoming)
        if errors:
            print("Validation FAILED:", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
            sys.exit(1)
        print(f"Validation OK: {len(get_pack_rules(incoming))} rules in {len(incoming)} pack(s)")

        bundle_manifest = read_manifest(bundle_dir)
        installed_commit = manifest_sigma_commit(installed_manifest)
        bundle_commit = manifest_sigma_commit(bundle_manifest)
        if bundle_commit:
            print(f"Bundle source commit:  {bundle_commit}")
        if installed_commit:
            print(f"Installed source commit: {installed_commit}")

        diff = diff_packs(load_packs(str(packs_dir)), incoming)
        _print_diff(diff)
        has_diff = bool(diff["added"] or diff["removed"] or diff["changed"])

        if args.check:
            print("Updates available." if has_diff else "Already up to date.")
            sys.exit(1 if has_diff else 0)

        if args.dry_run:
            print("Dry run — no changes applied.")
            return

        if not has_diff:
            print("Already up to date; nothing to do.")
            return

        if not args.yes:
            response = input("Apply these changes? [y/N] ").strip().lower()
            if response not in ("y", "yes"):
                print("Aborted.")
                return

        db = get_db(db_config)
        try:
            report = apply_bundle(bundle_dir, packs_dir, db, db_type)
        finally:
            db.close()

    print(f"Applied. Installed {len(report['installed'])} pack file(s).")
    if report.get("backup_dir"):
        print(f"Backup of previous packs: {report['backup_dir']}")
    print("Restart vespid-server to expose the new packs to the running process.")


def build_parser():
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="vespid-server",
        description="Vespid Server — centralized dashboard and event management",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to YAML or JSON configuration file (auto-discovers if not specified)",
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "init-db",
        help="Create or reset database tables",
    )

    create_admin_parser = subparsers.add_parser(
        "create-admin",
        help="Create the initial admin user (prompts for username/password)",
    )
    create_admin_parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Auto-create admin user with a generated password (for packaging)",
    )
    create_admin_parser.add_argument(
        "--username",
        default="admin",
        help="Admin username (only with --non-interactive)",
    )

    # ── Alert management commands ────────────────────────────────────────
    alerts_parser = subparsers.add_parser(
        "alerts",
        help="Alert management commands (apply, dump, silence)",
    )
    alerts_subparsers = alerts_parser.add_subparsers(dest="alerts_command")

    apply_parser = alerts_subparsers.add_parser(
        "apply",
        help="Upsert global alert rules and channels from a YAML file",
    )
    apply_parser.add_argument("file", help="Path to YAML file")

    alerts_subparsers.add_parser(
        "dump",
        help="Export global alert rules and channels to YAML (stdout)",
    )

    silence_parser = alerts_subparsers.add_parser(
        "silence",
        help="Manage alert silences",
    )
    silence_subparsers = silence_parser.add_subparsers(dest="silence_command")

    silence_add = silence_subparsers.add_parser("add", help="Create a silence")
    silence_add.add_argument(
        "--rule-id", type=int, default=None, help="Specific rule ID to silence"
    )
    silence_add.add_argument(
        "--matcher", action="append", default=[], help="Label matcher (e.g. hostname=web-1)"
    )
    silence_add.add_argument(
        "--duration", type=int, default=3600, help="Duration in seconds (default: 3600)"
    )
    silence_add.add_argument("--reason", required=True, help="Reason for silence")

    silence_subparsers.add_parser("list", help="List active silences")

    silence_rm = silence_subparsers.add_parser("rm", help="Remove a silence")
    silence_rm.add_argument("id", type=int, help="Silence ID to remove")

    alerts_subparsers.add_parser(
        "channels",
        help="List notification channels",
    )

    # ── Rule pack management commands ────────────────────────────────────
    rules_parser = subparsers.add_parser(
        "rules",
        help="Rule pack management (update, status)",
    )
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command")

    rules_update = rules_subparsers.add_parser(
        "update",
        help="Validate, diff and apply a rule pack bundle",
    )
    rules_update.add_argument(
        "--from",
        dest="source",
        required=True,
        help="Pack bundle: a directory, .tar.gz/.zip archive, or http(s) URL to one",
    )
    rules_update.add_argument(
        "--check",
        action="store_true",
        help="Report differences and exit (status 1 if updates are available)",
    )
    rules_update.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and show the diff without applying anything",
    )
    rules_update.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Apply without prompting for confirmation",
    )

    rules_export = rules_subparsers.add_parser(
        "export",
        help="Create a distributable pack bundle from installed packs",
    )
    rules_export.add_argument(
        "--to",
        required=True,
        help="Destination directory, .tar.gz, or .zip archive",
    )
    rules_export.add_argument(
        "--from",
        dest="from_dir",
        default=None,
        help="Source packs directory (default: the server's installed packs)",
    )
    rules_export.add_argument(
        "--packs",
        default=None,
        help="Comma-separated pack names to include (default: all installed packs)",
    )

    rules_subparsers.add_parser(
        "status",
        help="List installed packs and their rule counts",
    )

    return parser


def cmd_alerts(args):
    """Dispatch alert subcommands."""
    config = load_config(args.config)
    db_type = config.get("DATABASE_TYPE", "sqlite").lower()
    if db_type == "sqlite":
        db_config = config["DATABASE_PATH"]
    else:
        db_config = {
            "DATABASE_TYPE": config["DATABASE_TYPE"],
            "DATABASE_HOST": config["DATABASE_HOST"],
            "DATABASE_PORT": config["DATABASE_PORT"],
            "DATABASE_NAME": config["DATABASE_NAME"],
            "DATABASE_USER": config["DATABASE_USER"],
            "DATABASE_PASSWORD": config["DATABASE_PASSWORD"],
        }

    if args.alerts_command == "apply":
        _alerts_apply(args, db_config)
    elif args.alerts_command == "dump":
        _alerts_dump(db_config)
    elif args.alerts_command == "silence":
        _alerts_silence(args, db_config)
    elif args.alerts_command == "channels":
        _alerts_channels(db_config)


def _alerts_apply(args, db_config):
    """Upsert global rules and channels from a YAML file."""
    import yaml

    from app.models import (
        create_alert_rule,
        create_notification_channel,
        get_alert_rules,
        get_db,
        get_notification_channels,
        set_rule_channels,
        update_alert_rule,
        update_notification_channel,
    )

    with open(args.file) as f:
        data = yaml.safe_load(f)

    db = get_db(db_config)
    try:
        # Upsert channels
        existing_channels = {c["name"]: c for c in get_notification_channels(db)}
        channels_applied = {"created": 0, "updated": 0}
        for ch in data.get("channels", []):
            name = ch.get("name", "").strip()
            if not name:
                continue
            config = ch.get("config", {})
            # Interpolate environment variables
            for key, val in list(config.items()):
                if isinstance(val, str) and val.startswith("${") and val.endswith("}"):
                    env_var = val[2:-1]
                    config[key] = os.environ.get(env_var, "")

            if name in existing_channels:
                ec = existing_channels[name]
                update_notification_channel(
                    db,
                    ec["id"],
                    type=ch.get("type"),
                    config=config,
                    enabled=ch.get("enabled", True),
                )
                channels_applied["updated"] += 1
            else:
                create_notification_channel(
                    db,
                    name=name,
                    channel_type=ch.get("type"),
                    config=config,
                    enabled=ch.get("enabled", True),
                )
                channels_applied["created"] += 1

        # Refresh channel map for rule linking
        existing_channels = {c["name"]: c for c in get_notification_channels(db)}

        # Upsert rules
        existing_rules = {r["name"]: r for r in get_alert_rules(db, admin_view=True)}
        rules_applied = {"created": 0, "updated": 0}
        for rule in data.get("rules", []):
            name = rule.get("name", "").strip()
            if not name:
                continue

            payload = {
                "query": rule.get("query"),
                "check_name": rule.get("check_name"),
                "operator": rule.get("operator", ">"),
                "threshold": float(rule.get("threshold", 0)),
                "severity": rule.get("severity", "warning"),
                "for_duration": int(rule.get("for_duration", 0)),
                "interval_secs": int(rule.get("interval_secs", 60)),
                "enabled": rule.get("enabled", True),
            }
            if "resolve_threshold" in rule:
                payload["resolve_threshold"] = float(rule["resolve_threshold"])
            if "cooldown_secs" in rule:
                payload["cooldown_secs"] = int(rule["cooldown_secs"])
            if "tags" in rule:
                payload["tags"] = rule["tags"]

            if name in existing_rules:
                rid = existing_rules[name]["id"]
                update_alert_rule(db, rid, **payload)
                rules_applied["updated"] += 1
            else:
                r = create_alert_rule(db, user_id=None, name=name, **payload)
                rid = r["id"]
                rules_applied["created"] += 1

            # Link channels
            channel_names = rule.get("channels", [])
            channel_ids = []
            for cn in channel_names:
                if cn in existing_channels:
                    channel_ids.append(existing_channels[cn]["id"])
            if channel_ids:
                set_rule_channels(db, rid, channel_ids)

        print(
            f"Applied {rules_applied['created'] + rules_applied['updated']} rules "
            f"({rules_applied['updated']} updated, {rules_applied['created']} created), "
            f"{channels_applied['created'] + channels_applied['updated']} channels "
            f"({channels_applied['updated']} updated, {channels_applied['created']} created)"
        )
    finally:
        db.close()


def _alerts_dump(db_config):
    """Export global rules and channels to YAML on stdout."""
    import yaml

    from app.models import get_alert_rules, get_channels_for_rule, get_db, get_notification_channels

    db = get_db(db_config)
    try:
        rules = get_alert_rules(db, admin_view=True)
        channels = get_notification_channels(db)

        output = {"rules": [], "channels": []}

        for ch in channels:
            config = ch.get("config", "{}")
            try:
                config = yaml.safe_load(config) if isinstance(config, str) else config
            except Exception:
                config = {}
            output["channels"].append(
                {
                    "name": ch["name"],
                    "type": ch["type"],
                    "config": config,
                    "enabled": bool(ch.get("enabled", 1)),
                }
            )

        for rule in rules:
            if rule.get("user_id") is not None:
                continue  # Only dump global rules
            rule_data = {
                "name": rule["name"],
                "operator": rule["operator"],
                "threshold": rule["threshold"],
                "severity": rule["severity"],
                "interval_secs": rule["interval_secs"],
                "enabled": bool(rule.get("enabled", 1)),
            }
            if rule.get("query"):
                rule_data["query"] = rule["query"]
            if rule.get("check_name"):
                rule_data["check_name"] = rule["check_name"]
            if rule.get("resolve_threshold") is not None:
                rule_data["resolve_threshold"] = rule["resolve_threshold"]
            if rule.get("for_duration"):
                rule_data["for_duration"] = rule["for_duration"]
            if rule.get("cooldown_secs"):
                rule_data["cooldown_secs"] = rule["cooldown_secs"]
            if rule.get("tags"):
                try:
                    tags = (
                        yaml.safe_load(rule["tags"])
                        if isinstance(rule["tags"], str)
                        else rule["tags"]
                    )
                    if tags:
                        rule_data["tags"] = tags
                except Exception:
                    pass

            # Include channel names
            chs = get_channels_for_rule(db, rule["id"], default_to_all=False)
            if chs:
                rule_data["channels"] = [c["name"] for c in chs]

            output["rules"].append(rule_data)

        print(yaml.dump(output, default_flow_style=False, sort_keys=False))
    finally:
        db.close()


def _alerts_silence(args, db_config):
    """Manage alert silences from CLI."""
    from datetime import datetime

    from app.models import create_silence, delete_silence, get_db, get_silences

    db = get_db(db_config)
    try:
        if args.silence_command == "add":
            matchers = []
            for m in args.matcher:
                if "=" in m:
                    parts = m.split("=", 1)
                    matchers.append({"label": parts[0], "op": "=", "value": parts[1]})
            now = datetime.now(UTC)
            ends = now + __import__("datetime").timedelta(seconds=args.duration)
            silence = create_silence(
                db,
                matchers=matchers,
                rule_id=args.rule_id,
                starts_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                ends_at=ends.strftime("%Y-%m-%dT%H:%M:%SZ"),
                reason=args.reason,
                created_by=1,  # Default to admin user id 1
            )
            print(f"Created silence #{silence['id']}")

        elif args.silence_command == "list":
            silences = get_silences(db, include_expired=False)
            if not silences:
                print("No active silences")
                return
            for s in silences:
                print(
                    f"#{s['id']} rule={s.get('rule_id', 'ALL')} ends={s['ends_at']} reason={s['reason']}"
                )

        elif args.silence_command == "rm":
            ok = delete_silence(db, args.id)
            if ok:
                print(f"Removed silence #{args.id}")
            else:
                print(f"Silence #{args.id} not found")
    finally:
        db.close()


def _alerts_channels(db_config):
    """List notification channels from CLI."""
    from app.models import get_db, get_notification_channels

    db = get_db(db_config)
    try:
        channels = get_notification_channels(db)
        if not channels:
            print("No notification channels")
            return
        for c in channels:
            status = "enabled" if c.get("enabled") else "disabled"
            print(f"#{c['id']} {c['name']} ({c['type']}) [{status}]")
    finally:
        db.close()


def main(argv=None):
    """Parse arguments and dispatch to the appropriate command handler."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "init-db":
        cmd_init_db(args)
    elif args.command == "create-admin":
        cmd_create_admin(args)
    elif args.command == "alerts":
        cmd_alerts(args)
    elif args.command == "rules":
        cmd_rules(args)
    else:
        # No subcommand — start the Flask dev server
        cmd_run_server(args)


if __name__ == "__main__":
    main()
