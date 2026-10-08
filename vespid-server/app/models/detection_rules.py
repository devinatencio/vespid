from __future__ import annotations

import json
import logging
import sqlite3

from .db_core import _deserialize_tags, _insert_ignore, _utcnow_iso

logger = logging.getLogger(__name__)

# ── Detection Rules seed data and helpers ────────────────────────────────

_DEFAULT_BRUTE_FORCE_RULES = [
    {
        "name": "ssh_fast_brute",
        "event_type": "SSH_BRUTE",
        "max_attempts": 5,
        "window_seconds": 60,
        "parser": "secure",
    },
    {
        "name": "ssh_medium_brute",
        "event_type": "SSH_MEDIUM_BRUTE",
        "max_attempts": 4,
        "window_seconds": 600,
        "parser": "secure",
    },
    {
        "name": "ssh_slow_brute",
        "event_type": "SSH_SLOW_BRUTE",
        "max_attempts": 5,
        "window_seconds": 21600,
        "parser": "secure",
    },
    {
        "name": "http_auth_brute",
        "event_type": "HTTP_AUTH_BRUTE",
        "max_attempts": 20,
        "window_seconds": 600,
        "parser": "apache",
    },
    {
        "name": "ssh_negotiate_fail",
        "event_type": "SSH_NEGOTIATE_FAIL",
        "max_attempts": 3,
        "window_seconds": 86400,
        "parser": "secure_negotiate_fail",
    },
    {
        "name": "ssh_recon_strong",
        "event_type": "SSH_BANNER_GRAB",
        "max_attempts": 3,
        "window_seconds": 86400,
        "parser": "secure_recon_strong",
    },
    {
        "name": "ssh_recon_weak",
        "event_type": "SSH_RECON_WEAK",
        "max_attempts": 8,
        "window_seconds": 86400,
        "parser": "secure_recon_weak",
    },
]


def _seed_detection_rules(conn, db_type: str = "sqlite") -> None:
    """Insert default detection rules and pack templates from YAML files."""
    ignore = _insert_ignore(db_type)
    for rule in _DEFAULT_BRUTE_FORCE_RULES:
        conn.execute(
            f"{ignore} INTO detection_rules_brute_force "
            "(name, event_type, max_attempts, window_seconds, parser) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                rule["name"],
                rule["event_type"],
                rule["max_attempts"],
                rule["window_seconds"],
                rule["parser"],
            ),
        )
    # Load pack rules from YAML files on disk
    from app.pack_loader import get_pack_rules, load_packs

    packs = load_packs()
    pack_rules = get_pack_rules(packs)
    for rule in pack_rules:
        conn.execute(
            f"{ignore} INTO detection_rules_custom "
            "(name, event_type, regex, log_sources, max_attempts, window_seconds, enabled, is_template, pack_name, tags, sigma_id, sigma_status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rule["name"],
                rule["event_type"],
                rule["regex"],
                rule["log_sources"],
                rule["max_attempts"],
                rule["window_seconds"],
                rule["enabled"],
                rule["is_template"],
                rule.get("pack_name", ""),
                rule.get("tags", "[]"),
                rule.get("sigma_id", ""),
                rule.get("sigma_status", ""),
            ),
        )
    # Bump revision
    conn.execute(
        "UPDATE detection_rules_revision SET revision = revision + 1, updated_at = ? WHERE id = 1",
        (_utcnow_iso(),),
    )
    conn.commit()


def _seed_apache_attack_templates(
    conn, db_type: str = "sqlite", packs_dir: str | None = None
) -> None:
    """Reconcile pack template rules from YAML into the database.

    Non-destructive, version-aware merge (safe to run on every startup):

    * New rule (by name) -> inserted as a disabled template.
    * Existing rule with no baseline ``content_hash`` (first run after the
      provenance migration) -> baseline backfill. A pack template is
      pack-owned and divergence cannot be attributed to the user without a
      baseline, so the shipped definition is adopted (``user_modified=0``)
      while the user's ``enabled`` state is preserved. Edits made from this
      point on are tracked and protected via ``user_modified``.
    * Existing rule with ``user_modified=1`` -> never touched, except rows
      whose ``content_hash`` equals their own definition's hash: those were
      mis-marked by the pre-1.0 baseline pass and are un-frozen so shipped
      fixes can reach them.
    * Existing rule with ``user_modified=0`` whose shipped definition changed
      -> pack-owned fields refreshed; the user's ``enabled`` state is preserved.

    Bumps the detection rules revision when anything is inserted or refreshed
    so agents re-pull.
    """
    from app.pack_loader import get_pack_rules, load_packs, rule_content_hash

    packs = load_packs(packs_dir)
    if not packs:
        # Never reconcile (or retire) when packs could not be loaded — e.g. a
        # missing PyYAML dependency would otherwise wipe every pack template.
        return
    pack_rules = get_pack_rules(packs)
    ignore = _insert_ignore(db_type)
    now = _utcnow_iso()
    changed = 0
    touched = False

    shipped_names = {r["name"] for r in pack_rules}

    # ── Rename pass ──────────────────────────────────────────────────────
    # Upstream sometimes renames a rule while keeping its stable Sigma UUID
    # (e.g. blocklist -> blacklist). Renaming the pristine existing row keeps
    # the user's enabled state and avoids a duplicate, simultaneously-active
    # rule. Rows the user modified are never renamed.
    existing_by_name: dict[str, tuple] = {}
    existing_by_sigma: dict[str, list[tuple]] = {}
    for row in conn.execute(
        "SELECT id, name, sigma_id, user_modified FROM detection_rules_custom "
        "WHERE pack_name != '' AND is_template = 1"
    ).fetchall():
        existing_by_name[row[1]] = row
        if row[2]:
            existing_by_sigma.setdefault(row[2], []).append(row)

    for rule in pack_rules:
        name = rule["name"]
        sigma_id = rule.get("sigma_id") or ""
        if name in existing_by_name or not sigma_id:
            continue
        for cand in existing_by_sigma.get(sigma_id, []):
            cand_name, cand_user_modified = cand[1], int(cand[3] or 0)
            if cand_name in shipped_names or cand_user_modified:
                continue
            conn.execute(
                "UPDATE detection_rules_custom SET name = ?, updated_at = ? WHERE id = ?",
                (name, now, cand[0]),
            )
            existing_by_name.pop(cand_name, None)
            existing_by_name[name] = (cand[0], name, sigma_id, 0)
            touched = True
            break

    for rule in pack_rules:
        yaml_hash = rule.get("content_hash") or rule_content_hash(
            rule["event_type"],
            rule["regex"],
            rule["log_sources"],
            rule["max_attempts"],
            rule["window_seconds"],
            rule.get("tags", "[]"),
            rule.get("sigma_id", ""),
            rule.get("sigma_status", ""),
        )

        # Positional access (the init connection does not set a Row factory).
        # cols: id,event_type,regex,log_sources,max_attempts,window_seconds,
        #       enabled,tags,sigma_id,sigma_status,content_hash,user_modified
        row = conn.execute(
            "SELECT id, event_type, regex, log_sources, max_attempts, window_seconds, "
            "enabled, tags, sigma_id, sigma_status, content_hash, user_modified "
            "FROM detection_rules_custom WHERE name = ?",
            (rule["name"],),
        ).fetchone()

        if row is None:
            conn.execute(
                f"{ignore} INTO detection_rules_custom "
                "(name, event_type, regex, log_sources, max_attempts, window_seconds, "
                "enabled, is_template, pack_name, tags, sigma_id, sigma_status, "
                "content_hash, user_modified) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (
                    rule["name"],
                    rule["event_type"],
                    rule["regex"],
                    rule["log_sources"],
                    rule["max_attempts"],
                    rule["window_seconds"],
                    rule["enabled"],
                    rule["is_template"],
                    rule.get("pack_name", ""),
                    rule.get("tags", "[]"),
                    rule.get("sigma_id", ""),
                    rule.get("sigma_status", ""),
                    yaml_hash,
                ),
            )
            changed += 1
            continue

        rule_id = row[0]
        stored_hash = row[10] or ""
        user_modified = int(row[11] or 0)

        if user_modified:
            # A genuine UI edit leaves content_hash pointing at the shipped
            # pack definition (the edit path never rewrites it). The pre-1.0
            # baseline pass instead stored the row's *own* definition hash
            # while flagging it user_modified, which permanently froze
            # shipped fixes for that rule. Detect that self-referential
            # signature and un-freeze the row so the reconcile below applies.
            db_hash = rule_content_hash(
                row[1], row[2], row[3], row[4], row[5], row[7], row[8], row[9]
            )
            if stored_hash != db_hash:
                continue  # genuine user edit -> protected
            conn.execute(
                "UPDATE detection_rules_custom SET user_modified = 0 WHERE id = ?",
                (rule_id,),
            )
            touched = True

        if stored_hash == "":
            # First-upgrade baseline (predates content_hash provenance). We
            # cannot distinguish a pre-migration user edit from a pack update,
            # and freezing the row permanently blocked shipped detection fixes
            # from ever reaching upgrading deployments. Pack templates are
            # pack-owned, so adopt the shipped definition here and preserve
            # only the user's enabled state. Edits from this point on are
            # tracked via user_modified and will be protected.
            db_hash = rule_content_hash(
                row[1], row[2], row[3], row[4], row[5], row[7], row[8], row[9]
            )
            if db_hash == yaml_hash:
                conn.execute(
                    "UPDATE detection_rules_custom SET content_hash = ?, user_modified = 0 "
                    "WHERE id = ?",
                    (yaml_hash, rule_id),
                )
            else:
                conn.execute(
                    "UPDATE detection_rules_custom SET "
                    "event_type = ?, regex = ?, log_sources = ?, max_attempts = ?, "
                    "window_seconds = ?, tags = ?, sigma_id = ?, sigma_status = ?, "
                    "content_hash = ?, user_modified = 0, updated_at = ? "
                    "WHERE id = ?",
                    (
                        rule["event_type"],
                        rule["regex"],
                        rule["log_sources"],
                        rule["max_attempts"],
                        rule["window_seconds"],
                        rule.get("tags", "[]"),
                        rule.get("sigma_id", ""),
                        rule.get("sigma_status", ""),
                        yaml_hash,
                        now,
                        rule_id,
                    ),
                )
                changed += 1
            touched = True
            continue

        if stored_hash != yaml_hash:
            # Pristine rule, pack shipped a new version -> safe to refresh the
            # definition. Preserve the user's enabled state.
            conn.execute(
                "UPDATE detection_rules_custom SET "
                "event_type = ?, regex = ?, log_sources = ?, max_attempts = ?, "
                "window_seconds = ?, tags = ?, sigma_id = ?, sigma_status = ?, "
                "content_hash = ?, updated_at = ? "
                "WHERE id = ?",
                (
                    rule["event_type"],
                    rule["regex"],
                    rule["log_sources"],
                    rule["max_attempts"],
                    rule["window_seconds"],
                    rule.get("tags", "[]"),
                    rule.get("sigma_id", ""),
                    rule.get("sigma_status", ""),
                    yaml_hash,
                    now,
                    rule_id,
                ),
            )
            changed += 1

    # ── Retire pass ──────────────────────────────────────────────────────
    # Pristine pack templates that the pack no longer ships are removed so they
    # don't linger as stale, duplicate detections. User-modified rows are kept.
    retired = 0
    for row in conn.execute(
        "SELECT id, name FROM detection_rules_custom "
        "WHERE pack_name != '' AND is_template = 1 AND user_modified = 0"
    ).fetchall():
        if row[1] not in shipped_names:
            conn.execute("DELETE FROM detection_rules_custom WHERE id = ?", (row[0],))
            retired += 1

    if changed or retired:
        conn.execute(
            "UPDATE detection_rules_revision SET revision = revision + 1, "
            "updated_at = ? WHERE id = 1",
            (now,),
        )

    if changed or touched or retired:
        conn.commit()
        if changed:
            logger.info("Reconciled pack templates: %d rule(s) inserted/refreshed", changed)
        if retired:
            logger.info("Retired %d stale pack template(s)", retired)


def _seed_default_noise_suppression(conn) -> None:
    """Seed default noise disable rules into existing config profiles.

    Runs as a migration: if any active config profile already has
    disabled_host_threat_rules configured, no action is taken. Otherwise,
    all active profiles are seeded with the built-in default noise rules
    so that known false positives are disabled from agent distribution
    out of the box — no events are ever shipped for these rules.

    Suppress is intentionally NOT seeded here; suppress is for rules users
    choose to hide but still collect data for. Disabled rules never
    produce data, so there is nothing to suppress.
    """
    from app.default_noise_rules import get_default_suppress_rule_names

    rows = conn.execute("SELECT id, settings FROM config_profiles WHERE is_active = 1").fetchall()

    if not rows:
        return

    # Skip if any profile already has disabled_host_threat_rules configured
    for row in rows:
        try:
            settings = (
                json.loads(row["settings"]) if isinstance(row["settings"], str) else row["settings"]
            )
        except (json.JSONDecodeError, TypeError):
            settings = {}
        if settings.get("disabled_host_threat_rules"):
            return

    default_rules = get_default_suppress_rule_names()

    seeded_count = 0
    for row in rows:
        try:
            settings = (
                json.loads(row["settings"]) if isinstance(row["settings"], str) else row["settings"]
            )
        except (json.JSONDecodeError, TypeError):
            settings = {}

        if "disabled_host_threat_rules" not in settings:
            settings["disabled_host_threat_rules"] = default_rules
            seeded_count += 1

        if "suppress_rules" not in settings:
            # Only seed suppress as empty — defaults are disabled, not suppressed
            settings["suppress_rules"] = []

        settings_json = json.dumps(settings)
        conn.execute(
            "UPDATE config_profiles SET settings = ? WHERE id = ?",
            (settings_json, row["id"]),
        )

    if seeded_count:
        conn.commit()
        logger.info(
            "Seeded default noise disable rules (%d rules) into %d config profile(s)",
            len(default_rules),
            seeded_count,
        )


def get_detection_rules_revision(conn: sqlite3.Connection) -> int:
    """Return the current detection rules revision number."""
    row = conn.execute("SELECT revision FROM detection_rules_revision WHERE id = 1").fetchone()
    return row["revision"] if row else 0


def increment_detection_rules_revision(conn: sqlite3.Connection) -> int:
    """Increment and return the new revision number."""
    conn.execute(
        "UPDATE detection_rules_revision SET revision = revision + 1, updated_at = ? WHERE id = 1",
        (_utcnow_iso(),),
    )
    conn.commit()
    return get_detection_rules_revision(conn)


def list_detection_rules(
    conn: sqlite3.Connection,
    page: int = 1,
    per_page: int = 50,
    enabled_only: bool = False,
) -> dict:
    """List all detection rules (both types) with pagination.

    Template/pack rules (is_template=1) are excluded from this listing —
    they are managed via the dedicated pack UI instead.

    Returns a dict with keys: rules, total, page, per_page, total_pages.
    """
    per_page = max(1, min(200, per_page))
    offset = (page - 1) * per_page

    bf_where = "WHERE enabled = 1" if enabled_only else ""
    cr_conditions = ["is_template = 0"]
    if enabled_only:
        cr_conditions.append("enabled = 1")
    cr_where = "WHERE " + " AND ".join(cr_conditions)

    # Count totals
    bf_count = conn.execute(
        f"SELECT COUNT(*) FROM detection_rules_brute_force {bf_where}"
    ).fetchone()[0]
    cr_count = conn.execute(f"SELECT COUNT(*) FROM detection_rules_custom {cr_where}").fetchone()[0]
    total = bf_count + cr_count

    # Fetch brute force rules
    bf_rows = conn.execute(
        f"SELECT *, 'brute_force' as rule_type FROM detection_rules_brute_force "
        f"{bf_where} ORDER BY name"
    ).fetchall()

    # Fetch custom rules (excluding templates)
    cr_rows = conn.execute(
        f"SELECT *, 'custom' as rule_type FROM detection_rules_custom {cr_where} ORDER BY name"
    ).fetchall()

    # Combine and paginate
    all_rules = [dict(r) for r in bf_rows] + [dict(r) for r in cr_rows]
    all_rules.sort(key=lambda r: r["name"])
    paginated = all_rules[offset : offset + per_page]

    import math

    total_pages = max(1, math.ceil(total / per_page))

    return {
        "rules": paginated,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
    }


def get_enabled_detection_rules(conn: sqlite3.Connection) -> dict:
    """Return all enabled rules grouped by type for node distribution."""
    bf_rows = conn.execute(
        "SELECT name, event_type, max_attempts, window_seconds, parser "
        "FROM detection_rules_brute_force WHERE enabled = 1 ORDER BY name"
    ).fetchall()

    cr_rows = conn.execute(
        "SELECT name, event_type, regex, log_sources, max_attempts, window_seconds, pack_name, tags, sigma_id, sigma_status "
        "FROM detection_rules_custom WHERE enabled = 1 ORDER BY name"
    ).fetchall()

    corr_rows = conn.execute(
        "SELECT name, event_type, min_categories, window_seconds "
        "FROM detection_rules_correlation WHERE enabled = 1 ORDER BY name"
    ).fetchall()

    brute_force_rules = []
    for r in bf_rows:
        brute_force_rules.append(
            {
                "name": r["name"],
                "event_type": r["event_type"],
                "max_attempts": r["max_attempts"],
                "window_seconds": r["window_seconds"],
                "parser": r["parser"],
            }
        )

    custom_rules = []
    for r in cr_rows:
        log_sources = r["log_sources"]
        if isinstance(log_sources, str):
            try:
                log_sources = json.loads(log_sources)
            except (json.JSONDecodeError, TypeError):
                log_sources = ["*"]
        custom_rules.append(
            {
                "name": r["name"],
                "event_type": r["event_type"],
                "regex": r["regex"],
                "log_sources": log_sources,
                "max_attempts": r["max_attempts"],
                "window_seconds": r["window_seconds"],
                "enabled": True,
                "pack_name": r["pack_name"] or "",
                "tags": _deserialize_tags(r["tags"] if "tags" in r.keys() else "[]"),
                "sigma_id": r["sigma_id"] if "sigma_id" in r.keys() else "",
                "sigma_status": r["sigma_status"] if "sigma_status" in r.keys() else "",
            }
        )

    correlation_rules = []
    for r in corr_rows:
        correlation_rules.append(
            {
                "name": r["name"],
                "event_type": r["event_type"],
                "min_categories": r["min_categories"],
                "window_seconds": r["window_seconds"],
                "enabled": True,
            }
        )

    return {
        "brute_force_rules": brute_force_rules,
        "custom_rules": custom_rules,
        "correlation_rules": correlation_rules,
    }
