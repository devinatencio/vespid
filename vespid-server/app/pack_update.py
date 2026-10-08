"""Rule pack update utilities.

Backs the operator-facing ``vespid-server-admin rules update`` workflow:
validate a bundle of pack YAML files, diff it against the installed packs and,
on request, apply it — backing up the previous packs and reconciling the
database so that user ``enabled`` / ``user_modified`` state is preserved.

A *bundle* is simply a directory (or archive) containing one or more pack
``*.yaml`` files, optionally with a ``manifest.json`` recording provenance
(e.g. the upstream Sigma commit the packs were generated from):

    manifest.json
    sigma-web-attacks.yaml
    sigma-ssh-attacks.yaml
    sigma-host-threats.yaml
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import re
import shutil
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from app.pack_loader import load_packs

logger = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.json"
_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".zip")


def _log_sources(rule: dict) -> list[str]:
    """Return a rule's log_sources as a list, tolerating a JSON string."""
    value = rule.get("log_sources", [])
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []
    return value if isinstance(value, list) else []


def validate_packs(packs: list[dict]) -> list[str]:
    """Validate loaded packs and return a list of errors (empty == valid).

    Checks the invariants the runtime relies on: unique rule names, compiling
    regexes, an ``(?P<ip>...)`` capture group for log-based rules (auditd rules
    are exempt), and sane thresholds. Run against the target runtime Python, as
    regex validity can differ between Python versions.
    """
    errors: list[str] = []
    seen: dict[str, str] = {}

    for pack in packs:
        pack_name = pack.get("pack_name", "")
        if not pack_name:
            errors.append("pack with missing pack_name")
            continue

        for rule in pack.get("rules", []):
            name = rule.get("name", "")
            if not name:
                errors.append(f"{pack_name}: rule with empty name")
                continue

            if name in seen:
                errors.append(f"duplicate rule name '{name}' ({seen[name]} and {pack_name})")
            else:
                seen[name] = pack_name

            try:
                compiled = re.compile(rule.get("regex", ""))
            except re.error as exc:
                errors.append(f"{name}: regex does not compile: {exc}")
                continue

            if "auditd" not in _log_sources(rule) and "ip" not in compiled.groupindex:
                errors.append(f"{name}: regex missing (?P<ip>...) group")

            try:
                if int(rule.get("max_attempts", 0)) < 1:
                    errors.append(f"{name}: max_attempts must be >= 1")
                if int(rule.get("window_seconds", 0)) < 1:
                    errors.append(f"{name}: window_seconds must be >= 1")
            except (TypeError, ValueError):
                errors.append(f"{name}: max_attempts/window_seconds must be integers")

    return errors


def _index_rules(packs: list[dict]) -> dict[str, tuple[str, dict]]:
    """Map rule name -> (pack_name, rule) across a set of packs."""
    indexed: dict[str, tuple[str, dict]] = {}
    for pack in packs:
        pack_name = pack.get("pack_name", "")
        for rule in pack.get("rules", []):
            indexed[rule["name"]] = (pack_name, rule)
    return indexed


def diff_packs(current: list[dict], incoming: list[dict]) -> dict:
    """Compare two sets of packs rule-by-rule.

    Only rules belonging to packs present in ``incoming`` are compared, so a
    bundle that ships a subset of packs (e.g. only the Sigma packs) does not
    report the other installed packs as removed.

    Returns ``{"added", "removed", "changed"}`` lists of rule names plus a few
    summary counts. ``changed`` uses the pack-owned content hash, so it ignores
    user state.
    """
    incoming_pack_names = {p.get("pack_name", "") for p in incoming}
    inc = {name: rule for name, (_, rule) in _index_rules(incoming).items()}
    cur = {
        name: rule
        for name, (pack_name, rule) in _index_rules(current).items()
        if pack_name in incoming_pack_names
    }

    added = sorted(set(inc) - set(cur))
    removed = sorted(set(cur) - set(inc))
    changed = sorted(
        name
        for name in (set(cur) & set(inc))
        if (cur[name].get("content_hash") or "") != (inc[name].get("content_hash") or "")
    )

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "current_packs": sorted(p["pack_name"] for p in current),
        "incoming_packs": sorted(incoming_pack_names),
        "current_rule_count": len(cur),
        "incoming_rule_count": len(inc),
    }


def read_manifest(bundle_dir: str | Path) -> dict:
    """Read ``manifest.json`` from a bundle directory, if present."""
    manifest_path = Path(bundle_dir) / "manifest.json"
    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not read manifest %s: %s", manifest_path, exc)
    return {}


def apply_bundle(
    bundle_dir: str | Path,
    packs_dir: str | Path,
    conn,
    db_type: str = "sqlite",
    *,
    dry_run: bool = False,
    backup: bool = True,
) -> dict:
    """Validate, diff and (unless ``dry_run``) apply a pack bundle.

    Returns a report dict. Raises :class:`ValueError` if the bundle is empty or
    fails validation while not a dry run.
    """
    from app.models.detection_rules import _seed_apache_attack_templates

    bundle_dir = Path(bundle_dir)
    packs_dir = Path(packs_dir)

    incoming = load_packs(str(bundle_dir))
    if not incoming:
        raise ValueError(f"No pack YAML files found in {bundle_dir}")

    errors = validate_packs(incoming)
    report: dict = {
        "valid": not errors,
        "errors": errors,
        "diff": diff_packs(load_packs(str(packs_dir)), incoming),
        "installed": [],
        "backup_dir": None,
        "applied": False,
    }
    if errors or dry_run:
        return report

    if backup and packs_dir.exists():
        timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        backup_dir = packs_dir / ".backups" / timestamp
        backup_dir.mkdir(parents=True, exist_ok=True)
        for existing in packs_dir.glob("*.yaml"):
            shutil.copy2(existing, backup_dir / existing.name)
        report["backup_dir"] = str(backup_dir)

    packs_dir.mkdir(parents=True, exist_ok=True)
    for path in sorted(bundle_dir.glob("*.yaml")):
        shutil.copy2(path, packs_dir / path.name)
        report["installed"].append(path.name)

    _seed_apache_attack_templates(conn, db_type, packs_dir=str(packs_dir))
    report["applied"] = True
    return report


# ── Bundles: export, resolve (local dir / archive / URL) ─────────────────


def manifest_sigma_commit(manifest: dict) -> str:
    """Return the ``sigma_commit`` recorded in a manifest, if any."""
    return str(manifest.get("sigma_commit", "") or "")


def _build_manifest(files: list[Path], packs_dir: Path) -> dict:
    """Build a manifest describing ``files``, preserving any existing commit."""
    existing = read_manifest(packs_dir)
    packs: dict[str, dict] = {}
    for path in files:
        text = path.read_text(encoding="utf-8")
        rule_count = sum(1 for line in text.splitlines() if line.strip().startswith("- name: "))
        packs[path.name] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "rules": rule_count,
        }
    return {
        "sigma_commit": manifest_sigma_commit(existing),
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rules_imported": sum(p["rules"] for p in packs.values()),
        "packs": packs,
    }


def export_bundle(
    packs_dir: str | Path,
    dest: str | Path,
    pack_names: list[str] | None = None,
) -> list[str]:
    """Create a distributable bundle from installed packs.

    ``dest`` may be a directory, a ``.tar.gz``/``.tgz`` archive or a ``.zip``
    archive. Returns the list of pack filenames included.
    """
    packs_dir = Path(packs_dir)
    dest = Path(dest)

    files = sorted(packs_dir.glob("*.yaml"))
    if pack_names:
        wanted = set(pack_names)
        files = [f for f in files if f.stem in wanted]
    if not files:
        raise ValueError(f"No packs found to export in {packs_dir}")

    manifest = _build_manifest(files, packs_dir)
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")

    if dest.name.endswith(".zip"):
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in files:
                zf.write(path, path.name)
            zf.writestr(MANIFEST_NAME, manifest_bytes)
    elif dest.name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(dest, "w:gz") as tf:
            for path in files:
                tf.add(path, arcname=path.name)
            info = tarfile.TarInfo(MANIFEST_NAME)
            info.size = len(manifest_bytes)
            tf.addfile(info, io.BytesIO(manifest_bytes))
    else:
        dest.mkdir(parents=True, exist_ok=True)
        for path in files:
            shutil.copy2(path, dest / path.name)
        (dest / MANIFEST_NAME).write_bytes(manifest_bytes)

    return [path.name for path in files]


def _find_pack_dir(root: Path) -> Path:
    """Return the directory under ``root`` that directly contains pack YAMLs."""
    if list(root.glob("*.yaml")):
        return root
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        if list(sub.glob("*.yaml")):
            return sub
    return root


def _extract_archive(archive_path: Path, dest_dir: Path) -> Path:
    """Safely extract a zip/tar archive and return the directory with packs."""
    extract_root = (dest_dir / "bundle").resolve()
    if extract_root.exists():
        shutil.rmtree(extract_root)
    extract_root.mkdir(parents=True, exist_ok=True)

    if archive_path.name.lower().endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            for name in zf.namelist():
                if not (extract_root / name).resolve().is_relative_to(extract_root):
                    raise ValueError(f"Unsafe path in archive: {name}")
            zf.extractall(extract_root)
    elif tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path) as tf:
            for member in tf.getmembers():
                target = (extract_root / member.name).resolve()
                if not target.is_relative_to(extract_root):
                    raise ValueError(f"Unsafe path in archive: {member.name}")
            tf.extractall(extract_root)
    else:
        raise ValueError(f"Unsupported archive format: {archive_path}")

    return _find_pack_dir(extract_root)


def _download(url: str, dest_dir: Path) -> Path:
    """Download ``url`` into ``dest_dir`` and return the local path."""
    import requests

    dest_dir.mkdir(parents=True, exist_ok=True)
    filename = url.split("?")[0].rstrip("/").split("/")[-1] or "bundle.tar.gz"
    dest = dest_dir / filename
    with requests.get(url, stream=True, timeout=60) as response:
        response.raise_for_status()
        with open(dest, "wb") as handle:
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    handle.write(chunk)
    return dest


def resolve_bundle(source: str | Path, dest_dir: str | Path) -> Path:
    """Resolve a bundle source to a directory containing pack YAMLs.

    Accepts a directory, a local archive (``.tar.gz``/``.tgz``/``.zip``) or an
    ``http(s)://`` URL pointing at such an archive. Downloaded/extracted content
    is placed under ``dest_dir`` (a caller-provided temp directory).
    """
    dest_dir = Path(dest_dir)

    if isinstance(source, str) and source.startswith(("http://", "https://")):
        return _extract_archive(_download(source, dest_dir), dest_dir)

    path = Path(source)
    if path.is_dir():
        return path
    if path.is_file():
        return _extract_archive(path, dest_dir)
    raise FileNotFoundError(str(source))
