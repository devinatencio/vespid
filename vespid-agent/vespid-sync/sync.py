#!/usr/bin/env python3
"""Vespid Sync Agent — discover assets from infrastructure providers.

Poll configured providers (Proxmox, etc.) and push discovered assets to the
Vespid server's ``/api/v1/inventory/sync`` endpoint.

Usage:
    python sync.py                    # Run once (for systemd timer)
    python sync.py --config other.yaml

Exit codes:
    0 — success
    1 — configuration error
    2 — discovery succeeded but push failed
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("vespid-sync")


def load_config(path: str) -> dict:
    """Load and validate the sync config YAML."""
    try:
        import yaml
    except ImportError:
        log.error("PyYAML is required. Install with: pip install pyyaml")
        sys.exit(1)

    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        log.error("Config file not found: %s", path)
        sys.exit(1)

    with open(path) as f:
        config = yaml.safe_load(f)

    if not isinstance(config, dict):
        log.error("Config file is empty or invalid")
        sys.exit(1)

    return config


def main():
    parser = argparse.ArgumentParser(description="Vespid Sync Agent")
    parser.add_argument("--config", default="/etc/vespid-sync/config.yaml",
                        help="Path to config YAML")
    parser.add_argument("--once", action="store_true",
                        help="Run once and exit (default)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    config = load_config(args.config)
    sync_cfg = config.get("sync", {})
    server_url = (sync_cfg.get("server_url") or "").rstrip("/")
    api_key = sync_cfg.get("api_key") or ""

    if not server_url or not api_key:
        log.error("server_url and api_key are required in sync config")
        sys.exit(1)

    providers_cfg = config.get("providers", [])
    if not providers_cfg:
        log.warning("No providers configured — nothing to sync")
        sys.exit(0)

    # Import providers
    from providers.proxmox import ProxmoxProvider

    PROVIDER_MAP = {
        "proxmox": ProxmoxProvider,
    }

    all_assets: list[dict] = []
    provider_names: list[str] = []

    for pcfg in providers_cfg:
        ptype = pcfg.get("type", "")
        provider_cls = PROVIDER_MAP.get(ptype)
        if not provider_cls:
            log.warning("Unknown provider type '%s', skipping", ptype)
            continue

        try:
            provider = provider_cls(pcfg)
            name = provider.name
            log.info("Discovering assets from %s (%s)...", name, ptype)

            cluster_assets = provider.discover_clusters()
            node_assets = provider.discover_nodes()
            vm_assets = provider.discover()

            for asset_list, label in [
                (cluster_assets, "clusters"),
                (node_assets, "nodes"),
                (vm_assets, "assets"),
            ]:
                for asset in asset_list:
                    all_assets.append(asset_to_dict(asset, name))
                log.info("  %s: %d %s", name, len(asset_list), label)

            provider_names.append(name)

        except Exception:
            log.exception("Provider %s failed", ptype)

    if not all_assets:
        log.info("No assets discovered")
        sys.exit(0)

    # Push to server
    cluster_name = config.get("cluster", "default")
    for pname in provider_names:
        batch = [a for a in all_assets if a.get("_provider") == pname]
        if not batch:
            continue
        _push_batch(server_url, api_key, pname, cluster_name, batch)

    log.info("Sync complete — %d total assets across %d provider(s)",
             len(all_assets), len(provider_names))


def asset_to_dict(asset, provider_name: str) -> dict:
    """Convert a SyncAsset to a plain dict for JSON serialisation."""
    result = {
        "external_id": asset.external_id,
        "display_name": asset.display_name,
        "asset_type": asset.asset_type,
        "metadata": asset.metadata,
        "labels": asset.labels,
        "aliases": asset.aliases,
        "status": asset.status,
        "_provider": provider_name,
    }
    if asset.parent_external_id:
        result["parent_external_id"] = asset.parent_external_id
    return result


def _push_batch(
    server_url: str, api_key: str,
    provider_name: str, cluster_name: str,
    assets: list[dict],
):
    """POST a batch of assets to the Vespid server."""
    url = f"{server_url}/api/v1/inventory/sync"
    payload = {
        "provider": provider_name,
        "cluster": cluster_name,
        "assets": assets,
    }

    log.info("Pushing %d assets from %s to %s ...", len(assets), provider_name, url)

    try:
        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=120,
        )
    except requests.RequestException as exc:
        log.error("POST failed: %s", exc)
        sys.exit(2)

    if resp.status_code == 200:
        data = resp.json()
        log.info(
            "Server response: %d created, %d updated, %d stale, %d relationships",
            data.get("created", 0),
            data.get("updated", 0),
            data.get("stale", 0),
            data.get("relationships", 0),
        )
    else:
        log.error("Server returned %d: %s", resp.status_code, resp.text)
        sys.exit(2)


if __name__ == "__main__":
    main()
