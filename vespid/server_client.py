"""HTTP client for the Vespid central server REST API.

Provides authenticated access to fleet, intel, config, nodes, and admin
endpoints. Credentials are resolved from (in priority order):

    1. Explicit constructor arguments
    2. Environment variables: VESPID_SERVER_URL, VESPID_API_KEY
    3. CLI config file: ~/.config/vespid/cli.yaml
    4. Agent config: /etc/vespid/vespid.yaml (SERVER_URL + API_KEY)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore[assignment]

try:
    import yaml as _yaml
except ImportError:
    _yaml = None  # type: ignore[assignment]

from . import __version__

CLI_CONFIG_PATH = Path.home() / ".config" / "vespid" / "cli.yaml"


class ServerClientError(Exception):
    """Raised when a server request fails."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class ServerClient:
    """Authenticated HTTP client for the vespid-server REST API."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
        *,
        verify: bool | str = True,
        cert: str | None = None,
        key: str | None = None,
    ) -> None:
        if httpx is None:
            raise ImportError(
                "httpx is required for server commands. Install with: pip install httpx"
            )

        resolved_url, resolved_key = self._resolve_credentials(base_url, api_key)
        if not resolved_url:
            raise ValueError(
                "No server URL configured. Set VESPID_SERVER_URL, "
                "run 'vespid-cli server login', or configure SERVER_URL in vespid.yaml"
            )
        if not resolved_key:
            raise ValueError(
                "No API key configured. Set VESPID_API_KEY, "
                "run 'vespid-cli server login', or configure API_KEY in vespid.yaml"
            )

        # Normalize: strip any API path suffix so we can build paths cleanly
        # SERVER_URL in agent config is typically https://host/api/v1/events
        self.base_url = resolved_url.rstrip("/")
        # Strip common suffixes to get the bare server origin
        for suffix in ("/api/v1/events", "/api/v1", "/api"):
            if self.base_url.endswith(suffix):
                self.base_url = self.base_url[: -len(suffix)]
                break

        client_kwargs: dict[str, Any] = {
            "base_url": self.base_url,
            "headers": {
                "Authorization": f"Bearer {resolved_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"Vespid/{__version__} CLI",
            },
            "timeout": timeout,
            "follow_redirects": True,
        }

        # SSL/TLS configuration
        client_kwargs["verify"] = verify
        if cert:
            client_kwargs["cert"] = (cert, key) if key else cert

        self._client = httpx.Client(**client_kwargs)

    def _resolve_credentials(
        self, base_url: str | None, api_key: str | None
    ) -> tuple[str | None, str | None]:
        """Resolve server URL and API key from available sources."""
        url = base_url
        key = api_key

        # 1. Environment variables
        if not url:
            url = os.environ.get("VESPID_SERVER_URL")
        if not key:
            key = os.environ.get("VESPID_API_KEY")

        # 2. CLI config file (~/.config/vespid/cli.yaml)
        if (not url or not key) and CLI_CONFIG_PATH.exists():
            try:
                if _yaml:
                    data = _yaml.safe_load(CLI_CONFIG_PATH.read_text()) or {}
                else:
                    data = json.loads(CLI_CONFIG_PATH.read_text())
                if not url:
                    url = data.get("server_url")
                if not key:
                    key = data.get("api_key")
            except Exception:
                pass

        # 3. Agent config (SERVER_URL / API_KEY from ShieldConfig)
        if not url or not key:
            try:
                from .config import CONFIG

                if not url and CONFIG.SERVER_URL and "example.invalid" not in CONFIG.SERVER_URL:
                    # Strip the API path to get the base origin
                    srv = CONFIG.SERVER_URL
                    for suffix in ("/api/v1/events", "/api/v1", "/api"):
                        if srv.endswith(suffix):
                            srv = srv[: -len(suffix)]
                            break
                    url = url or srv
                if not key and CONFIG.API_KEY and CONFIG.API_KEY.strip():
                    key = key or CONFIG.API_KEY
            except Exception:
                pass

        return url, key

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ServerClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Low-level request helpers
    # ------------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Make an HTTP request and return parsed JSON."""
        resp = self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            try:
                data = resp.json()
                detail = data.get("message") or data.get("error") or resp.text
            except Exception:
                detail = resp.text[:200] if resp.text else f"HTTP {resp.status_code}"
            raise ServerClientError(resp.status_code, str(detail))
        if resp.status_code == 204:
            return {}
        # Handle non-JSON responses (e.g. HTML redirects to login page)
        content_type = resp.headers.get("content-type", "")
        if "application/json" not in content_type:
            # Server returned non-JSON (likely HTML login page)
            raise ServerClientError(
                resp.status_code,
                f"Server returned non-JSON response (content-type: {content_type}). "
                f"Check your server URL and API key.",
            )
        try:
            return resp.json()
        except Exception as exc:
            raise ServerClientError(
                resp.status_code,
                "Server returned invalid JSON. Check your server URL.",
            ) from exc

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._request("GET", path, params=params)

    def post(self, path: str, data: dict[str, Any] | None = None) -> Any:
        return self._request("POST", path, json=data)

    def put(self, path: str, data: dict[str, Any] | None = None) -> Any:
        return self._request("PUT", path, json=data)

    def delete(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self._request("DELETE", path, params=params)

    # ------------------------------------------------------------------
    # Fleet API
    # ------------------------------------------------------------------

    def fleet_list_blocks(
        self,
        page: int = 1,
        per_page: int = 50,
        source_ip: str | None = None,
        event_type: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page, "per_page": per_page}
        if source_ip:
            params["source_ip"] = source_ip
        if event_type:
            params["event_type"] = event_type
        if status:
            params["status"] = status
        return self.get("/api/v1/fleet/blocks", params=params)

    def fleet_add_block(
        self, ip: str, reason: str = "cli", ttl: int | None = None
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"source_ip": ip, "reason": reason}
        if ttl is not None:
            data["ttl_seconds"] = ttl
        return self.post("/api/v1/fleet/blocks", data=data)

    def fleet_remove_block(self, ip: str) -> dict[str, Any]:
        return self.delete(f"/api/v1/fleet/blocks/{ip}")

    def fleet_block_history(self, ip: str) -> dict[str, Any]:
        return self.get(f"/api/v1/fleet/blocks/{ip}/history")

    def fleet_list_allowlist(self) -> Any:
        return self.get("/api/v1/fleet/allowlist")

    def fleet_add_allowlist(self, ip: str, reason: str = "cli") -> dict[str, Any]:
        return self.post("/api/v1/fleet/allowlist", data={"ip": ip, "reason": reason})

    def fleet_remove_allowlist(self, entry_id: int) -> dict[str, Any]:
        return self.delete(f"/api/v1/fleet/allowlist/{entry_id}")

    def fleet_get_config(self) -> dict[str, Any]:
        return self.get("/api/v1/fleet/config")

    def fleet_update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        return self.put("/api/v1/fleet/config", data=config)

    def fleet_toggle_pause(self) -> dict[str, Any]:
        return self.post("/api/v1/fleet/pause")

    def fleet_reenable_block(self, ip: str) -> dict[str, Any]:
        return self.post(f"/api/v1/fleet/blocks/{ip}/reenable")

    def fleet_active_blocks(self) -> dict[str, Any]:
        return self.get("/api/v1/fleet/blocks/active")

    def fleet_reap(self) -> dict[str, Any]:
        return self.post("/api/v1/fleet/reap")

    # ------------------------------------------------------------------
    # Intel API
    # ------------------------------------------------------------------

    def intel_search(
        self,
        query: str | None = None,
        page: int = 1,
        per_page: int = 50,
        min_score: int | None = None,
        threat_tag: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page, "per_page": per_page}
        if query:
            params["q"] = query
        if min_score is not None:
            params["min_score"] = min_score
        if threat_tag:
            params["threat_tag"] = threat_tag
        return self.get("/api/v1/intel/ips", params=params)

    def intel_get_ip(self, ip: str) -> dict[str, Any]:
        return self.get(f"/api/v1/intel/ips/{ip}")

    def intel_blocklist(
        self,
        min_score: int | None = None,
        min_sightings: int | None = None,
        threat_tag: str | None = None,
        geo_country: str | None = None,
        repeat_offender: bool | None = None,
        output_format: str = "json",
    ) -> Any:
        """Fetch the intel blocklist (list of IPs)."""
        params: dict[str, Any] = {"format": output_format}
        if min_score is not None:
            params["min_score"] = min_score
        if min_sightings is not None:
            params["min_sightings"] = min_sightings
        if threat_tag:
            params["threat_tag"] = threat_tag
        if geo_country:
            params["geo_country"] = geo_country
        if repeat_offender is not None:
            params["repeat_offender"] = "true" if repeat_offender else "false"
        return self.get("/api/v1/intel/blocklist", params=params)

    # ------------------------------------------------------------------
    # Nodes / Dashboard API
    # ------------------------------------------------------------------

    def nodes_list(self) -> Any:
        return self.get("/nodes")

    def nodes_get(self, node_id: str) -> dict[str, Any]:
        return self.get(f"/nodes/{node_id}")

    def nodes_send_command(
        self, node_id: str, command_type: str, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"command_type": command_type}
        if payload:
            data["payload"] = payload
        return self.post(f"/nodes/{node_id}/commands", data=data)

    # ------------------------------------------------------------------
    # Config Management API
    # ------------------------------------------------------------------

    def config_list_profiles(self, page: int = 1, per_page: int = 50) -> dict[str, Any]:
        return self.get("/api/v1/config/profiles", params={"page": page, "per_page": per_page})

    def config_get_profile(self, profile_id: int) -> dict[str, Any]:
        return self.get(f"/api/v1/config/profiles/{profile_id}")

    def config_create_profile(
        self, name: str, settings: dict[str, Any], description: str = ""
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"name": name, "settings": settings}
        if description:
            data["description"] = description
        return self.post("/api/v1/config/profiles", data=data)

    def config_update_profile(
        self, profile_id: int, settings: dict[str, Any], description: str | None = None
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"settings": settings}
        if description is not None:
            data["description"] = description
        return self.put(f"/api/v1/config/profiles/{profile_id}", data=data)

    def config_delete_profile(self, profile_id: int) -> dict[str, Any]:
        return self.delete(f"/api/v1/config/profiles/{profile_id}")

    def config_list_groups(self, page: int = 1, per_page: int = 50) -> dict[str, Any]:
        return self.get("/api/v1/config/groups", params={"page": page, "per_page": per_page})

    def config_create_group(self, name: str, description: str = "") -> dict[str, Any]:
        data: dict[str, Any] = {"name": name}
        if description:
            data["description"] = description
        return self.post("/api/v1/config/groups", data=data)

    def config_delete_group(self, group_id: int) -> dict[str, Any]:
        return self.delete(f"/api/v1/config/groups/{group_id}")

    def config_add_group_member(self, group_id: int, node_id: str) -> dict[str, Any]:
        return self.post(f"/api/v1/config/groups/{group_id}/members", data={"node_id": node_id})

    def config_remove_group_member(self, group_id: int, node_id: str) -> dict[str, Any]:
        return self.delete(f"/api/v1/config/groups/{group_id}/members/{node_id}")

    def config_create_assignment(
        self, profile_id: int, node_id: str | None = None, group_id: int | None = None
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"profile_id": profile_id}
        if node_id:
            data["node_id"] = node_id
        if group_id:
            data["group_id"] = group_id
        return self.post("/api/v1/config/assignments", data=data)

    def config_delete_assignment(self, assignment_id: int) -> dict[str, Any]:
        return self.delete(f"/api/v1/config/assignments/{assignment_id}")

    def config_profile_history(
        self, profile_id: int, page: int = 1, per_page: int = 50
    ) -> dict[str, Any]:
        return self.get(
            f"/api/v1/config/profiles/{profile_id}/history",
            params={"page": page, "per_page": per_page},
        )

    def config_profile_version(self, profile_id: int, version: int) -> dict[str, Any]:
        return self.get(f"/api/v1/config/profiles/{profile_id}/history/{version}")

    def config_profile_diff(
        self, profile_id: int, from_version: int, to_version: int
    ) -> dict[str, Any]:
        return self.get(
            f"/api/v1/config/profiles/{profile_id}/diff",
            params={"from_version": from_version, "to_version": to_version},
        )

    def config_profile_rollback(
        self, profile_id: int, target_version: int, reason: str = ""
    ) -> dict[str, Any]:
        data: dict[str, Any] = {"target_version": target_version}
        if reason:
            data["reason"] = reason
        return self.post(f"/api/v1/config/profiles/{profile_id}/rollback", data=data)

    # ------------------------------------------------------------------
    # Admin API
    # ------------------------------------------------------------------

    def admin_list_users(self) -> Any:
        return self.get("/admin/users")

    def admin_create_user(
        self, username: str, password: str, role: str = "viewer"
    ) -> dict[str, Any]:
        return self.post(
            "/admin/users", data={"username": username, "password": password, "role": role}
        )

    def admin_list_keys(self) -> Any:
        return self.get("/admin/keys")

    def admin_create_key(self, name: str, role: str = "agent") -> dict[str, Any]:
        return self.post("/admin/keys", data={"name": name, "role": role})

    def admin_revoke_key(self, key_id: int) -> dict[str, Any]:
        return self.post(f"/admin/keys/{key_id}/revoke")

    def admin_audit_log(
        self,
        page: int = 1,
        per_page: int = 50,
        actor: str | None = None,
        action_type: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page, "per_page": per_page}
        if actor:
            params["actor"] = actor
        if action_type:
            params["action_type"] = action_type
        return self.get("/admin/audit", params=params)

    def admin_list_enrollments(self) -> Any:
        return self.get("/admin/enrollment")

    def admin_approve_enrollment(self, enrollment_id: int) -> dict[str, Any]:
        return self.post(f"/admin/enrollment/{enrollment_id}/approve")

    def admin_reject_enrollment(self, enrollment_id: int) -> dict[str, Any]:
        return self.post(f"/admin/enrollment/{enrollment_id}/reject")

    def admin_revoke_enrollment(self, enrollment_id: int) -> dict[str, Any]:
        return self.post(f"/admin/enrollment/{enrollment_id}/revoke")

    def admin_change_user_role(self, user_id: int, role: str) -> dict[str, Any]:
        return self.put(f"/admin/users/{user_id}/role", data={"role": role})

    def admin_change_user_password(self, user_id: int, new_password: str) -> dict[str, Any]:
        return self.post(f"/admin/users/{user_id}/password", data={"new_password": new_password})

    def admin_delete_key(self, key_id: int) -> dict[str, Any]:
        return self.post(f"/admin/keys/{key_id}/delete")

    def admin_update_key_node_restriction(self, key_id: int, node_id: str | None) -> dict[str, Any]:
        data: dict[str, Any] = {}
        if node_id is not None:
            data["node_id_restriction"] = node_id
        return self.put(f"/admin/keys/{key_id}/node-restriction", data=data)

    def admin_enrollment_settings(self) -> dict[str, Any]:
        result = self.admin_list_enrollments()
        if isinstance(result, dict):
            return result.get("settings", {})
        return result

    def admin_update_enrollment_settings(self, settings: dict[str, str]) -> dict[str, Any]:
        return self.post("/admin/enrollment/settings", data=settings)

    def admin_rotate_enrollment(self, enrollment_id: int) -> dict[str, Any]:
        return self.post(f"/admin/enrollment/{enrollment_id}/rotate")

    def admin_delete_enrollment_record(self, enrollment_id: int) -> dict[str, Any]:
        return self.post(f"/admin/enrollment/{enrollment_id}/delete")

    def admin_reissue_enrollment(self, enrollment_id: int) -> dict[str, Any]:
        return self.post(f"/admin/enrollment/{enrollment_id}/reissue")

    def admin_allow_unrestricted_api_keys(self, value: str) -> dict[str, Any]:
        return self.post(
            "/admin/enrollment/allow-unrestricted",
            data={"allow_unrestricted_api_keys": value},
        )

    # -- Admin: Cleanup / Retention --

    def admin_cleanup_status(self) -> dict[str, Any]:
        return self.get("/admin/cleanup")

    def admin_cleanup_save_retention(self, days: int) -> dict[str, Any]:
        return self.post(
            "/admin/cleanup", data={"action": "save_retention", "retention_days": str(days)}
        )

    def admin_cleanup_purge(self) -> dict[str, Any]:
        return self.post("/admin/cleanup", data={"action": "purge_now"})

    # -- Admin: Command Queue --

    def admin_commands_list(self, status: str = "", node_id: str = "") -> dict[str, Any]:
        params = {}
        if status:
            params["status"] = status
        if node_id:
            params["node_id"] = node_id
        return self.get("/admin/commands", params=params)

    def admin_commands_delete(self, command_id: str) -> dict[str, Any]:
        return self.post("/admin/commands", data={"action": "delete", "command_id": command_id})

    def admin_commands_expire_pending(self, hours: int = 24) -> dict[str, Any]:
        return self.post("/admin/commands", data={"action": "expire_pending", "hours": str(hours)})

    def admin_commands_purge_old(self, days: int = 30) -> dict[str, Any]:
        return self.post("/admin/commands", data={"action": "purge_old", "days": str(days)})

    def admin_commands_save_settings(
        self, expiry_hours: int = 24, retention_days: int = 30
    ) -> dict[str, Any]:
        return self.post(
            "/admin/commands",
            data={
                "action": "save_settings",
                "expiry_hours": str(expiry_hours),
                "retention_days": str(retention_days),
            },
        )

    # -- Admin: Backups --

    def admin_backups_list(self) -> dict[str, Any]:
        return self.get("/admin/backups")

    def admin_backups_run(self) -> dict[str, Any]:
        return self.post("/admin/backups/run")

    def admin_backups_delete(self, filename: str) -> dict[str, Any]:
        return self.post(f"/admin/backups/delete/{filename}")

    def admin_backups_save_settings(
        self,
        enabled: str = "false",
        interval_hours: int = 24,
        retention_days: int = 30,
        backup_directory: str = "",
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "backup_enabled": enabled,
            "backup_interval_hours": str(interval_hours),
            "backup_retention_days": str(retention_days),
        }
        if backup_directory:
            data["backup_directory"] = backup_directory
        return self.post("/admin/backups/settings", data=data)

    # -- Admin: Logs --

    def admin_logs(self, lines: int = 200) -> dict[str, Any]:
        return self.get("/admin/logs", params={"lines": str(lines)})

    # -- Admin: Inventory --

    def admin_inventory_status(self) -> dict[str, Any]:
        return self.get("/admin/inventory")

    def admin_inventory_purge_stale(self) -> dict[str, Any]:
        return self.post("/admin/inventory/purge-stale")

    def admin_inventory_merge(self, keep_id: str, discard_id: str) -> dict[str, Any]:
        return self.post(
            "/admin/inventory/merge", data={"keep_id": keep_id, "discard_id": discard_id}
        )

    def admin_inventory_delete_asset(self, asset_id: str) -> dict[str, Any]:
        return self.post(f"/admin/inventory/{asset_id}/delete")

    # ------------------------------------------------------------------
    # Alert Management API
    # ------------------------------------------------------------------

    def alerts_health(self) -> dict[str, Any]:
        return self.get("/health/alerts")

    # -- Alert Rules --

    def alerts_rules_list(self) -> Any:
        return self.get("/alerts/api/rules")

    def alerts_rules_create(self, rule: dict[str, Any]) -> dict[str, Any]:
        return self.post("/alerts/api/rules", data=rule)

    def alerts_rules_update(self, rule_id: int, rule: dict[str, Any]) -> dict[str, Any]:
        return self.put(f"/alerts/api/rules/{rule_id}", data=rule)

    def alerts_rules_delete(self, rule_id: int) -> dict[str, Any]:
        return self.delete(f"/alerts/api/rules/{rule_id}")

    # -- Active Alerts / Events --

    def alerts_active_list(self) -> Any:
        return self.get("/alerts/api/active")

    def alerts_active_count(self, severity: str | None = None) -> dict[str, Any]:
        params = {}
        if severity:
            params["severity"] = severity
        return self.get("/alerts/api/active/count", params=params)

    def alerts_event_ack(self, event_id: int) -> dict[str, Any]:
        return self.post(f"/alerts/api/events/{event_id}/ack")

    def alerts_event_resolve(self, event_id: int) -> dict[str, Any]:
        return self.post(f"/alerts/api/events/{event_id}/resolve")

    # -- Alert History --

    def alerts_history(
        self,
        page: int = 1,
        per_page: int = 50,
        filter: str = "all",
        q: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page, "per_page": per_page, "filter": filter}
        if q:
            params["q"] = q
        return self.get("/alerts/api/history", params=params)

    # -- Notification Channels --

    def alerts_channels_list(self) -> Any:
        return self.get("/alerts/api/channels")

    def alerts_channels_create(self, channel: dict[str, Any]) -> dict[str, Any]:
        return self.post("/alerts/api/channels", data=channel)

    def alerts_channels_update(self, channel_id: int, channel: dict[str, Any]) -> dict[str, Any]:
        return self.put(f"/alerts/api/channels/{channel_id}", data=channel)

    def alerts_channels_delete(self, channel_id: int) -> dict[str, Any]:
        return self.delete(f"/alerts/api/channels/{channel_id}")

    def alerts_channels_test(self, channel_id: int) -> dict[str, Any]:
        return self.post(f"/alerts/api/channels/{channel_id}/test")

    # -- Silences --

    def alerts_silences_list(self, include_expired: bool = False) -> Any:
        params = {"include_expired": "true"} if include_expired else {}
        return self.get("/alerts/api/silences", params=params)

    def alerts_silences_get(self, silence_id: int) -> dict[str, Any]:
        return self.get(f"/alerts/api/silences/{silence_id}")

    def alerts_silences_create(self, silence: dict[str, Any]) -> dict[str, Any]:
        return self.post("/alerts/api/silences", data=silence)

    def alerts_silences_update(self, silence_id: int, silence: dict[str, Any]) -> dict[str, Any]:
        return self.put(f"/alerts/api/silences/{silence_id}", data=silence)

    def alerts_silences_delete(self, silence_id: int) -> dict[str, Any]:
        return self.delete(f"/alerts/api/silences/{silence_id}")

    # -- Monitoring Groups --

    def alerts_groups_list(self) -> Any:
        return self.get("/alerts/api/groups")

    def alerts_groups_create(self, group: dict[str, Any]) -> dict[str, Any]:
        return self.post("/alerts/api/groups", data=group)

    def alerts_groups_get(self, group_id: int) -> dict[str, Any]:
        return self.get(f"/alerts/api/groups/{group_id}")

    def alerts_groups_update(self, group_id: int, group: dict[str, Any]) -> dict[str, Any]:
        return self.put(f"/alerts/api/groups/{group_id}", data=group)

    def alerts_groups_delete(self, group_id: int) -> dict[str, Any]:
        return self.delete(f"/alerts/api/groups/{group_id}")

    def alerts_groups_instances(self, group_id: int) -> Any:
        return self.get(f"/alerts/api/groups/{group_id}/instances")

    def alerts_groups_active(self, group_id: int) -> Any:
        return self.get(f"/alerts/api/groups/{group_id}/active")

    def alerts_groups_status(self, group_id: int) -> dict[str, Any]:
        return self.get(f"/alerts/api/groups/{group_id}/status")

    # -- Group Conditions --

    def alerts_conditions_create(self, group_id: int, condition: dict[str, Any]) -> dict[str, Any]:
        return self.post(f"/alerts/api/groups/{group_id}/conditions", data=condition)

    def alerts_conditions_update(
        self, group_id: int, condition_id: int, condition: dict[str, Any]
    ) -> dict[str, Any]:
        return self.put(f"/alerts/api/groups/{group_id}/conditions/{condition_id}", data=condition)

    def alerts_conditions_delete(self, group_id: int, condition_id: int) -> dict[str, Any]:
        return self.delete(f"/alerts/api/groups/{group_id}/conditions/{condition_id}")

    def alerts_conditions_set_channels(
        self, group_id: int, condition_id: int, channel_ids: list[int]
    ) -> dict[str, Any]:
        return self.put(
            f"/alerts/api/groups/{group_id}/conditions/{condition_id}/channels",
            data={"channel_ids": channel_ids},
        )

    # -- Hosts / Agents --

    def alerts_hosts(self) -> Any:
        return self.get("/alerts/api/hosts")

    def alerts_agent(self, agent_id: str) -> dict[str, Any]:
        return self.get(f"/alerts/api/agents/{agent_id}")

    def alerts_agent_check_history(
        self, agent_id: str, condition_id: int, range: str = "24h", step: str = "60s"
    ) -> dict[str, Any]:
        params = {"range": range, "step": step}
        return self.get(
            f"/alerts/api/agents/{agent_id}/checks/{condition_id}/history", params=params
        )

    # ------------------------------------------------------------------
    # Events / Export
    # ------------------------------------------------------------------

    def events_search(
        self,
        page: int = 1,
        per_page: int = 50,
        source_ip: str | None = None,
        event_type: str | None = None,
        node_id: str | None = None,
        action_taken: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"page": page, "per_page": per_page}
        if source_ip:
            params["source_ip"] = source_ip
        if event_type:
            params["event_type"] = event_type
        if node_id:
            params["node_id"] = node_id
        if action_taken:
            params["action_taken"] = action_taken
        return self.get("/events", params=params)

    def events_export(self, format: str = "json", **filters: Any) -> Any:
        params = {"format": format, **{k: v for k, v in filters.items() if v}}
        return self.get("/api/v1/events/export", params=params)

    # ------------------------------------------------------------------
    # Detection Rules API (/api/v1/rules)
    # ------------------------------------------------------------------

    def rules_list(self, page: int = 1, per_page: int = 50) -> dict[str, Any]:
        params = {"page": page, "per_page": per_page}
        return self.get("/api/v1/rules", params=params)

    def rules_create_brute_force(self, rule: dict[str, Any]) -> dict[str, Any]:
        return self.post("/api/v1/rules/brute-force", data=rule)

    def rules_update_brute_force(self, rule_id: int, rule: dict[str, Any]) -> dict[str, Any]:
        return self.put(f"/api/v1/rules/brute-force/{rule_id}", data=rule)

    def rules_delete_brute_force(self, rule_id: int) -> dict[str, Any]:
        return self.delete(f"/api/v1/rules/brute-force/{rule_id}")

    def rules_create_custom(self, rule: dict[str, Any]) -> dict[str, Any]:
        return self.post("/api/v1/rules/custom", data=rule)

    def rules_update_custom(self, rule_id: int, rule: dict[str, Any]) -> dict[str, Any]:
        return self.put(f"/api/v1/rules/custom/{rule_id}", data=rule)

    def rules_delete_custom(self, rule_id: int) -> dict[str, Any]:
        return self.delete(f"/api/v1/rules/custom/{rule_id}")

    def rules_create_correlation(self, rule: dict[str, Any]) -> dict[str, Any]:
        return self.post("/api/v1/rules/correlation", data=rule)

    def rules_update_correlation(self, rule_id: int, rule: dict[str, Any]) -> dict[str, Any]:
        return self.put(f"/api/v1/rules/correlation/{rule_id}", data=rule)

    def rules_delete_correlation(self, rule_id: int) -> dict[str, Any]:
        return self.delete(f"/api/v1/rules/correlation/{rule_id}")

    def rules_packs_list(self) -> Any:
        return self.get("/api/v1/rules/packs")

    def rules_templates_list(self, pack_name: str) -> dict[str, Any]:
        return self.get(f"/api/v1/rules/templates/{pack_name}")

    def rules_templates_enable_all(self, pack_name: str) -> dict[str, Any]:
        return self.post(f"/api/v1/rules/templates/{pack_name}/enable-all")

    def rules_templates_disable_all(self, pack_name: str) -> dict[str, Any]:
        return self.post(f"/api/v1/rules/templates/{pack_name}/disable-all")

    def rules_templates_toggle(self, pack_name: str, rule_id: int) -> dict[str, Any]:
        return self.post(f"/api/v1/rules/templates/{pack_name}/{rule_id}/toggle")

    def rules_sigma_sync(self) -> dict[str, Any]:
        return self.post("/api/v1/rules/sigma/sync")

    # ------------------------------------------------------------------
    # Metrics API
    # ------------------------------------------------------------------

    def metrics_summary(self) -> dict[str, Any]:
        return self.get("/metrics/api/summary")

    def metrics_agent_range(self, agent_id: str, range: str = "1h") -> dict[str, Any]:
        return self.get(f"/metrics/api/{agent_id}/range", params={"range": range})

    def metrics_query(self, q: str) -> Any:
        return self.get("/metrics/api/query", params={"q": q})

    def metrics_query_range(
        self, q: str, start: str = "-1h", step: str = "60s", end: str | None = None
    ) -> Any:
        params: dict[str, Any] = {"q": q, "start": start, "step": step}
        if end:
            params["end"] = end
        return self.get("/metrics/api/query_range", params=params)

    def metrics_labels(self, label_name: str) -> Any:
        return self.get(f"/metrics/api/labels/{label_name}")

    def metrics_saved_queries_list(self) -> Any:
        return self.get("/metrics/api/queries")

    def metrics_saved_queries_create(self, name: str, query: str) -> dict[str, Any]:
        return self.post("/metrics/api/queries", data={"name": name, "query": query})

    def metrics_saved_queries_update(self, query_id: int, name: str, query: str) -> dict[str, Any]:
        return self.put(f"/metrics/api/queries/{query_id}", data={"name": name, "query": query})

    def metrics_saved_queries_delete(self, query_id: int) -> dict[str, Any]:
        return self.delete(f"/metrics/api/queries/{query_id}")

    # -- Logfile Watches --

    def logfile_watches_list(self, agent_id: str | None = None) -> Any:
        params = {}
        if agent_id:
            params["agent_id"] = agent_id
        return self.get("/api/v1/logfile-watches", params=params)

    def logfile_watches_create(self, watch: dict[str, Any]) -> dict[str, Any]:
        return self.post("/api/v1/logfile-watches", data=watch)

    def logfile_watches_update(self, watch_id: int, watch: dict[str, Any]) -> dict[str, Any]:
        return self.put(f"/api/v1/logfile-watches/{watch_id}", data=watch)

    def logfile_watches_delete(self, watch_id: int) -> dict[str, Any]:
        return self.delete(f"/api/v1/logfile-watches/{watch_id}")

    # ------------------------------------------------------------------
    # Inventory API
    # ------------------------------------------------------------------

    def inventory_query(
        self,
        q: str | None = None,
        asset_type: str | None = None,
        source: str | None = None,
        status: str | None = None,
        label: str | None = None,
        parent: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if q:
            params["q"] = q
        if asset_type:
            params["type"] = asset_type
        if source:
            params["source"] = source
        if status:
            params["status"] = status
        if label:
            params["label"] = label
        if parent:
            params["parent"] = parent
        return self.get("/inventory/api/query", params=params)

    def inventory_asset(self, asset_id: str) -> dict[str, Any]:
        return self.get(f"/inventory/api/asset/{asset_id}")

    def inventory_export(self) -> Any:
        return self.get("/inventory/api/export")

    def inventory_graph(self) -> dict[str, Any]:
        return self.get("/inventory/api/graph")

    def inventory_relationships(self, asset_id: str) -> Any:
        return self.get(f"/inventory/api/{asset_id}/relationships")

    # ------------------------------------------------------------------
    # Synthetic Checks API
    # ------------------------------------------------------------------

    def synth_checks_list(self) -> Any:
        return self.get("/api/v1/synthetic-checks")

    def synth_checks_create(self, check: dict[str, Any]) -> dict[str, Any]:
        return self.post("/api/v1/synthetic-checks", data=check)

    def synth_checks_get(self, check_id: int) -> dict[str, Any]:
        return self.get(f"/api/v1/synthetic-checks/{check_id}")

    def synth_checks_update(self, check_id: int, check: dict[str, Any]) -> dict[str, Any]:
        return self.put(f"/api/v1/synthetic-checks/{check_id}", data=check)

    def synth_checks_delete(self, check_id: int) -> dict[str, Any]:
        return self.delete(f"/api/v1/synthetic-checks/{check_id}")

    def synth_checks_history(self, check_id: int) -> Any:
        return self.get(f"/api/v1/synthetic-checks/{check_id}/history")

    def synth_alerts_list(self) -> Any:
        return self.get("/api/v1/synthetic-alerts")

    def synth_alerts_get(self, alert_id: int) -> dict[str, Any]:
        return self.get(f"/api/v1/synthetic-alerts/{alert_id}")

    def synth_alerts_create(self, alert: dict[str, Any]) -> dict[str, Any]:
        return self.post("/api/v1/synthetic-alerts", data=alert)

    def synth_alerts_update(self, alert_id: int, alert: dict[str, Any]) -> dict[str, Any]:
        return self.put(f"/api/v1/synthetic-alerts/{alert_id}", data=alert)

    def synth_alerts_delete(self, alert_id: int) -> dict[str, Any]:
        return self.delete(f"/api/v1/synthetic-alerts/{alert_id}")

    def synth_alerts_resolve(self, alert_id: int) -> dict[str, Any]:
        return self.post(f"/api/v1/synthetic-alerts/{alert_id}/resolve")

    def synth_policies_list(self) -> Any:
        return self.get("/api/v1/synthetic-alert-policies")

    def synth_policies_update(self, policy_id: int, policy: dict[str, Any]) -> dict[str, Any]:
        return self.put(f"/api/v1/synthetic-alert-policies/{policy_id}", data=policy)

    def synth_policies_reconcile(self, policy_id: int) -> dict[str, Any]:
        return self.post(f"/api/v1/synthetic-alert-policies/{policy_id}/reconcile")

    def synth_policies_reconcile_all(self) -> dict[str, Any]:
        return self.post("/api/v1/synthetic-alert-policies/reconcile-all")


def get_client(
    base_url: str | None = None,
    api_key: str | None = None,
    *,
    verify: bool | str | None = None,
    cert: str | None = None,
    key: str | None = None,
) -> ServerClient:
    """Factory function to create a configured ServerClient.

    Args:
        base_url: Server base URL. Resolved from env/config if not given.
        api_key:  API key. Resolved from env/config if not given.
        verify:   SSL verification mode. Falls back to config.SSL_VERIFY
                  or ``True`` if not specified.
        cert:     Path to client certificate file.
        key:      Path to client certificate key file.
    """
    if verify is None:
        try:
            from .config import CONFIG

            verify = CONFIG.ssl_verify
        except Exception:
            verify = True
    if not cert:
        try:
            from .config import CONFIG

            cert = CONFIG.ssl_cert or None  # type: ignore[assignment]
            key = CONFIG.ssl_key or None
        except Exception:
            pass
    return ServerClient(base_url=base_url, api_key=api_key, verify=verify, cert=cert, key=key)
