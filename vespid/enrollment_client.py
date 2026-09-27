"""Agent-side enrollment client for zero-touch credential provisioning.

Handles credential detection, enrollment requests, polling for approval,
and rotation recovery. Invoked by the daemon at startup when no credentials
file is found, or on 401 errors during normal operation.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import time
from datetime import datetime, timezone

import httpx

from . import __version__
from .config import STATE_DIR, ShieldConfig
from .host_info import _get_machine_id
from .http_client import build_ssl_context

log = logging.getLogger(__name__)

_UA = {"User-Agent": f"Vespid/{__version__} Enrollment"}


class EnrollmentError(Exception):
    """Raised when enrollment is permanently rejected (403)."""


class EnrollmentClient:
    """Handles credential detection, enrollment, and rotation recovery."""

    CREDENTIALS_PATH = STATE_DIR / "credentials.json"

    def __init__(self, config: ShieldConfig) -> None:
        self.config = config
        self.server_url = config.SERVER_URL.rstrip("/")
        # Strip trailing path segments (e.g. /api/v1/events) to get base URL
        if "/api/v1" in self.server_url:
            self.server_url = self.server_url.split("/api/v1")[0].rstrip("/")
        self.node_id = config.node_id
        self._poll_initial = getattr(config, "enrollment_poll_initial_seconds", 30)
        self._poll_max = getattr(config, "enrollment_poll_max_seconds", 300)

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Build the SSL context for httpx from config settings."""
        return build_ssl_context(
            self.config.ssl_verify,
            self.config.ssl_cert,
            self.config.ssl_key,
        )

    def has_credentials(self) -> bool:
        """Check if valid credentials file exists."""
        return self.CREDENTIALS_PATH.is_file()

    def load_credentials(self) -> dict | None:
        """Load and validate credentials from disk.

        Returns the credentials dict if valid, or None if the file is
        missing, unreadable, or malformed.
        """
        if not self.has_credentials():
            return None

        try:
            data = json.loads(self.CREDENTIALS_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            log.error("Failed to read credentials file %s: %s", self.CREDENTIALS_PATH, exc)
            return None

        # Validate required fields
        required = ("api_key", "server_url", "node_id")
        for field in required:
            if field not in data or not data[field]:
                log.error("Credentials file missing required field: %s", field)
                return None

        return data

    def enroll(self) -> str | None:
        """Execute enrollment flow.

        Sends POST to /api/v1/enroll with node_id and hostname.

        Returns:
            The API key string on immediate approval (open mode),
            or None if the request is pending (manual_approval mode).

        Raises:
            EnrollmentError: If enrollment is rejected (403) or the node
                is already enrolled (409).
        """
        url = f"{self.server_url}/api/v1/enroll"
        machine_id = _get_machine_id()
        payload = {
            "node_id": self.node_id,
            "hostname": socket.gethostname(),
            "display_name": self.config.display_name,
        }
        if machine_id:
            payload["machine_id"] = machine_id

        log.info("Submitting enrollment request to %s (node_id=%s)", url, self.node_id)

        # Warn if SSL verification is disabled
        if self.config.ssl_verify is False:
            log.warning("SSL verification is disabled - this is insecure!")

        ctx = self._build_ssl_context()

        try:
            with httpx.Client(verify=ctx, timeout=30.0, headers=_UA) as client:
                resp = client.post(url, json=payload)
        except httpx.HTTPError as exc:
            log.error("Enrollment request failed: %s", exc)
            raise EnrollmentError(f"Network error during enrollment: {exc}") from exc

        if resp.status_code == 200:
            # Credentials issued immediately (open mode)
            data = resp.json()
            api_key = data.get("api_key", "")
            server_url = data.get("server_url", self.server_url)
            asset_id = data.get("asset_id", "") or ""
            log.info("Enrollment approved immediately (open mode)")
            self._persist_credentials(api_key, server_url, asset_id)
            return api_key

        elif resp.status_code == 202:
            # Pending approval (manual_approval mode)
            log.info("Enrollment request accepted, pending admin approval")
            return None

        elif resp.status_code == 403:
            # Rejected or disabled
            detail = ""
            try:
                detail = resp.json().get("error", resp.text)
            except (ValueError, AttributeError):
                detail = resp.text
            log.error("Enrollment rejected (403): %s", detail)
            raise EnrollmentError(f"Enrollment rejected: {detail}")

        elif resp.status_code == 409:
            # Already enrolled or pending
            detail = ""
            try:
                detail = resp.json().get("error", resp.text)
            except (ValueError, AttributeError):
                detail = resp.text
            log.error("Enrollment conflict (409): %s", detail)
            raise EnrollmentError(f"Enrollment conflict: {detail}")

        elif resp.status_code == 429:
            # Rate limited
            log.error("Enrollment rate limited (429). Retry later.")
            raise EnrollmentError("Rate limited during enrollment")

        else:
            log.error("Unexpected enrollment response: %d %s", resp.status_code, resp.text)
            raise EnrollmentError(f"Unexpected response {resp.status_code}: {resp.text}")

    def poll_until_approved(self) -> str:
        """Poll with exponential backoff until credentials are issued.

        Returns:
            The API key string when approved.

        Raises:
            EnrollmentError: If the enrollment is rejected or revoked.
        """
        url = f"{self.server_url}/api/v1/enroll/status/{self.node_id}"
        attempt = 0

        log.info("Starting enrollment poll loop (node_id=%s)", self.node_id)

        # Warn if SSL verification is disabled
        if self.config.ssl_verify is False:
            log.warning("SSL verification is disabled - this is insecure!")

        ctx = self._build_ssl_context()

        while True:
            interval = min(
                self._poll_initial * (2**attempt),
                self._poll_max,
            )
            log.debug("Poll attempt %d, sleeping %ds before next check", attempt, interval)
            time.sleep(interval)

            try:
                with httpx.Client(verify=ctx, timeout=30.0, headers=_UA) as client:
                    resp = client.get(url)
            except httpx.HTTPError as exc:
                log.debug("Poll request failed (attempt %d): %s", attempt, exc)
                attempt += 1
                continue

            if resp.status_code == 200:
                data = resp.json()
                api_key = data.get("api_key")
                if api_key:
                    server_url = data.get("server_url", self.server_url)
                    asset_id = data.get("asset_id", "") or ""
                    log.info("Enrollment approved after %d poll attempts", attempt + 1)
                    self._persist_credentials(api_key, server_url, asset_id)
                    return api_key
                else:
                    # Approved but credentials already retrieved
                    log.info("Enrollment approved but credentials already retrieved")
                    attempt += 1
                    continue

            elif resp.status_code == 202:
                # Still pending
                log.debug("Enrollment still pending (attempt %d)", attempt)
                attempt += 1
                continue

            elif resp.status_code == 403:
                # Rejected or revoked
                detail = ""
                try:
                    detail = resp.json().get("error", resp.text)
                except (ValueError, AttributeError):
                    detail = resp.text
                log.error("Enrollment rejected during polling: %s", detail)
                raise EnrollmentError(f"Enrollment rejected: {detail}")

            else:
                log.debug("Unexpected poll response %d (attempt %d)", resp.status_code, attempt)
                attempt += 1
                continue

    def check_rotation(self) -> str | None:
        """Check if rotated credentials are available.

        Called when the agent receives a 401 during normal operation.
        Queries the status endpoint to see if new credentials have been
        issued via rotation.

        Returns:
            The new API key if rotation credentials are available,
            or None if not available (still pending or no record).
        """
        url = f"{self.server_url}/api/v1/enroll/status/{self.node_id}"

        log.info("Checking for rotated credentials (node_id=%s)", self.node_id)

        # Warn if SSL verification is disabled
        if self.config.ssl_verify is False:
            log.warning("SSL verification is disabled - this is insecure!")

        ctx = self._build_ssl_context()

        try:
            headers = dict(_UA)
            if self.config.API_KEY and self.config.API_KEY.strip():
                headers["Authorization"] = f"Bearer {self.config.API_KEY}"
            with httpx.Client(verify=ctx, timeout=30.0) as client:
                resp = client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            log.error("Rotation check failed: %s", exc)
            return None

        if resp.status_code == 200:
            data = resp.json()
            api_key = data.get("api_key")
            if api_key:
                server_url = data.get("server_url", self.server_url)
                asset_id = data.get("asset_id", "") or ""
                log.info("Rotated credentials retrieved successfully")
                self._persist_credentials(api_key, server_url, asset_id)
                return api_key
            else:
                log.debug("Status is approved but no new credentials available")
                return None

        elif resp.status_code == 403:
            # Revoked — cannot recover via rotation
            log.error("Enrollment has been revoked, rotation not possible")
            return None

        else:
            log.debug("Rotation check returned status %d", resp.status_code)
            return None

    def _persist_credentials(self, api_key: str, server_url: str, asset_id: str = "") -> None:
        """Write credentials to disk with mode 0600.

        Creates the state directory if it doesn't exist. The credentials
        file contains the API key, server URL, node_id, asset_id, and
        enrollment timestamp.
        """
        credentials = {
            "api_key": api_key,
            "server_url": server_url,
            "node_id": self.node_id,
            "asset_id": asset_id,
            "enrolled_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

        creds_path = self.CREDENTIALS_PATH

        try:
            creds_path.parent.mkdir(parents=True, exist_ok=True)

            # Write to a temp file first, then atomically replace
            tmp_path = creds_path.with_suffix(".tmp")
            tmp_path.write_text(
                json.dumps(credentials, indent=2),
                encoding="utf-8",
            )
            # Set restrictive permissions before moving into place
            os.chmod(tmp_path, 0o600)
            tmp_path.replace(creds_path)

            log.info("Credentials persisted to %s (mode 0600)", creds_path)
        except OSError as exc:
            log.error("Failed to persist credentials to %s: %s", creds_path, exc)
            raise
