"""Thin HTTP client wrapper with standard Vespid auth headers.

Consolidates HTTP boilerplate (headers, timeout, error classification) so
callers in ``databus.py`` and ``daemon.py`` don't repeat it.

Uses ``httpx`` for all HTTP transport — the same library used by the SSE
subscribers, subscription manager, and enrollment client — giving the
entire agent a single, consistent HTTP stack with unified SSL handling.
"""

from __future__ import annotations

import json
import logging
import ssl
from dataclasses import dataclass
from typing import Any

import httpx

from . import __version__

log = logging.getLogger("vespid.http")


@dataclass
class HttpResponse:
    status: int
    body: bytes

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        return json.loads(self.body)


class HttpError(Exception):
    """Raised on HTTP 4xx/5xx responses or connection failures.

    Attributes:
        status:  HTTP status code, or ``None`` for connection-level failures.
        body:    Response body bytes (may be empty).
        is_server_error: ``True`` for 5xx and connection errors (retryable).
    """

    def __init__(
        self,
        message: str,
        status: int | None = None,
        body: bytes = b"",
    ) -> None:
        super().__init__(message)
        self.status = status
        self.body = body

    @property
    def is_server_error(self) -> bool:
        """Connection errors and 5xx are considered server-side failures."""
        return self.status is None or self.status >= 500

    @property
    def is_retryable(self) -> bool:
        """Whether the request should be retried later.

        Connection errors, 5xx responses, and 429 rate-limit responses are
        transient and should be retried. Other 4xx responses indicate a
        permanent problem with the request and should not be retried.
        """
        return self.is_server_error or self.status == 429


def build_ssl_context(verify: bool | str, cert: str = "", key: str = "") -> ssl.SSLContext:
    """Build an SSL context based on Vespid's SSL configuration.

    Args:
        verify: ``True`` for system defaults, ``False`` to skip verification,
                or a path string to a CA bundle file.
        cert:   Path to a client certificate file (optional).
        key:    Path to the client certificate's private key (optional).

    Returns:
        A configured ``ssl.SSLContext``.
    """
    context = ssl.create_default_context()

    if isinstance(verify, str):
        context.load_verify_locations(cafile=verify)
    elif not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    if cert:
        context.load_cert_chain(cert, keyfile=key or None)

    return context


def request(
    api_key: str,
    node_id: str,
    method: str,
    url: str,
    *,
    json_data: Any = None,
    extra_headers: dict[str, str] | None = None,
    timeout: int = 10,
    verify: bool | str = True,
    cert: str = "",
    key: str = "",
) -> HttpResponse:
    """Send an HTTP request with Vespid authentication headers.

    Args:
        api_key:   Bearer token for the ``Authorization`` header.
        node_id:   Value for the ``X-Node-Id`` header.
        method:    HTTP method (``"GET"``, ``"POST"``, etc.).
        url:       Full URL to request.
        json_data: Payload — serialised as JSON and sent as the body.
                   When ``None`` no body is sent.
        extra_headers: Additional headers merged into the request.
        timeout:   Request timeout in seconds (default 10).
        verify:   SSL verification mode — ``True`` (system CAs), ``False``
                  (skip), or a path to a CA bundle file.
        cert:     Path to a client certificate file for mutual TLS.
        key:      Path to the client certificate key file.

    Returns:
        ``HttpResponse`` with ``status`` and ``body``.

    Raises:
        HttpError:  On any 4xx/5xx response or connection failure.
                    Use ``.is_server_error`` to distinguish retryable failures.
    """
    headers: dict[str, str] = {
        "Authorization": f"Bearer {api_key}",
        "X-Node-Id": node_id,
        "User-Agent": f"Vespid/{__version__} Agent",
    }
    if json_data is not None:
        headers["Content-Type"] = "application/json"

    if extra_headers:
        headers.update(extra_headers)

    body = json.dumps(json_data).encode("utf-8") if json_data is not None else None
    ctx = build_ssl_context(verify, cert, key)

    try:
        with httpx.Client(verify=ctx, timeout=float(timeout)) as client:
            resp = client.request(
                method,
                url,
                headers=headers,
                content=body,
            )
            if resp.status_code >= 400:
                raise HttpError(
                    f"HTTP {resp.status_code}",
                    status=resp.status_code,
                    body=resp.content,
                )
            return HttpResponse(status=resp.status_code, body=resp.content)
    except HttpError:
        raise
    except httpx.HTTPStatusError as exc:
        raise HttpError(
            f"HTTP {exc.response.status_code}",
            status=exc.response.status_code,
            body=exc.response.content,
        ) from exc
    except (httpx.HTTPError, OSError) as exc:
        raise HttpError(str(exc)) from exc
