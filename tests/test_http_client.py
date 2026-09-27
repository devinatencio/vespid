"""Tests for vespid.http_client.HttpError retry classification."""

from __future__ import annotations

from vespid.http_client import HttpError


class TestHttpErrorRetryable:
    def test_connection_error_is_retryable(self):
        err = HttpError("connection failed")
        assert err.is_server_error
        assert err.is_retryable

    def test_5xx_is_retryable(self):
        err = HttpError("HTTP 503", status=503)
        assert err.is_server_error
        assert err.is_retryable

    def test_429_is_retryable_but_not_server_error(self):
        err = HttpError("HTTP 429", status=429)
        assert not err.is_server_error
        assert err.is_retryable

    def test_400_is_not_retryable(self):
        err = HttpError("HTTP 400", status=400)
        assert not err.is_retryable

    def test_422_is_not_retryable(self):
        err = HttpError("HTTP 422", status=422)
        assert not err.is_retryable
