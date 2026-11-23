"""Tests for default log source detection, including nginx discovery."""

from __future__ import annotations

import pytest

from vespid import config as cfg

NGINX_ACCESS = "/var/log/nginx/access.log"
NGINX_ERROR = "/var/log/nginx/error.log"


def _nginx_sources(sources: list[cfg.LogSource]) -> dict[str, str]:
    return {s.path: s.parser for s in sources if s.path.startswith("/var/log/nginx/")}


@pytest.mark.parametrize(
    "family",
    [
        cfg.FAMILY_DEBIAN,
        cfg.FAMILY_REDHAT,
        cfg.FAMILY_SUSE,
        cfg.FAMILY_UNKNOWN,
    ],
)
def test_default_log_sources_adds_nginx_when_files_exist(monkeypatch, family):
    """Nginx paths are added on every distro family when the files exist."""
    monkeypatch.setattr(cfg, "detect_distro_family", lambda: family)
    monkeypatch.setattr(cfg, "_log_file_exists", lambda path: path in {NGINX_ACCESS, NGINX_ERROR})

    sources = cfg._default_log_sources()

    assert _nginx_sources(sources) == {
        NGINX_ACCESS: "apache",
        NGINX_ERROR: "apache",
    }
    # Existing distro defaults must still be present alongside nginx.
    assert any(s.parser == "haproxy" for s in sources)
    assert len(sources) >= 7


def test_default_log_sources_skips_nginx_when_files_absent(monkeypatch):
    """No nginx sources are added when the standard log files do not exist."""
    monkeypatch.setattr(cfg, "detect_distro_family", lambda: cfg.FAMILY_REDHAT)
    monkeypatch.setattr(cfg, "_log_file_exists", lambda path: False)

    sources = cfg._default_log_sources()

    assert _nginx_sources(sources) == {}
    assert any(s.path == "/var/log/httpd/access_log" for s in sources)


def test_append_detected_nginx_sources_adds_only_existing(monkeypatch):
    """Only the nginx files that exist are appended."""
    monkeypatch.setattr(cfg, "_log_file_exists", lambda path: path == NGINX_ACCESS)

    sources = cfg._append_detected_nginx_sources(
        [cfg.LogSource(path="/var/log/secure", parser="secure")]
    )

    assert _nginx_sources(sources) == {NGINX_ACCESS: "apache"}


def test_append_detected_nginx_sources_does_not_duplicate_paths(monkeypatch):
    """A path already configured elsewhere is not added a second time."""
    monkeypatch.setattr(cfg, "_log_file_exists", lambda path: path in {NGINX_ACCESS, NGINX_ERROR})

    sources = cfg._append_detected_nginx_sources(
        [cfg.LogSource(path=NGINX_ACCESS, parser="apache")]
    )

    paths = [s.path for s in sources]
    assert paths.count(NGINX_ACCESS) == 1
    assert paths.count(NGINX_ERROR) == 1


def test_log_file_exists_returns_false_on_oserror(monkeypatch):
    """Probe failures should not prevent the agent from starting."""

    def raise_oserror(path: str) -> bool:
        raise OSError("permission denied")

    monkeypatch.setattr(cfg.os.path, "isfile", raise_oserror)

    assert cfg._log_file_exists(NGINX_ACCESS) is False
