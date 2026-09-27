"""Tests for the Flask app factory (app/__init__.py)."""

import json
import os
import stat
import tempfile

import pytest
from flask import Flask

from app import create_app
from app.sse import SSEManager


class TestCreateApp:
    """Test that create_app returns a properly configured Flask app."""

    def test_returns_flask_instance(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))
        app = create_app(str(config_file))
        assert isinstance(app, Flask)

    def test_sets_secret_key_from_config(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "my-test-secret-key",
            "DATABASE_PATH": db_path,
        }))
        app = create_app(str(config_file))
        assert app.config["SECRET_KEY"] == "my-test-secret-key"

    def test_stores_config_values_in_app_config(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
            "PORT": 9999,
            "EVENTS_PER_PAGE": 25,
        }))
        app = create_app(str(config_file))
        assert app.config["PORT"] == 9999
        assert app.config["EVENTS_PER_PAGE"] == 25

    def test_uses_defaults_without_config_file(self, tmp_path, monkeypatch):
        db_path = str(tmp_path / "test.db")
        monkeypatch.setenv("VESPID_DATABASE_PATH", db_path)
        monkeypatch.setenv("VESPID_SECRET_KEY", "test-secret-no-config")
        app = create_app()
        assert app.config["SECRET_KEY"] == "test-secret-no-config"
        assert app.config["DATABASE_PATH"] == db_path


class TestBlueprintRegistration:
    """Test that all blueprints are registered."""

    @pytest.fixture()
    def app(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))
        return create_app(str(config_file))

    def test_auth_blueprint_registered(self, app):
        assert "auth" in app.blueprints

    def test_api_blueprint_registered(self, app):
        assert "api" in app.blueprints

    def test_dashboard_blueprint_registered(self, app):
        assert "dashboard" in app.blueprints

    def test_admin_blueprint_registered(self, app):
        assert "admin" in app.blueprints


class TestFlaskLogin:
    """Test that Flask-Login is configured."""

    @pytest.fixture()
    def app(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))
        return create_app(str(config_file))

    def test_login_manager_configured(self, app):
        # Flask-Login adds a 'login_manager' attribute to the app
        assert hasattr(app, "login_manager")

    def test_login_view_set(self, app):
        assert app.login_manager.login_view == "auth.login"


class TestSSEManager:
    """Test that the SSE manager is initialized."""

    def test_sse_manager_attached_to_app(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))
        app = create_app(str(config_file))
        assert hasattr(app, "sse_manager")
        assert isinstance(app.sse_manager, SSEManager)

    def test_sse_manager_uses_config_history_size(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
            "SSE_HISTORY_SIZE": 1000,
        }))
        app = create_app(str(config_file))
        assert app.sse_manager.history_size == 1000


class TestDatabasePathValidation:
    """Test that the app factory validates the database path."""

    def test_creates_db_directory_if_missing(self, tmp_path):
        db_path = str(tmp_path / "subdir" / "nested" / "test.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))
        app = create_app(str(config_file))
        assert os.path.isdir(os.path.dirname(db_path))

    def test_exits_if_db_directory_not_writable(self, tmp_path):
        # Create a read-only directory
        read_only_dir = tmp_path / "readonly"
        read_only_dir.mkdir()
        db_path = str(read_only_dir / "test.db")

        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret",
            "DATABASE_PATH": db_path,
        }))

        # Remove write permission
        read_only_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)

        try:
            with pytest.raises(SystemExit) as exc_info:
                create_app(str(config_file))
            assert exc_info.value.code == 1
        finally:
            # Restore permissions for cleanup
            read_only_dir.chmod(stat.S_IRWXU)
