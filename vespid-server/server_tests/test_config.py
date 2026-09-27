"""Tests for app.config module."""

import json
import os
import tempfile

import yaml

from app.config import DEFAULTS, ENV_PREFIX, load_config


class TestLoadConfigDefaults:
    """Test that defaults are returned when no file or env vars are set."""

    def test_returns_all_default_keys(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
        config = load_config()
        for key in DEFAULTS:
            assert key in config

    def test_default_values_match(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
        config = load_config()
        for key, value in DEFAULTS.items():
            if key == "SECRET_KEY":
                assert config[key] == "test"  # env override
            else:
                assert config[key] == value

    def test_returns_dict(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
        config = load_config()
        assert isinstance(config, dict)


class TestLoadConfigFromJSON:
    """Test loading configuration from a JSON file."""

    def test_file_overrides_defaults(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"PORT": 9999, "DEBUG": True, "SECRET_KEY": "json-secret"}, f)
            f.flush()
            config = load_config(f.name)
        os.unlink(f.name)
        assert config["PORT"] == 9999
        assert config["DEBUG"] is True
        assert config["SECRET_KEY"] == "json-secret"

    def test_missing_file_uses_defaults(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
        config = load_config("/nonexistent/path/config.json")
        for key, value in DEFAULTS.items():
            if key == "SECRET_KEY":
                assert config[key] == "test"
            else:
                assert config[key] == value

    def test_invalid_json_uses_defaults(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write("not valid json {{{")
            f.flush()
            config = load_config(f.name)
        os.unlink(f.name)
        for key, value in DEFAULTS.items():
            if key == "SECRET_KEY":
                assert config[key] == "test"
            else:
                assert config[key] == value

    def test_non_dict_json_uses_defaults(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump([1, 2, 3], f)
            f.flush()
            config = load_config(f.name)
        os.unlink(f.name)
        for key, value in DEFAULTS.items():
            if key == "SECRET_KEY":
                assert config[key] == "test"
            else:
                assert config[key] == value


class TestLoadConfigFromYAML:
    """Test loading configuration from a YAML file."""

    def test_yaml_overrides_defaults(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump({"PORT": 7777, "DEBUG": True, "SECRET_KEY": "yaml-secret"}, f)
            f.flush()
            config = load_config(f.name)
        os.unlink(f.name)
        assert config["PORT"] == 7777
        assert config["DEBUG"] is True
        assert config["SECRET_KEY"] == "yaml-secret"

    def test_yml_extension_works(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            yaml.dump({"PORT": 6666, "HOST": "127.0.0.1", "SECRET_KEY": "yml-secret"}, f)
            f.flush()
            config = load_config(f.name)
        os.unlink(f.name)
        assert config["PORT"] == 6666
        assert config["HOST"] == "127.0.0.1"
        assert config["SECRET_KEY"] == "yml-secret"

    def test_yaml_with_comments(self):
        """YAML files with comments should load correctly."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("# This is a comment\n")
            f.write("PORT: 5555\n")
            f.write("# Another comment\n")
            f.write("SECRET_KEY: my-yaml-secret\n")
            f.flush()
            config = load_config(f.name)
        os.unlink(f.name)
        assert config["PORT"] == 5555
        assert config["SECRET_KEY"] == "my-yaml-secret"

    def test_invalid_yaml_uses_defaults(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("invalid: yaml: content: [[[")
            f.flush()
            config = load_config(f.name)
        os.unlink(f.name)
        for key, value in DEFAULTS.items():
            if key == "SECRET_KEY":
                assert config[key] == "test"
            else:
                assert config[key] == value

    def test_non_dict_yaml_uses_defaults(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump([1, 2, 3], f)
            f.flush()
            config = load_config(f.name)
        os.unlink(f.name)
        for key, value in DEFAULTS.items():
            if key == "SECRET_KEY":
                assert config[key] == "test"
            else:
                assert config[key] == value

    def test_yaml_all_settings(self):
        """All config keys should be loadable from YAML."""
        all_settings = {
            "SECRET_KEY": "yaml-secret",
            "DATABASE_PATH": "/tmp/yaml-test.db",
            "HOST": "192.168.1.1",
            "PORT": 3000,
            "DEBUG": True,
            "SESSION_LIFETIME_HOURS": 48,
            "EVENTS_PER_PAGE": 100,
            "SSE_HISTORY_SIZE": 1000,
            "NODE_HEALTHY_SECONDS": 600,
            "NODE_DEGRADED_SECONDS": 1800,
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(all_settings, f)
            f.flush()
            config = load_config(f.name)
        os.unlink(f.name)
        for key, value in all_settings.items():
            assert config[key] == value


class TestLoadConfigFromEnv:
    """Test that environment variables override file and defaults."""

    def test_env_overrides_default(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}PORT", "1234")
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
        config = load_config()
        assert config["PORT"] == 1234

    def test_env_overrides_json_file(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}PORT", "5555")
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"PORT": 9999, "SECRET_KEY": "file-secret"}, f)
            f.flush()
            config = load_config(f.name)
        os.unlink(f.name)
        assert config["PORT"] == 5555

    def test_env_overrides_yaml_file(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}PORT", "4444")
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump({"PORT": 8888, "SECRET_KEY": "file-secret"}, f)
            f.flush()
            config = load_config(f.name)
        os.unlink(f.name)
        assert config["PORT"] == 4444

    def test_env_bool_true_values(self, monkeypatch):
        for val in ("true", "1", "yes", "True", "YES"):
            monkeypatch.setenv(f"{ENV_PREFIX}DEBUG", val)
            monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
            config = load_config()
            assert config["DEBUG"] is True, f"Failed for DEBUG={val}"

    def test_env_bool_false_values(self, monkeypatch):
        for val in ("false", "0", "no", "anything"):
            monkeypatch.setenv(f"{ENV_PREFIX}DEBUG", val)
            monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
            config = load_config()
            assert config["DEBUG"] is False, f"Failed for DEBUG={val}"

    def test_env_string_value(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "my-secret")
        config = load_config()
        assert config["SECRET_KEY"] == "my-secret"

    def test_env_invalid_int_keeps_default(self, monkeypatch):
        monkeypatch.setenv(f"{ENV_PREFIX}PORT", "not-a-number")
        monkeypatch.setenv(f"{ENV_PREFIX}SECRET_KEY", "test")
        config = load_config()
        # Invalid int should keep the default
        assert config["PORT"] == DEFAULTS["PORT"]


class TestConfigAutoDiscovery:
    """Test the auto-discovery of config files."""

    def test_vespid_config_env_var(self, monkeypatch, tmp_path):
        """VESPID_CONFIG env var should be used when set."""
        config_file = tmp_path / "custom.yaml"
        config_file.write_text("PORT: 1111\nSECRET_KEY: test-key\n")
        monkeypatch.setenv("VESPID_CONFIG", str(config_file))
        config = load_config()
        assert config["PORT"] == 1111

    def test_explicit_path_takes_precedence(self, monkeypatch, tmp_path):
        """Explicit --config path should override env var discovery."""
        env_file = tmp_path / "env.yaml"
        env_file.write_text("PORT: 2222\nSECRET_KEY: test-key\n")
        monkeypatch.setenv("VESPID_CONFIG", str(env_file))

        explicit_file = tmp_path / "explicit.yaml"
        explicit_file.write_text("PORT: 3333\nSECRET_KEY: test-key\n")

        config = load_config(str(explicit_file))
        assert config["PORT"] == 3333
