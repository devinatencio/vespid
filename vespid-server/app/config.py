"""Vespid Server configuration.

Loads configuration from a YAML or JSON file and/or environment variables.
Environment variables use the VESPID_ prefix and override file values.

File resolution order (when --config is not specified):
    1. /etc/vespid-server/config.yaml
    2. /etc/vespid-server/config.yml
    3. /etc/vespid-server/config.json

YAML is the preferred format. JSON is supported for backward compatibility.
"""

import json
import logging
import os


class ConfigError(Exception):
    """Raised when configuration validation fails."""

    pass


logger = logging.getLogger(__name__)

# Default configuration values
DEFAULTS = {
    "SECRET_KEY": None,  # Must be set via config file or environment variable
    "DATABASE_PATH": "/var/lib/vespid-server/vespid.db",
    "HOST": "127.0.0.1",
    "PORT": 8000,
    "DEBUG": False,
    "SESSION_LIFETIME_HOURS": 24,
    "EVENTS_PER_PAGE": 50,
    "SSE_HISTORY_SIZE": 500,
    "NODE_HEALTHY_SECONDS": 300,
    "NODE_DEGRADED_SECONDS": 900,
    "RATELIMIT_EVENTS_INGEST": "60 per minute",
    "RATELIMIT_HEARTBEAT": "120 per minute",
    "RATELIMIT_COMMANDS": "60 per minute",
    "RATELIMIT_EXPORT": "10 per minute",
    "RATELIMIT_STORAGE_URI": "memory://",
    "RATELIMIT_ENABLED": True,
    # Rate limits for additional subsystems (can be overridden)
    "RATELIMIT_DEFAULT": "120 per minute",
    "RATELIMIT_CONFIG_ADMIN": "30 per minute",
    "RATELIMIT_CONFIG_READ": "60 per minute",
    "RATELIMIT_CONFIG_CHECKIN": "120 per minute",
    "RATELIMIT_RULES_DISTRIBUTION": "60 per minute",
    "RATELIMIT_INVENTORY_SYNC": "30 per minute",
    # Custom themes directory (optional) — drop .css files here to add themes
    "CUSTOM_THEME_DIR": None,
    # Fleet blocklist sharing defaults
    "FLEET_SSE_HISTORY_SIZE": 1000,
    "FLEET_REAPER_INTERVAL_SECONDS": 60,
    "RATELIMIT_FLEET_BLOCKS": "60 per minute",
    "RATELIMIT_FLEET_ADMIN": "30 per minute",
    # Database backend configuration
    "DATABASE_TYPE": "sqlite",
    "DATABASE_HOST": "localhost",
    "DATABASE_PORT": 3306,
    "DATABASE_NAME": "vespid",
    "DATABASE_USER": "vespid",
    "DATABASE_PASSWORD": "",
    # Intelligence Database settings
    "INTEL_INGEST_ACTIONS": "BLOCKED",
    # Connection Debug Monitor (disabled by default in production)
    "CONNECTION_DEBUG_ENABLED": False,
    "CONNECTION_DEBUG_INTERVAL": 30,
    "CONNECTION_DEBUG_LOG": "/var/log/vespid-server/connection_debug.log",
    "CONNECTION_DEBUG_ALLOW_REMOTE": False,
    # Application log file
    "LOG_FILE": "/var/log/vespid-server/vespid-server.log",
    "LOG_LEVEL": "INFO",
    "LOG_FORMAT": "text",  # "text" or "json" (for SIEM integration)
    "LOG_MAX_BYTES": 10485760,  # 10 MB
    "LOG_BACKUP_COUNT": 5,
    # Database backup settings
    "BACKUP_DIRECTORY": "/var/lib/vespid-server/backups",
    # Trust X-Forwarded-For from reverse proxies (0 = disabled)
    "PROXY_TRUST_COUNT": 1,
    # Metrics subsystem (disabled by default — opt-in)
    "METRICS_ENABLED": False,
    "VICTORIAMETRICS_URL": "http://localhost:8428",
    # Subsystem control
    "SECURITY_ENABLED": True,
    # Alert subsystem (auto-enabled when METRICS_ENABLED is True)
    "ALERTS_ENABLED": False,
}

# Maps config keys to their expected Python types for env var conversion
_TYPE_MAP = {
    "SECRET_KEY": str,
    "DATABASE_PATH": str,
    "HOST": str,
    "PORT": int,
    "DEBUG": bool,
    "SESSION_LIFETIME_HOURS": int,
    "EVENTS_PER_PAGE": int,
    "SSE_HISTORY_SIZE": int,
    "NODE_HEALTHY_SECONDS": int,
    "NODE_DEGRADED_SECONDS": int,
    "RATELIMIT_EVENTS_INGEST": str,
    "RATELIMIT_HEARTBEAT": str,
    "RATELIMIT_COMMANDS": str,
    "RATELIMIT_EXPORT": str,
    "RATELIMIT_STORAGE_URI": str,
    "RATELIMIT_ENABLED": bool,
    # Additional rate limit keys (overrideable)
    "RATELIMIT_DEFAULT": str,
    "RATELIMIT_CONFIG_ADMIN": str,
    "RATELIMIT_CONFIG_READ": str,
    "RATELIMIT_CONFIG_CHECKIN": str,
    "RATELIMIT_RULES_DISTRIBUTION": str,
    "RATELIMIT_INVENTORY_SYNC": str,
    # Fleet blocklist sharing
    "FLEET_SSE_HISTORY_SIZE": int,
    "FLEET_REAPER_INTERVAL_SECONDS": int,
    "RATELIMIT_FLEET_BLOCKS": str,
    "RATELIMIT_FLEET_ADMIN": str,
    # Database backend configuration
    "DATABASE_TYPE": str,
    "DATABASE_HOST": str,
    "DATABASE_PORT": int,
    "DATABASE_NAME": str,
    "DATABASE_USER": str,
    "DATABASE_PASSWORD": str,
    # Intelligence Database settings
    "INTEL_INGEST_ACTIONS": str,
    # Connection Debug Monitor
    "CUSTOM_THEME_DIR": str,
    "CONNECTION_DEBUG_ENABLED": bool,
    "CONNECTION_DEBUG_INTERVAL": int,
    "CONNECTION_DEBUG_LOG": str,
    "CONNECTION_DEBUG_ALLOW_REMOTE": bool,
    # Application log file
    "LOG_FILE": str,
    "LOG_LEVEL": str,
    "LOG_FORMAT": str,
    "LOG_MAX_BYTES": int,
    "LOG_BACKUP_COUNT": int,
    # Database backup settings
    "BACKUP_DIRECTORY": str,
    # Trust X-Forwarded-For from reverse proxies
    "PROXY_TRUST_COUNT": int,
    # Metrics subsystem
    "METRICS_ENABLED": bool,
    "VICTORIAMETRICS_URL": str,
    "SECURITY_ENABLED": bool,
    "ALERTS_ENABLED": bool,
}

ENV_PREFIX = "VESPID_"

# Standard config directory for auto-discovery
_CONFIG_DIR = "/etc/vespid-server"


def _cast_env_value(key: str, value: str):
    """Cast a string environment variable value to the expected type."""
    expected_type = _TYPE_MAP.get(key, str)
    if expected_type is bool:
        return value.lower() in ("true", "1", "yes")
    if expected_type is int:
        return int(value)
    return value


def _load_yaml(path: str) -> dict | None:
    """Load a YAML file and return its contents as a dict.

    Returns None if PyYAML is not installed or the file cannot be parsed.
    """
    try:
        import yaml
    except ImportError:
        logger.error(
            "PyYAML is required to load %s — install it with: pip install pyyaml",
            path,
        )
        return None

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        logger.error("Failed to parse YAML config %s: %s", path, exc)
        return None
    except OSError as exc:
        logger.error("Failed to read config file %s: %s", path, exc)
        return None

    if not isinstance(data, dict):
        logger.error("Configuration file %s did not produce a mapping", path)
        return None

    return data


def _load_json(path: str) -> dict | None:
    """Load a JSON file and return its contents as a dict."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse JSON config %s: %s", path, exc)
        return None
    except OSError as exc:
        logger.error("Failed to read config file %s: %s", path, exc)
        return None

    if not isinstance(data, dict):
        logger.error("Configuration file %s does not contain a JSON object", path)
        return None

    return data


def _load_file(path: str) -> dict | None:
    """Load a config file, auto-detecting format from the file extension.

    Supports .yaml, .yml (YAML) and .json, .conf (JSON).
    """
    suffix = os.path.splitext(path)[1].lower()
    if suffix in (".yaml", ".yml"):
        return _load_yaml(path)
    else:
        return _load_json(path)


def _discover_config_path() -> str | None:
    """Search standard locations for a config file.

    Checks (in order):
        1. $VESPID_CONFIG environment variable
        2. /etc/vespid-server/config.yaml
        3. /etc/vespid-server/config.yml
        4. /etc/vespid-server/config.json

    Returns the first path that exists, or None.
    """
    env_path = os.environ.get("VESPID_CONFIG")
    if env_path and os.path.isfile(env_path):
        return env_path

    candidates = [
        os.path.join(_CONFIG_DIR, "config.yaml"),
        os.path.join(_CONFIG_DIR, "config.yml"),
        os.path.join(_CONFIG_DIR, "config.json"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path

    return None


def load_config(config_path: str | None = None) -> dict:
    """Load configuration from a YAML/JSON file and environment variables.

    Priority (highest to lowest):
        1. Environment variables with VESPID_ prefix
        2. Values from the config file (YAML or JSON)
        3. Built-in defaults

    If config_path is None, the loader searches standard locations
    (see _discover_config_path). If no file is found anywhere, only
    defaults and environment variables are used.

    Args:
        config_path: Path to a YAML or JSON configuration file. The format
            is auto-detected from the file extension (.yaml/.yml for YAML,
            .json/.conf for JSON). If None, standard locations are searched.

    Returns:
        A dict containing all configuration values.
    """
    config = dict(DEFAULTS)

    # Resolve the config file path
    resolved_path = config_path
    if resolved_path:
        resolved_path = os.path.expanduser(resolved_path)
    else:
        resolved_path = _discover_config_path()

    # Layer 2: Load from file if it exists
    if resolved_path and os.path.isfile(resolved_path):
        file_config = _load_file(resolved_path)
        if file_config is not None:
            config.update(file_config)
            logger.info("Loaded configuration from %s", resolved_path)
    elif config_path:
        # Explicit path was given but doesn't exist
        logger.warning("Configuration file %s not found, using defaults", config_path)

    # Layer 1: Environment variables override everything
    for key in DEFAULTS:
        env_key = f"{ENV_PREFIX}{key}"
        env_value = os.environ.get(env_key)
        if env_value is not None:
            try:
                config[key] = _cast_env_value(key, env_value)
                logger.debug("Config %s overridden by env var %s", key, env_key)
            except (ValueError, TypeError) as exc:
                logger.error("Invalid value for environment variable %s: %s", env_key, exc)

    # Validate DATABASE_TYPE
    valid_db_types = ("sqlite", "mysql", "mariadb")
    db_type = config.get("DATABASE_TYPE", "sqlite")
    if isinstance(db_type, str) and db_type.lower() not in valid_db_types:
        raise ConfigError(
            f"Unsupported DATABASE_TYPE '{db_type}'. Valid options are: {', '.join(valid_db_types)}"
        )

    # Validate DATABASE_PORT
    db_port = config.get("DATABASE_PORT", 3306)
    if isinstance(db_port, int) and not (1 <= db_port <= 65535):
        raise ConfigError(f"DATABASE_PORT {db_port} is out of valid range (1-65535)")

    # Validate SECRET_KEY - must be set and not the default placeholder
    secret_key = config.get("SECRET_KEY")
    if not secret_key or secret_key == "change-me-to-a-random-string":
        raise ConfigError(
            "SECRET_KEY must be set to a secure random string. "
            "Set VESPID_SECRET_KEY environment variable or configure in config file."
        )

    return config
