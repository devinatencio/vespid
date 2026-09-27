"""Centralized configuration for Vespid.

Values can be overridden via environment variables or a config file at
``/etc/vespid/vespid.conf`` (JSON) **or**
``/etc/vespid/vespid.yaml`` (YAML).  YAML is recommended for
human-edited configs because regex strings don't need double-escaping.

If the ``VESPID_CONFIG`` environment variable is set it takes
precedence.  Otherwise the loader checks for ``.yaml`` first, then
falls back to ``.conf`` (JSON).
"""

from __future__ import annotations

import json
import logging
import os
import platform
import socket
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

log = logging.getLogger("vespid.config")

# ---------------------------------------------------------------------------
# OS / distro family detection
# ---------------------------------------------------------------------------

# Distro family constants
FAMILY_DEBIAN = "debian"
FAMILY_REDHAT = "redhat"
FAMILY_SUSE = "suse"
FAMILY_UNKNOWN = "unknown"

# IDs (from /etc/os-release) that map to each family
_DEBIAN_IDS = {
    "debian",
    "ubuntu",
    "linuxmint",
    "pop",
    "raspbian",
    "kali",
    "elementary",
    "zorin",
    "mx",
}
_REDHAT_IDS = {"rhel", "centos", "fedora", "rocky", "almalinux", "ol", "amzn", "amazon"}
_SUSE_IDS = {"suse", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles"}


def detect_distro_family() -> str:
    """Detect the Linux distribution family from /etc/os-release.

    Returns one of: "debian", "redhat", "suse", "unknown".
    Uses the ID and ID_LIKE fields to classify the running system.
    """
    if platform.system() != "Linux":
        return FAMILY_UNKNOWN

    os_release: dict[str, str] = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os_release[key] = value.strip('"')
    except OSError:
        return FAMILY_UNKNOWN

    distro_id = os_release.get("ID", "").lower()
    id_like = os_release.get("ID_LIKE", "").lower().split()

    # Check direct ID match first
    if distro_id in _DEBIAN_IDS:
        return FAMILY_DEBIAN
    if distro_id in _REDHAT_IDS:
        return FAMILY_REDHAT
    if distro_id in _SUSE_IDS:
        return FAMILY_SUSE

    # Fall back to ID_LIKE (e.g. Ubuntu derivatives say ID_LIKE="debian")
    for like in id_like:
        if like in _DEBIAN_IDS:
            return FAMILY_DEBIAN
        if like in ("rhel", "fedora", "centos"):
            return FAMILY_REDHAT
        if like in ("suse", "opensuse"):
            return FAMILY_SUSE

    return FAMILY_UNKNOWN


def _default_log_sources() -> list[LogSource]:
    """Return the appropriate default log sources for the detected OS.

    Distro family → standard log paths:

        Debian/Ubuntu:
            SSH auth   → /var/log/auth.log
            Syslog     → /var/log/syslog
            Apache     → /var/log/apache2/access.log, error.log

        RedHat/CentOS/Fedora:
            SSH auth   → /var/log/secure
            Syslog     → /var/log/messages
            Apache     → /var/log/httpd/access_log, error_log

        SUSE/openSUSE:
            SSH auth   → /var/log/messages  (auth mixed into messages by default)
            Syslog     → /var/log/messages
            Apache     → /var/log/apache2/access_log, error_log

        All distros:
            HAProxy    → /var/log/haproxy/access.log (standard rsyslog template)

        Unknown:
            Includes both RedHat and Debian paths (original behaviour).
    """
    family = detect_distro_family()
    log.info("Detected distro family: %s", family)

    # HAProxy path is the same across all distros — the standard rsyslog
    # template (49-haproxy.conf) writes access logs to this location.
    _haproxy_path = "/var/log/haproxy/access.log"

    if family == FAMILY_DEBIAN:
        return [
            LogSource(path="/var/log/auth.log", parser="secure"),
            LogSource(path="/var/log/syslog", parser="messages"),
            LogSource(path="/var/log/apache2/access.log", parser="apache"),
            LogSource(path="/var/log/apache2/error.log", parser="apache"),
            LogSource(path=_haproxy_path, parser="haproxy"),
        ]

    if family == FAMILY_REDHAT:
        return [
            LogSource(path="/var/log/secure", parser="secure"),
            LogSource(path="/var/log/messages", parser="messages"),
            LogSource(path="/var/log/httpd/access_log", parser="apache"),
            LogSource(path="/var/log/httpd/error_log", parser="apache"),
            LogSource(path=_haproxy_path, parser="haproxy"),
        ]

    if family == FAMILY_SUSE:
        return [
            LogSource(path="/var/log/messages", parser="secure"),
            LogSource(path="/var/log/messages", parser="messages"),
            LogSource(path="/var/log/apache2/access_log", parser="apache"),
            LogSource(path="/var/log/apache2/error_log", parser="apache"),
            LogSource(path=_haproxy_path, parser="haproxy"),
        ]

    # Unknown: include both families as a safe fallback
    return [
        LogSource(path="/var/log/secure", parser="secure"),
        LogSource(path="/var/log/auth.log", parser="secure"),
        LogSource(path="/var/log/messages", parser="messages"),
        LogSource(path="/var/log/syslog", parser="messages"),
        LogSource(path="/var/log/httpd/access_log", parser="apache"),
        LogSource(path="/var/log/httpd/error_log", parser="apache"),
        LogSource(path="/var/log/apache2/access.log", parser="apache"),
        LogSource(path="/var/log/apache2/error.log", parser="apache"),
        LogSource(path=_haproxy_path, parser="haproxy"),
    ]


# ---------------------------------------------------------------------------

_CONFIG_DIR = Path(os.environ.get("VESPID_CONFIG_DIR", "/etc/vespid"))


def _resolve_config_path() -> Path:
    """Return the config file path, respecting env override and YAML preference."""
    env = os.environ.get("VESPID_CONFIG")
    if env:
        return Path(env)
    # Prefer YAML when both exist; fall back to JSON .conf
    yaml_path = _CONFIG_DIR / "vespid.yaml"
    yml_path = _CONFIG_DIR / "vespid.yml"
    conf_path = _CONFIG_DIR / "vespid.conf"
    for candidate in (yaml_path, yml_path, conf_path):
        if candidate.exists():
            return candidate
    # Default (may not exist yet — that's fine, load() handles it)
    return yaml_path


CONFIG_PATH = _resolve_config_path()
NODE_ID_PATH = Path(os.environ.get("VESPID_ID_FILE", "/var/lib/vespid/node_id"))
STATE_DIR = Path(os.environ.get("VESPID_STATE_DIR", "/var/lib/vespid"))
SOCKET_PATH = Path(os.environ.get("VESPID_SOCKET", "/run/vespid.sock"))


def _load_or_create_node_id() -> str:
    try:
        if NODE_ID_PATH.exists():
            value = NODE_ID_PATH.read_text().strip()
            if value:
                return value
        NODE_ID_PATH.parent.mkdir(parents=True, exist_ok=True)
        new_id = str(uuid.uuid4())
        NODE_ID_PATH.write_text(new_id)
        return new_id
    except (PermissionError, OSError):
        # Fall back to an in-memory id when not running as root (dev mode).
        return str(uuid.uuid4())


def set_node_id(new_id: str) -> None:
    """Persist a new node_id to the node_id file.

    The server may return a reformatted node_id during enrollment.
    The daemon calls this to keep its local node_id in sync so the
    change survives restart.
    """
    try:
        NODE_ID_PATH.parent.mkdir(parents=True, exist_ok=True)
        NODE_ID_PATH.write_text(new_id)
    except (PermissionError, OSError) as exc:
        log.warning("Could not write node_id to %s: %s", NODE_ID_PATH, exc)


def _default_display_name() -> str:
    """Return the hostname as the default human-readable node name."""
    return socket.gethostname()


@dataclass
class LogSource:
    path: str
    parser: str  # "secure" | "messages" | "apache" | "haproxy"
    haproxy_log_format: str = ""  # HAProxy log-format template (empty = auto-detect)
    haproxy_mode: str = "auto"  # "auto" | "http" | "tcp"; avoids unnecessary regex fallback


@dataclass
class BruteForceRule:
    name: str
    event_type: str
    max_attempts: int
    window_seconds: int
    parser: str = "secure"


@dataclass
class CorrelationRule:
    """Multi-signal correlation rule.

    Fires when a single IP triggers observations across enough *distinct*
    signal categories within a time window.  This catches "low and slow"
    reconnaissance where an attacker probes multiple services/vectors but
    stays below any individual rule's threshold.

    ``min_categories`` is the number of distinct signal types required.
    For example, min_categories=3 means the IP must trigger 3 different
    kinds of suspicious activity (e.g. scanner UA + TLS probe + bad request).
    """

    name: str
    event_type: str
    min_categories: int = 3
    window_seconds: int = 600  # 10 minutes
    enabled: bool = True


@dataclass
class CustomRule:
    """User-defined regex-based detection rule.

    Users add these to the config file to detect new log patterns without
    touching source code.  The ``regex`` must contain a named group
    ``(?P<ip>...)`` that captures the offending source IP.

    ``log_sources`` lists which parser names (e.g. "secure", "messages",
    "apache") the regex should be evaluated against.  Use ``["*"]`` to
    match against every log pattern.

    ``tags`` holds MITRE ATT&CK technique IDs and other metadata (imported
    from Sigma rules or set by the admin).  ``sigma_id`` and ``sigma_status``
    track the source Sigma rule UUID and status (test/stable/deprecated)
    for sync-tracking of imported rules.
    """

    name: str
    event_type: str
    regex: str
    log_sources: list[str]  # ["secure"], ["*"], etc.
    max_attempts: int = 3
    window_seconds: int = 3600
    enabled: bool = True
    pack_name: str = ""  # which detection pack this rule belongs to (empty = user-created)
    tags: list[str] = field(default_factory=list)  # ATT&CK technique IDs, categories
    sigma_id: str = ""  # Sigma rule UUID (empty for non-Sigma rules)
    sigma_status: str = ""  # Sigma status: test, stable, experimental, deprecated


@dataclass
class SubscriptionFeed:
    name: str
    url: str
    format: str = "plain"  # "plain" | "cidr"
    refresh_seconds: int = 3600
    enabled: bool = True


@dataclass
class AuditdConfig:
    """Configuration for the auditd monitoring subsystem."""

    enabled: bool = False
    log_path: str = "/var/log/audit/audit.log"
    process_tree_ttl_seconds: int = 3600  # min=60, max=604800
    scorer_half_life_seconds: int = 1800  # min=60, max=86400
    scorer_threshold: int = 100  # min=1, max=10000
    alert_cooldown_seconds: int = 900  # min=0, max=86400
    exclude_pids: list[int] = field(default_factory=list)
    exclude_uids: list[int] = field(default_factory=list)
    exclude_exe_prefixes: list[str] = field(
        default_factory=lambda: [
            "/usr/lib/dpkg",
            "/usr/bin/apt",
            "/usr/bin/rpm",
            "/usr/bin/dnf",
            "/usr/lib/systemd",
            "/opt/vespid",
            "/usr/bin/vespid",
            "/usr/bin/vespid-agent",
            "/usr/sbin/nft",
        ]
    )
    mode: str = "learning"  # "learning" | "detecting" | "alerting"
    learning_duration_hours: int = 24  # min=1, max=720

    def __post_init__(self) -> None:
        """Validate field bounds, log warning and reset to default if invalid."""
        _bounds: dict[str, tuple[int, int, int]] = {
            "process_tree_ttl_seconds": (60, 604800, 3600),
            "scorer_half_life_seconds": (60, 86400, 1800),
            "scorer_threshold": (1, 10000, 100),
            "alert_cooldown_seconds": (0, 86400, 900),
            "learning_duration_hours": (1, 720, 24),
        }
        for field_name, (min_val, max_val, default_val) in _bounds.items():
            val = getattr(self, field_name)
            if not isinstance(val, int) or val < min_val or val > max_val:
                log.warning(
                    "AuditdConfig.%s=%r is outside valid range [%d, %d]; using default %d",
                    field_name,
                    val,
                    min_val,
                    max_val,
                    default_val,
                )
                object.__setattr__(self, field_name, default_val)

        # Validate mode
        if self.mode not in ("learning", "detecting", "alerting"):
            log.warning(
                "AuditdConfig.mode=%r is not valid; using default 'learning'",
                self.mode,
            )
            object.__setattr__(self, "mode", "learning")


@dataclass
class ShieldConfig:
    # --- Future central management server (placeholders) ----------------
    SERVER_URL: str = "https://server.example.com/api/v1/events"
    API_KEY: str = ""
    upload_enabled: bool = False  # flip to True once a real server exists

    # --- SSL/TLS verification ------------------------------------------
    # Controls certificate verification for all outbound HTTPS connections.
    #   - True (default): verify using system CA trust store
    #   - False:          skip verification (insecure — only for testing)
    #   - "/path/to/ca.pem": verify using a custom CA bundle file
    ssl_verify: bool | str = True
    # Path to a client certificate file for mutual TLS (optional).
    ssl_cert: str = ""
    # Path to the client certificate's private key file (optional).
    ssl_key: str = ""

    # --- Node identity --------------------------------------------------
    node_id: str = field(default_factory=_load_or_create_node_id)
    display_name: str = field(default_factory=_default_display_name)

    # --- Telemetry bus --------------------------------------------------
    queue_max_size: int = 10000
    flush_interval_seconds: int = 5
    flush_batch_size: int = 100
    spool_path: str = str(STATE_DIR / "spool.jsonl")
    spool_max_size_bytes: int = 100 * 1024 * 1024  # 100 MiB
    spool_max_events: int = 100_000
    heartbeat_interval_seconds: int = 300  # 5 minutes

    # --- Log processor --------------------------------------------------
    # Auto-detected based on OS family (Debian, RedHat, SUSE).
    # Override in /etc/vespid/vespid.yaml to use custom paths.
    log_sources: list[LogSource] = field(default_factory=_default_log_sources)

    # --- Auditd monitoring ----------------------------------------------
    auditd: AuditdConfig = field(default_factory=AuditdConfig)

    # --- Detection rules ------------------------------------------------
    brute_force_rules: list[BruteForceRule] = field(
        default_factory=lambda: [
            # Classic fast brute-force: 5 attempts in 1 minute.
            BruteForceRule(
                name="ssh_fast_brute",
                event_type="SSH_BRUTE",
                max_attempts=5,
                window_seconds=60,
                parser="secure",
            ),
            # Medium-speed brute-force: catches the ~2-min-interval pattern.
            BruteForceRule(
                name="ssh_medium_brute",
                event_type="SSH_MEDIUM_BRUTE",
                max_attempts=4,
                window_seconds=10 * 60,
                parser="secure",
            ),
            # Slow brute-force: low-and-slow over hours (lowered from 10).
            BruteForceRule(
                name="ssh_slow_brute",
                event_type="SSH_SLOW_BRUTE",
                max_attempts=5,
                window_seconds=6 * 3600,
                parser="secure",
            ),
            BruteForceRule(
                name="http_auth_brute",
                event_type="HTTP_AUTH_BRUTE",
                max_attempts=20,
                window_seconds=10 * 60,
                parser="apache",
            ),
            # SSH negotiation failures: client offers only deprecated algorithms
            # (ssh-rsa, ssh-dss, weak DH groups).  Modern legitimate clients
            # never do this — it's a strong indicator of scanning tools or
            # exploit kits probing for weak SSH configs.  Block after 3 in 24h.
            BruteForceRule(
                name="ssh_negotiate_fail",
                event_type="SSH_NEGOTIATE_FAIL",
                max_attempts=3,
                window_seconds=24 * 3600,
                parser="secure_negotiate_fail",
            ),
            # SSH recon (strong signal): pre-auth disconnects and auth timeouts.
            # These almost never happen on legitimate sessions — 3 in 24h is
            # a reliable indicator of scanning / banner grabbing.
            BruteForceRule(
                name="ssh_recon_strong",
                event_type="SSH_BANNER_GRAB",
                max_attempts=3,
                window_seconds=24 * 3600,
                parser="secure_recon_strong",
            ),
            # SSH recon (weak signal): generic connection resets / closes.
            # Legitimate users trigger these routinely (flaky Wi-Fi, laptop
            # lid close, NAT timeout), so the threshold is much higher to
            # avoid false positives.
            BruteForceRule(
                name="ssh_recon_weak",
                event_type="SSH_RECON_WEAK",
                max_attempts=8,
                window_seconds=24 * 3600,
                parser="secure_recon_weak",
            ),
            # HAProxy auth brute-force: 401/403 responses (login pages, basic auth).
            # Overridden by server pack when connected.
            BruteForceRule(
                name="haproxy_auth_brute",
                event_type="HAPROXY_AUTH_BRUTE",
                max_attempts=10,
                window_seconds=300,
                parser="haproxy",
            ),
            # HAProxy bad requests: 400 status (malformed requests, automated scanning).
            BruteForceRule(
                name="haproxy_bad_request",
                event_type="HAPROXY_BAD_REQUEST",
                max_attempts=10,
                window_seconds=60,
                parser="haproxy_bad_request",
            ),
            # HAProxy path probing: 404 status (directory brute-force, recon).
            BruteForceRule(
                name="haproxy_path_probe",
                event_type="HAPROXY_PATH_PROBE",
                max_attempts=5,
                window_seconds=120,
                parser="haproxy_not_found",
            ),
            # HAProxy TLS/cipher scanning: repeated SSL handshake failures.
            # These are connection-level errors (not HTTP access lines) and
            # almost never occur on legitimate traffic.
            BruteForceRule(
                name="haproxy_ssl_handshake_probe",
                event_type="HAPROXY_SSL_HANDSHAKE_PROBE",
                max_attempts=5,
                window_seconds=300,
                parser="haproxy_ssl_fail",
            ),
        ]
    )

    # --- NFTables -------------------------------------------------------
    nft_table: str = "shield"
    nft_family: str = "inet"
    nft_set_local: str = "shield_local"
    nft_set_subscribed: str = "shield_subscribed"
    nft_local_block_ttl: int = 24 * 3600  # 24 hours
    allowlist: list[str] = field(
        default_factory=lambda: [
            "127.0.0.1/32",
            "::1/128",
        ]
    )

    # --- Blocklist (server-managed persistent blocks) ------------------
    blocklist: list[str] = field(default_factory=list)

    # --- Repeat-offender escalation ------------------------------------
    # Each entry is a TTL in seconds.  Index 0 = first offense,
    # index 1 = second offense, etc.  The last tier is used for all
    # subsequent offenses.
    recidive_tiers: list[int] = field(
        default_factory=lambda: [
            24 * 3600,  # 1st offense: 24 hours
            72 * 3600,  # 2nd offense: 3 days
            7 * 24 * 3600,  # 3rd offense: 7 days
            30 * 24 * 3600,  # 4th+ offense: 30 days
        ]
    )
    # After this many seconds without a new offense, the strike count
    # resets to zero.  Default: 30 days.
    recidive_decay_seconds: int = 30 * 24 * 3600
    # How often (seconds) the daemon reaps expired entries from the
    # in-memory local block list.  Default: 60 seconds.
    expiry_reap_interval: int = 60

    # --- Subscription feeds --------------------------------------------
    subscriptions: list[SubscriptionFeed] = field(
        default_factory=lambda: [
            SubscriptionFeed(
                name="firehol_level1",
                url="https://iplists.firehol.org/files/firehol_level1.netset",
                format="cidr",
                refresh_seconds=6 * 3600,
            ),
        ]
    )

    # --- Custom detection rules (user-defined regex) -------------------
    custom_rules: list[CustomRule] = field(default_factory=list)

    # --- Multi-signal correlation rules --------------------------------
    correlation_rules: list[CorrelationRule] = field(
        default_factory=lambda: [
            # Default: block if an IP triggers 3+ distinct signal categories
            # within 10 minutes.  Catches multi-vector recon (scanner UA +
            # bad request + TLS probe, etc.) that stays below individual rule
            # thresholds.  Previously set to 2, but that caused false positives
            # when a single log line matched both a built-in parser and a custom
            # rule (counting as 2 categories from 1 event).
            CorrelationRule(
                name="recon_correlation",
                event_type="RECON_CORRELATION",
                min_categories=3,
                window_seconds=600,
            ),
        ]
    )

    # --- Catchup -------------------------------------------------------
    catchup_on_start: bool = True  # replay from saved offset on restart
    offsets_path: str = str(STATE_DIR / "tailer_offsets.json")

    # --- Enrollment ----------------------------------------------------
    enrollment_server_url: str = ""  # Base URL for enrollment (derived from SERVER_URL if empty)
    enrollment_poll_initial_seconds: int = 30
    enrollment_poll_max_seconds: int = 300  # 5 minutes

    # --- Fleet blocklist sharing ----------------------------------------
    fleet_blocklist_report_enabled: bool = True
    fleet_blocklist_subscribe_enabled: bool = True
    fleet_block_ttl_seconds: int = 86400
    fleet_local_allow_list: list[str] = field(default_factory=list)
    fleet_queue_dir: str = "/var/lib/vespid/fleet_queue"
    fleet_queue_max_size: int = 1000

    # --- Server-side rule management -----------------------------------
    rule_subscribe_enabled: bool = True
    rule_poll_interval_seconds: int = 300
    rule_merge_strategy: str = "layer"  # "layer" | "replace"

    # --- Centralized Management -----------------------------------------
    management_mode: str = "standalone"  # "standalone" | "server-managed"
    config_conflict_strategy: str = "server-wins"  # "server-wins" | "local-wins" | "merge"

    # --- HTTP request path exclusion -----------------------------------
    # Request paths that should never count toward detection thresholds.
    # A log line is skipped entirely if any of these substrings appear in it.
    # Useful for excluding noise like favicon 404s that aren't actual recon.
    excluded_http_paths: list[str] = field(default_factory=lambda: ["/favicon.ico"])

    # --- Misc ----------------------------------------------------------
    log_level: str = "INFO"

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path: Path | None = None) -> ShieldConfig:
        """Load config from disk if available, otherwise return defaults.

        Supports both JSON (``.conf``) and YAML (``.yaml`` / ``.yml``)
        formats.  YAML requires the ``PyYAML`` package; if it is not
        installed and a YAML file is encountered, a warning is logged and
        defaults are returned.
        """
        cfg = cls()
        path = path or CONFIG_PATH
        if not path.exists():
            return cfg

        raw = path.read_text(encoding="utf-8")
        suffix = path.suffix.lower()

        if suffix in (".yaml", ".yml"):
            try:
                import yaml
            except ImportError:
                log.error(
                    "PyYAML is required to load %s — install it with: pip install pyyaml",
                    path,
                )
                return cfg
            try:
                data = yaml.safe_load(raw)
            except yaml.YAMLError as exc:
                log.error("Failed to parse YAML config %s: %s", path, exc)
                return cfg
        else:
            # Default: treat as JSON (.conf or any other extension)
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, OSError) as exc:
                log.error("Failed to parse JSON config %s: %s", path, exc)
                return cfg

        if not isinstance(data, dict):
            log.error("Config file %s did not produce a mapping", path)
            return cfg

        for key, value in data.items():
            if not hasattr(cfg, key):
                # Handle nested 'fleet_blocklist' section → flat attributes
                if key == "fleet_blocklist" and isinstance(value, dict):
                    _fleet_key_map = {
                        "report_enabled": "fleet_blocklist_report_enabled",
                        "subscribe_enabled": "fleet_blocklist_subscribe_enabled",
                        "fleet_block_ttl_seconds": "fleet_block_ttl_seconds",
                        "local_allow_list": "fleet_local_allow_list",
                        "queue_dir": "fleet_queue_dir",
                        "queue_max_size": "fleet_queue_max_size",
                    }
                    for sub_key, sub_value in value.items():
                        attr = _fleet_key_map.get(sub_key) or sub_key
                        if hasattr(cfg, attr):
                            setattr(cfg, attr, sub_value)
                continue
            if key == "log_sources":
                cfg.log_sources = [LogSource(**v) for v in value]
            elif key == "brute_force_rules":
                cfg.brute_force_rules = [BruteForceRule(**v) for v in value]
            elif key == "custom_rules":
                cfg.custom_rules = [CustomRule(**v) for v in value]
            elif key == "correlation_rules":
                cfg.correlation_rules = [CorrelationRule(**v) for v in value]
            elif key == "subscriptions":
                cfg.subscriptions = [SubscriptionFeed(**v) for v in value]
            elif key == "auditd":
                if isinstance(value, dict):
                    try:
                        cfg.auditd = AuditdConfig(**value)
                    except TypeError as exc:
                        log.warning(
                            "Failed to parse auditd config block: %s; using defaults",
                            exc,
                        )
            else:
                setattr(cfg, key, value)
        return cfg

    def to_dict(self) -> dict:
        return asdict(self)


CONFIG = ShieldConfig.load()
