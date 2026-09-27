"""Default noise suppression rules for Host Threat Detection.

These are Sigma rules known to produce common false positives during
normal system operation. They ship with the product and can be enabled
or modified via the config profile editor or Noise Analysis panel.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class NoiseRule:
    """A known-noise detection rule with metadata."""

    rule_name: str
    description: str
    reason: str
    suppression_strategy: str = "suppress"
    # "suppress" — completely remove events matching this rule
    # "group" — collapse repeated firings into one event
    # "threshold" — only show if firing exceeds a count


# Curated list of rules known to produce false positives during normal
# system operation. Each entry includes a human-readable description
# and the rationale for why it is considered noise.
DEFAULT_NOISE_RULES: list[NoiseRule] = [
    NoiseRule(
        rule_name="sigma_execution_of_script_located_in_potentially_suspicious_direct",
        description="Execution of script located in potentially suspicious directory",
        reason="Normal cron/anacron jobs in /etc/cron.hourly trigger this rule",
    ),
    NoiseRule(
        rule_name="sigma_python_one-liners_with_base64_decoding_-_linux",
        description="Python one-liners with base64 decoding",
        reason="The vespid daemon Python process is flagged as a Python one-liner",
    ),
    NoiseRule(
        rule_name="sigma_linux_shell_pipe_to_shell",
        description="Linux shell pipe to shell",
        reason="Common administrative commands like 'python3 -m json.tool' pipe through shell",
    ),
    NoiseRule(
        rule_name="sigma_os_architecture_discovery_via_grep",
        description="OS architecture discovery via grep",
        reason="Normal shell initialization scripts grep configuration files like /etc/GREP_COLORS",
    ),
    NoiseRule(
        rule_name="sigma_system_network_discovery_-_linux",
        description="System network discovery",
        reason="Routine network interface queries like 'ip -o addr show dev ens3'",
    ),
    NoiseRule(
        rule_name="sigma_print_history_file_contents",
        description="Print history file contents",
        reason="Cron jobs reading spool files like /var/spool/anacron/cron.daily",
    ),
    NoiseRule(
        rule_name="sigma_potential_container_discovery_via_inodes_listing",
        description="Potential container discovery via inodes listing",
        reason="Normal directory listing of application files triggers inode enumeration",
    ),
    NoiseRule(
        rule_name="sigma_file_deletion",
        description="File deletion detected",
        reason="Routine cleanup of runtime files (e.g., /run/chrony-dhcp/ens3.sources)",
    ),
    NoiseRule(
        rule_name="sigma_history_file_deletion",
        description="History file deletion",
        reason="Same as file_deletion — routine cleanup of temporary runtime files",
    ),
    NoiseRule(
        rule_name="sigma_bash_interactive_shell",
        description="Bash interactive shell detected",
        reason="Interactive rm commands during maintenance flag as interactive shell usage",
    ),
    NoiseRule(
        rule_name="sigma_local_system_accounts_discovery_-_linux",
        description="Local system accounts discovery",
        reason="Normal 'id -un' calls by system services and cron jobs",
    ),
    NoiseRule(
        rule_name="sigma_copy_passwd_or_shadow_from_tmp_path",
        description="Copy passwd or shadow from temp path",
        reason="Application deployment copies files that match the copy-from-tmp pattern",
    ),
    NoiseRule(
        rule_name="sigma_system_information_discovery",
        description="System information discovery",
        reason="Routine 'uname' calls by system services and monitoring agents",
    ),
    NoiseRule(
        rule_name="sigma_potential_suspicious_change_to_sensitivecritical_files",
        description="Suspicious change to sensitive/critical files",
        reason="Commands like 'head -20' reading system files during normal operation",
    ),
    NoiseRule(
        rule_name="sigma_suspicious_invocation_of_shell_via_awk_-_linux",
        description="Suspicious invocation of shell via awk",
        reason="Standard 'id' commands triggered as awk shell invocations",
    ),
    NoiseRule(
        rule_name="sigma_curl_usage_on_linux",
        description="curl usage on Linux",
        reason="Internal health-check curls to localhost monitoring endpoints",
    ),
    NoiseRule(
        rule_name="sigma_file_and_directory_discovery_-_linux",
        description="File and directory discovery",
        reason="Normal MIME type detection via 'file -N --mime-type -f -'",
    ),
    NoiseRule(
        rule_name="sigma_suspicious_curl_file_upload_-_linux",
        description="Suspicious curl file upload",
        reason="Internal health-check curls to localhost monitoring endpoints",
    ),
    NoiseRule(
        rule_name="sigma_system_network_connections_discovery_-_linux",
        description="System network connections discovery",
        reason="Single 'w' command during maintenance flagged as network connections discovery",
    ),
    NoiseRule(
        rule_name="sigma_shell_invocation_via_env_command_-_linux",
        description="Shell invocation via env command",
        reason="Cron jobs, MOTD updates, and apt daily timers use 'env -i PATH=... run-parts' wrappers",
    ),
    NoiseRule(
        rule_name="sigma_disable_or_stop_services",
        description="Disable or stop services",
        reason="Package manager routinely stops/disables timers like apt-listchanges during upgrades",
    ),
    NoiseRule(
        rule_name="sigma_setuid_and_setgid",
        description="Setuid and setgid via chown",
        reason="System services like exim4 daily cron set ownership on config files (chown root:Debian-exim)",
    ),
    NoiseRule(
        rule_name="sigma_potential_perl_reverse_shell_execution",
        description="Potential Perl reverse shell execution",
        reason="Kernel package hooks invoke '/usr/bin/perl /usr/bin/linux-run-hooks' during dpkg operations",
    ),
    NoiseRule(
        rule_name="sigma_crontab_enumeration",
        description="Crontab enumeration",
        reason="Routine 'crontab -l' calls by administrators and monitoring scripts",
    ),
    NoiseRule(
        rule_name="sigma_suspicious_curl_change_user_agents_-_linux",
        description="Suspicious curl user agent change",
        reason="acme.sh (Let's Encrypt client) uses a custom user-agent during certificate renewal",
    ),
    NoiseRule(
        rule_name="sigma_linux_base64_encoded_pipe_to_shell",
        description="Base64 encoded pipe to shell",
        reason="acme.sh certificate renewal runs 'openssl base64 -e' during normal ACME operations",
    ),
]


def get_default_suppress_rule_names() -> list[str]:
    """Return the list of rule names that should be suppressed by default.

    Returns only rules using the 'suppress' strategy.
    """
    return [r.rule_name for r in DEFAULT_NOISE_RULES if r.suppression_strategy == "suppress"]


def get_default_group_rule_names() -> list[str]:
    """Return the list of rule names that should be grouped by default.

    Returns only rules using the 'group' strategy.
    """
    return [r.rule_name for r in DEFAULT_NOISE_RULES if r.suppression_strategy == "group"]


def get_default_threshold_rules() -> dict[str, dict]:
    """Return threshold rules for rules using the 'threshold' strategy."""
    result: dict[str, dict] = {}
    for r in DEFAULT_NOISE_RULES:
        if r.suppression_strategy == "threshold":
            result[r.rule_name] = {"min_count": 10, "window_minutes": 60}
    return result


def is_default_noise(rule_name: str) -> bool:
    """Check if a rule name is in the default noise list."""
    return rule_name in {r.rule_name for r in DEFAULT_NOISE_RULES}
