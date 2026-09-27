"""Tests for vespid.file_tailer — self-log detection.

The daemon and agents write their human-readable log lines to stdout, which
systemd journald captures and rsyslog mirrors into /var/log/messages
(RHEL/SUSE) and /var/log/syslog (Debian). Since vespid tails those files,
_is_self_log_line() is used to skip its own mirrored lines instead of counting
them as parse failures (self-tailing feedback loop).
"""

from __future__ import annotations

from vespid.file_tailer import _is_self_log_line


class TestIsSelfLogLine:
    def test_own_log_line_with_program_tag(self):
        line = (
            "Aug  1 15:59:11 myhost vespid: "
            "2026-08-01T15:59:11+0000 INFO    vespid.logproc.tailer  "
            "Parser messages: 204000 consecutive non-matching lines for "
            "/var/log/messages"
        )
        assert _is_self_log_line(line) is True

    def test_own_log_line_without_program_tag(self):
        line = (
            "2026-08-01T15:59:11+0000 INFO    vespid.logproc.tailer  "
            "Tailing /var/log/messages (messages, catchup=True)"
        )
        assert _is_self_log_line(line) is True

    def test_own_log_line_level_warning(self):
        line = (
            "Aug  1 15:59:12 myhost vespid: "
            "2026-08-01T15:59:12+0000 WARNING vespid.config  "
            "Ignoring unknown key foo"
        )
        assert _is_self_log_line(line) is True

    def test_root_logger_name(self):
        line = (
            "Aug  1 15:59:13 myhost vespid: "
            "2026-08-01T15:59:13+0000 INFO    vespid  "
            "Logging configured"
        )
        assert _is_self_log_line(line) is True

    def test_rust_agent_log_line(self):
        line = (
            "Aug  1 16:13:11 vps-43d4bac7 vespid-agent[1388]: "
            "2026-08-01T16:13:11.088555Z  INFO Sending batch  212 metrics, "
            "39643 bytes  \u2192 https://demo.vespid.app/api/v1/metrics/write"
        )
        assert _is_self_log_line(line) is True

    def test_rust_agent_shipped_log_line(self):
        line = (
            "Aug  1 16:13:11 vps-43d4bac7 vespid-agent[1388]: "
            "2026-08-01T16:13:11.107951Z  INFO Shipped 212 metrics "
            "(39643 bytes)  \u2713"
        )
        assert _is_self_log_line(line) is True

    def test_rust_sync_agent_log_line(self):
        line = (
            "Aug  1 16:13:12 vps-43d4bac7 vespid-sync-agent[1402]: "
            "2026-08-01T16:13:12.000123Z  WARN Sync failed, will retry"
        )
        assert _is_self_log_line(line) is True

    def test_real_security_event_not_skipped(self):
        line = (
            "Aug  1 16:00:01 myhost sshd[1234]: "
            "Failed password for invalid user root from 203.0.113.5 port "
            "53422 ssh2"
        )
        assert _is_self_log_line(line) is False

    def test_firewall_deny_not_skipped(self):
        line = (
            "Aug  1 16:00:02 myhost kernel: "
            "IN=eth0 OUT= MAC=.. SRC=198.51.100.9 DST=192.0.2.1 "
            "PROTO=TCP SPT=4444 DPT=22 DROP"
        )
        assert _is_self_log_line(line) is False

    def test_apache_line_not_skipped(self):
        line = (
            "192.0.2.7 - - [01/Aug/2026:15:59:11 +0000] "
            '"GET /wp-login.php HTTP/1.1" 404 489 "-" "-"'
        )
        assert _is_self_log_line(line) is False
