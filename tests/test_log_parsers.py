"""Tests for vespid.log_parsers — regex-based log line extraction.

Covers:
- parse_secure: all SSH variants (failed password, invalid user, auth timeout,
  negotiate fail, banner exchange, preauth disconnect, banner grab)
- parse_messages: firewall DROP/REJECT lines
- parse_apache: Combined Log Format with status-based classification and
  scanner user-agent detection
- Timestamp extraction: syslog BSD format, ISO 8601, Apache CLF
- Non-matching lines return None
"""

from __future__ import annotations

import pytest

from vespid.log_parsers import (
    _is_scanner_ua,
    _parse_apache_timestamp,
    _parse_syslog_timestamp,
    parse_apache,
    parse_haproxy,
    parse_messages,
    parse_secure,
)

# ---------------------------------------------------------------------------
# parse_secure — SSH auth failure variants
# ---------------------------------------------------------------------------


class TestParseSecure:
    def test_failed_password(self):
        line = "Jun 12 22:00:56 myhost sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2"
        result = parse_secure(line)
        assert result is not None
        assert result.parser == "secure"
        assert result.source_ip == "192.168.1.50"

    def test_invalid_user(self):
        line = "Jun 12 22:01:00 myhost sshd[1235]: Failed password for invalid user admin from 10.20.30.40 port 54321 ssh2"
        result = parse_secure(line)
        assert result is not None
        assert result.parser == "secure"
        assert result.source_ip == "10.20.30.40"

    def test_authentication_failure_rhost(self):
        line = "Jun 12 22:02:00 myhost sshd[1236]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5"
        result = parse_secure(line)
        assert result is not None
        assert result.parser == "secure"
        assert result.source_ip == "203.0.113.5"

    def test_auth_timeout(self):
        line = "Jun 12 22:03:00 myhost sshd[1237]: Timeout before authentication from 45.33.32.156"
        result = parse_secure(line)
        assert result is not None
        assert result.parser == "secure_recon_strong"
        assert result.source_ip == "45.33.32.156"

    def test_negotiate_fail_host_key(self):
        line = "Jun 12 22:04:00 myhost sshd[1238]: Unable to negotiate with 198.51.100.1 port 44444: no matching host key type found. [preauth]"
        result = parse_secure(line)
        assert result is not None
        assert result.parser == "secure_negotiate_fail"
        assert result.source_ip == "198.51.100.1"

    def test_negotiate_fail_kex(self):
        line = "Jun 12 22:04:00 myhost sshd[1238]: Unable to negotiate with 198.51.100.2 port 44444: no matching key exchange method found. [preauth]"
        result = parse_secure(line)
        assert result is not None
        assert result.parser == "secure_negotiate_fail"
        assert result.source_ip == "198.51.100.2"

    def test_banner_exchange_failure(self):
        line = "Jun 12 22:05:00 myhost sshd[1239]: banner exchange: Connection from 172.16.0.1 port 9999: could not read protocol version"
        result = parse_secure(line)
        assert result is not None
        assert result.parser == "secure_recon_strong"
        assert result.source_ip == "172.16.0.1"

    def test_disconnect_preauth_invalid_user(self):
        line = "Jun 12 22:06:00 myhost sshd[1240]: Disconnected from invalid user test 192.0.2.1 port 55555 [preauth]"
        result = parse_secure(line)
        assert result is not None
        assert result.parser == "secure_recon_strong"
        assert result.source_ip == "192.0.2.1"

    def test_disconnect_preauth_authenticating_user(self):
        line = "Jun 12 22:07:00 myhost sshd[1241]: Disconnected from authenticating user root 192.0.2.2 port 55556 [preauth]"
        result = parse_secure(line)
        assert result is not None
        assert result.parser == "secure_recon_weak"
        assert result.source_ip == "192.0.2.2"

    def test_connection_reset_banner_grab(self):
        line = "Jun 12 22:08:00 myhost sshd[1242]: Connection reset by 192.0.2.3 port 55557"
        result = parse_secure(line)
        assert result is not None
        assert result.parser == "secure_recon_weak"
        assert result.source_ip == "192.0.2.3"

    def test_non_matching_line_returns_none(self):
        line = "Jun 12 22:09:00 myhost sshd[1243]: Accepted publickey for deploy from 10.0.0.1 port 22 ssh2"
        result = parse_secure(line)
        assert result is None

    def test_cron_line_returns_none(self):
        line = "Jun 12 22:10:00 myhost CRON[9999]: (root) CMD (/usr/sbin/logrotate)"
        result = parse_secure(line)
        assert result is None

    def test_ipv6_address_extracted(self):
        line = "Jun 12 22:11:00 myhost sshd[1244]: Failed password for root from 2001:db8::1 port 22 ssh2"
        result = parse_secure(line)
        assert result is not None
        assert result.source_ip == "2001:db8::1"


# ---------------------------------------------------------------------------
# parse_messages — firewall DROP/REJECT
# ---------------------------------------------------------------------------


class TestParseMessages:
    def test_kernel_drop(self):
        line = (
            "Jun 12 22:12:00 myhost kernel: [12345.678] DROP IN=eth0 SRC=203.0.113.10 DST=10.0.0.1"
        )
        result = parse_messages(line)
        assert result is not None
        assert result.parser == "messages"
        assert result.source_ip == "203.0.113.10"

    def test_reject_line(self):
        # The regex matches SRC= pattern in kernel log lines
        line = "Jun 12 22:13:00 myhost kernel: [12345.678] REJECT IN=eth0 OUT= SRC=192.168.99.1 DST=10.0.0.1"
        result = parse_messages(line)
        assert result is not None
        assert result.source_ip == "192.168.99.1"

    def test_non_matching_returns_none(self):
        line = "Jun 12 22:14:00 myhost systemd[1]: Started Daily Cleanup of Temporary Directories."
        result = parse_messages(line)
        assert result is None


# ---------------------------------------------------------------------------
# parse_apache — Combined Log Format
# ---------------------------------------------------------------------------


class TestParseApache:
    def test_401_response(self):
        line = '192.168.1.10 - - [12/Jun/2026:15:30:00 +0000] "GET /admin HTTP/1.1" 401 512 "-" "Mozilla/5.0"'
        result = parse_apache(line)
        assert result is not None
        assert result.parser == "apache"
        assert result.source_ip == "192.168.1.10"

    def test_403_response(self):
        line = '10.20.30.40 - user [12/Jun/2026:15:31:00 +0000] "POST /secret HTTP/1.1" 403 256 "-" "curl/7.68"'
        result = parse_apache(line)
        assert result is not None
        # curl/ is a scanner token, so scanner_ua takes priority
        assert result.parser == "apache_scanner_ua"
        assert result.source_ip == "10.20.30.40"

    def test_400_bad_request(self):
        line = '44.55.66.77 - - [12/Jun/2026:15:32:00 +0000] "GET /bad%request HTTP/1.1" 400 0 "-" "Mozilla/5.0"'
        result = parse_apache(line)
        assert result is not None
        assert result.parser == "apache_bad_request"
        assert result.source_ip == "44.55.66.77"

    def test_404_not_found(self):
        line = '88.99.11.22 - - [12/Jun/2026:15:33:00 +0000] "GET /wp-admin HTTP/1.1" 404 1234 "-" "Mozilla/5.0"'
        result = parse_apache(line)
        assert result is not None
        assert result.parser == "apache_not_found"
        assert result.source_ip == "88.99.11.22"

    def test_200_ok_classified_as_other(self):
        line = (
            '1.2.3.4 - - [12/Jun/2026:15:34:00 +0000] "GET / HTTP/1.1" 200 5000 "-" "Mozilla/5.0"'
        )
        result = parse_apache(line)
        assert result is not None
        assert result.parser == "apache_other"

    def test_scanner_ua_overrides_status(self):
        line = '5.6.7.8 - - [12/Jun/2026:15:35:00 +0000] "GET / HTTP/1.1" 200 1000 "-" "Nuclei Scanner v2"'
        result = parse_apache(line)
        assert result is not None
        assert result.parser == "apache_scanner_ua"

    def test_zgrab_scanner_detected(self):
        line = '9.8.7.6 - - [12/Jun/2026:15:36:00 +0000] "GET / HTTP/1.1" 200 500 "-" "Mozilla/5.0 zgrab/0.x"'
        result = parse_apache(line)
        assert result is not None
        assert result.parser == "apache_scanner_ua"

    def test_non_matching_line(self):
        line = "This is not an access log line at all"
        result = parse_apache(line)
        assert result is None

    def test_timestamp_extracted(self):
        line = '1.1.1.1 - - [15/Jun/2026:10:20:30 +0000] "GET / HTTP/1.1" 200 100 "-" "test"'
        result = parse_apache(line)
        assert result is not None
        assert result.timestamp is not None
        assert result.timestamp > 0


# ---------------------------------------------------------------------------
# Scanner UA Detection
# ---------------------------------------------------------------------------


class TestScannerUA:
    @pytest.mark.parametrize(
        "token",
        [
            "Nuclei",
            "zgrab",
            "masscan",
            "nikto",
            "sqlmap",
            "nmap",
            "Censys",
            "Shodan",
            "WPScan",
            "gobuster",
            "python-requests",
            "Go-http-client",
            "curl/7.68",
            "wget/1.21",
        ],
    )
    def test_known_scanners_detected(self, token):
        line = f'1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "{token}"'
        assert _is_scanner_ua(line) is True

    def test_normal_browser_not_flagged(self):
        line = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        assert _is_scanner_ua(line) is False

    def test_python_httpx_not_flagged(self):
        # Regression: the agent's own httpx traffic must not be seen as a scanner.
        line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "POST /api/v1/events HTTP/1.1" 200 0 "-" "python-httpx/0.28.1"'
        assert _is_scanner_ua(line) is False

    def test_projectdiscovery_detected(self):
        line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "projectdiscovery/httpx"'
        assert _is_scanner_ua(line) is True


# ---------------------------------------------------------------------------
# Timestamp Parsing
# ---------------------------------------------------------------------------


class TestTimestampParsing:
    def test_syslog_bsd_format(self):
        line = "Jun 12 22:00:56 myhost sshd[1234]: something"
        ts = _parse_syslog_timestamp(line)
        assert ts is not None
        assert ts > 0

    def test_iso8601_utc(self):
        line = "2026-06-12T22:00:56Z some message"
        ts = _parse_syslog_timestamp(line)
        assert ts is not None

    def test_iso8601_with_offset(self):
        line = "2026-06-12T22:00:56+05:30 some message"
        ts = _parse_syslog_timestamp(line)
        assert ts is not None

    def test_iso8601_with_microseconds(self):
        line = "2026-06-12T22:00:56.123456+00:00 some message"
        ts = _parse_syslog_timestamp(line)
        assert ts is not None

    def test_non_timestamp_line_returns_none(self):
        line = "no timestamp here at all"
        ts = _parse_syslog_timestamp(line)
        assert ts is None

    def test_apache_clf_timestamp(self):
        ts = _parse_apache_timestamp("12/Jun/2026:15:30:00 +0000")
        assert ts is not None
        assert ts > 0

    def test_apache_timestamp_with_millis(self):
        ts = _parse_apache_timestamp("12/Jun/2026:15:30:00.123")
        assert ts is not None

    def test_apache_invalid_returns_none(self):
        ts = _parse_apache_timestamp("not a timestamp")
        assert ts is None


# ---------------------------------------------------------------------------
# parse_haproxy — basic coverage
# ---------------------------------------------------------------------------


class TestParseHAProxy:
    def test_http_log_401(self):
        # HAProxy HTTP log matching the _RE_HAPROXY_HTTP regex:
        # ip:port [timestamp] frontend~ backend/server timers status size CC CS tsc conns {req_hdrs} {resp_hdrs} "request"
        line = '192.168.1.1:54321 [20/Jun/2026:14:30:45.123] frontend~ backend/srv1 0/0/1/2/3 401 1234 - - ---- 1/1/0/0/0 {Mozilla/5.0} {-} "GET / HTTP/1.1"'
        result = parse_haproxy(line)
        assert result is not None
        assert result.source_ip == "192.168.1.1"
        assert result.parser == "haproxy"
        assert result.timestamp is not None

    def test_http_log_default_format_with_queue(self):
        # Default `option httplog` format includes the %sq/%bq queue field
        # (the "0/0" before the captured-headers block).
        line = '15.204.59.125:52368 [21/Jun/2026:16:09:15.405] https~ vespid/vespid 0/0/0/18/18 204 405 - - ---- 6/6/5/5/0 0/0 {} "POST /api/v1/metrics/write HTTP/1.1"'
        result = parse_haproxy(line)
        assert result is not None
        assert result.source_ip == "15.204.59.125"
        assert result.parser == "haproxy_other"

    def test_http_log_scanner_ua(self):
        line = '10.20.30.40:9999 [20/Jun/2026:14:30:45.123] ft~ be/srv 0/0/1/2/3 200 500 - - ---- 1/1/0/0/0 {Nuclei scanner} {-} "GET / HTTP/1.1"'
        result = parse_haproxy(line)
        assert result is not None
        assert result.parser == "haproxy_scanner_ua"
        assert result.source_ip == "10.20.30.40"

    def test_tcp_log(self):
        # HAProxy TCP log: ip:port [timestamp] frontend~ backend/server tw/tc/tt bytes termstate conns sq/bq
        line = "10.0.0.5:12345 [12/Jun/2026:15:29:48.886] fe~ be/srv 0/0/500 1234 -- 1/1/0/0/0 0/0"
        result = parse_haproxy(line)
        assert result is not None
        assert result.source_ip == "10.0.0.5"
        assert result.parser == "haproxy"

    def test_ssl_handshake_failure(self):
        # Connection-level TLS error (not an access-log line) — repeated
        # failures from one IP indicate cipher/TLS scanning.
        line = "51.222.168.136:39542 [21/Jun/2026:15:10:51.985] https/4: SSL handshake failure (error:0A0000EA:SSL routines::callback failed)"
        result = parse_haproxy(line)
        assert result is not None
        assert result.parser == "haproxy_ssl_fail"
        assert result.source_ip == "51.222.168.136"
        assert result.timestamp is not None

    def test_ssl_handshake_failure_leading_space(self):
        line = " 185.218.138.31:44762 [21/Jun/2026:15:28:05.025] https/3: SSL handshake failure (error:0A0000EA:SSL routines::callback failed)"
        result = parse_haproxy(line)
        assert result is not None
        assert result.parser == "haproxy_ssl_fail"
        assert result.source_ip == "185.218.138.31"

    def test_non_matching_returns_none(self):
        line = "This is just a random log message"
        result = parse_haproxy(line)
        assert result is None
