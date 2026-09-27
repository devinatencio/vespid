"""Log parsers — regex-based extractors that turn raw log lines into ``ParsedLine`` objects.

Each parser function takes a single raw line and returns ``ParsedLine | None``.
The ``_get_parser()`` resolver maps a ``LogSource`` config entry to the correct
parser callable.
"""

from __future__ import annotations

import functools
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .config import LogSource

log = logging.getLogger("vespid.logproc.parsers")

# ---------------------------------------------------------------------------
# Parsers - extract (event_type, source_ip) from a raw log line
# ---------------------------------------------------------------------------
_RE_SECURE_FAIL = re.compile(
    r"sshd.*?(?:Failed password|Invalid user|authentication failure).*?"
    r"(?:from\s+|rhost=)(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)"
)
_RE_SSH_BANNER_GRAB = re.compile(
    r"sshd.*?Connection (?:reset|closed) by"
    r".*?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+port\s+\d+"
    r"(?::\s+Connection reset by peer)?"
)
_RE_SSH_DISCONNECT_PREAUTH = re.compile(
    r"sshd.*?(?:Received disconnect from|Disconnected from|Connection closed by)"
    r"\s+invalid user \S+ "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+port\s+\d+"
    r".*?\[preauth\]"
)
_RE_SSH_DISCONNECT_AUTH_USER = re.compile(
    r"sshd.*?(?:Received disconnect from|Disconnected from|Connection closed by)"
    r"\s+authenticating user \S+ "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+port\s+\d+"
    r".*?\[preauth\]"
)
_RE_SSH_AUTH_TIMEOUT = re.compile(
    r"sshd.*?Timeout before authentication.*?"
    r"(?:from\s+|connection from\s+)"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)"
)
_RE_SSH_NEGOTIATE_FAIL = re.compile(
    r"sshd.*?Unable to negotiate with\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+port\s+\d+:\s+"
    r"no matching (?:host key type|key exchange method) found\."
    r".*?\[preauth\]"
)
_RE_SSH_BANNER_EXCHANGE = re.compile(
    r"sshd.*?banner exchange:\s+Connection from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+port\s+\d+:\s+"
    r"(?:could not read protocol version|invalid format)"
)
_RE_MESSAGES_DENY = re.compile(r"(?:DROP|REJECT|kernel:.*?SRC=)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
_RE_APACHE_AUTH_FAIL = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s.*\"\s(?:401|403)\s"
)

_RE_APACHE_COMBINED = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+\S+\s+\S+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
)

_SCANNER_TOKENS = (
    "/scan",
    "zgrab",
    "masscan",
    "nuclei",
    "nikto",
    "sqlmap",
    "nmap",
    "dirbuster",
    "gobuster",
    "wpscan",
    "projectdiscovery",
    "censys",
    "shodan",
    "netcraft",
    "qualys",
    "openvas",
    "nessus",
    "acunetix",
    "burpsuite",
    "python-requests",
    "python-urllib",
    "python-aiohttp",
    "go-http-client",
    "curl/",
    "wget/",
)


def _is_scanner_ua(line: str) -> bool:
    lower = line.lower()
    return any(t in lower for t in _SCANNER_TOKENS)


_RE_SYSLOG_TS = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2})"
)
_MONTH_MAP = {
    name: idx
    for idx, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}

_RE_ISO8601_TS = re.compile(
    r"^(?P<Y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})T"
    r"(?P<H>\d{2}):(?P<M>\d{2}):(?P<S>\d{2})"
    r"(?:\.\d+)?"
    r"(?P<tz>[+-]\d{2}:\d{2}|Z)?"
)


def _parse_syslog_timestamp(line: str) -> float | None:
    m = _RE_SYSLOG_TS.match(line)
    if m:
        now = time.time()
        lt = time.localtime(now)
        month = _MONTH_MAP.get(m.group("mon"))
        if month is None:
            return None
        try:
            ts = datetime(
                year=lt.tm_year,
                month=month,
                day=int(m.group("day")),
                hour=int(m.group("H")),
                minute=int(m.group("M")),
                second=int(m.group("S")),
            ).timestamp()
        except (ValueError, OverflowError):
            return None
        if ts > now + 86400:
            try:
                ts = datetime(
                    year=lt.tm_year - 1,
                    month=month,
                    day=int(m.group("day")),
                    hour=int(m.group("H")),
                    minute=int(m.group("M")),
                    second=int(m.group("S")),
                ).timestamp()
            except (ValueError, OverflowError):
                return None
        return ts

    m = _RE_ISO8601_TS.match(line)
    if m:
        try:
            tz_str = m.group("tz")
            if tz_str and tz_str != "Z":
                sign = 1 if tz_str[0] == "+" else -1
                tz_h, tz_m = int(tz_str[1:3]), int(tz_str[4:6])
                tzinfo = timezone(timedelta(hours=sign * tz_h, minutes=sign * tz_m))
            else:
                tzinfo = timezone.utc
            dt = datetime(
                year=int(m.group("Y")),
                month=int(m.group("m")),
                day=int(m.group("d")),
                hour=int(m.group("H")),
                minute=int(m.group("M")),
                second=int(m.group("S")),
                tzinfo=tzinfo,
            )
            return dt.timestamp()
        except (ValueError, OverflowError):
            return None

    return None


@dataclass
class ParsedLine:
    parser: str
    source_ip: str
    raw: str
    timestamp: float | None = None


def parse_secure(line: str) -> ParsedLine | None:
    m = _RE_SECURE_FAIL.search(line)
    if m:
        return ParsedLine(
            parser="secure",
            source_ip=m.group("ip"),
            raw=line,
            timestamp=_parse_syslog_timestamp(line),
        )
    m = _RE_SSH_AUTH_TIMEOUT.search(line)
    if m:
        return ParsedLine(
            parser="secure_recon_strong",
            source_ip=m.group("ip"),
            raw=line,
            timestamp=_parse_syslog_timestamp(line),
        )
    m = _RE_SSH_NEGOTIATE_FAIL.search(line)
    if m:
        return ParsedLine(
            parser="secure_negotiate_fail",
            source_ip=m.group("ip"),
            raw=line,
            timestamp=_parse_syslog_timestamp(line),
        )
    m = _RE_SSH_BANNER_EXCHANGE.search(line)
    if m:
        return ParsedLine(
            parser="secure_recon_strong",
            source_ip=m.group("ip"),
            raw=line,
            timestamp=_parse_syslog_timestamp(line),
        )
    m = _RE_SSH_DISCONNECT_PREAUTH.search(line)
    if m:
        return ParsedLine(
            parser="secure_recon_strong",
            source_ip=m.group("ip"),
            raw=line,
            timestamp=_parse_syslog_timestamp(line),
        )
    m = _RE_SSH_DISCONNECT_AUTH_USER.search(line)
    if m:
        return ParsedLine(
            parser="secure_recon_weak",
            source_ip=m.group("ip"),
            raw=line,
            timestamp=_parse_syslog_timestamp(line),
        )
    m = _RE_SSH_BANNER_GRAB.search(line)
    if m:
        return ParsedLine(
            parser="secure_recon_weak",
            source_ip=m.group("ip"),
            raw=line,
            timestamp=_parse_syslog_timestamp(line),
        )
    return None


def parse_messages(line: str) -> ParsedLine | None:
    m = _RE_MESSAGES_DENY.search(line)
    if m:
        return ParsedLine(
            parser="messages",
            source_ip=m.group("ip"),
            raw=line,
            timestamp=_parse_syslog_timestamp(line),
        )
    return None


def _parse_apache_timestamp(ts_str: str) -> float | None:
    for fmt in (
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S.%f",
        "%d/%b/%Y:%H:%M:%S",
    ):
        try:
            return datetime.strptime(ts_str, fmt).timestamp()
        except (ValueError, TypeError):
            continue
    return None


def parse_apache(line: str) -> ParsedLine | None:
    m = _RE_APACHE_COMBINED.match(line)
    if m:
        ip = m.group("ip")
        status = m.group("status")
        ts_str = m.group("timestamp")
        timestamp = _parse_apache_timestamp(ts_str)

        if _is_scanner_ua(line):
            parser_name = "apache_scanner_ua"
        elif status in ("401", "403"):
            parser_name = "apache"
        elif status == "400":
            parser_name = "apache_bad_request"
        elif status == "404":
            parser_name = "apache_not_found"
        else:
            parser_name = "apache_other"

        return ParsedLine(
            parser=parser_name,
            source_ip=ip,
            raw=line,
            timestamp=timestamp,
        )

    m = _RE_APACHE_AUTH_FAIL.match(line)
    if m:
        return ParsedLine(
            parser="apache",
            source_ip=m.group("ip"),
            raw=line,
            timestamp=_parse_syslog_timestamp(line),
        )
    return None


# ---------------------------------------------------------------------------
# HAProxy parser
# ---------------------------------------------------------------------------


def _strip_syslog_prefix(line: str) -> str:
    if line and (line[0].isdigit() or line[0] == "["):
        return line
    m = re.search(r"(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):\d+\s+\[", line)
    if m:
        return line[m.start() :]
    return line


_RE_HAPROXY_HTTP = re.compile(
    r"(?P<ip>"
    r"\d{1,3}(?:\.\d{1,3}){3}"
    r"|\[[0-9a-fA-F:]+\]"
    r")(?::\d+)?\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r"\S+~?\s+"
    r"\S+/\S+\s+"
    r"\S+\s+"
    r"(?P<status>\d{3})\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"(?:\d+/\d+\s+)?"
    r"(?:(?:\{(?P<req_headers>[^}]*)\}|-)\s+)?"
    r"(?:(?:\{[^}]*\}|-)\s+)?"
    r'"(?P<request>[^"]*)"'
    r"\s*$",
)

# HAProxy connection-level SSL handshake failure. Emitted by the TLS layer
# before HTTP processing, so it is independent of the access-log format.
# Repeated failures from one IP indicate cipher/TLS scanning.
_RE_HAPROXY_SSL_FAIL = re.compile(
    r"(?P<ip>"
    r"\d{1,3}(?:\.\d{1,3}){3}"
    r"|\[[0-9a-fA-F:]+\]"
    r")(?::\d+)?\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r"\S+:\s+SSL handshake failure"
)

_RE_HAPROXY_TCP = re.compile(
    r"(?P<ip>"
    r"\d{1,3}(?:\.\d{1,3}){3}"
    r"|\[[0-9a-fA-F:]+\]"
    r")(?::\d+)?\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r"\S+~?\s+"
    r"\S+/\S+\s+"
    r"\S+\s+"
    r"(?P<size>\S+)\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"\S+\s*$",
)

_HAPROXY_VARS: list[tuple[str, str, str | None]] = [
    ("%{+Q}r", r'"(?P<request>[^"]*)"', None),
    ("%r", r"(?P<request>\S+\s+\S+\s+\S+)", None),
    ("%ci", r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\])", "ip"),
    ("%cp", r"\d+", None),
    ("%t", r"[^\]]+", None),
    ("%tr", r"[^\]]+", None),
    ("%ft", r"\S+", None),
    ("%b", r"\S+", None),
    ("%s", r"\S+", None),
    ("%ST", r"(?P<status>\d{3})", "status"),
    ("%B", r"\S+", None),
    ("%CC", r"\S+", None),
    ("%CS", r"\S+", None),
    ("%tsc", r"\S{4}|-", None),
    ("%ts", r"\S{2,4}|-", None),
    ("%ac", r"\d+", None),
    ("%fc", r"\d+", None),
    ("%bc", r"\d+", None),
    ("%sc", r"\d+", None),
    ("%rc", r"\d+", None),
    ("%sq", r"\S+", None),
    ("%bq", r"\S+", None),
    ("%hr", r"\{(?P<req_headers>[^}]*)\}|-", None),
    ("%hs", r"\{[^}]*\}|-", None),
]


def _build_haproxy_regex(format_template: str) -> re.Pattern | None:
    if not format_template or not format_template.strip():
        return None
    try:
        parts: list[str] = []
        remaining = format_template

        while remaining:
            best_start = len(remaining)
            best_token = None
            best_pattern = None

            for token, pattern, _ in _HAPROXY_VARS:
                idx = remaining.find(token)
                if idx != -1 and idx < best_start:
                    best_start = idx
                    best_token = token
                    best_pattern = pattern

            if best_token is None:
                parts.append(re.escape(remaining))
                break

            if best_start > 0:
                parts.append(re.escape(remaining[:best_start]))

            assert best_pattern is not None
            parts.append(best_pattern)
            remaining = remaining[best_start + len(best_token) :]

        pattern = "".join(parts)
        pattern = re.sub(r"(?:\\ )+", r"\\s+", pattern)
        return re.compile("^" + pattern)
    except re.error:
        return None


def _haproxy_parser_name(
    status_str: str | None,
    line: str,
    user_agent: str | None = None,
) -> str:
    if _is_scanner_ua(user_agent if user_agent is not None else line):
        return "haproxy_scanner_ua"
    if status_str in ("401", "403"):
        return "haproxy"
    if status_str == "400":
        return "haproxy_bad_request"
    if status_str == "404":
        return "haproxy_not_found"
    return "haproxy_other"


def _parse_haproxy_ssl_fail(line: str) -> ParsedLine | None:
    stripped = _strip_syslog_prefix(line)
    m = _RE_HAPROXY_SSL_FAIL.match(stripped)
    if not m:
        return None
    return ParsedLine(
        parser="haproxy_ssl_fail",
        source_ip=m.group("ip"),
        raw=line,
        timestamp=_parse_apache_timestamp(m.group("timestamp")),
    )


def _parse_haproxy_with_regex(
    line: str,
    compiled: re.Pattern,
    has_status: bool,
) -> ParsedLine | None:
    ssl_fail = _parse_haproxy_ssl_fail(line)
    if ssl_fail is not None:
        return ssl_fail

    stripped = _strip_syslog_prefix(line)
    m = compiled.match(stripped)
    if not m:
        return None

    ip = m.group("ip")
    gd = m.groupdict()
    ts_str = gd.get("timestamp")
    timestamp = _parse_apache_timestamp(ts_str) if ts_str else None
    user_agent = gd.get("req_headers")

    if has_status:
        status = gd.get("status")
        parser_name = _haproxy_parser_name(status, stripped, user_agent)
    else:
        parser_name = "haproxy"

    return ParsedLine(
        parser=parser_name,
        source_ip=ip,
        raw=line,
        timestamp=timestamp,
    )


def _parse_haproxy_http(line: str) -> ParsedLine | None:
    ssl_fail = _parse_haproxy_ssl_fail(line)
    if ssl_fail is not None:
        return ssl_fail

    stripped = _strip_syslog_prefix(line)
    m = _RE_HAPROXY_HTTP.match(stripped)
    if not m:
        return None
    user_agent = m.groupdict().get("req_headers")
    return ParsedLine(
        parser=_haproxy_parser_name(m.group("status"), stripped, user_agent),
        source_ip=m.group("ip"),
        raw=line,
        timestamp=_parse_apache_timestamp(m.group("timestamp")),
    )


def _parse_haproxy_tcp(line: str) -> ParsedLine | None:
    ssl_fail = _parse_haproxy_ssl_fail(line)
    if ssl_fail is not None:
        return ssl_fail

    stripped = _strip_syslog_prefix(line)
    m = _RE_HAPROXY_TCP.match(stripped)
    if not m:
        return None
    return ParsedLine(
        parser="haproxy",
        source_ip=m.group("ip"),
        raw=line,
        timestamp=_parse_apache_timestamp(m.group("timestamp")),
    )


def parse_haproxy(line: str) -> ParsedLine | None:
    ssl_fail = _parse_haproxy_ssl_fail(line)
    if ssl_fail is not None:
        return ssl_fail

    stripped = _strip_syslog_prefix(line)

    m = _RE_HAPROXY_HTTP.match(stripped)
    if m:
        user_agent = m.groupdict().get("req_headers")
        return ParsedLine(
            parser=_haproxy_parser_name(m.group("status"), stripped, user_agent),
            source_ip=m.group("ip"),
            raw=line,
            timestamp=_parse_apache_timestamp(m.group("timestamp")),
        )

    m = _RE_HAPROXY_TCP.match(stripped)
    if m:
        return ParsedLine(
            parser="haproxy",
            source_ip=m.group("ip"),
            raw=line,
            timestamp=_parse_apache_timestamp(m.group("timestamp")),
        )

    return None


PARSERS: dict[str, Callable[[str], ParsedLine | None]] = {
    "secure": parse_secure,
    "messages": parse_messages,
    "apache": parse_apache,
    "haproxy": parse_haproxy,
}


def _auditd_passthrough_parser(line: str) -> ParsedLine | None:
    if not line.strip():
        return None
    return ParsedLine(parser="auditd", source_ip="", raw=line)


# ---------------------------------------------------------------------------
# Parser resolution (supports HAProxy custom log formats)
# ---------------------------------------------------------------------------


def _get_parser(source: LogSource) -> Callable[[str], ParsedLine | None] | None:
    if source.parser == "auditd":
        return _auditd_passthrough_parser

    if source.parser != "haproxy":
        return PARSERS.get(source.parser)

    if source.haproxy_log_format:
        compiled = _build_haproxy_regex(source.haproxy_log_format)
        if compiled is None:
            log.error(
                "Failed to compile haproxy_log_format for %s, falling back to mode detection",
                source.path,
            )
        else:
            has_status = "%ST" in source.haproxy_log_format
            log.info(
                "Using custom HAProxy log format for %s (status_capture=%s)",
                source.path,
                has_status,
            )
            return functools.partial(
                _parse_haproxy_with_regex, compiled=compiled, has_status=has_status
            )

    mode = source.haproxy_mode
    if mode == "http":
        return _parse_haproxy_http
    if mode == "tcp":
        return _parse_haproxy_tcp

    return parse_haproxy
