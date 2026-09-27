"""Test Rule Page — dry-run simulation engine and utilities.

Provides data models, helper functions, and detection infrastructure for
running log files through detection rules in a side-effect-free simulation
context. The detection logic (parsers, SlidingWindowDetector, CustomRuleEngine)
is copied from the vespid agent package to avoid cross-package imports.
"""

from __future__ import annotations

import json
import math
import queue
import re
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import (
    Any,
)

# ===========================================================================
# Detection infrastructure (copied from vespid agent)
# ===========================================================================

# --- Data models from vespid/config.py ---


@dataclass
class BruteForceRule:
    name: str
    event_type: str
    max_attempts: int
    window_seconds: int
    parser: str = "secure"


@dataclass
class CustomRule:
    """User-defined regex-based detection rule."""

    name: str
    event_type: str
    regex: str
    log_sources: list[str]
    max_attempts: int = 3
    window_seconds: int = 3600
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    sigma_id: str = ""
    sigma_status: str = ""


@dataclass
class CorrelationRule:
    """Multi-signal correlation rule for detecting multi-vector recon."""

    name: str
    event_type: str
    min_categories: int = 3
    window_seconds: int = 600
    enabled: bool = True


# --- Parsers from vespid/log_processor.py ---

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

# Scanner user-agent detection
_RE_SCANNER_UA = re.compile(
    r"(?:"
    r"/scan\b"
    r"|zgrab"
    r"|masscan"
    r"|nuclei"
    r"|nikto"
    r"|sqlmap"
    r"|nmap"
    r"|dirbuster"
    r"|gobuster"
    r"|wpscan"
    r"|httpx"
    r"|censys"
    r"|shodan"
    r"|netcraft"
    r"|qualys"
    r"|openvas"
    r"|nessus"
    r"|acunetix"
    r"|burpsuite"
    r"|python-requests"
    r"|python-urllib"
    r"|python-aiohttp"
    r"|go-http-client"
    r"|curl/"
    r"|wget/"
    r")",
    re.IGNORECASE,
)


def _strip_syslog_prefix(line: str) -> str:
    """Strip optional syslog prefix from HAProxy log lines."""
    if line and (line[0].isdigit() or line[0] == "["):
        return line
    m = re.search(r"(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):\d+\s+\[", line)
    if m:
        return line[m.start() :]
    return line


# HAProxy default HTTP log format (equivalent to ``option httplog``):
#   %ci:%cp [%t] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r
#
# Example:
#   66.132.224.85:16860 [26/May/2026:14:43:17.333] main main/<NOSRV> -1/-1/-1/-1/0 400 0 - - PR-- 3/1/0/0/0 0/0 "<BADREQ>"
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

# Default HAProxy TCP log format (equivalent to ``option tcplog``):
#   %ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq
_RE_HAPROXY_TCP = re.compile(
    r"(?P<ip>"
    r"\d{1,3}(?:\.\d{1,3}){3}"
    r"|\[[0-9a-fA-F:]+\]"
    r")(?::\d+)?\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r"\S+~?\s+"
    r"\S+/\S+\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"\S+\s+"
    r"\s*$",
)

# HAProxy connection-level SSL handshake failure (logged independently of the
# access-log format — emitted by the TLS layer before HTTP processing). Repeated
# failures from one IP indicate cipher/TLS scanning.
_RE_HAPROXY_SSL_FAIL = re.compile(
    r"(?P<ip>"
    r"\d{1,3}(?:\.\d{1,3}){3}"
    r"|\[[0-9a-fA-F:]+\]"
    r")(?::\d+)?\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r"\S+:\s+SSL handshake failure"
)

# Syslog timestamp: "Apr 28 10:33:01"
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


def _parse_syslog_timestamp(line: str) -> float | None:
    """Extract a UNIX timestamp from a syslog-style line prefix."""
    m = _RE_SYSLOG_TS.match(line)
    if not m:
        return None
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


def _parse_apache_timestamp(ts_str: str) -> float | None:
    """Parse Apache/HAProxy timestamp to UNIX epoch.

    Handles Apache CLF ('07/May/2026:21:27:43 +0000'),
    HAProxy %tr/%t ('12/Jun/2026:15:29:48.886'),
    and plain datetime without milliseconds or timezone.
    """
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


def parse_apache(line: str) -> ParsedLine | None:
    """Parse Apache Combined Log Format lines."""
    m = _RE_APACHE_COMBINED.match(line)
    if m:
        ip = m.group("ip")
        status = m.group("status")
        ts_str = m.group("timestamp")
        timestamp = _parse_apache_timestamp(ts_str)

        # Scanner UA takes priority as the parser name
        if _RE_SCANNER_UA.search(line):
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


def _haproxy_parser_name(
    status_str: str | None,
    line: str,
    user_agent: str | None = None,
) -> str:
    """Derive HAProxy sub-parser name from HTTP status code."""
    if _RE_SCANNER_UA.search(user_agent if user_agent is not None else line):
        return "haproxy_scanner_ua"
    if status_str in ("401", "403"):
        return "haproxy"
    if status_str == "400":
        return "haproxy_bad_request"
    if status_str == "404":
        return "haproxy_not_found"
    return "haproxy_other"


def parse_haproxy(line: str) -> ParsedLine | None:
    """Parse HAProxy HTTP or TCP log format lines."""
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

    m = _RE_HAPROXY_SSL_FAIL.match(stripped)
    if m:
        return ParsedLine(
            parser="haproxy_ssl_fail",
            source_ip=m.group("ip"),
            raw=line,
            timestamp=_parse_apache_timestamp(m.group("timestamp")),
        )

    return None


# --- Auditd minimal parser for server-side rule testing ---

# Regex to parse the auditd log line envelope:
#   type=RECORDTYPE msg=audit(TIMESTAMP:SERIAL): BODY
_RE_AUDITD_LINE = re.compile(r"^type=(\w+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)")

# Regex to match an unquoted hex string (even length, all hex chars).
_RE_HEX_VALUE = re.compile(r"^[0-9A-Fa-f]+$")

# ASCII Record Separator — used as field delimiter in flattened output.
_RS = "\x1e"


def _auditd_decode_hex(value: str) -> str:
    """Decode a hex-encoded auditd field value to UTF-8.

    If value is unquoted and matches ^[0-9A-Fa-f]+$ with even length,
    decode via bytes.fromhex(). Otherwise return value unchanged.
    """
    if not value:
        return value
    if value.startswith('"') or value.startswith("'"):
        return value
    if len(value) % 2 != 0:
        return value
    if not _RE_HEX_VALUE.match(value):
        return value
    try:
        return bytes.fromhex(value).decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return value


def _auditd_parse_kv(body: str) -> dict[str, str]:
    """Parse a key=value auditd record body into a dict.

    Handles quoted values (e.g., exe="/bin/bash") and unquoted values.
    """
    result: dict[str, str] = {}
    i = 0
    n = len(body)
    while i < n:
        while i < n and body[i] == " ":
            i += 1
        if i >= n:
            break
        eq_pos = body.find("=", i)
        if eq_pos == -1:
            break
        key = body[i:eq_pos]
        i = eq_pos + 1
        if i < n and body[i] == '"':
            i += 1
            end_quote = body.find('"', i)
            if end_quote == -1:
                value = body[i:]
                i = n
            else:
                value = body[i:end_quote]
                i = end_quote + 1
        else:
            space_pos = body.find(" ", i)
            if space_pos == -1:
                value = body[i:]
                i = n
            else:
                value = body[i:space_pos]
                i = space_pos
        result[key] = value
    return result


def _auditd_decode_execve(body: str) -> str | None:
    """Parse an EXECVE record body and return the concatenated command line."""
    fields = _auditd_parse_kv(body)
    args: list[str] = []
    idx = 0
    while True:
        key = f"a{idx}"
        if key not in fields:
            break
        raw_val = fields[key]
        decoded = _auditd_decode_hex(raw_val)
        args.append(decoded)
        idx += 1
    if not args:
        return None
    return " ".join(args)


def _auditd_decode_proctitle(body: str) -> str | None:
    """Decode the hex-encoded PROCTITLE field."""
    fields = _auditd_parse_kv(body)
    proctitle_hex = fields.get("proctitle")
    if not proctitle_hex:
        return None
    if not _RE_HEX_VALUE.match(proctitle_hex):
        return proctitle_hex
    if len(proctitle_hex) % 2 != 0:
        return None
    try:
        raw_bytes = bytes.fromhex(proctitle_hex)
        return raw_bytes.replace(b"\x00", b" ").decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return None


def parse_auditd(line: str) -> ParsedLine | None:
    """Minimal auditd parser for rule testing.

    Extracts key fields from auditd lines and builds a flattened string
    for regex matching using the \\x1e separator pattern. This duplicates
    just enough of the agent-side parser to enable the test-rule-match UI
    to validate auditd rules against sample auditd log input.

    Returns a ParsedLine where:
      - parser = "auditd"
      - source_ip = "" (auditd events are host-based, no IP)
      - raw = flattened field string for regex matching
      - timestamp = audit timestamp (epoch float)
    """
    line = line.strip()
    m = _RE_AUDITD_LINE.match(line)
    if not m:
        return None

    record_type = m.group(1)
    try:
        timestamp = float(m.group(2))
    except (ValueError, OverflowError):
        return None
    body = m.group(4)

    # For simple single-line testing, parse the SYSCALL record to extract fields
    # and build a flattened string suitable for regex matching.
    if record_type == "SYSCALL":
        fields = _auditd_parse_kv(body)
        exe = _auditd_decode_hex(fields.get("exe", "").strip('"'))
        comm = fields.get("comm", "").strip('"')
        pid = fields.get("pid", "0")
        ppid = fields.get("ppid", "0")
        uid = fields.get("uid", "0")
        auid = fields.get("auid", "0")
        euid = fields.get("euid", "0")

        # Build flattened string using \x1e separator (same as HostEvent.flattened())
        flattened = _RS.join(
            [
                f"exe={exe}",
                f"cmdline={comm}",
                f"comm={comm}",
                "cwd=",
                f"uid={uid}",
                f"auid={auid}",
                f"euid={euid}",
                f"pid={pid}",
                f"ppid={ppid}",
            ]
        )
        return ParsedLine(
            parser="auditd",
            source_ip="",
            raw=flattened,
            timestamp=timestamp,
        )

    elif record_type == "EXECVE":
        cmdline = _auditd_decode_execve(body)
        if cmdline:
            flattened = _RS.join(
                [
                    "exe=",
                    f"cmdline={cmdline}",
                    "comm=",
                    "cwd=",
                    "uid=0",
                    "auid=0",
                    "euid=0",
                    "pid=0",
                    "ppid=0",
                ]
            )
            return ParsedLine(
                parser="auditd",
                source_ip="",
                raw=flattened,
                timestamp=timestamp,
            )

    elif record_type == "PROCTITLE":
        cmdline = _auditd_decode_proctitle(body)
        if cmdline:
            flattened = _RS.join(
                [
                    "exe=",
                    f"cmdline={cmdline}",
                    "comm=",
                    "cwd=",
                    "uid=0",
                    "auid=0",
                    "euid=0",
                    "pid=0",
                    "ppid=0",
                ]
            )
            return ParsedLine(
                parser="auditd",
                source_ip="",
                raw=flattened,
                timestamp=timestamp,
            )

    # For other record types (CWD, PATH), return a basic parsed result
    # so detect_log_format counts them as auditd lines
    return ParsedLine(
        parser="auditd",
        source_ip="",
        raw=line,
        timestamp=timestamp,
    )


PARSERS: dict[str, Callable[[str], ParsedLine | None]] = {
    "secure": parse_secure,
    "messages": parse_messages,
    "apache": parse_apache,
    "haproxy": parse_haproxy,
    "auditd": parse_auditd,
}


# --- SlidingWindowDetector from vespid/detectors.py ---


@dataclass
class Detection:
    rule: BruteForceRule
    source_ip: str
    attempts: int
    first_seen: float
    last_seen: float
    contributing_lines: list[tuple[float, int, str]] = field(default_factory=list)


class SlidingWindowDetector:
    """One detector instance can host many rules."""

    def __init__(self, rules: Iterable[BruteForceRule]) -> None:
        self.rules: list[BruteForceRule] = list(rules)
        # Buckets now store (timestamp, line_number, raw_line) tuples
        self._buckets: dict[tuple[str, str], deque[tuple[float, int, str]]] = defaultdict(deque)
        self._cooldown: dict[str, dict[str, float]] = defaultdict(dict)
        self.cooldown_seconds = 300

    def record(
        self,
        *,
        parser: str,
        source_ip: str,
        timestamp: float | None = None,
        raw_line: str = "",
        line_number: int = 0,
    ) -> list[Detection]:
        """Record an attempt and return any rules that just tripped."""
        ts = timestamp if timestamp is not None else time.time()
        fired: list[Detection] = []

        for rule in self.rules:
            if rule.parser != parser:
                continue

            cd = self._cooldown[rule.name].get(source_ip, 0.0)
            if ts < cd:
                continue

            key = (rule.name, source_ip)
            bucket = self._buckets[key]
            bucket.append((ts, line_number, raw_line))

            cutoff = ts - rule.window_seconds
            while bucket and bucket[0][0] < cutoff:
                bucket.popleft()

            if len(bucket) >= rule.max_attempts:
                fired.append(
                    Detection(
                        rule=rule,
                        source_ip=source_ip,
                        attempts=len(bucket),
                        first_seen=bucket[0][0],
                        last_seen=bucket[-1][0],
                        contributing_lines=list(bucket),
                    )
                )
                self._cooldown[rule.name][source_ip] = ts + self.cooldown_seconds
                bucket.clear()

        return fired


# --- CustomRuleEngine from vespid/log_processor.py ---


@dataclass
class _CompiledCustomRule:
    """Internal representation of a validated, compiled custom rule."""

    rule: CustomRule
    compiled: re.Pattern
    parser_name: str


class CustomRuleEngine:
    """Compiles user-defined regex rules and evaluates them against log lines."""

    def __init__(self, custom_rules: list[CustomRule]) -> None:
        self._rules: list[_CompiledCustomRule] = []
        for cr in custom_rules:
            if not cr.enabled:
                continue
            try:
                compiled = re.compile(cr.regex)
            except re.error:
                continue
            # Auditd rules do not require (?P<ip>) group (Req 3.3)
            if "auditd" not in cr.log_sources and "ip" not in compiled.groupindex:
                continue
            parser_name = f"custom:{cr.name}"
            self._rules.append(
                _CompiledCustomRule(rule=cr, compiled=compiled, parser_name=parser_name)
            )

    @property
    def brute_force_rules(self) -> list[BruteForceRule]:
        """Generate BruteForceRule entries for the SlidingWindowDetector."""
        return [
            BruteForceRule(
                name=r.rule.name,
                event_type=r.rule.event_type,
                max_attempts=r.rule.max_attempts,
                window_seconds=r.rule.window_seconds,
                parser=r.parser_name,
            )
            for r in self._rules
        ]

    def evaluate(
        self,
        line: str,
        source_parser: str,
    ) -> list[ParsedLine]:
        """Run all applicable custom rules against a log line."""
        effective_sources = {source_parser}
        if source_parser.startswith("apache"):
            effective_sources.add("apache")
        if source_parser.startswith("haproxy"):
            effective_sources.add("haproxy")

        results: list[ParsedLine] = []
        for cr in self._rules:
            if "*" not in cr.rule.log_sources and not effective_sources.intersection(
                cr.rule.log_sources
            ):
                continue
            m = cr.compiled.search(line)
            if m:
                # Auditd rules have no (?P<ip>) group — use empty string
                if "auditd" in cr.rule.log_sources:
                    source_ip = ""
                else:
                    source_ip = m.group("ip")
                results.append(
                    ParsedLine(
                        parser=cr.parser_name,
                        source_ip=source_ip,
                        raw=line,
                        timestamp=_parse_syslog_timestamp(line),
                    )
                )
        return results


# --- CorrelationDetector from vespid/detectors.py ---


@dataclass
class CorrelationHit:
    """Represents a signal category observation for correlation tracking."""

    category: str
    timestamp: float
    raw_line: str = ""
    line_number: int = 0


@dataclass
class CorrelationDetection:
    """Fired when an IP triggers enough distinct signal categories."""

    rule: CorrelationRule
    source_ip: str
    categories_seen: list[str]
    first_seen: float
    last_seen: float
    contributing_hits: list[CorrelationHit] = field(default_factory=list)


class CorrelationDetector:
    """Detects multi-vector reconnaissance by correlating distinct signal types.

    Tracks how many *different* signal categories an IP triggers within a
    time window. This catches "low and slow" recon where an attacker probes
    multiple services/vectors but stays below any individual rule's threshold.
    """

    CATEGORY_MAP: dict[str, str] = {
        "secure": "ssh_auth_fail",
        "secure_recon_strong": "ssh_recon",
        "secure_recon_weak": "ssh_recon_weak",
        "secure_negotiate_fail": "ssh_negotiate",
        "apache": "http_auth_fail",
        "apache_bad_request": "http_bad_request",
        "apache_not_found": "http_probe",
        "apache_other": "http_other",
        "apache_scanner_ua": "http_scanner_ua",
        "messages": "firewall_deny",
    }

    def __init__(self, rules: Iterable[CorrelationRule]) -> None:
        self.rules: list[CorrelationRule] = list(rules)
        self._observations: dict[str, list[CorrelationHit]] = defaultdict(list)
        self._cooldown: dict[tuple[str, str], float] = {}
        self.cooldown_seconds = 300

    def _categorize(self, parser: str) -> str:
        """Map a parser name to a coarse signal category."""
        if parser.startswith("custom:"):
            return parser
        return self.CATEGORY_MAP.get(parser, parser)

    def record(
        self,
        *,
        parser: str,
        source_ip: str,
        timestamp: float | None = None,
        raw_line: str = "",
        line_number: int = 0,
    ) -> list[CorrelationDetection]:
        """Record an observation and check if any correlation rule fires.

        Deduplicates by line number: if the same log line is parsed by
        multiple parsers, only the first category observed for that line
        counts toward the correlation threshold. This prevents a single
        log event from inflating the distinct-category count.
        """
        ts = timestamp if timestamp is not None else time.time()
        category = self._categorize(parser)
        fired: list[CorrelationDetection] = []

        # Deduplicate: skip if we already recorded a hit for this IP + line_number
        if line_number > 0:
            existing = self._observations[source_ip]
            for prev in existing:
                if prev.line_number == line_number:
                    # Same line already contributed a category — skip
                    return fired

        self._observations[source_ip].append(
            CorrelationHit(
                category=category, timestamp=ts, raw_line=raw_line, line_number=line_number
            )
        )

        for rule in self.rules:
            if not rule.enabled:
                continue

            cd_key = (rule.name, source_ip)
            cd_until = self._cooldown.get(cd_key, 0.0)
            if ts < cd_until:
                continue

            cutoff = ts - rule.window_seconds
            obs = self._observations[source_ip]

            categories_in_window: set[str] = set()
            for hit in obs:
                if hit.timestamp >= cutoff:
                    categories_in_window.add(hit.category)

            if len(categories_in_window) >= rule.min_categories:
                relevant_hits = [
                    h for h in obs if h.timestamp >= cutoff and h.category in categories_in_window
                ]
                relevant_times = [h.timestamp for h in relevant_hits]
                fired.append(
                    CorrelationDetection(
                        rule=rule,
                        source_ip=source_ip,
                        categories_seen=sorted(categories_in_window),
                        first_seen=min(relevant_times),
                        last_seen=max(relevant_times),
                        contributing_hits=relevant_hits,
                    )
                )
                self._cooldown[cd_key] = ts + self.cooldown_seconds
                self._observations[source_ip] = []
                break

        return fired


# ===========================================================================
# Simulation data models
# ===========================================================================


@dataclass
class SimulatedMatch:
    """A single log line match produced by a parser or custom rule."""

    parser: str
    source_ip: str
    raw_line: str
    line_number: int
    timestamp: float | None = None


@dataclass
class MatchedLineInfo:
    """A single log line that contributed to a detection."""

    line_number: int
    raw_line: str
    category: str = ""


@dataclass
class SimulatedDetection:
    """A detection event when a rule's threshold is met during simulation."""

    rule_name: str
    event_type: str
    source_ip: str
    attempt_count: int
    window_seconds: int
    triggered_at_line: int
    timestamp: float | None = None
    order: int = 0
    matched_lines: list[MatchedLineInfo] = field(default_factory=list)


@dataclass
class SimulationResult:
    """Complete results from a simulation run."""

    simulation_id: str
    total_lines: int
    lines_processed: int
    total_matches: int
    total_detections: int
    unique_ips: set[str]
    elapsed_seconds: float
    skipped_lines: int
    cancelled: bool
    detected_parser: str | None
    detections: list[SimulatedDetection]
    matches: list[SimulatedMatch]
    per_rule_breakdown: list[dict] = field(default_factory=list)
    per_ip_breakdown: list[dict] = field(default_factory=list)
    per_rule_matches: list[dict] = field(default_factory=list)
    total_rules: int = 0


# ===========================================================================
# Helper functions
# ===========================================================================


def validate_file_extension(filename: str) -> bool:
    """Validate that a filename has an acceptable extension.

    Accepts .log, .txt, or extensionless files (no '.' in the basename).
    Rejects all other extensions.
    """
    if not filename:
        return False
    # Get the basename (last component of path)
    basename = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if "." not in basename:
        # Extensionless file — accepted
        return True
    # Get the extension (last dot and everything after)
    ext = basename.rsplit(".", 1)[-1].lower()
    return ext in ("log", "txt")


def format_file_size(size_bytes: int) -> str:
    """Format a file size in bytes to a human-readable string.

    Returns:
        - "{n} bytes" for sizes < 1024
        - "{n} KB" for sizes < 1048576 (rounded to 1 decimal)
        - "{n} MB" for sizes >= 1048576 (rounded to 1 decimal)
    """
    if size_bytes < 0:
        size_bytes = 0
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1048576:
        kb = round(size_bytes / 1024, 1)
        return f"{kb} KB"
    else:
        mb = round(size_bytes / 1048576, 1)
        return f"{mb} MB"


def compute_rule_count(selected_packs: list[dict], selected_rules: list[object]) -> int:
    """Compute the total number of rules from selected packs plus individual rules.

    Args:
        selected_packs: List of pack dicts, each with a "rules" key containing a list.
        selected_rules: List of individually selected brute force rules.

    Returns:
        Sum of rules in all selected packs plus the count of individual rules.
    """
    pack_rule_count = sum(len(pack.get("rules", [])) for pack in selected_packs)
    return pack_rule_count + len(selected_rules)


def filter_standalone_rules(
    all_brute_force_rules: list[BruteForceRule],
    packs: list[dict],
) -> list[BruteForceRule]:
    """Return brute force rules that are not part of any pack.

    Args:
        all_brute_force_rules: All available brute force rules.
        packs: List of pack dicts, each with a "rules" key containing rule dicts
               that have a "name" field.

    Returns:
        Rules whose names do not appear in any pack's rule list.
    """
    pack_rule_names: set[str] = set()
    for pack in packs:
        for rule in pack.get("rules", []):
            if isinstance(rule, dict):
                name = rule.get("name", "")
            else:
                # Support objects with a .name attribute
                name = getattr(rule, "name", "")
            if name:
                pack_rule_names.add(name)

    return [r for r in all_brute_force_rules if r.name not in pack_rule_names]


def detect_log_format(lines: list[str], max_sample: int = 10) -> tuple[str | None, dict[str, int]]:
    """Sample lines and determine the best parser for the log file.

    Samples up to max_sample lines and tries each parser. Returns the parser
    with the most matches if it has >= 3 matches. Ties are broken by priority
    order: secure, apache, messages.

    Args:
        lines: All lines from the log file.
        max_sample: Maximum number of lines to sample (default 10).

    Returns:
        A tuple of (detected_parser_name_or_None, {parser: match_count}).
        Returns (None, counts) if no parser matches >= 3 lines.
    """
    sample = lines[:max_sample]
    counts: dict[str, int] = {name: 0 for name in PARSERS}

    for line in sample:
        for parser_name, parser_fn in PARSERS.items():
            result = parser_fn(line)
            if result is not None:
                counts[parser_name] += 1

    # Priority order for tie-breaking
    priority = ["secure", "apache", "haproxy", "auditd", "messages"]

    best_parser: str | None = None
    best_count = 0

    min_matches = max(1, min(3, len(sample)))
    for name in priority:
        count = counts.get(name, 0)
        if count >= min_matches and count > best_count:
            best_parser = name
            best_count = count

    return (best_parser, counts)


def paginate_detections(
    detections: list[SimulatedDetection],
    page: int,
    page_size: int = 50,
) -> tuple[list[SimulatedDetection], int, int]:
    """Paginate a list of detections.

    Args:
        detections: Full list of detections.
        page: 1-based page number.
        page_size: Number of items per page (default 50).

    Returns:
        A tuple of (page_items, total_pages, current_page).
        - page_items: The detections for the requested page.
        - total_pages: Total number of pages (minimum 1).
        - current_page: The clamped page number (1-based).
    """
    total = len(detections)
    total_pages = max(1, math.ceil(total / page_size))

    # Clamp page to valid range
    current_page = max(1, min(page, total_pages))

    start = (current_page - 1) * page_size
    end = start + page_size

    return (detections[start:end], total_pages, current_page)


# ===========================================================================
# SimulationEngine — dry-run log processing
# ===========================================================================


class SimulationEngine:
    """Runs a log file through detection rules in dry-run mode.

    Creates isolated instances of SlidingWindowDetector and CustomRuleEngine
    with NO shared state, NO database persistence, NO blocking actions,
    NO DataBus publishing, and NO offset store modification.

    Progress is published by putting ``(event_name, payload_dict)`` tuples
    onto ``progress_queue`` (a ``queue.Queue`` owned by the caller). Callers
    must drain this queue; if it fills up, progress events are dropped
    silently. Pass ``None`` to disable progress reporting entirely.
    """

    def __init__(
        self,
        simulation_id: str,
        log_lines: list[str],
        brute_force_rules: list[BruteForceRule],
        custom_rules: list[CustomRule],
        detected_parser: str,
        progress_queue: queue.Queue | None = None,
        correlation_rules: list[CorrelationRule] | None = None,
    ) -> None:
        self.simulation_id = simulation_id
        self.log_lines = log_lines
        self.brute_force_rules = list(brute_force_rules)
        self.custom_rules = list(custom_rules)
        self.correlation_rules = list(correlation_rules or [])
        self.detected_parser = detected_parser
        self.progress_queue = progress_queue

        # Cancellation flag — checked between lines
        self._cancel_event = threading.Event()

        # Build the custom rule engine from custom rules
        self._custom_engine = CustomRuleEngine(self.custom_rules)

        # Combine brute force rules with those generated by the custom engine
        all_rules = self.brute_force_rules + self._custom_engine.brute_force_rules

        # Create a fresh SlidingWindowDetector — no shared state
        self._detector = SlidingWindowDetector(all_rules)

        # Create a fresh CorrelationDetector — no shared state
        self._correlation = CorrelationDetector(self.correlation_rules)

        # Select the parser function based on detected/overridden format
        self._parser_fn = PARSERS.get(self.detected_parser)

    def run(self) -> SimulationResult:
        """Process all lines and return results. Publishes progress via the
        configured progress_queue (if any).
        """
        start_time = time.time()
        simulation_start_ts = start_time

        matches: list[SimulatedMatch] = []
        detections: list[SimulatedDetection] = []
        detection_order = 0
        lines_processed = 0
        skipped_lines = 0
        last_timestamp: float | None = None
        last_progress_time = start_time

        total_lines = len(self.log_lines)

        for line_idx, line in enumerate(self.log_lines):
            # Check cancellation between lines
            if self._cancel_event.is_set():
                break

            line_number = line_idx + 1  # 1-based
            lines_processed = line_number
            line_matched = False

            # Parse the line with the detected parser
            parsed: ParsedLine | None = None
            if self._parser_fn is not None:
                parsed = self._parser_fn(line)

            if parsed is not None:
                # Apply timestamp fallback
                if parsed.timestamp is not None:
                    last_timestamp = parsed.timestamp
                else:
                    parsed.timestamp = (
                        last_timestamp if last_timestamp is not None else simulation_start_ts
                    )

                # Record the match
                matches.append(
                    SimulatedMatch(
                        parser=parsed.parser,
                        source_ip=parsed.source_ip,
                        raw_line=parsed.raw,
                        line_number=line_number,
                        timestamp=parsed.timestamp,
                    )
                )
                line_matched = True

                # Feed to the sliding window detector
                fired = self._detector.record(
                    parser=parsed.parser,
                    source_ip=parsed.source_ip,
                    timestamp=parsed.timestamp,
                    raw_line=parsed.raw,
                    line_number=line_number,
                )
                for det in fired:
                    detection_order += 1
                    detections.append(
                        SimulatedDetection(
                            rule_name=det.rule.name,
                            event_type=det.rule.event_type,
                            source_ip=det.source_ip,
                            attempt_count=det.attempts,
                            window_seconds=det.rule.window_seconds,
                            triggered_at_line=line_number,
                            timestamp=parsed.timestamp,
                            order=detection_order,
                            matched_lines=[
                                MatchedLineInfo(
                                    line_number=ln,
                                    raw_line=rl,
                                    category=det.rule.parser,
                                )
                                for _ts, ln, rl in det.contributing_lines
                            ],
                        )
                    )

            # Evaluate custom rules on the line
            source_parser = parsed.parser if parsed else self.detected_parser
            # For auditd sources, evaluate rules against the flattened string
            # (stored in parsed.raw) which uses \x1e separators for field matching.
            if source_parser == "auditd" and parsed is not None:
                eval_line = parsed.raw
            else:
                eval_line = _strip_syslog_prefix(line)
            custom_matches = self._custom_engine.evaluate(eval_line, source_parser)

            for cm in custom_matches:
                # Apply timestamp fallback for custom matches
                if cm.timestamp is not None:
                    last_timestamp = cm.timestamp
                else:
                    cm.timestamp = (
                        last_timestamp if last_timestamp is not None else simulation_start_ts
                    )

                matches.append(
                    SimulatedMatch(
                        parser=cm.parser,
                        source_ip=cm.source_ip,
                        raw_line=cm.raw,
                        line_number=line_number,
                        timestamp=cm.timestamp,
                    )
                )
                line_matched = True

                # Feed custom rule matches to the detector
                fired = self._detector.record(
                    parser=cm.parser,
                    source_ip=cm.source_ip,
                    timestamp=cm.timestamp,
                    raw_line=cm.raw,
                    line_number=line_number,
                )
                for det in fired:
                    detection_order += 1
                    detections.append(
                        SimulatedDetection(
                            rule_name=det.rule.name,
                            event_type=det.rule.event_type,
                            source_ip=det.source_ip,
                            attempt_count=det.attempts,
                            window_seconds=det.rule.window_seconds,
                            triggered_at_line=line_number,
                            timestamp=cm.timestamp,
                            order=detection_order,
                            matched_lines=[
                                MatchedLineInfo(
                                    line_number=ln,
                                    raw_line=rl,
                                    category=det.rule.parser,
                                )
                                for _ts, ln, rl in det.contributing_lines
                            ],
                        )
                    )

            # Feed all observations into the correlation detector.
            # Collect all parsers seen for this line (built-in + custom).
            _corr_parsers_seen: list[tuple[str, str, float | None]] = []
            if parsed is not None:
                _corr_parsers_seen.append((parsed.parser, parsed.source_ip, parsed.timestamp))
            for cm in custom_matches:
                _corr_parsers_seen.append((cm.parser, cm.source_ip, cm.timestamp))

            for _cp_parser, _cp_ip, _cp_ts in _corr_parsers_seen:
                corr_fired = self._correlation.record(
                    parser=_cp_parser,
                    source_ip=_cp_ip,
                    timestamp=_cp_ts,
                    raw_line=line,
                    line_number=line_number,
                )
                for corr in corr_fired:
                    detection_order += 1
                    detections.append(
                        SimulatedDetection(
                            rule_name=corr.rule.name,
                            event_type=corr.rule.event_type,
                            source_ip=corr.source_ip,
                            attempt_count=len(corr.categories_seen),
                            window_seconds=corr.rule.window_seconds,
                            triggered_at_line=line_number,
                            timestamp=_cp_ts,
                            order=detection_order,
                            matched_lines=[
                                MatchedLineInfo(
                                    line_number=h.line_number,
                                    raw_line=h.raw_line,
                                    category=h.category,
                                )
                                for h in corr.contributing_hits
                            ],
                        )
                    )

            if not line_matched:
                skipped_lines += 1

            # Publish progress every 100 lines or 500ms
            if self.progress_queue is not None:
                now = time.time()
                if line_number % 100 == 0 or (now - last_progress_time) >= 0.5:
                    pct = (line_number / total_lines) * 100 if total_lines > 0 else 100.0
                    try:
                        self.progress_queue.put_nowait(
                            (
                                "progress",
                                {
                                    "current": line_number,
                                    "total": total_lines,
                                    "pct": round(pct, 1),
                                },
                            )
                        )
                    except queue.Full:
                        pass
                    last_progress_time = now

        elapsed = time.time() - start_time
        cancelled = self._cancel_event.is_set()

        # Compute unique IPs from matches
        unique_ips: set[str] = {m.source_ip for m in matches}

        # Compute per-rule breakdown
        per_rule_breakdown = self._compute_per_rule_breakdown(detections)

        # Compute per-IP breakdown
        per_ip_breakdown = self._compute_per_ip_breakdown(matches, detections)

        # Compute per-rule match summary (rules that matched at least one line)
        per_rule_matches = self._compute_per_rule_matches(matches)

        return SimulationResult(
            simulation_id=self.simulation_id,
            total_lines=total_lines,
            lines_processed=lines_processed,
            total_matches=len(matches),
            total_detections=len(detections),
            unique_ips=unique_ips,
            elapsed_seconds=elapsed,
            skipped_lines=skipped_lines,
            cancelled=cancelled,
            detected_parser=self.detected_parser,
            detections=detections,
            matches=matches,
            per_rule_breakdown=per_rule_breakdown,
            per_ip_breakdown=per_ip_breakdown,
            per_rule_matches=per_rule_matches,
            total_rules=len(self._custom_engine._rules) + len(self.brute_force_rules),
        )

    def cancel(self) -> None:
        """Signal the engine to stop processing."""
        self._cancel_event.set()

    @staticmethod
    def _compute_per_rule_breakdown(
        detections: list[SimulatedDetection],
    ) -> list[dict]:
        """Compute per-rule breakdown sorted by trigger_count descending.

        Each entry: {rule_name, trigger_count, distinct_ips}.
        """
        rule_data: dict[str, dict[str, Any]] = {}
        for det in detections:
            if det.rule_name not in rule_data:
                rule_data[det.rule_name] = {
                    "rule_name": det.rule_name,
                    "trigger_count": 0,
                    "distinct_ips": set(),
                }
            rule_data[det.rule_name]["trigger_count"] += 1
            rule_data[det.rule_name]["distinct_ips"].add(det.source_ip)

        result = sorted(
            rule_data.values(),
            key=lambda x: x["trigger_count"],
            reverse=True,
        )
        return list(result)

    @staticmethod
    def _compute_per_rule_matches(
        matches: list[SimulatedMatch],
    ) -> list[dict]:
        """Compute per-rule match summary from custom rule matches only.

        Extracts rule names from matches where the parser starts with
        ``custom:`` (i.e. matches produced by CustomRuleEngine.evaluate).
        Each entry: {rule_name, match_count, distinct_ips}.
        Sorted by match_count descending.
        """
        rule_data: dict[str, dict[str, Any]] = {}
        for m in matches:
            if not m.parser.startswith("custom:"):
                continue
            rule_name = m.parser[len("custom:") :]
            if rule_name not in rule_data:
                rule_data[rule_name] = {
                    "rule_name": rule_name,
                    "match_count": 0,
                    "distinct_ips": set(),
                }
            rule_data[rule_name]["match_count"] += 1
            rule_data[rule_name]["distinct_ips"].add(m.source_ip)

        result = sorted(
            rule_data.values(),
            key=lambda x: x["match_count"],
            reverse=True,
        )
        return list(result)

    @staticmethod
    def _compute_per_ip_breakdown(
        matches: list[SimulatedMatch],
        detections: list[SimulatedDetection],
    ) -> list[dict]:
        """Compute per-IP breakdown sorted by match_count descending.

        Each entry: {source_ip, match_count, rules_fired}.
        """
        ip_match_count: dict[str, int] = defaultdict(int)
        ip_rules_fired: dict[str, set[str]] = defaultdict(set)

        for m in matches:
            ip_match_count[m.source_ip] += 1

        for det in detections:
            ip_rules_fired[det.source_ip].add(det.rule_name)

        result = []
        for ip, count in ip_match_count.items():
            result.append(
                {
                    "source_ip": ip,
                    "match_count": count,
                    "rules_fired": ip_rules_fired.get(ip, set()),
                }
            )

        result.sort(key=lambda x: x["match_count"], reverse=True)
        return result


# ===========================================================================
# SimulationSSEManager — per-simulation SSE connections
# ===========================================================================


class SimulationSSEManager:
    """Manages SSE connections for simulation runs.

    Each simulation has at most one connected SSE client (the browser tab
    running the simulation). Messages are keyed by simulation_id and pushed
    to the corresponding client queue.

    Thread-safe: all access to internal state is protected by a lock.

    Requirements: 5.1, 5.2, 5.5
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Map of simulation_id -> set of client queues
        self._clients: dict[str, set[queue.Queue]] = defaultdict(set)

    @staticmethod
    def _format_sse(event: str, data: str) -> str:
        """Format an SSE message with event type and data.

        SSE message format:
            event: <event_type>
            data: <line1>
            data: <line2>
            ...

            (terminated by a blank line)
        """
        lines = data.split("\n")
        data_section = "\n".join(f"data: {line}" for line in lines)
        return f"event: {event}\n{data_section}\n\n"

    def publish_progress(self, sim_id: str, current: int, total: int, pct: float) -> None:
        """Publish a progress SSE event for a simulation.

        Args:
            sim_id: The simulation identifier.
            current: Number of lines processed so far.
            total: Total number of lines in the log file.
            pct: Percentage complete (0.0 to 100.0).
        """
        data = json.dumps({"current": current, "total": total, "pct": round(pct, 1)})
        message = self._format_sse("progress", data)
        self._broadcast(sim_id, message)

    def publish_result(self, sim_id: str, html: str) -> None:
        """Publish the final results SSE event for a simulation.

        Args:
            sim_id: The simulation identifier.
            html: Rendered HTML fragment containing the results.
        """
        message = self._format_sse("result", html)
        self._broadcast(sim_id, message)

    def publish_cancelled(self, sim_id: str, lines_processed: int, html: str) -> None:
        """Publish a cancellation SSE event for a simulation.

        Args:
            sim_id: The simulation identifier.
            lines_processed: Number of lines processed before cancellation.
            html: Rendered HTML fragment containing partial results.
        """
        data = json.dumps({"lines_processed": lines_processed, "html": html})
        message = self._format_sse("cancelled", data)
        self._broadcast(sim_id, message)

    def create_client(self, sim_id: str) -> queue.Queue:
        """Create and register a client queue for a simulation.

        Args:
            sim_id: The simulation identifier.

        Returns:
            A per-client queue that will receive SSE-formatted messages.
            The caller must call :meth:`remove_client` when done.
        """
        client_queue: queue.Queue = queue.Queue(maxsize=1000)
        with self._lock:
            self._clients[sim_id].add(client_queue)
        return client_queue

    def remove_client(self, sim_id: str, client_queue: queue.Queue) -> None:
        """Unregister a client queue for a simulation.

        Args:
            sim_id: The simulation identifier.
            client_queue: The queue previously returned by :meth:`create_client`.
        """
        with self._lock:
            if sim_id in self._clients:
                self._clients[sim_id].discard(client_queue)
                # Clean up empty sets
                if not self._clients[sim_id]:
                    del self._clients[sim_id]

    def _broadcast(self, sim_id: str, message: str) -> None:
        """Send a message to all clients connected to a simulation.

        Removes any client whose queue is full (assumed disconnected).
        """
        with self._lock:
            if sim_id not in self._clients:
                return

            dead_clients: list[queue.Queue] = []
            for client_queue in self._clients[sim_id]:
                try:
                    client_queue.put_nowait(message)
                except queue.Full:
                    dead_clients.append(client_queue)

            for dead in dead_clients:
                self._clients[sim_id].discard(dead)

            if not self._clients[sim_id]:
                del self._clients[sim_id]
