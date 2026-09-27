"""Auditd log line parser and event assembly.

Provides functions to parse individual auditd log lines and assemble
grouped records into HostEvent objects.
"""

from __future__ import annotations

import logging
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any

from vespid.auditd.events import HostEvent

logger = logging.getLogger(__name__)

# Regex to parse the auditd log line envelope:
#   type=RECORDTYPE msg=audit(TIMESTAMP:SERIAL): BODY
_LINE_RE = re.compile(r"^type=(\w+)\s+msg=audit\((\d+\.\d+):(\d+)\):\s*(.*)")

# Regex to match an unquoted hex string (even length, all hex chars).
_HEX_VALUE_RE = re.compile(r"^[0-9A-Fa-f]+$")


def parse_auditd_line(line: str) -> tuple[str, float, int, str] | None:
    """Extract (record_type, timestamp, serial, body) from a single auditd line.

    Returns None for unparseable lines.
    """
    line = line.strip()
    m = _LINE_RE.match(line)
    if not m:
        return None
    record_type = m.group(1)
    try:
        timestamp = float(m.group(2))
        serial = int(m.group(3))
    except (ValueError, OverflowError):
        return None
    body = m.group(4)
    return (record_type, timestamp, serial, body)


def _decode_hex_exe(value: str) -> str:
    """Detect and decode hex-encoded exe values (Req 1.12).

    If value is unquoted and matches pattern ^[0-9A-Fa-f]+$ with even length,
    decode via bytes.fromhex(value).decode('utf-8', errors='replace').
    Otherwise return value unchanged.
    """
    if not value:
        return value
    # Quoted values are never hex-encoded
    if value.startswith('"') or value.startswith("'"):
        return value
    if len(value) % 2 != 0:
        return value
    if not _HEX_VALUE_RE.match(value):
        return value
    try:
        return bytes.fromhex(value).decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return value


def _parse_key_value_body(body: str) -> dict[str, str]:
    """Parse a key=value auditd record body into a dict.

    Handles quoted values (e.g., exe="/bin/bash") and unquoted values.
    """
    result: dict[str, str] = {}
    i = 0
    n = len(body)
    while i < n:
        # Skip whitespace
        while i < n and body[i] == " ":
            i += 1
        if i >= n:
            break
        # Find key
        eq_pos = body.find("=", i)
        if eq_pos == -1:
            break
        key = body[i:eq_pos]
        i = eq_pos + 1
        # Parse value
        if i < n and body[i] == '"':
            # Quoted value — find closing quote
            i += 1  # skip opening quote
            end_quote = body.find('"', i)
            if end_quote == -1:
                # Malformed — take rest of string
                value = body[i:]
                i = n
            else:
                value = body[i:end_quote]
                i = end_quote + 1
        else:
            # Unquoted value — find next space or end
            space_pos = body.find(" ", i)
            if space_pos == -1:
                value = body[i:]
                i = n
            else:
                value = body[i:space_pos]
                i = space_pos
        result[key] = value
    return result


def _decode_execve_args(body: str) -> str | None:
    """Parse an EXECVE record body and return the concatenated command line.

    Decodes hex-encoded arguments (unquoted hex values with even length).
    Returns None if the body is malformed.
    """
    fields = _parse_key_value_body(body)
    argc_str = fields.get("argc")
    if argc_str is None:
        # Try to just collect all a* fields even without argc
        pass
    else:
        try:
            int(argc_str)
        except (ValueError, TypeError):
            return None

    # Collect arguments in order: a0, a1, a2, ...
    args: list[str] = []
    idx = 0
    while True:
        key = f"a{idx}"
        if key not in fields:
            break
        raw_val = fields[key]
        # Decode hex-encoded arguments: if unquoted and matches hex pattern
        decoded = _decode_hex_exe(raw_val)
        args.append(decoded)
        idx += 1

    if not args:
        return None
    return " ".join(args)


def _decode_proctitle(body: str) -> str | None:
    """Decode the hex-encoded PROCTITLE field.

    The proctitle field is hex-encoded: each byte pair is a hex value,
    NUL (00) separates arguments → decode to spaces.
    Returns None if malformed.
    """
    fields = _parse_key_value_body(body)
    proctitle_hex = fields.get("proctitle")
    if not proctitle_hex:
        return None
    # Some systems may produce "(null)" or other non-hex values
    if not _HEX_VALUE_RE.match(proctitle_hex):
        # Not hex — might be a plain string like "(null)"
        return proctitle_hex
    if len(proctitle_hex) % 2 != 0:
        return None
    try:
        raw_bytes = bytes.fromhex(proctitle_hex)
        # NUL bytes separate arguments — replace with spaces
        return raw_bytes.replace(b"\x00", b" ").decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return None


def assemble_to_host_event(records: dict[str, Any], hostname: str) -> HostEvent | None:
    """Convert a complete set of assembled records into a HostEvent.

    Returns None if SYSCALL record missing or syscall != 59 (execve).

    Multi-line EXECVE handling (Req 1.11): When records["EXECVE"] is a list,
    accumulates all argument fields across lines in record order.

    Hex-encoded exe detection (Req 1.12): Calls _decode_hex_exe() on the exe
    value extracted from the SYSCALL record before storing in HostEvent.
    """
    # --- SYSCALL record (required) ---
    syscall_body = records.get("SYSCALL")
    if syscall_body is None:
        return None
    if isinstance(syscall_body, list):
        syscall_body = syscall_body[0]

    try:
        syscall_fields = _parse_key_value_body(syscall_body)
    except Exception:
        logger.warning("Malformed SYSCALL record body, skipping event")
        return None

    # Must be execve (syscall=59)
    syscall_num = syscall_fields.get("syscall")
    if syscall_num is None:
        return None
    try:
        if int(syscall_num) != 59:
            return None
    except (ValueError, TypeError):
        return None

    # Extract fields from SYSCALL
    try:
        pid = int(syscall_fields.get("pid", "0"))
        ppid = int(syscall_fields.get("ppid", "0"))
        uid = int(syscall_fields.get("uid", "0"))
        auid = int(syscall_fields.get("auid", "-1"))
        euid = int(syscall_fields.get("euid", "-1"))
    except (ValueError, TypeError) as e:
        logger.warning("Malformed numeric field in SYSCALL record: %s", e)
        return None

    comm = syscall_fields.get("comm", "")
    exe_raw = syscall_fields.get("exe", "")
    exe = _decode_hex_exe(exe_raw)

    # Extract timestamp from the records metadata if available,
    # otherwise fall back to 0.0 (caller should set it from parse result)
    timestamp = 0.0
    # Check if we have a _timestamp key (set by assembler)
    if "_timestamp" in records:
        ts_val = records["_timestamp"]
        if isinstance(ts_val, (int, float)):
            timestamp = float(ts_val)
        elif isinstance(ts_val, str):
            try:
                timestamp = float(ts_val)
            except (ValueError, TypeError):
                pass

    # --- CWD record ---
    cwd = ""
    cwd_body = records.get("CWD")
    if cwd_body is not None:
        if isinstance(cwd_body, list):
            cwd_body = cwd_body[0]
        try:
            cwd_fields = _parse_key_value_body(cwd_body)
            cwd = cwd_fields.get("cwd", "")
        except Exception:
            logger.warning("Malformed CWD record, using empty cwd")

    # --- PROCTITLE record ---
    proctitle_cmdline: str | None = None
    proctitle_body = records.get("PROCTITLE")
    if proctitle_body is not None:
        if isinstance(proctitle_body, list):
            proctitle_body = proctitle_body[0]
        try:
            proctitle_cmdline = _decode_proctitle(proctitle_body)
        except Exception:
            logger.warning("Malformed PROCTITLE record, skipping")

    # --- EXECVE record(s) ---
    execve_cmdline: str | None = None
    execve_data = records.get("EXECVE")
    if execve_data is not None:
        if isinstance(execve_data, str):
            # Single EXECVE line
            try:
                execve_cmdline = _decode_execve_args(execve_data)
            except Exception:
                logger.warning("Malformed EXECVE record, skipping")
        elif isinstance(execve_data, list):
            # Multi-line EXECVE (Req 1.11): accumulate all argument fields
            # across lines in record order. Arguments may continue numbering
            # from where the previous line left off (e.g., line 1 has a0,a1;
            # line 2 has a2,a3,a4).
            all_fields: dict[str, str] = {}
            for execve_body in execve_data:
                try:
                    fields = _parse_key_value_body(execve_body)
                except Exception:
                    logger.warning("Malformed EXECVE record line, skipping")
                    continue
                # Merge all a* fields from this line
                for k, v in fields.items():
                    if k.startswith("a") and k[1:].isdigit():
                        all_fields[k] = v

            # Collect arguments in ascending numeric order
            all_args: list[str] = []
            idx = 0
            while True:
                key = f"a{idx}"
                if key not in all_fields:
                    break
                raw_val = all_fields[key]
                decoded = _decode_hex_exe(raw_val)
                all_args.append(decoded)
                idx += 1
            if all_args:
                execve_cmdline = " ".join(all_args)

    # Prefer EXECVE over PROCTITLE (Req 1.6)
    command_line = ""
    if execve_cmdline:
        command_line = execve_cmdline
    elif proctitle_cmdline:
        command_line = proctitle_cmdline

    return HostEvent(
        hostname=hostname,
        timestamp=timestamp,
        pid=pid,
        ppid=ppid,
        uid=uid,
        auid=auid,
        euid=euid,
        exe=exe,
        command_line=command_line,
        comm=comm,
        cwd=cwd,
    )


# Record types accepted by the assembler (Req 2.4).
# Unrecognized types are silently ignored (Req 2.6).
ACCEPTED_TYPES = {"SYSCALL", "EXECVE", "PROCTITLE", "CWD", "PATH"}


@dataclass
class AssemblyBuffer:
    """Tracks partially assembled auditd records for one timestamp:serial pair."""

    key: tuple[float, int]  # (timestamp, serial)
    records: dict[str, Any] = field(default_factory=dict)
    last_seen: float = 0.0  # wall-clock time of last record addition
    record_count: int = 0  # total records added (for max_records enforcement)


class AuditdAssembler:
    """Stateful multi-line assembler for auditd records.

    Groups auditd log lines by their shared timestamp:serial key and flushes
    completed events based on inactivity timeout or buffer limits.
    """

    def __init__(
        self,
        flush_timeout: float = 2.0,
        max_records: int = 50,
        max_buffers: int = 100,
    ):
        self._flush_timeout = flush_timeout
        self._max_records = max_records
        self._max_buffers = max_buffers
        self._buffers: dict[tuple[float, int], AssemblyBuffer] = {}
        self._hostname: str = socket.gethostname()

    def feed(self, line: str) -> HostEvent | None:
        """Feed a raw line; may return a completed HostEvent if assembly triggers flush.

        Returns at most one HostEvent per call (the first flushed stale buffer
        that produces a valid event).
        """
        parsed = parse_auditd_line(line)
        if parsed is None:
            return None

        record_type, timestamp, serial, body = parsed

        # Silently ignore unrecognized types (Req 2.6)
        if record_type not in ACCEPTED_TYPES:
            return None

        now = time.time()
        key = (timestamp, serial)

        # Look up or create buffer for this key
        buf = self._buffers.get(key)
        if buf is None:
            # Enforce max_buffers limit (Req 2.7) — evict oldest before creating new
            if len(self._buffers) >= self._max_buffers:
                self._evict_oldest()
            buf = AssemblyBuffer(key=key)
            # Store the audit event timestamp so assemble_to_host_event can use it
            buf.records["_timestamp"] = str(timestamp)
            self._buffers[key] = buf

        # Add record to buffer
        if record_type == "EXECVE":
            # Multi-line EXECVE support (Req 1.11): accumulate as list
            existing = buf.records.get("EXECVE")
            if existing is None:
                buf.records["EXECVE"] = [body]
            elif isinstance(existing, list):
                existing.append(body)
            else:
                # Shouldn't happen, but handle gracefully
                buf.records["EXECVE"] = [existing, body]
        else:
            # For other types: last one wins if duplicated
            buf.records[record_type] = body

        buf.record_count += 1
        buf.last_seen = now

        # Enforce max_records per buffer (Req 2.5)
        if buf.record_count > self._max_records:
            # Flush and discard — don't produce an event
            del self._buffers[key]
            return None

        # Check all OTHER buffers for staleness and flush them (Req 2.2)
        result = self._flush_one_stale(now, exclude_key=key)
        return result

    def flush_stale(self, now: float | None = None) -> list[HostEvent]:
        """Flush any buffers that have exceeded the inactivity timeout.

        Returns a list of HostEvents (may be empty if events had no SYSCALL 59).
        """
        if now is None:
            now = time.time()

        results: list[HostEvent] = []
        stale_keys = [
            k for k, buf in self._buffers.items() if buf.last_seen + self._flush_timeout < now
        ]

        for key in stale_keys:
            buf = self._buffers.pop(key)
            event = assemble_to_host_event(buf.records, self._hostname)
            if event is not None:
                results.append(event)

        return results

    def _flush_one_stale(
        self, now: float, exclude_key: tuple[float, int] | None = None
    ) -> HostEvent | None:
        """Flush the first stale buffer found (excluding the given key).

        Returns the first non-None HostEvent produced, or None.
        """
        stale_keys = [
            k
            for k, buf in self._buffers.items()
            if k != exclude_key and buf.last_seen + self._flush_timeout < now
        ]

        for key in stale_keys:
            buf = self._buffers.pop(key)
            event = assemble_to_host_event(buf.records, self._hostname)
            if event is not None:
                return event

        return None

    def _evict_oldest(self) -> None:
        """Evict the oldest buffer (by last_seen) to make room for a new one.

        Discards without attempting to assemble (Req 2.7).
        """
        if not self._buffers:
            return
        oldest_key = min(self._buffers, key=lambda k: self._buffers[k].last_seen)
        del self._buffers[oldest_key]
