"""Pretty printer for HostEvent objects back into auditd log format.

Used for round-trip testing: pretty_print(event) produces lines that
parse_auditd_line + assemble_to_host_event can reconstruct into an
equivalent HostEvent.
"""

from __future__ import annotations

from vespid.auditd.events import HostEvent


def pretty_print(event: HostEvent, serial: int = 1) -> list[str]:
    """Format a HostEvent back into auditd log lines.

    Returns a list of lines: [SYSCALL, EXECVE, CWD, PROCTITLE].
    All lines share the same msg=audit(timestamp:serial).
    Used for round-trip testing.

    Args:
        event: The HostEvent to format.
        serial: The serial number for the audit message identifier.

    Returns:
        A list of four auditd log lines.
    """
    ts = f"{event.timestamp:.3f}"
    msg = f"msg=audit({ts}:{serial})"

    syscall_line = _format_syscall(event, msg)
    execve_line = _format_execve(event, msg)
    cwd_line = _format_cwd(event, msg)
    proctitle_line = _format_proctitle(event, msg)

    return [syscall_line, execve_line, cwd_line, proctitle_line]


def _format_syscall(event: HostEvent, msg: str) -> str:
    """Produce a SYSCALL line with key fields from the HostEvent."""
    parts = [
        f"type=SYSCALL {msg}:",
        "arch=c000003e",
        "syscall=59",
        "success=yes",
        "exit=0",
        f"pid={event.pid}",
        f"ppid={event.ppid}",
        f"uid={event.uid}",
        f"gid={event.uid}",
        f"euid={event.euid}",
        f"auid={event.auid}",
        f'comm="{event.comm}"',
        f'exe="{event.exe}"',
    ]
    return " ".join(parts)


def _format_execve(event: HostEvent, msg: str) -> str:
    """Produce an EXECVE line with argc and individual argument fields.

    Arguments are always quoted in the pretty printer output for consistency.
    The parser handles both quoted and unquoted values.
    """
    if event.command_line:
        args = event.command_line.split(" ")
    else:
        args = []

    argc = len(args)
    parts = [f"type=EXECVE {msg}:", f"argc={argc}"]
    for i, arg in enumerate(args):
        # Always quote arguments for consistency (parser handles quoted values)
        parts.append(f'a{i}="{arg}"')

    return " ".join(parts)


def _format_cwd(event: HostEvent, msg: str) -> str:
    """Produce a CWD line with the cwd value (empty string if absent)."""
    return f'type=CWD {msg}: cwd="{event.cwd}"'


def _format_proctitle(event: HostEvent, msg: str) -> str:
    """Produce a PROCTITLE line with hex-encoded command_line.

    The command_line is split on spaces, joined with NUL bytes,
    then hex-encoded. This is the inverse of the parser's PROCTITLE
    decoding (which hex-decodes and replaces NUL with space).
    """
    if event.command_line:
        # Split on spaces → join with NUL bytes → hex encode
        args = event.command_line.split(" ")
        nul_separated = b"\x00".join(a.encode("utf-8") for a in args)
        hex_value = nul_separated.hex()
    else:
        hex_value = ""

    return f"type=PROCTITLE {msg}: proctitle={hex_value}"
