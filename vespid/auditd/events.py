"""HostEvent: immutable representation of a single process execution event.

Extracted from assembled auditd records (SYSCALL, EXECVE, PROCTITLE, CWD).
"""

from __future__ import annotations

from dataclasses import dataclass

# ASCII Record Separator — used as field delimiter in flattened() output.
# Cannot appear in normal auditd field values, preventing cross-field regex
# matches (Req 3.12).
_RS = "\x1e"


@dataclass(frozen=True)
class HostEvent:
    """Immutable representation of a single process execution event."""

    hostname: str
    timestamp: float  # epoch seconds (float with ms precision)
    pid: int
    ppid: int
    uid: int
    auid: int
    euid: int = -1
    exe: str = ""  # e.g. "/usr/bin/curl"
    command_line: str = ""  # full command with args
    comm: str = ""  # short command name
    cwd: str = ""  # working directory, empty if CWD record absent

    def flattened(self) -> str:
        """Return a single string combining all fields for regex matching.

        Uses ASCII record separator (\\x1e) between field name-value pairs
        (Req 3.12).  This prevents false regex matches across field boundaries
        — e.g., an exe path containing "cmdline=" will not cause a regex
        targeting command_line to match.

        Format example:
            'exe=/bin/bash\\x1ecmdline=bash -i\\x1ecomm=bash\\x1ecwd=/tmp\\x1e'
            'uid=33\\x1eauid=33\\x1eeuid=33\\x1epid=1234\\x1eppid=1000'

        Note: parent_exe and parent_command_line are NOT included here —
        those are appended by the HostDetector at evaluation time after
        resolving the ProcessTree.
        """
        return _RS.join(
            [
                f"exe={self.exe}",
                f"cmdline={self.command_line}",
                f"comm={self.comm}",
                f"cwd={self.cwd}",
                f"uid={self.uid}",
                f"auid={self.auid}",
                f"euid={self.euid}",
                f"pid={self.pid}",
                f"ppid={self.ppid}",
            ]
        )
