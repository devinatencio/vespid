"""Auditd prerequisite checking for Vespid.

Verifies that auditd has execve audit rules configured so that
process creation events will be generated. This check is purely
advisory — it never raises exceptions or blocks startup.
"""

from __future__ import annotations

import glob
import logging
import subprocess

logger = logging.getLogger(__name__)

_EXAMPLE_RULE = "auditctl -a always,exit -F arch=b64 -S execve -a always,exit -F arch=b32 -S execve"


def check_auditd_prerequisites() -> bool:
    """Check if auditd has execve audit rules configured.

    Returns True if rules found, False otherwise.
    Logs appropriate warning when rules are missing.
    Never raises exceptions — always returns a boolean.
    """
    try:
        return _check_prerequisites_inner()
    except Exception:
        # Catch-all: never let this function raise
        logger.warning(
            "Auditd prerequisite check failed unexpectedly. "
            "Continuing startup without confirmation of execve rules."
        )
        return False


def _check_prerequisites_inner() -> bool:
    """Internal implementation of the prerequisite check."""
    # Step 1: Try running auditctl -l
    if _check_via_auditctl():
        return True

    # Step 2: Fall back to reading rules files
    if _check_via_rules_files():
        return True

    # No execve rules found anywhere
    logger.warning(
        "No auditd execve rules detected. Process creation events will not "
        "be generated. Configure with: %s",
        _EXAMPLE_RULE,
    )
    return False


def _has_execve_rule(text: str) -> bool:
    """Check if text contains an execve-related audit rule.

    Looks for '-S execve' or '-S all' which would capture execve syscalls.
    """
    return "-S execve" in text or "-S all" in text


def _check_via_auditctl() -> bool:
    """Attempt to check prerequisites via auditctl -l.

    Returns True if execve rules found, False if auditctl fails or
    no execve rules are present in its output.
    """
    try:
        result = subprocess.run(
            ["auditctl", "-l"],
            capture_output=True,
            timeout=5,
            text=True,
        )
    except FileNotFoundError:
        logger.debug("auditctl binary not found, falling back to rules files.")
        return False
    except subprocess.TimeoutExpired:
        logger.debug("auditctl -l timed out, falling back to rules files.")
        return False
    except OSError as exc:
        logger.debug("auditctl -l failed with OSError: %s", exc)
        return False

    if result.returncode != 0:
        logger.debug(
            "auditctl -l returned non-zero exit code %d, falling back to rules files.",
            result.returncode,
        )
        return False

    if _has_execve_rule(result.stdout):
        logger.info("Auditd prerequisite satisfied: execve audit rules are loaded.")
        return True

    return False


def _check_via_rules_files() -> bool:
    """Fall back to scanning /etc/audit/rules.d/*.rules for execve rules.

    Returns True if execve rules found in any rules file.
    """
    rules_pattern = "/etc/audit/rules.d/*.rules"
    rules_files = glob.glob(rules_pattern)

    if not rules_files:
        logger.debug("No rules files found at %s", rules_pattern)
        return False

    for rules_file in rules_files:
        try:
            with open(rules_file, encoding="utf-8", errors="replace") as f:
                content = f.read()
            if _has_execve_rule(content):
                logger.info(
                    "Auditd prerequisite satisfied: execve rules found in %s.",
                    rules_file,
                )
                return True
        except OSError as exc:
            logger.debug("Could not read %s: %s", rules_file, exc)
            continue

    return False
