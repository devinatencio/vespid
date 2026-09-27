"""Custom rule engine — compiles user-defined regex rules from config.

Each enabled custom rule is compiled at init time. Rules with invalid
regex or missing ``(?P<ip>...)`` group are logged and skipped so one bad
rule cannot break the whole processor.

The engine also generates the ``BruteForceRule`` objects that feed into
the existing ``SlidingWindowDetector``, keeping the detection pipeline
unified.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from .config import BruteForceRule, CustomRule
from .log_parsers import ParsedLine, _parse_syslog_timestamp

log = logging.getLogger("vespid.logproc.custom_rules")


@dataclass
class _CompiledCustomRule:
    """Internal representation of a validated, compiled custom rule."""

    rule: CustomRule
    compiled: re.Pattern
    parser_name: str  # "custom:<rule_name>"


class CustomRuleEngine:
    """Compiles user-defined regex rules and evaluates them against log lines.

    Each enabled custom rule is compiled at init time.  Rules with invalid
    regex or missing ``(?P<ip>...)`` group are logged and skipped so one bad
    rule cannot break the whole processor.

    The engine also generates the ``BruteForceRule`` objects that feed into
    the existing ``SlidingWindowDetector``, keeping the detection pipeline
    unified.
    """

    def __init__(self, custom_rules: list[CustomRule]) -> None:
        self._rules: list[_CompiledCustomRule] = []
        for cr in custom_rules:
            if not cr.enabled:
                log.info("Custom rule '%s' is disabled, skipping", cr.name)
                continue
            try:
                compiled = re.compile(cr.regex)
            except re.error as exc:
                log.error(
                    "Custom rule '%s' has invalid regex, skipping: %s",
                    cr.name,
                    exc,
                )
                continue
            # Auditd rules do not require (?P<ip>) group (Req 3.3)
            if "auditd" not in cr.log_sources and "ip" not in compiled.groupindex:
                log.error(
                    "Custom rule '%s' regex is missing required (?P<ip>...) named group, skipping",
                    cr.name,
                )
                continue
            parser_name = f"custom:{cr.name}"
            self._rules.append(
                _CompiledCustomRule(rule=cr, compiled=compiled, parser_name=parser_name)
            )
            log.info(
                "Loaded custom rule '%s' (event=%s, sources=%s, max_attempts=%d, window=%ds)",
                cr.name,
                cr.event_type,
                cr.log_sources,
                cr.max_attempts,
                cr.window_seconds,
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
        """Run all applicable custom rules against a log line.

        Returns a ``ParsedLine`` for every rule whose regex matches.
        ``source_parser`` is the built-in parser name for the log source
        (e.g. "secure") so we can filter rules by ``log_sources``.

        For Apache log sources, rules targeting "apache" will also match
        lines parsed as "apache_bad_request", "apache_not_found", or
        "apache_other" — this allows rules to broadly target all HTTP
        traffic without listing every sub-parser.
        """
        # Build the set of effective source names for matching
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
                results.append(
                    ParsedLine(
                        parser=cr.parser_name,
                        source_ip=m.group("ip"),
                        raw=line,
                        timestamp=_parse_syslog_timestamp(line),
                    )
                )
        return results
