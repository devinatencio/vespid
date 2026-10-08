"""Sigma → Vespid CustomRule Converter.

Parses Sigma YAML detection rules and converts compatible rules into
Vespid CustomRule definitions (YAML pack format).  Only rules targeting
log sources that Vespid can parse (Apache/Nginx access logs via the
"apache" parser, SSH syslog via the "secure" parser) are converted.

Built around a modular pipeline:
    SigmaRuleParser → CompatibilityClassifier → RegexBuilder → MetadataMapper
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

from yaml import safe_load as yaml_load

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity → Vespid threshold / window mapping
# ---------------------------------------------------------------------------

_SEVERITY_MAP = {
    "critical": (1, 60),  # fire on first hit within 1 min
    "high": (2, 120),  # 2 hits in 2 min
    "medium": (3, 300),  # 3 hits in 5 min
    "low": (5, 600),  # 5 hits in 10 min
    "informational": (5, 600),
}

# ---------------------------------------------------------------------------
# Log-source → Vespid parser mapping
# ---------------------------------------------------------------------------

_LOG_SOURCE_MAP = {
    # Web server access logs → apache parser (also covers nginx)
    "webserver": ["apache"],
    "proxy": ["apache"],
    # SSH / syslog → secure parser
    "sshd": ["secure"],
}

# Sigma fields that can appear in Apache combined-log-format lines
_APACHE_FIELDS = {
    "cs-method",
    "cs-uri-query",
    "cs-uri-stem",
    "cs-uri",
    "cs-user-agent",
    "cs-referer",
    "sc-status",
    "c-uri",
    "c-uri-query",  # alternate naming
}

# Sigma fields that use raw keyword matching (no structured log parsing)
_KEYWORD_ONLY_FIELDS = {"keywords", "msg", "message"}

# Sigma condition patterns we can handle
_SIMPLE_CONDITION = re.compile(r"^\w+$")
_MEDIUM_CONDITION = re.compile(
    r"^((?:\w|[*])+)\s+and\s+(not\s+)?((?:\d+\s+of\s+)?(?:\w|[*])+)"
    r"(?:\s+and\s+(not\s+)?((?:\d+\s+of\s+)?(?:\w|[*])+))?$"
)


# ============================================================================
# Data classes
# ============================================================================


@dataclass
class ConvertedRule:
    """A single converted rule ready for YAML output."""

    name: str
    event_type: str
    regex: str
    log_sources: list[str] = field(default_factory=list)
    max_attempts: int = 3
    window_seconds: int = 300
    tags: list[str] = field(default_factory=list)
    sigma_id: str = ""
    sigma_status: str = ""
    sigma_title: str = ""
    enabled: bool = False


@dataclass
class ConversionReport:
    """Summary of a conversion run."""

    total: int = 0
    converted: int = 0
    skipped_complex: int = 0
    skipped_platform: int = 0
    skipped_unsupported: int = 0
    errors: int = 0
    details: list[str] = field(default_factory=list)


# ============================================================================
# Sigma rule parser
# ============================================================================


def parse_sigma_rule(yaml_text: str) -> dict | None:
    """Parse a Sigma YAML rule string into a dict.

    Returns None if the text is not valid YAML or doesn't look like a Sigma rule.
    """
    try:
        data = yaml_load(yaml_text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    # A Sigma rule must have at least: title, logsource, detection
    if "title" not in data or "logsource" not in data or "detection" not in data:
        return None
    return data


# ============================================================================
# Compatibility classifier
# ============================================================================


def classify(rule: dict) -> tuple[str, str]:
    """Classify a Sigma rule for Vespid compatibility.

    Returns (category, reason) where category is one of:
        - "compatible"       – can be fully converted
        - "compatible_medium"– AND/AND-NOT conditions, convertable with care
        - "skip_complex"     – all of / 1 of / nested conditions
        - "skip_platform"    – Windows / macOS / cloud / unsupported log source
        - "skip_unsupported" – other reason (e.g., process_creation fields)
    """
    logsource = rule.get("logsource", {})

    # ── Check platform ──────────────────────────────────────────────────
    product = str(logsource.get("product", "")).lower()
    category = str(logsource.get("category", "")).lower()
    service = str(logsource.get("service", "")).lower()

    # Explicitly unsupported platforms
    if product in ("windows", "macos", "azure", "aws", "gcp"):
        return ("skip_platform", f"unsupported product: {product}")

    # Cloud categories
    if category in ("cloud", "identity"):
        return ("skip_platform", f"unsupported category: {category}")

    # Determine the Vespid parser(s) that could serve this rule
    parser = _resolve_parser(logsource)
    if not parser:
        return (
            "skip_platform",
            f"no parser for product={product} category={category} service={service}",
        )

    # ── Check detection fields for unsupported types ────────────────────
    # Fields supported by auditd parser (Req 6.11)
    _auditd_supported_fields = {"Image", "CommandLine", "ParentImage", "ParentCommandLine", "User"}

    detection = rule.get("detection", {})
    for key, value in detection.items():
        if key == "condition":
            continue
        if not isinstance(value, dict):
            continue
        for field_name in value:
            # Strip modifiers like |contains, |endswith, |startswith
            base_field = field_name.split("|")[0]
            # For auditd parser, supported fields are allowed (Req 6.11)
            if parser == "auditd" and base_field in _auditd_supported_fields:
                continue
            # Fields that require process creation / auditd logs we can't parse
            if base_field in (
                "Image",
                "CommandLine",
                "ParentImage",
                "ParentCommandLine",
                "ProcessName",
                "ProcessId",
                "TargetFilename",
                "TargetObject",
                "Details",
                "EventID",
                "Provider_Name",
                "Channel",
                "PipeName",
                "DestinationIp",
                "DestinationPort",
                "SourceIp",
                "SourcePort",
                "Protocol",
                "Hashes",
                "Signature",
                "Signed",
                "OriginalFileName",
                "User",
            ):
                if parser == "auditd":
                    return ("skip_unsupported", f"unsupported auditd field: {base_field}")
                return ("skip_unsupported", f"unsupported field: {base_field}")

    # ── Check condition complexity ──────────────────────────────────────
    condition = str(detection.get("condition", "")).strip()
    if not condition:
        return ("skip_unsupported", "no condition")

    if _SIMPLE_CONDITION.match(condition):
        return ("compatible", "simple OR condition")

    if _MEDIUM_CONDITION.match(condition):
        return ("compatible_medium", f"AND/AND-NOT condition: {condition}")

    # Auditd rules: allow more complex conditions that the auditd regex builder
    # can handle (e.g., "1 of selection*", "all of selection*", "selection or keywords",
    # "selection and not filter"). These patterns use _resolve_block which supports wildcards.
    if parser == "auditd":
        return ("compatible_medium", f"auditd complex condition: {condition}")

    # Complex: all of, 1 of with wildcards, nested expressions
    return ("skip_complex", f"complex condition: {condition}")


def _resolve_parser(logsource: dict) -> str | None:
    """Resolve the Vespid parser for a Sigma logsource."""
    category = str(logsource.get("category", "")).lower()
    service = str(logsource.get("service", "")).lower()
    product = str(logsource.get("product", "")).lower()

    # Web server access logs
    if product in ("apache", "nginx", "iis"):
        return "apache"
    if service in ("apache", "nginx", "iis"):
        return "apache"
    if category in ("webserver", "web"):
        return "apache"

    # Proxy logs
    if product == "proxy" or category == "proxy":
        return "apache"

    # SSH / syslog-based rules
    if service in ("sshd", "ssh"):
        return "secure"
    if category == "sshd":
        return "secure"

    # Linux rules with sshd service
    if product == "linux" and service in ("sshd", "ssh"):
        return "secure"

    # Linux process creation / keyword rules → auditd parser
    if product == "linux" and category in ("process_creation", "keyword"):
        return "auditd"

    # OpenCanary / honeypots
    if product == "opencanary":
        return "secure"

    return None


# ============================================================================
# Regex builder
# ============================================================================


def build_regex(rule: dict, parser: str) -> str | None:
    """Build a Vespid-compatible regex from a Sigma rule.

    The regex MUST contain a ``(?P<ip>...)`` named group that captures
    the offending source IP address.
    """
    detection = rule.get("detection", {})
    condition = str(detection.get("condition", "")).strip()

    if parser == "apache":
        return _build_apache_regex(detection, condition)
    elif parser == "secure":
        return _build_secure_regex(detection, condition)
    elif parser == "auditd":
        return _build_auditd_regex(detection, condition)
    return None


def _resolve_block(blocks: dict[str, dict | list], name: str) -> dict | list | None:
    """Resolve a condition block name to its detection block dict.

    Handles Sigma naming conventions:
    1. Exact match: ``selection`` → block named ``selection``
    2. Wildcard suffix: ``filter_main_*`` → block named ``filter_main_status``
    3. ``1 of / all of`` prefix: strips the quantifier
    4. Loose prefix match: ``selection`` → ``select_method``
    """
    if name in blocks:
        return blocks[name]

    # Handle "1 of selection_*" or "all of filter_main_*"
    if " of " in name:
        inner = name.split(" of ", 1)[1]
        if inner in blocks:
            return blocks[inner]
        if inner.endswith("_*"):
            prefix = inner[:-2]
            matches = [(k, v) for k, v in blocks.items() if k.startswith(prefix)]
            if len(matches) == 1:
                return matches[0][1]
            # Multiple matches — return first (caller decides how to handle)

    # Handle wildcard suffix: "filter_main_*" matches "filter_main_status"
    if name.endswith("_*"):
        prefix = name[:-2]
        for k, v in blocks.items():
            if k.startswith(prefix):
                return v

    # Loose prefix: "selection" → "select_method", "sel_method", etc.
    for k, v in blocks.items():
        if k.startswith(name):
            return v

    return None


def _build_apache_regex(detection: dict, condition: str) -> str | None:
    """Build regex for Apache combined log format lines."""
    block_map: dict[str, dict | list] = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, (dict, list)):
            block_map[key] = value

    # Try simple: single block
    block = _resolve_block(block_map, condition)
    if block is not None and len(block_map) <= 1:
        return _apache_single_block(block)

    # Parse condition into tokens: "selection and keywords and not 1 of filter_main_*"
    tokens = _parse_condition_tokens(condition)
    # tokens is list of (negated: bool, block_name: str)

    if not tokens:
        return None

    # Resolve all blocks
    resolved: list[tuple[bool, dict | list | None]] = []
    for negated, name in tokens:
        block = _resolve_block(block_map, name)
        resolved.append((negated, block))

    if any(b is None for _, b in resolved):
        return None

    # All resolved blocks combined
    blocks = [b for _, b in resolved if b is not None]
    negations = [neg for neg, _ in resolved]

    if len(blocks) == 1:
        return _apache_single_block(blocks[0])
    elif len(blocks) == 2:
        return _apache_and_block(blocks[0], blocks[1], negated=negations[1])
    elif len(blocks) >= 3:
        return _apache_multi_block(blocks, negations)

    return None


def _parse_condition_tokens(condition: str) -> list[tuple[bool, str]]:
    """Parse a Sigma condition string into (negated, block_name) tokens.

    Example:
        "selection and keywords and not 1 of filter_main_*"
        → [("selection", False), ("keywords", False), ("filter_main_*", True)]
    """
    tokens: list[tuple[bool, str]] = []
    parts = condition.split(" and ")
    for part in parts:
        part = part.strip()
        negated = False
        if part.startswith("not "):
            negated = True
            part = part[4:]
        # Strip "1 of" or "all of" prefixes — they don't affect single-block resolution
        if " of " in part:
            part = part.split(" of ", 1)[1]
        if part:
            tokens.append((negated, part))
    return tokens


def _apache_single_block(block: dict | list) -> str | None:
    """Build regex from a single selection or keywords block.

    Handles both:
    - dict blocks (structured field matching)
    - list blocks (anonymous keyword lists)
    """
    # Anonymous keyword list: ["pattern1", "pattern2", ...]
    if isinstance(block, list):
        patterns = [str(v) for v in block if isinstance(v, str)]
        if not patterns:
            return None
        escaped = [_re_escape(p) for p in patterns]
        uri_pattern = "(?:" + "|".join(escaped) + ")"
        return _assemble_apache_line(uri_pattern=uri_pattern)

    # Structured field matching block
    literal_patterns: list[str] = []  # plain keywords — will be escaped
    raw_patterns: list[str] = []  # pre-built regex — used as-is
    ua_patterns: list[str] = []
    anchor_method: str | None = None
    require_not_status: int | None = None
    require_null_referer: bool = False
    require_null_ua: bool = False

    for sigma_field, value in block.items():
        base, modifier = _split_field_modifier(sigma_field)

        if base in ("cs-method", "c-method"):
            if isinstance(value, str):
                anchor_method = value
        elif base in ("cs-uri-query", "cs-uri", "cs-uri-stem", "c-uri", "c-uri-query"):
            if modifier == "re":
                if isinstance(value, str):
                    raw_patterns.append(value)
            elif isinstance(value, list):
                literal_patterns.extend(str(v) for v in value)
            elif isinstance(value, str):
                literal_patterns.append(value)
        elif base in ("cs-user-agent", "c-useragent"):
            if modifier == "startswith":
                if isinstance(value, list):
                    ua_patterns.append(_anchor_in_ua_startswith(value))
                elif isinstance(value, str):
                    ua_patterns.append(_anchor_in_ua_startswith([value]))
            elif modifier == "contains":
                if isinstance(value, list):
                    ua_patterns.append(_anchor_in_ua(value))
                elif isinstance(value, str):
                    ua_patterns.append(_anchor_in_ua([value]))
            elif value is None or value == "":
                require_null_ua = True
            elif isinstance(value, list):
                ua_patterns.append(_anchor_in_ua(value))
            elif isinstance(value, str):
                ua_patterns.append(_anchor_in_ua([value]))
        elif base == "cs-referer":
            if value is None:
                require_null_referer = True
        elif base == "sc-status":
            if isinstance(value, int):
                require_not_status = value
        elif base in ("cs-host", "c-host"):
            # Host header matching — skip for access logs (combined format
            # doesn't include Host by default; these are proxy-only fields)
            pass
        elif base in ("c-uri-extension", "cs-uri-extension"):
            # File extension matching — build regex directly
            if isinstance(value, list):
                for ext in value:
                    raw_patterns.append(r"\." + _re_escape(ext) + r"\b")
            elif isinstance(value, str):
                raw_patterns.append(r"\." + _re_escape(value) + r"\b")
        # Unnamed keywords block
        elif base == "keywords":
            if isinstance(value, list):
                literal_patterns.extend(str(v) for v in value)
        # Catch-all: treat string/list values as generic line patterns
        elif isinstance(value, list):
            literal_patterns.extend(str(v) for v in value)
        elif isinstance(value, str) and base:
            literal_patterns.append(value)

    if (
        not literal_patterns
        and not raw_patterns
        and not ua_patterns
        and not require_null_ua
        and not require_null_referer
    ):
        return None

    # Build the URI keyword portion — escape literal patterns, keep raw as-is
    uri_parts = [_re_escape(p) for p in literal_patterns] + raw_patterns
    uri_pattern = "(?:" + "|".join(uri_parts) + ")" if uri_parts else ""

    # Build the UA portion
    ua_pattern = "(?:" + "|".join(ua_patterns) + ")" if ua_patterns else None

    return _assemble_apache_line(
        uri_pattern=uri_pattern,
        method=anchor_method,
        not_status=require_not_status,
        null_referer=require_null_referer,
        null_ua=require_null_ua,
        ua_pattern=ua_pattern,
    )


def _apache_and_block(
    block_a: dict | list,
    block_b: dict | list,
    negated: bool = False,
) -> str | None:
    """Build regex from two blocks ANDed together (or first AND NOT second)."""
    # Extract keywords from first block
    a_patterns: list[str] = []  # literal keywords
    a_raw_patterns: list[str] = []  # pre-built regex (|re, c-uri-extension)
    a_method: str | None = None
    a_ua_patterns: list[str] = []

    if isinstance(block_a, list):
        a_patterns = [str(v) for v in block_a if isinstance(v, str)]
    else:
        for field, value in block_a.items():
            base, modifier = _split_field_modifier(field)
            if base == "cs-method":
                if isinstance(value, str):
                    a_method = value
            elif base in ("cs-uri-query", "cs-uri", "cs-uri-stem", "c-uri", "c-uri-query"):
                if modifier == "re":
                    if isinstance(value, str):
                        a_raw_patterns.append(value)
                elif isinstance(value, list):
                    a_patterns.extend(value)
            elif base in ("cs-user-agent",):
                if modifier == "startswith":
                    if isinstance(value, list):
                        a_ua_patterns.append(_anchor_in_ua_startswith(value))
                    elif isinstance(value, str):
                        a_ua_patterns.append(_anchor_in_ua_startswith([value]))
                elif modifier == "contains":
                    if isinstance(value, list):
                        a_ua_patterns.append(_anchor_in_ua(value))
                    elif isinstance(value, str):
                        a_ua_patterns.append(_anchor_in_ua([value]))
                elif isinstance(value, list):
                    a_ua_patterns.append(_anchor_in_ua(value))
                elif isinstance(value, str):
                    a_ua_patterns.append(_anchor_in_ua([value]))
            elif base in ("c-uri-extension", "cs-uri-extension"):
                if isinstance(value, list):
                    for ext in value:
                        a_raw_patterns.append(r"\." + _re_escape(ext) + r"\b")
            elif base == "keywords" and isinstance(value, list):
                a_patterns.extend(value)

    # Extract fields from second block
    b_method: str | None = None
    b_not_status: int | None = None
    b_null_referer: bool = False
    b_null_ua: bool = False
    b_patterns: list[str] = []
    b_ua_patterns: list[str] = []

    if isinstance(block_b, dict):
        for field, value in block_b.items():
            base, modifier = _split_field_modifier(field)
            if base == "cs-method":
                if isinstance(value, str):
                    b_method = value
            elif base == "sc-status":
                if isinstance(value, int):
                    b_not_status = value
            elif base == "cs-referer":
                if value is None:
                    b_null_referer = True
            elif base == "cs-user-agent":
                if value is None:
                    b_null_ua = True
                elif modifier == "contains":
                    if isinstance(value, list):
                        b_ua_patterns.append(_anchor_in_ua(value))
                    elif isinstance(value, str):
                        b_ua_patterns.append(_anchor_in_ua([value]))
                elif modifier == "startswith":
                    if isinstance(value, list):
                        b_ua_patterns.append(_anchor_in_ua_startswith(value))
                    elif isinstance(value, str):
                        b_ua_patterns.append(_anchor_in_ua_startswith([value]))
                elif isinstance(value, list):
                    b_ua_patterns.append(_anchor_in_ua(value))
                elif isinstance(value, str):
                    b_ua_patterns.append(_anchor_in_ua([value]))
            elif base in ("cs-uri-query", "cs-uri", "cs-uri-stem", "c-uri", "c-uri-query"):
                if modifier == "re":
                    if isinstance(value, str):
                        a_raw_patterns.append(value)
                elif isinstance(value, list):
                    b_patterns.extend(str(v) for v in value)
                elif isinstance(value, str):
                    b_patterns.append(value)
            elif base == "keywords" and isinstance(value, list):
                b_patterns.extend(str(v) for v in value)

    # Merge: method from block_a wins, blocker fields from block_b
    method = a_method or b_method
    not_status = b_not_status
    null_referer = b_null_referer
    null_ua = b_null_ua

    # Merge keywords: block B positive keywords augment block A
    all_literal = a_patterns + b_patterns
    all_ua = a_ua_patterns + b_ua_patterns

    if not all_literal and not a_raw_patterns and not all_ua:
        return None

    uri_parts = [_re_escape(p) for p in all_literal] + a_raw_patterns
    uri_pattern = "(?:" + "|".join(uri_parts) + ")" if uri_parts else ""
    ua_pat = "(?:" + "|".join(all_ua) + ")" if all_ua else None

    return _assemble_apache_line(
        uri_pattern=uri_pattern,
        method=method,
        not_status=not_status,
        null_referer=null_referer,
        null_ua=null_ua,
        ua_pattern=ua_pat,
    )


def _apache_multi_block(
    blocks: list[dict | list],
    negations: list[bool],
) -> str | None:
    """Build regex from 3+ blocks.  Merges keyword blocks and applies a filter block.

    Common pattern: ``selection and keywords and not 1 of filter_main_*``
    - selection: method constraint (cs-method: 'GET')
    - keywords: attack patterns (may be dict or raw list)
    - filter: status constraint (sc-status: 404) — negated
    """
    patterns: list[str] = []  # literal keywords — will be escaped
    raw_patterns: list[str] = []  # pre-built regex — used as-is
    ua_patterns: list[str] = []
    method: str | None = None
    not_status: int | None = None
    null_referer: bool = False
    null_ua: bool = False

    for i, block in enumerate(blocks):
        negated = negations[i] if i < len(negations) else False

        if isinstance(block, list):
            # Raw keyword list
            patterns.extend(str(v) for v in block if isinstance(v, str))
            continue

        for sigma_field, value in block.items():
            base, modifier = _split_field_modifier(sigma_field)

            if base == "cs-method":
                if isinstance(value, str):
                    method = value
            elif base in ("cs-uri-query", "cs-uri", "cs-uri-stem", "c-uri", "c-uri-query"):
                if modifier == "re":
                    if isinstance(value, str):
                        raw_patterns.append(value)
                elif isinstance(value, list):
                    patterns.extend(str(v) for v in value)
            elif base == "cs-user-agent":
                if modifier == "startswith":
                    if isinstance(value, list):
                        ua_patterns.append(_anchor_in_ua_startswith(value))
                    elif isinstance(value, str):
                        ua_patterns.append(_anchor_in_ua_startswith([value]))
                elif modifier == "contains":
                    if isinstance(value, list):
                        ua_patterns.append(_anchor_in_ua(value))
                    elif isinstance(value, str):
                        ua_patterns.append(_anchor_in_ua([value]))
                elif value is None or value == "":
                    null_ua = True
                elif isinstance(value, list):
                    ua_patterns.append(_anchor_in_ua(value))
                elif isinstance(value, str):
                    ua_patterns.append(_anchor_in_ua([value]))
            elif base == "cs-referer":
                if value is None:
                    null_referer = True
            elif base == "sc-status":
                if isinstance(value, int):
                    if negated:
                        not_status = value
            elif base == "keywords" and isinstance(value, list):
                patterns.extend(str(v) for v in value)

    if not patterns and not raw_patterns and not ua_patterns and not null_ua and not null_referer:
        return None

    uri_parts = [_re_escape(p) for p in patterns] + raw_patterns
    uri_pattern = "(?:" + "|".join(uri_parts) + ")" if uri_parts else ""
    ua_pat = "(?:" + "|".join(ua_patterns) + ")" if ua_patterns else None

    return _assemble_apache_line(
        uri_pattern=uri_pattern,
        method=method,
        not_status=not_status,
        null_referer=null_referer,
        null_ua=null_ua,
        ua_pattern=ua_pat,
    )


def _assemble_apache_line(
    uri_pattern: str,
    method: str | None = None,
    not_status: int | None = None,
    null_referer: bool = False,
    null_ua: bool = False,
    ua_pattern: str | None = None,
) -> str:
    """Assemble a full Apache combined-log-format regex."""

    # IP + whitespace-delimited fixed fields + timestamp
    parts = [
        r"(?P<ip>\S+)",  # %h  — client IP
        r"\s+\S+",  # %l  — ident (usually "-")
        r"\s+\S+",  # %u  — user  (usually "-")
        r"\s+\[[^\]]*\]",  # %t  — [timestamp]
    ]

    # Request line: "METHOD /path?query HTTP/1.1"
    quoted = _build_quoted_request(method, uri_pattern)

    # Status code: number or "-"
    if not_status is not None:
        quoted += rf"\s+(?!{not_status}\s)\d+"
    else:
        quoted += r"\s+\d+"

    # Size: number or "-"
    quoted += r"\s+\S+"

    # Referer: quoted string or "-"
    quoted += r'\s+"' + (r"-" if null_referer else r'[^"]*') + r'"'

    # User-Agent: quoted string or "-", optionally constrained by ua_pattern
    if null_ua:
        quoted += r'\s+"-"'
    elif ua_pattern:
        quoted += rf'\s+"{ua_pattern}"'
    else:
        quoted += r'\s+"[^"]*"'

    return "".join(parts) + quoted


def _build_quoted_request(method: str | None, uri_pattern: str) -> str:
    """Build the quoted request part: ` "METHOD /uri HTTP/version" `"""
    method = method if method else r"\S+"
    return rf'\s+"{method}\s+[^"]*?{uri_pattern}[^"]*?"'


def _build_secure_regex(detection: dict, condition: str) -> str | None:
    """Build regex for SSH secure log lines (syslog format).

    SSH syslog lines like:
        Jun 10 08:15:32 hostname sshd[1234]: error: ... 192.168.1.1 port 12345 ...

    The IP appears somewhere in the message, not at line start.
    Captures any IPv4 address in the line.
    """
    block_map: dict[str, dict] = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, (dict, list)):
            block_map[key] = value

    # Simple: single block
    block = _resolve_block(block_map, condition)
    if block is None:
        return None

    patterns: list[str] = []

    # Handle unnamed keyword blocks (value is a list directly)
    if isinstance(block, list):
        patterns.extend(str(v) for v in block if isinstance(v, str))
    elif isinstance(block, dict):
        for field, value in block.items():
            base, _modifier = _split_field_modifier(field)
            if base == "keywords" and isinstance(value, list):
                patterns.extend(str(v) for v in value if isinstance(v, str))
            elif isinstance(value, str):
                patterns.append(value)
            elif isinstance(value, list):
                patterns.extend(str(v) for v in value if isinstance(v, str))

    if patterns:
        escaped = [_re_escape(p) for p in patterns]
        return r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+.*?" + "(?:" + "|".join(escaped) + ")"

    return None


# ============================================================================
# Auditd regex builder
# ============================================================================

# Sigma field → HostEvent flattened field name mapping (Req 6.3, 6.4, 6.5)
_AUDITD_FIELD_MAP: dict[str, str] = {
    "Image": "exe",
    "CommandLine": "cmdline",
    "ParentImage": "parent_exe",
    "ParentCommandLine": "parent_cmdline",
    "User": "uid",
}

# Set of supported auditd fields (used for skip detection in Req 6.9)
_AUDITD_SUPPORTED_FIELDS_SET = frozenset(_AUDITD_FIELD_MAP.keys())


def _build_auditd_regex(detection: dict, condition: str) -> str | None:
    """Build regex for auditd rules. No (?P<ip>...) required (Req 6.6).

    Maps Sigma fields to HostEvent flattened field names and applies
    Sigma modifiers (|contains, |endswith, |startswith, |re).
    Multiple AND conditions use lookahead assertions (Req 6.10).

    Returns None if the rule references unsupported fields.
    """
    # Collect detection blocks (skip the "condition" key)
    block_map: dict[str, dict | list] = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, (dict, list)):
            block_map[key] = value

    # Handle "1 of selection*" / "all of selection*" / "1 of them" patterns
    condition_stripped = condition.strip()
    if condition_stripped == "1 of them" or condition_stripped == "all of them":
        # Merge all detection blocks into one
        all_patterns: list[str] = []
        for block in block_map.values():
            regex = _auditd_block_to_regex(block)
            if regex:
                all_patterns.append(regex)
        if not all_patterns:
            return None
        if condition_stripped.startswith("1 of"):
            # OR: any block matches
            return "(?:" + "|".join(all_patterns) + ")"
        else:
            # AND: all blocks match (lookahead)
            return "".join(f"(?=.*{p})" for p in all_patterns)

    # Handle "1 of selection*" pattern (single quantifier expression)
    one_of_match = re.match(r"^(1|all)\s+of\s+(\w+\*?)$", condition_stripped)
    if one_of_match:
        quantifier = one_of_match.group(1)
        block_pattern = one_of_match.group(2)
        block = _resolve_block(block_map, f"{quantifier} of {block_pattern}")
        if block is None:
            # Try direct wildcard resolution
            block = _resolve_block(block_map, block_pattern)
        if block is None:
            # Collect all blocks matching the prefix
            prefix = block_pattern.rstrip("*")
            matching_blocks = [v for k, v in block_map.items() if k.startswith(prefix)]
            if matching_blocks:
                all_patterns = []
                for b in matching_blocks:
                    regex = _auditd_block_to_regex(b)
                    if regex:
                        all_patterns.append(regex)
                if not all_patterns:
                    return None
                if quantifier == "1":
                    return "(?:" + "|".join(all_patterns) + ")"
                else:
                    return "".join(f"(?=.*{p})" for p in all_patterns)
            return None
        return _auditd_block_to_regex(block)

    # Handle "selection or keywords" (OR conditions)
    if " or " in condition_stripped:
        or_parts = [p.strip() for p in condition_stripped.split(" or ")]
        or_patterns: list[str] = []
        for part in or_parts:
            block = _resolve_block(block_map, part)
            if block is not None:
                regex = _auditd_block_to_regex(block)
                if regex:
                    or_patterns.append(regex)
        if not or_patterns:
            return None
        return "(?:" + "|".join(or_patterns) + ")"

    # Parse condition tokens (handles "and" / "and not" patterns)
    tokens = _parse_condition_tokens(condition)
    if not tokens:
        return None

    # For simple conditions, just use the single block
    if _SIMPLE_CONDITION.match(condition):
        block = _resolve_block(block_map, condition)
        if block is None:
            return None
        return _auditd_block_to_regex(block)

    # For AND conditions, combine with lookahead assertions
    # Resolve positive blocks (ignore negated filter blocks for auditd —
    # they typically filter out noise which doesn't apply to host detection)
    positive_blocks: list[dict | list] = []
    for negated, name in tokens:
        if negated:
            continue  # Skip NOT blocks for auditd rules
        block = _resolve_block(block_map, name)
        if block is None:
            continue
        positive_blocks.append(block)

    if not positive_blocks:
        return None

    # If there's only one positive block, build directly
    if len(positive_blocks) == 1:
        return _auditd_block_to_regex(positive_blocks[0])

    # Merge all positive blocks into one for combined regex
    merged_conditions: list[str] = []
    for block in positive_blocks:
        if isinstance(block, list):
            # Keyword list — match any keyword in the flattened string
            patterns = [_re_escape(str(v)) for v in block if isinstance(v, str)]
            if patterns:
                merged_conditions.append("(?:" + "|".join(patterns) + ")")
        elif isinstance(block, dict):
            field_patterns = _auditd_fields_to_patterns(block)
            if field_patterns is None:
                return None  # Unsupported field
            merged_conditions.extend(field_patterns)

    if not merged_conditions:
        return None

    # Single pattern → return directly
    if len(merged_conditions) == 1:
        return merged_conditions[0]

    # Multiple → combine with lookahead assertions (Req 6.10)
    return "".join(f"(?=.*{p})" for p in merged_conditions)


def _auditd_block_to_regex(block: dict | list) -> str | None:
    """Convert a single detection block into an auditd regex pattern."""
    if isinstance(block, list):
        # Keyword list — match any keyword anywhere in the flattened string
        patterns = [_re_escape(str(v)) for v in block if isinstance(v, str)]
        if not patterns:
            return None
        return "(?:" + "|".join(patterns) + ")"

    if not isinstance(block, dict):
        return None

    field_patterns = _auditd_fields_to_patterns(block)
    if field_patterns is None:
        return None  # Unsupported field encountered

    if not field_patterns:
        return None

    if len(field_patterns) == 1:
        return field_patterns[0]

    # Multiple field conditions → combine with lookahead (Req 6.10)
    return "".join(f"(?=.*{p})" for p in field_patterns)


def _auditd_fields_to_patterns(block: dict) -> list[str] | None:
    """Convert detection block fields to individual regex patterns.

    Returns None if an unsupported field is encountered (Req 6.9).
    Returns a list of regex pattern strings for each field condition.
    """
    patterns: list[str] = []

    for field_with_modifier, value in block.items():
        base_field, modifier = _split_field_modifier(field_with_modifier)

        # Skip the "keywords" pseudo-field (handled at block level)
        if base_field == "keywords":
            if isinstance(value, list):
                keyword_patterns = [_re_escape(str(v)) for v in value if isinstance(v, str)]
                if keyword_patterns:
                    patterns.append("(?:" + "|".join(keyword_patterns) + ")")
            continue

        # Check if field is supported
        if base_field not in _AUDITD_FIELD_MAP:
            return None  # Unsupported field → skip entire rule (Req 6.9)

        mapped_field = _AUDITD_FIELD_MAP[base_field]

        # Handle value — could be a string or a list (OR within a field)
        if isinstance(value, list):
            # OR: any value in the list matches
            value_patterns = []
            for v in value:
                p = _auditd_value_pattern(mapped_field, str(v), modifier)
                if p:
                    value_patterns.append(p)
            if value_patterns:
                if len(value_patterns) == 1:
                    patterns.append(value_patterns[0])
                else:
                    patterns.append("(?:" + "|".join(value_patterns) + ")")
        elif isinstance(value, str):
            p = _auditd_value_pattern(mapped_field, value, modifier)
            if p:
                patterns.append(p)
        elif isinstance(value, (int, float)):
            p = _auditd_value_pattern(mapped_field, str(value), modifier)
            if p:
                patterns.append(p)

    return patterns


def _auditd_value_pattern(field: str, value: str, modifier: str | None) -> str:
    """Build a single field=value regex pattern with the appropriate modifier.

    The pattern accounts for the \\x1e field separator used in
    HostEvent.flattened() (Req 3.12).

    Modifier semantics:
    - None (no modifier): exact match → (?:^|\\x1e)FIELD=VALUE(?:\\x1e|$)
    - |contains: value anywhere → FIELD=.*VALUE
    - |startswith: value at start of field value → FIELD=VALUE
    - |endswith: value at end of field value → FIELD=.*VALUE(?:\\x1e|$)
    - |re: raw regex in field context → FIELD=.*VALUE_AS_REGEX
    """
    sep = r"\x1e"

    if modifier == "re":
        # Pass value as raw regex (Req 6.4)
        return f"{field}=.*{value}"
    elif modifier == "contains":
        # Value anywhere in the field value
        escaped = _re_escape(value)
        return f"{field}=.*{escaped}"
    elif modifier == "startswith":
        # Value at start of the field value
        escaped = _re_escape(value)
        return f"{field}={escaped}"
    elif modifier == "endswith":
        # Value at end of field value, anchored to separator or end
        escaped = _re_escape(value)
        return f"{field}=.*{escaped}(?:{sep}|$)"
    else:
        # No modifier: exact match, bounded by separators
        escaped = _re_escape(value)
        return f"(?:^|{sep}){field}={escaped}(?:{sep}|$)"


# ============================================================================
# Metadata mapper
# ============================================================================


def _make_event_type(rule: dict) -> str:
    """Derive a Vespid event_type from the Sigma rule."""
    title = rule.get("title", "UNKNOWN")
    category = str(rule.get("logsource", {}).get("category", "")).upper()
    product = str(rule.get("logsource", {}).get("product", "")).upper()
    service = str(rule.get("logsource", {}).get("service", "")).upper()

    # Map to a concise event type
    mapping = {
        ("sql", "injection"): "SIGMA_WEB_SQLI",
        ("xss",): "SIGMA_WEB_XSS",
        ("path", "traversal"): "SIGMA_WEB_PATH_TRAVERSAL",
        ("jndi",): "SIGMA_WEB_JNDI",
        ("log4j",): "SIGMA_WEB_LOG4J",
        ("ssti",): "SIGMA_WEB_SSTI",
        ("template", "injection"): "SIGMA_WEB_SSTI",
        ("webshell",): "SIGMA_WEB_WEBSHELL",
        ("webshells",): "SIGMA_WEB_WEBSHELL",
        ("shellshock",): "SIGMA_WEB_SHELLSHOCK",
        ("user", "agent"): "SIGMA_WEB_SUSP_UA",
        ("useragent",): "SIGMA_WEB_SUSP_UA",
        ("scanner",): "SIGMA_WEB_SCANNER",
        ("download", "cradle"): "SIGMA_WEB_DOWNLOAD_CRADLE",
        ("file", "download"): "SIGMA_WEB_DOWNLOAD_CRADLE",
        ("enumeration",): "SIGMA_WEB_ENUM",
        ("source", "code"): "SIGMA_WEB_SOURCE_ENUM",
        ("sensitive", "file"): "SIGMA_WEB_SENSITIVE_FILE",
        ("sshd", "error"): "SIGMA_SSH_SUSP_ERROR",
        ("sshd", "suspicious"): "SIGMA_SSH_SUSP_ERROR",
        ("ssh", "error"): "SIGMA_SSH_SUSP_ERROR",
        ("ssh", "suspicious"): "SIGMA_SSH_SUSP_ERROR",
        ("ssh", "shell"): "SIGMA_SSH_SHELL_EXEC",
        ("ssh", "tunneling"): "SIGMA_SSH_TUNNEL",
        ("ssh", "proxy"): "SIGMA_SSH_TUNNEL",
        ("brute",): "SIGMA_BRUTE_FORCE",
        ("rce",): "SIGMA_WEB_RCE",
        ("code", "injection"): "SIGMA_WEB_RCE",
        ("command", "injection"): "SIGMA_WEB_RCE",
        ("proxy",): "SIGMA_WEB_PROXY",
        ("cobalt", "strike"): "SIGMA_WEB_C2_TOOL",
        ("empire",): "SIGMA_WEB_C2_TOOL",
        ("metasploit",): "SIGMA_WEB_C2_TOOL",
        ("request", "smuggling"): "SIGMA_WEB_REQ_SMUGGLING",
    }

    title_lower = title.lower()
    for keys, evt in mapping.items():
        if all(k in title_lower for k in keys):
            return evt

    # Fallback: derive from title keywords
    if "sql" in title_lower:
        return "SIGMA_WEB_SQLI"
    if "xss" in title_lower or "cross" in title_lower:
        return "SIGMA_WEB_XSS"
    if "traversal" in title_lower:
        return "SIGMA_WEB_PATH_TRAVERSAL"
    if "sshd" in title_lower or "ssh " in title_lower:
        return "SIGMA_SSH_SUSP_ERROR"
    if "rce" in title_lower or "remote code" in title_lower:
        return "SIGMA_WEB_RCE"
    if "user" in title_lower and "agent" in title_lower:
        return "SIGMA_WEB_SUSP_UA"

    # Generic category-based fallback
    if category == "WEBSERVER" or product in ("APACHE", "NGINX"):
        return "SIGMA_WEB_ATTACK"
    if service == "SSHD":
        return "SIGMA_SSH_ATTACK"
    if product == "LINUX" and category in ("PROCESS_CREATION", "KEYWORD"):
        return "SIGMA_HOST_DETECTION"

    return "SIGMA_DETECTION"


def _extract_tags(rule: dict) -> list[str]:
    """Extract tags from a Sigma rule, preserving ATT&CK IDs."""
    tags = rule.get("tags", [])
    if isinstance(tags, list):
        return [str(t) for t in tags if t]
    return []


def _level_to_thresholds(level: str) -> tuple[int, int]:
    """Map Sigma severity level to (max_attempts, window_seconds)."""
    return _SEVERITY_MAP.get(str(level).lower().strip(), (3, 300))


def _make_rule_name(rule: dict) -> str:
    """Generate a Vespid rule name from the Sigma rule title."""
    title = rule.get("title", "").lower()
    # Remove special chars, replace spaces with underscores
    name = re.sub(r"[^a-z0-9\s_-]", "", title)
    name = re.sub(r"\s+", "_", name.strip())
    name = name[:60]  # Vespid name limit is 64, leave some room
    return "sigma_" + name


# ============================================================================
# Main converter
# ============================================================================


def convert_rule(rule: dict) -> tuple[ConvertedRule | None, str]:
    """Convert a single parsed Sigma rule dict to a ConvertedRule.

    Returns (ConvertedRule, "") on success, (None, reason) on skip/failure.
    """
    category, reason = classify(rule)
    if category.startswith("skip_"):
        return (None, reason)

    parser = _resolve_parser(rule.get("logsource", {}))
    if not parser:
        return (None, "no parser resolved")

    regex = build_regex(rule, parser)
    if not regex:
        return (None, "could not build regex")

    # Normalise inline flags so the regex is valid on Python 3.11+.
    regex = _hoist_inline_flags(regex)

    # Validate the regex compiles and has (?P<ip>...) — except for auditd rules (Req 6.6)
    try:
        compiled = re.compile(regex)
        if parser != "auditd" and "ip" not in compiled.groupindex:
            return (None, "regex missing (?P<ip>...) group")
    except re.error:
        return (None, "regex does not compile")

    level = str(rule.get("level", "medium")).lower().strip()

    # Auditd rules use immediate-match semantics (Req 6.8)
    if parser == "auditd":
        max_attempts = 1
        window_seconds = 1
    else:
        max_attempts, window_seconds = _level_to_thresholds(level)

    log_sources_map = {
        "apache": ["apache"],
        "secure": ["secure"],
        "auditd": ["auditd"],
    }

    return (
        ConvertedRule(
            name=_make_rule_name(rule),
            event_type=_make_event_type(rule),
            regex=regex,
            log_sources=log_sources_map.get(parser, ["*"]),
            max_attempts=max_attempts,
            window_seconds=window_seconds,
            tags=_extract_tags(rule),
            sigma_id=str(rule.get("id", "")),
            sigma_status=str(rule.get("status", "")),
            sigma_title=str(rule.get("title", "")),
            enabled=False,
        ),
        "",
    )


def convert_rules(rules: list[dict]) -> tuple[list[ConvertedRule], ConversionReport]:
    """Convert a list of parsed Sigma rule dicts.

    Returns (converted_rules, report).
    """
    report = ConversionReport()
    converted: list[ConvertedRule] = []

    for rule in rules:
        report.total += 1
        result, reason = convert_rule(rule)
        if result is not None:
            converted.append(result)
            report.converted += 1
            report.details.append(f"✓ {rule.get('title', 'unknown')} → {result.name}")
        else:
            if "complex" in reason:
                report.skipped_complex += 1
            elif "platform" in reason:
                report.skipped_platform += 1
            else:
                report.skipped_unsupported += 1
            report.details.append(f"✗ {rule.get('title', 'unknown')}: {reason}")

    return converted, report


# ============================================================================
# YAML pack generation
# ============================================================================


def generate_pack_yaml(
    rules: list[ConvertedRule],
    pack_name: str,
    display_name: str,
    icon: str,
    description: str,
    prerequisite: str = "",
) -> str:
    """Generate a Vespid pack YAML string from converted rules.

    Returns the YAML as a string (no pyyaml dependency — manual construction
    for precise formatting).
    """
    lines = [
        f"pack_name: {pack_name}",
        f"display_name: {display_name}",
        f"icon: {icon}",
        "description: >",
    ]
    for desc_line in description.strip().split("\n"):
        if desc_line.strip():
            lines.append(f"  {desc_line.strip()}")
    if prerequisite:
        lines.append(f"prerequisite: {prerequisite}")
    lines.append("rules:")
    for rule in rules:
        lines.append("  - name: " + rule.name)
        lines.append("    event_type: " + rule.event_type)
        lines.append("    regex: >-")
        # Break long regex into a folded scalar
        if len(rule.regex) > 80:
            lines.append("      " + rule.regex)
        else:
            lines.append("      " + rule.regex)
        log_sources_yaml = json.dumps(rule.log_sources)
        lines.append("    log_sources: " + log_sources_yaml)
        lines.append("    max_attempts: " + str(rule.max_attempts))
        lines.append("    window_seconds: " + str(rule.window_seconds))
        if rule.tags:
            tags_yaml = json.dumps(rule.tags)
            lines.append("    tags: " + tags_yaml)
        if rule.sigma_id:
            lines.append("    sigma_id: " + rule.sigma_id)
        if rule.sigma_status:
            lines.append("    sigma_status: " + rule.sigma_status)

    return "\n".join(lines) + "\n"


# ============================================================================
# Helpers
# ============================================================================


def _split_field_modifier(field: str) -> tuple[str, str | None]:
    """Split a Sigma field like 'cs-uri-query|contains' into (base, modifier)."""
    parts = field.split("|", 1)
    return parts[0], parts[1] if len(parts) > 1 else None


# Global inline-flag groups such as (?i) must appear at the very start of a
# Python 3.11+ regex. Sigma rules (especially ``|re`` values) sometimes embed
# them mid-pattern, which compiles on older Pythons but raises re.error on
# 3.11+. Hoist any such flags to the front so the generated regex is portable
# and still case-insensitive where the author intended.
_INLINE_FLAG_RE = re.compile(r"\(\?([aimsxu]+)\)")


def _hoist_inline_flags(pattern: str) -> str:
    """Move any global inline flags (e.g. ``(?i)``) to the start of the regex."""
    found: set[str] = set()

    def _collect(match: re.Match) -> str:
        found.update(match.group(1))
        return ""

    body = _INLINE_FLAG_RE.sub(_collect, pattern)
    if not found:
        return pattern
    return "(?" + "".join(sorted(found)) + ")" + body


def _re_escape(pattern: str) -> str:
    """Escape a string for use in a regex alternation.

    Escapes regex metacharacters (., ^, $, *, +, ?, {, }, [, ], |, (, ))
    but preserves already-escaped sequences like ``\\.``, ``\\+``, ``\\b`` etc.
    and Sigma regex modifiers like ``(?i)``.
    """
    chars_to_escape = frozenset(r".^$*+?{}[]|()")
    result: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            # Already regex-escaped: pass through both characters as-is
            result.append(ch)
            result.append(pattern[i + 1])
            i += 2
        elif ch in chars_to_escape:
            result.append("\\" + ch)
            i += 1
        else:
            result.append(ch)
            i += 1
    return "".join(result)


def _anchor_in_ua(keywords: list[str]) -> str:
    """Create a pattern matching keywords inside the user-agent field.

    Returns an inner pattern (no surrounding quotes) suitable for placing
    directly into the UA field of the assembled regex.
    """
    escaped = [_re_escape(k) for k in keywords]
    return r'[^"]*?(?:' + "|".join(escaped) + r')[^"]*'


def _anchor_in_ua_startswith(keywords: list[str]) -> str:
    """Create a pattern matching keywords at the START of the user-agent field.

    Returns an inner pattern (no surrounding quotes) suitable for placing
    directly into the UA field of the assembled regex.
    """
    escaped = [_re_escape(k) for k in keywords]
    return r"(" + "|".join(escaped) + r')[^"]*'
