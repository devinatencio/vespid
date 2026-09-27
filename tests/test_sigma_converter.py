"""Tests for the Sigma → Vespid rule converter."""

from vespid.scripts.sigma_converter import (
    _apache_single_block,
    _parse_condition_tokens,
    _resolve_block,
    _resolve_parser,
    classify,
    convert_rule,
    parse_sigma_rule,
)

# ── Parser resolution ───────────────────────────────────────────────────


def test_parser_webserver_category():
    assert _resolve_parser({"category": "webserver"}) == "apache"


def test_parser_apache_product():
    assert _resolve_parser({"product": "apache"}) == "apache"


def test_parser_nginx_product():
    assert _resolve_parser({"product": "nginx"}) == "apache"


def test_parser_proxy_category():
    assert _resolve_parser({"category": "proxy"}) == "apache"


def test_parser_sshd_service():
    assert _resolve_parser({"service": "sshd"}) == "secure"


def test_parser_linux_sshd():
    assert _resolve_parser({"product": "linux", "service": "sshd"}) == "secure"


def test_parser_process_creation():
    assert _resolve_parser({"product": "linux", "category": "process_creation"}) == "auditd"


def test_parser_windows():
    assert _resolve_parser({"product": "windows"}) is None


# ── Condition token parsing ─────────────────────────────────────────────


def test_parse_simple_condition():
    tokens = _parse_condition_tokens("selection")
    assert tokens == [(False, "selection")]


def test_parse_and_condition():
    tokens = _parse_condition_tokens("selection and filter")
    assert tokens == [(False, "selection"), (False, "filter")]


def test_parse_and_not_condition():
    tokens = _parse_condition_tokens("selection and not filter")
    assert tokens == [(False, "selection"), (True, "filter")]


def test_parse_three_block_with_not():
    tokens = _parse_condition_tokens("select_method and keywords and not filter")
    assert tokens == [
        (False, "select_method"),
        (False, "keywords"),
        (True, "filter"),
    ]


def test_parse_with_1_of_prefix():
    tokens = _parse_condition_tokens("selection and keywords and not 1 of filter_main_*")
    assert tokens == [
        (False, "selection"),
        (False, "keywords"),
        (True, "filter_main_*"),
    ]


# ── Block resolution ────────────────────────────────────────────────────


def test_resolve_exact_match():
    blocks = {"selection": {"cs-method": "GET"}}
    assert _resolve_block(blocks, "selection") == {"cs-method": "GET"}


def test_resolve_wildcard():
    blocks = {"filter_main_status": {"sc-status": 404}}
    assert _resolve_block(blocks, "filter_main_*") == {"sc-status": 404}


def test_resolve_1_of_wildcard():
    blocks = {"filter_main_status": {"sc-status": 404}}
    assert _resolve_block(blocks, "1 of filter_main_*") == {"sc-status": 404}


def test_resolve_list_block():
    blocks = {"keywords": ["pattern1", "pattern2"]}
    assert _resolve_block(blocks, "keywords") == ["pattern1", "pattern2"]


# ── Classify ────────────────────────────────────────────────────────────


def test_classify_webserver_rule():
    rule = {
        "title": "Test",
        "logsource": {"category": "webserver"},
        "detection": {
            "selection": {"cs-method": "GET"},
            "condition": "selection",
        },
    }
    cat, reason = classify(rule)
    assert cat == "compatible"


def test_classify_sshd_rule():
    rule = {
        "title": "Test SSH",
        "logsource": {"product": "linux", "service": "sshd"},
        "detection": {
            "keywords": ["error"],
            "condition": "keywords",
        },
    }
    cat, reason = classify(rule)
    assert cat == "compatible"


def test_classify_skip_windows():
    rule = {
        "title": "Windows Rule",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"Image": "cmd.exe"},
            "condition": "selection",
        },
    }
    cat, reason = classify(rule)
    assert cat == "skip_platform"


def test_classify_skip_process_creation_field():
    rule = {
        "title": "Linux Proc Rule",
        "logsource": {"product": "linux", "category": "sshd"},
        "detection": {
            "selection": {"Image": "/usr/bin/ssh"},
            "condition": "selection",
        },
    }
    cat, reason = classify(rule)
    assert cat == "skip_unsupported"


# ── Simple block regex ──────────────────────────────────────────────────


def test_single_block_keywords_list():
    regex = _apache_single_block(["keyword1", "keyword2"])
    assert regex is not None
    assert "(?P<ip>" in regex
    assert "keyword1" in regex
    assert "keyword2" in regex


def test_single_block_cs_method_and_uri():
    block = {
        "cs-method": "GET",
        "cs-uri-query|contains": ["UNION SELECT", "SELECT * FROM"],
    }
    regex = _apache_single_block(block)
    assert regex is not None
    assert "(?P<ip>" in regex
    assert "GET" in regex
    assert "UNION SELECT" in regex or "UNION\\ SELECT" in regex


# ── Full conversion pipeline ────────────────────────────────────────────


def test_convert_simple_webserver_rule():
    yaml = """
title: Test SQL Injection
id: 12345678-1234-1234-1234-123456789abc
status: test
level: high
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-method: GET
    keywords:
        - 'UNION SELECT'
        - 'SELECT * FROM'
    filter_main_status:
        sc-status: 404
    condition: selection and keywords and not 1 of filter_main_*
"""
    rule = parse_sigma_rule(yaml)
    assert rule is not None

    result, reason = convert_rule(rule)
    assert result is not None, f"Conversion failed: {reason}"
    assert result.name.startswith("sigma_")
    assert result.event_type == "SIGMA_WEB_SQLI"
    assert result.sigma_id == "12345678-1234-1234-1234-123456789abc"
    assert result.sigma_status == "test"
    assert "attack.t1190" in result.tags
    assert result.max_attempts == 2  # high severity
    assert result.window_seconds == 120
    assert result.enabled is False  # sigma rules start disabled
    assert "apache" in result.log_sources


def test_convert_sshd_error_rule():
    yaml = """
title: Suspicious OpenSSH Daemon Error
id: e76b413a-83d0-4b94-8e4c-85db4a5b8bdc
status: test
level: medium
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    product: linux
    service: sshd
detection:
    keywords:
        - 'unexpected internal error'
        - 'bad client public DH value'
    condition: keywords
"""
    rule = parse_sigma_rule(yaml)
    assert rule is not None

    result, reason = convert_rule(rule)
    assert result is not None, f"Conversion failed: {reason}"
    assert "secure" in result.log_sources


def test_convert_skip_windows():
    yaml = """
title: Windows Process
id: 00000000-0000-0000-0000-000000000001
logsource:
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
"""
    rule = parse_sigma_rule(yaml)
    assert rule is not None

    result, reason = convert_rule(rule)
    assert result is None
    assert "windows" in reason.lower() or "platform" in reason


def test_regex_has_ip_capture():
    """All converted rules must have (?P<ip>...) in their regex."""
    yaml = """
title: Test Rule
id: 99999999-9999-9999-9999-999999999999
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - '/etc/passwd'
    condition: selection
"""
    rule = parse_sigma_rule(yaml)
    result, reason = convert_rule(rule)
    assert result is not None, reason
    assert "(?P<ip>" in result.regex
