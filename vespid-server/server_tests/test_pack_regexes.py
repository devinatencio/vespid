"""Regression tests for web-attack pack regexes.

These cover the false positives that blocked normal dashboard traffic:

* ``sigma_exploit_framework_user_agent`` used to contain a bare
  ``Mozilla/5.0`` alternative and matched every modern browser UA.
* ``sigma_malware_user_agent`` used to contain bare ``M`` / ``Safari/537.36``
  / ``Gecko/20100101`` alternatives with the same effect.
* ``cms_multi_probe`` / ``cms_multi_probe_haproxy`` matched generic
  ``/api/`` and ``/admin/`` paths, including the dashboard's own
  ``/api/stats`` and ``/admin/config/`` requests.
"""

import re

import pytest

from app.pack_loader import get_pack_rules, load_packs

OPERA_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/153.0.0.0 Safari/537.36 OPR/137.0.0.0"
)

RULES = {rule["name"]: rule for rule in get_pack_rules(load_packs())}


def _apache(path: str, ua: str = OPERA_UA, status: int = 200) -> str:
    return (
        f'172.56.87.84 - - [08/Oct/2026:20:35:22 +0000] '
        f'"GET {path} HTTP/1.1" {status} 91 "-" "{ua}" rid=abc D=9243'
    )


def _haproxy(path: str, ua: str = OPERA_UA, full_url: bool = False) -> str:
    target = f"https://demo.vespid.app{path}" if full_url else path
    return (
        f'172.56.87.84:49737 [26/Oct/2026:05:47:53.321] https~ vespid/vespid '
        f'0/0/1/-1/6601 200 0 - - ---- 6/6/4/4/0 0/0 {{{ua}}} '
        f'"GET {target} HTTP/2.0"'
    )


BENIGN_APACHE = [
    _apache("/api/stats"),
    _apache("/api/health"),
    _apache("/admin/config/"),
    _apache("/static/style.css?v=38"),
]

BENIGN_HAPROXY = [
    _haproxy("/api/stats", full_url=True),
    _haproxy("/api/stats"),
    _haproxy("/admin/config/", full_url=True),
    _haproxy("/static/style.css?v=38", full_url=True),
]

UA_RULES = [
    "sigma_exploit_framework_user_agent",
    "sigma_malware_user_agent",
]

CMS_RULES = [
    "cms_multi_probe",
    "cms_multi_probe_haproxy",
]


@pytest.mark.parametrize("name", UA_RULES + CMS_RULES)
def test_regex_compiles_and_has_ip_group(name):
    rule = RULES[name]
    compiled = re.compile(rule["regex"])
    assert "ip" in compiled.groupindex


@pytest.mark.parametrize("name", UA_RULES)
@pytest.mark.parametrize("line", BENIGN_APACHE)
def test_normal_browser_ua_does_not_match(name, line):
    """Opera/Chrome dashboard requests must not look like exploit frameworks."""
    assert re.search(RULES[name]["regex"], line) is None


@pytest.mark.parametrize("name", CMS_RULES)
@pytest.mark.parametrize("line", BENIGN_APACHE + BENIGN_HAPROXY)
def test_dashboard_paths_do_not_match_cms_rules(name, line):
    """The app's own /api/* and /admin/* paths are not CMS probes."""
    assert re.search(RULES[name]["regex"], line) is None


def test_cms_rules_do_not_contain_generic_api_or_admin_prefixes():
    for name in CMS_RULES:
        regex = RULES[name]["regex"]
        assert "api\\/(?!v1\\/)" not in regex
        assert "|admin(?:[" not in regex


def test_exploit_rule_no_longer_has_bare_mozilla_prefix():
    regex = RULES["sigma_exploit_framework_user_agent"]["regex"]
    assert "|Mozilla/5\\.0|" not in regex


def test_malware_rule_no_longer_has_unbounded_browser_tokens():
    regex = RULES["sigma_malware_user_agent"]["regex"]
    assert "|M|" not in regex
    assert "|Safari/537\\.36|" not in regex
    assert "|Gecko/20100101|" not in regex


@pytest.mark.parametrize(
    ("name", "line"),
    [
        (
            "sigma_exploit_framework_user_agent",
            _apache("/", ua="Mozilla/4.0 (compatible; Metasploit RSPEC)"),
        ),
        (
            "sigma_malware_user_agent",
            _apache("/", ua="Havana/0.1"),
        ),
        (
            "sigma_hack_tool_user_agent",
            _apache("/", ua="sqlmap/1.7"),
        ),
    ],
)
def test_known_malicious_user_agents_still_match(name, line):
    assert re.search(RULES[name]["regex"], line) is not None


@pytest.mark.parametrize(
    "line",
    [
        _apache("/administrator/"),
        _apache("/wp-json/wp/v2/users"),
        _apache("/xmlrpc.php"),
        _apache("/graphql"),
        _apache("/rest/V1/orders"),
    ],
)
def test_cms_paths_still_match(line):
    assert re.search(RULES["cms_multi_probe"]["regex"], line) is not None


def test_cms_haproxy_path_still_matches():
    line = _haproxy("/administrator/")
    assert re.search(RULES["cms_multi_probe_haproxy"]["regex"], line) is not None


def test_thresholds_raised_for_noise_prone_rules():
    assert RULES["sigma_exploit_framework_user_agent"]["max_attempts"] == 3
    assert RULES["sigma_exploit_framework_user_agent"]["window_seconds"] == 300
    assert RULES["sigma_malware_user_agent"]["max_attempts"] == 3
    assert RULES["sigma_malware_user_agent"]["window_seconds"] == 300
    for name in CMS_RULES:
        assert RULES[name]["max_attempts"] == 5
        assert RULES[name]["window_seconds"] == 300
