# Detection Rule Packs

Detection rule packs are curated sets of detection rules that ship with
the Vespid Server.  Each pack targets a specific service or attack
category and contains rules with pre-tuned thresholds and time windows.

## Available packs

| Pack | Service | Rules | Description |
|------|---------|-------|-------------|
| **Apache Attacks** | Apache HTTPD | 14 | TLS probing, path scanning, RCE attempts, path traversal, credential scanning, IoT exploits |
| **NGINX Attacks** | NGINX | 10 | Auth brute force, bot/scanner detection, SQLi, XSS, shellshock, request smuggling, sensitive file probing |
| **HAProxy Attacks** | HAProxy | 14 | Auth brute force, directory scanning, path traversal, RCE, SQLi, scanner UAs, IoT exploits |
| **OpenSSH Attacks** | OpenSSH | 9 | Root brute force, username enumeration, pubkey probing, password spraying, protocol violations, PAM failures |
| **Postfix Attacks** | Postfix | 9 | SASL auth brute force, relay abuse, VRFY/RCPT enumeration, command pipelining, non-SMTP abuse |
| **Sigma Web Attacks** | Apache/NGINX | 34 | SQLi, XSS, JNDI/Log4Shell, SSTI, webshells, suspicious UAs, scanner tools (Sigma-converted) |
| **Sigma SSH Attacks** | OpenSSH | 1 | Suspicious SSHD error patterns indicating exploitation (Sigma-converted) |
| **Sigma Host Threats** | auditd | 115 | Reverse shells, privilege escalation, credential dumping, C2, defense evasion (Sigma-converted) |
| **CMS / E-Commerce Probes** | Apache/NGINX, HAProxy | 22 | WooCommerce, Magento, WordPress API, Drupal, Joomla, Laravel, Django, Shopify fingerprinting; multi-platform scanner catch-all; generic CMS scanner detection |

## Enabling packs

Packs are managed in the server dashboard under **Security → Detection Rules**.
Each pack appears as a collapsible section with individual rules inside.

### Enable an entire pack

```bash
# Via dashboard: click "Enable All" on the pack header
# Via API:
curl -X POST https://server/api/v1/rules/templates/apache-attacks/enable-all \
     -H "Cookie: session=..."
```

### Toggle individual rules

```bash
curl -X POST https://server/api/v1/rules/templates/apache-attacks/3/toggle \
     -H "Cookie: session=..."
```

### Per-node filtering

Nodes only receive rules relevant to the log sources they monitor.
When an agent connects, it reports its `active_parsers` (e.g., `["secure", "apache"]`).
The server filters the rule set so a node monitoring only SSH logs
never receives Apache attack rules.

Two gates control which rules reach a node:

1. **Global enable** — the rule must be enabled on the server
2. **Parser relevance** — the rule's `log_sources` must match the node's `active_parsers`

## Rule structure

Each rule in a pack has these fields:

| Field | Description |
|-------|-------------|
| `name` | Unique rule identifier (e.g., `apache_path_traversal`) |
| `event_type` | Event type generated on match (e.g., `APACHE_PATH_TRAVERSAL`) |
| `regex` | Pattern to match against log lines, with `(?P<ip>...)` capture group |
| `log_sources` | List of parsers this rule applies to (e.g., `["apache"]`) |
| `max_attempts` | Number of matches within the window before triggering |
| `window_seconds` | Sliding window duration |
| `tags` | ATT&CK technique tags (Sigma rules only) |
| `sigma_id` | Original Sigma rule ID (Sigma rules only) |

### Example rule

```yaml
- name: apache_path_traversal
  event_type: APACHE_PATH_TRAVERSAL
  regex: '(?P<ip>\d+\.\d+\.\d+\.\d+) .+ "(?:GET|POST|PUT) .*(?:\.\./|\.\.\\|%2e%2e).*"'
  log_sources: [apache]
  max_attempts: 5
  window_seconds: 60
```

## Custom rules

Beyond built-in packs, admins can create custom rules via the dashboard
or API.

### Brute-force rules

Count occurrences of a pattern within a time window:

```bash
curl -X POST https://server/api/v1/rules/brute-force \
     -H "Cookie: session=..." \
     -H "Content-Type: application/json" \
     -d '{
       "name": "custom_ssh_root",
       "event_type": "SSH_ROOT_BRUTE",
       "parser": "secure",
       "regex": "Failed password for root from (?P<ip>\\S+)",
       "max_attempts": 3,
       "window_seconds": 120
     }'
```

### Custom regex rules

Match a single pattern and take action:

```bash
curl -X POST https://server/api/v1/rules/custom \
     -H "Cookie: session=..." \
     -H "Content-Type: application/json" \
     -d '{
       "name": "custom_scanner_ua",
       "event_type": "SCANNER_UA",
       "parser": "apache",
       "regex": "(?P<ip>\\S+) .+\"(?:Nmap|masscan|zgrab)\""
     }'
```

## Rule distribution

Agents poll the server for rule updates using conditional requests:

```
GET /api/v1/rules/distribution
Authorization: Bearer <token>
If-None-Match: "42"
```

- Returns **304** if the rule set hasn't changed
- Returns **200** with the full rule set when rules are added, modified, or toggled
- The agent merges server rules with local config and hot-reloads the
  detector — no restart required

### Merge strategies

| Strategy | Behavior |
|----------|----------|
| `layer` (default) | Server rules are added on top of local rules |
| `replace` | Server rules completely replace local detection config |

## Sigma rule integration

The Sigma packs are generated by converting rules from the
[SigmaHQ](https://github.com/SigmaHQ/sigma) repository using the built-in
`sigma_converter.py` tool.  See the
[Sigma Integration Guide](../SIGMA_INTEGRATION.md) for details on
importing additional Sigma rules.

## Pack file format

Packs are stored as YAML files in `vespid-server/packs/`:

```yaml
pack_name: apache-attacks
display_name: Apache Attacks
icon: shield
description: Detection rules for Apache HTTP Server attacks
prerequisite: apache

rules:
  - name: apache_tls_on_http
    event_type: APACHE_TLS_ON_HTTP
    regex: '(?P<ip>\d+\.\d+\.\d+\.\d+) .+ "\\x16\\x03'
    log_sources: [apache]
    max_attempts: 3
    window_seconds: 60
  # ... more rules
```
