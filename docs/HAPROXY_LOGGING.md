# HAProxy Logging

Vespid can parse HAProxy log lines and detect brute-force attacks, scanner
probes, and other malicious patterns — the same way it handles Apache/NGINX
access logs.

## Contents

- [Supported log formats](#supported-log-formats)
- [Quick start](#quick-start)
- [Config reference](#config-reference)
  - [Basic log source](#basic-log-source)
  - [Mode hint (`haproxy_mode`)](#mode-hint-haproxy_mode)
  - [Custom log format (`haproxy_log_format`)](#custom-log-format-haproxy_log_format)
  - [Full example](#full-example)
- [Sub-parsers and detection](#sub-parsers-and-detection)
- [Performance](#performance)
- [Troubleshooting](#troubleshooting)

---

## Supported log formats

The parser recognises the two default HAProxy log formats out of the box:

### HTTP mode (`option httplog`)

```
log-format "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r"
```

Example line:

```
192.168.1.1:54321 [20/Dec/2025:14:30:45.123] frontend~ backend/srv1 0/0/1/2/3 200 1234 - - ---- 1/1/0/0/0 0/0 {req_hdrs} {resp_hdrs} "GET / HTTP/1.1"
```

### TCP mode (`option tcplog`)

```
log-format "%ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq"
```

Example line:

```
10.0.0.1:54321 [20/Dec/2025:14:30:45] frontend~ backend/srv1 0/0/3 1234 ---- 1/1/0/0/0 0/0
```

### Custom `log-format`

If you use a custom `log-format` directive, tell Vespid the template string
and it will compile the appropriate regex (see [Custom log format](#custom-log-format-haproxy_log_format)).

---

## Quick start

### 1. Configure HAProxy to send logs

Add a `log` directive in the HAProxy config:

```haproxy
global
    log 127.0.0.1:514 local0 info

defaults
    log global
    option httplog
```

### 2. Configure rsyslog to write to a file

`/etc/rsyslog.d/haproxy.conf`:

```
$ModLoad imudp
$UDPServerAddress 127.0.0.1
$UDPServerRun 514
local0.* /var/log/haproxy-traffic.log
```

Restart rsyslog, then tail the file to confirm lines are arriving:

```bash
tail -f /var/log/haproxy-traffic.log
```

### 3. Add the log source to Vespid

`/etc/vespid/vespid.yaml`:

```yaml
log_sources:
  - path: /var/log/haproxy-traffic.log
    parser: haproxy
    haproxy_mode: http
```

Restart the daemon:

```bash
systemctl restart vespid
```

---

## Config reference

### Basic log source

```yaml
log_sources:
  - path: /var/log/haproxy-traffic.log
    parser: haproxy
```

With no extra options the parser tries the default HTTP format first, then
falls back to TCP format.

### Mode hint (`haproxy_mode`)

When you know which mode your HAProxy proxy uses, set `haproxy_mode` to skip
the fallback chain — one regex attempt per line instead of up to two.

| Value   | Behaviour                                      |
|---------|------------------------------------------------|
| `auto`  | Try HTTP first, fall back to TCP (default).    |
| `http`  | Match only the default HTTP log format.        |
| `tcp`   | Match only the default TCP log format.         |

On a busy server with thousands of requests per second, setting this correctly
avoids the overhead of matching the HTTP regex against every TCP line (and vice
versa).

```yaml
log_sources:
  - path: /var/log/haproxy-traffic.log
    parser: haproxy
    haproxy_mode: http      # <-- avoids TCP fallback
```

### Custom log format (`haproxy_log_format`)

If you define a custom `log-format` in your HAProxy config, you can mirror it
in Vespid. The parser maps known `%variables` to named capture groups.

```yaml
log_sources:
  - path: /var/log/haproxy.log
    parser: haproxy
    haproxy_log_format: "%ci:%cp [%t] %ft %b/%s %ST %B %r"
```

#### Supported variables

| Variable     | Extracts                        | Required for sub-parsers |
|--------------|---------------------------------|--------------------------|
| `%ci`        | Client IP                       | Yes (always needed)      |
| `%cp`        | Client port                     | No                       |
| `%t`         | TCP timestamp                   | No                       |
| `%tr`        | HTTP request timestamp          | No                       |
| `%ft`        | Frontend name                   | No                       |
| `%b`         | Backend name                    | No                       |
| `%s`         | Server name                     | No                       |
| `%ST`        | HTTP status code                | **Yes** — status-based   |
| `%B`         | Response bytes                  | No                       |
| `%CC`        | Captured request cookie         | No                       |
| `%CS`        | Captured response cookie        | No                       |
| `%tsc`       | Termination state (HTTP)        | No                       |
| `%ts`        | Termination state (TCP)         | No                       |
| `%ac`/`%fc`/`%bc`/`%sc`/`%rc` | Connection counters | No                       |
| `%sq`/`%bq`  | Queue sizes                     | No                       |
| `%hr`        | Captured request headers        | No                       |
| `%hs`        | Captured response headers       | No                       |
| `%r`         | HTTP request line (unquoted)    | No                       |
| `%{+Q}r`     | HTTP request line (quoted)      | No                       |

**`%ST` must be present** in the template for status-based sub-parsers to work
(see [Sub-parsers and detection](#sub-parsers-and-detection)). Without it, every
match is assigned the `haproxy` parser regardless of HTTP status.

Any variable not in the table above is matched as any non-whitespace token
(`\S+`).

#### `%r` vs `%{+Q}r`

The default HTTP format quotes the request line via `%{+Q}r`:

```
"GET / HTTP/1.1"
```

If your custom format uses `%r` instead (no quoting), the request line is
matched as three space-separated tokens: `GET / HTTP/1.1`.

### Full example

```yaml
log_sources:
  - path: /var/log/haproxy-traffic.log
    parser: haproxy
    haproxy_mode: http
    haproxy_log_format: "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r"

brute_force_rules:
  - name: haproxy_auth_brute
    event_type: HAPROXY_AUTH_BRUTE
    max_attempts: 20
    window_seconds: 600
    parser: haproxy
```

---

## Sub-parsers and detection

When the parser extracts an HTTP status code (`%ST`), it derives a sub-parser
name — exactly like the Apache parser — which enables fine-grained detection
rules and correlation:

| Sub-parser             | Trigger              | Typical use                        |
|------------------------|----------------------|------------------------------------|
| `haproxy`              | 401 or 403 status    | Auth brute force                   |
| `haproxy_bad_request`  | 400 status           | Malformed request scanning         |
| `haproxy_not_found`    | 404 status           | Directory brute force / path probe |
| `haproxy_scanner_ua`   | Scanner UA detected  | Automated recon / scanning tools   |
| `haproxy_ssl_fail`     | SSL handshake failure | TLS/cipher scanning (not an HTTP access line) |
| `haproxy_other`        | Any other status     | Catch-all for custom rules         |

These sub-parsers feed into the correlation detector just like Apache's — if an
IP triggers `haproxy_bad_request` + `haproxy_not_found` + `haproxy_scanner_ua`
within the correlation window, the `RECON_CORRELATION` rule fires.

Custom rules targeting `haproxy` in their `log_sources` will match all
sub-parsers (the same wildcard behaviour as `apache`).

### Detection pack

Vespid ships an **HAProxy Attack Detection Pack** (`haproxy-attacks`) that
provides 15 pre-built rules covering common HTTP attacks. Enable it in the
server UI or by adding `detection_packs: ["haproxy-attacks"]` to the
configuration profile.

| Rule | Event Type | Detects |
|---|---|---|
| `haproxy_auth_brute` | `HAPROXY_AUTH_BRUTE` | 401/403 status (auth brute force) |
| `haproxy_bad_request` | `HAPROXY_BAD_REQUEST` | 400 status (malformed request scanning) |
| `haproxy_path_probe` | `HAPROXY_PATH_PROBE` | 404 on admin/CMS/probe paths |
| `haproxy_tls_on_http` | `HAPROXY_TLS_PROBE` | TLS ClientHello on HTTP port |
| `haproxy_path_traversal` | `HAPROXY_PATH_TRAVERSAL` | `../`, `%2e%2e`, `%252e%252e` in URI |
| `haproxy_rce_attempt` | `HAPROXY_RCE_ATTEMPT` | `;wget`, `;curl`, `/bin/sh`, eval injection |
| `haproxy_sqli` | `HAPROXY_SQL_INJECTION` | SQL keywords in URI (spaces or `+`-encoded) |
| `haproxy_sensitive_file_probe` | `HAPROXY_SENSITIVE_FILE` | `/server-status`, `/actuator`, `/info.php` |
| `haproxy_docker_api_probe` | `HAPROXY_DOCKER_PROBE` | `/containers/json`, `/images/json` |
| `haproxy_wp_scan` | `HAPROXY_WP_SCAN` | `/wp-login`, `/wp-admin`, `/wp-config` |
| `haproxy_iot_exploit` | `HAPROXY_IOT_EXPLOIT` | `boaform`, `setup.cgi` (router/IoT probes) |
| `haproxy_env_secret_scan` | `HAPROXY_SECRET_SCAN` | `/.env`, `/.git`, `credentials.json` |
| `haproxy_vite_fs_traversal` | `HAPROXY_VITE_TRAVERSAL` | `/@fs/` (Vite dev server traversal) |
| `haproxy_script_injection` | `HAPROXY_SCRIPT_INJECTION` | `<script>`, `onerror=`, `alert()` in URI |
| `haproxy_ssl_handshake_probe` | `HAPROXY_SSL_HANDSHAKE_PROBE` | Repeated TLS handshake failures (cipher/TLS scanning) |

The pack file lives at `packs/haproxy-attacks.yaml` and can be customised or
used as a template for additional HAProxy-specific rules.

When the pack is enabled alongside the HAProxy log source, the daemon auto-selects
it via the `log_sources` field — no manual pack assignment required.

---

## Performance

- **No custom format, mode=hint set**: 1 regex attempt per line.
- **No custom format, mode=auto**: up to 2 regex attempts (HTTP → TCP).
- **Custom format**: 1 regex attempt per line (compiled at startup).
- **Scanner UA check**: runs on every HTTP match — same substring scan used by
  the Apache parser.

For high-throughput HAProxy instances, set `haproxy_mode` to `"http"` or `"tcp"`
to eliminate the fallback chain entirely.

---

## Troubleshooting

### No lines are parsed

1. Confirm HAProxy logs are reaching the file:
   ```bash
   tail -f /var/log/haproxy-traffic.log
   ```
2. Check Vespid's log for parser registration:
   ```
   journalctl -u vespid | grep -i haproxy
   ```
3. If you use a custom `log-format`, verify the template string matches
   exactly (including quotes and spacing).
4. Try `mode=auto` if `mode=http` produces no matches — your log may be in TCP
   format.

### Only some fields are extracted

If `%ST` is absent from your custom `log-format` template, all HTTP matches
produce the generic `haproxy` parser name — status-based sub-parsers will not
be active. Add `%ST` to your template to enable them.

### Syslog prefix in log lines

If your HAProxy logs include a syslog prefix (e.g.
`May 17 14:30:45 haproxy[12345]: ...`), the parser may not match. Configure
rsyslog to strip the prefix, or use HAProxy's `format raw` option when logging
to stdout/stderr (Docker):

```haproxy
global
    log stdout format raw local0 info
```
