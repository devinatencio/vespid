# Server Deployment

## MySQL/MariaDB backend

For high-volume deployments, switch from SQLite to MySQL/MariaDB.

=== "Create database"

    ```sql
    CREATE DATABASE vespid CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    CREATE USER 'vespid'@'localhost' IDENTIFIED BY 'your-secure-password';
    GRANT ALL PRIVILEGES ON vespid.* TO 'vespid'@'localhost';
    FLUSH PRIVILEGES;
    ```

=== "Configure server"

    ```yaml
    # /etc/vespid-server/config.yaml
    DATABASE_TYPE: mysql
    DATABASE_HOST: localhost
    DATABASE_PORT: 3306
    DATABASE_NAME: vespid
    DATABASE_USER: vespid
    DATABASE_PASSWORD: your-secure-password
    ```

=== "Initialize"

    ```bash
    python vespid_server.py --config /etc/vespid-server/config.yaml init-db
    ```

### Migrate from SQLite

```bash
python migrate_sqlite_to_mysql.py \
    --sqlite /var/lib/vespid-server/vespid.db \
    --host localhost --port 3306 --database vespid \
    --user vespid --password 'your-secure-password'

# Preview without writing:
python migrate_sqlite_to_mysql.py \
    --sqlite /var/lib/vespid-server/vespid.db --dry-run
```

### When to use MySQL

| Factor | SQLite | MySQL/MariaDB |
|--------|--------|---------------|
| Setup | Zero-config | Requires server |
| Write concurrency | Single writer (WAL helps reads) | Full concurrent writes |
| Recommended for | < 50 nodes, < 100k events/day | 50+ nodes, high volume |
| Backup | Copy `.db` file | `mysqldump` or replication |

The abstraction layer (`app/db_compat.py`) handles placeholder translation
(`?` → `%s`), row access, and driver differences transparently.

## Gunicorn configuration

The server uses Gunicorn with `gevent` workers.  Defaults are in
`gunicorn.conf.py`; override via `/etc/vespid-server/environment`.

### Worker sizing

```
# /etc/vespid-server/environment
GUNICORN_WORKERS=1              # 1 for SQLite, CPU cores for MySQL
GUNICORN_WORKER_CLASS=gevent    # Required for SSE streams
GUNICORN_WORKER_CONNECTIONS=1000
GUNICORN_TIMEOUT=120
GUNICORN_KEEPALIVE=65           # Keep-above heartbeat interval
GUNICORN_MAX_REQUESTS=8000      # Recycle workers periodically
GUNICORN_MAX_REQUESTS_JITTER=800
```

**SQLite:** Use 1 worker.  More workers cause lock contention.
**MySQL:** Use 1 worker per CPU core.  MySQL handles concurrent writes natively.

### Why gevent?

SSE streams hold connections open for hours.  Gevent greenlets multiplex
thousands of idle connections on a single OS thread with near-zero overhead.

### Applying changes

```bash
sudo vim /etc/vespid-server/environment
sudo systemctl restart vespid-server
```

!!! warning
    With `preload_app = True` (the default), graceful reload is not
    supported.  Always use `restart` to apply config changes.

## Database schema

The server maintains 54 tables across both SQLite and MySQL backends:

| Group | Tables |
|-------|--------|
| **Core** | `app_settings`, `check_results`, `counter_snapshots`, `event_log_context`, `events`, `feed_catalog`, `ip_rules`, `nodes`, `pending_commands`, `saved_queries`, `users` |
| **Auth** | `api_keys`, `audit_log` |
| **Enrollment** | `enrollment_requests`, `enrollment_settings` |
| **Fleet** | `fleet_allowlist`, `fleet_block_reports`, `fleet_blocks`, `fleet_config` |
| **Detection rules** | `detection_rules_brute_force`, `detection_rules_correlation`, `detection_rules_custom`, `detection_rules_revision` |
| **Config management** | `agent_group_members`, `agent_groups`, `config_agent_status`, `config_assignments`, `config_profiles`, `config_rollouts`, `config_version_history` |
| **Alerts** | `alert_eval_lock`, `alert_events`, `alert_rules`, `alert_silences`, `notification_channels`, `rule_notification_channels` |
| **Monitoring groups** | `group_alert_conditions`, `group_condition_channels`, `monitoring_group_status`, `monitoring_groups` |
| **Host monitoring** | `host_events`, `host_threat_alert_config`, `host_threat_notifications` |
| **Synthetic checks** | `synthetic_alert_policies`, `synthetic_alert_rules`, `synthetic_check_jobs`, `synthetic_checks`, `synthetic_workers` |
| **Log monitoring** | `logfile_watches` |
| **Assets** | `asset_aliases`, `asset_relationships`, `assets` |
| **Intel** | `ip_intel`, `ip_intel_events` |

All `CREATE` statements use `IF NOT EXISTS` — `init-db` is idempotent.
Schema migrations are applied incrementally on each startup.

## Database backup

The server includes an automated backup engine that runs on a configurable
schedule.

### Configuration

```yaml
# /etc/vespid-server/config.yaml
BACKUP_ENABLED: true
BACKUP_DIR: /var/lib/vespid-server/backups
BACKUP_INTERVAL_HOURS: 24
BACKUP_RETENTION_DAYS: 7
```

| Setting | Default | Description |
|---------|---------|-------------|
| `BACKUP_ENABLED` | `false` | Enable automated backups |
| `BACKUP_DIR` | `/var/lib/vespid-server/backups` | Backup storage directory |
| `BACKUP_INTERVAL_HOURS` | `24` | Interval between backups |
| `BACKUP_RETENTION_DAYS` | `7` | Delete backups older than this |

### How it works

- **SQLite:** Uses Python's `sqlite3.backup()` API for a consistent
  online backup — no downtime required
- **MySQL:** Runs `mysqldump` with gzip compression

Backup files are named `vespid-backup-<timestamp>.db` (SQLite) or
`vespid-backup-<timestamp>.sql.gz` (MySQL).  Old backups beyond the
retention period are automatically pruned.

### Manual backup

```bash
# SQLite — simple file copy (stop writes first for consistency)
sudo systemctl stop vespid-server
cp /var/lib/vespid-server/vespid.db /var/lib/vespid-server/vespid.db.bak
sudo systemctl start vespid-server

# MySQL
mysqldump -u vespid -p vespid | gzip > vespid-backup-$(date +%Y%m%d).sql.gz
```

## Schema migrations

The server uses incremental `ALTER TABLE` migrations applied automatically
on startup.  Each migration adds columns or indexes without dropping
existing data.  This means:

- Upgrades are safe — just restart the server after updating the binary
- Downgrades are not supported — back up before upgrading
- The `init-db` command is idempotent and can be run at any time

## Troubleshooting

### Node not picking up commands

Commands poll after each heartbeat (default 5 min).  Check:
1. Node logs for `Command poll` messages
2. Command queue on the Rules page or node detail page
3. API key is valid and not restricted to a different `node_id`

### Feed deploy not taking effect

Flow: deploy → `pending` → heartbeat → `acknowledged` → sync → `completed`.
If stuck at `pending`, the node may be offline.  If `failed`, check the
result message.

### Database permission errors

```bash
sudo chown -R vespid:vespid /var/lib/vespid-server
sudo chmod 750 /var/lib/vespid-server
```

### Service won't start

```bash
journalctl -u vespid-server -n 50 --no-pager
```

### Common Gunicorn mistakes

| Mistake | Symptom | Fix |
|---------|---------|-----|
| Too many workers, few cores | High CPU, slow responses | Workers = core count |
| Many workers + SQLite | Write timeouts, "database locked" | Use 1 worker |
| Low keepalive, many nodes | Constant TCP reconnects | `GUNICORN_KEEPALIVE=65` |
| No worker recycling | Memory grows over days | Set `GUNICORN_MAX_REQUESTS` |
| `sync` worker class | SSE streams block workers | Use `gevent` |
