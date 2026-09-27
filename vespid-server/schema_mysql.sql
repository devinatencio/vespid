-- ShieldNode Server: MySQL/MariaDB Schema
-- This file creates all tables, indexes, and seed data for the MySQL/MariaDB backend.
-- Compatible with MySQL 8.0+ and MariaDB 10.5+.
-- All statements use IF NOT EXISTS for idempotent execution.

-- ============================================================================
-- Events table: stores all ingested SecurityEvents
-- ============================================================================
CREATE TABLE IF NOT EXISTS events (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    event_id        VARCHAR(255) NOT NULL UNIQUE,
    node_id         VARCHAR(255) NOT NULL,
    timestamp       VARCHAR(255) NOT NULL,
    source_ip       VARCHAR(255) NOT NULL,
    event_type      VARCHAR(255) NOT NULL,
    action_taken    VARCHAR(255) NOT NULL,
    geo_country     VARCHAR(255),
    geo_city        VARCHAR(255),
    geo_asn         VARCHAR(255),
    geo_org         VARCHAR(255),
    geo_latitude    VARCHAR(255),
    geo_longitude   VARCHAR(255),
    geo_data        TEXT NOT NULL DEFAULT ('{}'),
    metadata        TEXT NOT NULL DEFAULT ('{}'),
    ingested_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE events ADD INDEX IF NOT EXISTS idx_events_timestamp (timestamp);
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_events_source_ip (source_ip);
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_events_node_id (node_id);
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_events_event_type (event_type);
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_events_geo_country (geo_country);
ALTER TABLE events ADD INDEX IF NOT EXISTS idx_events_ingested (ingested_at);

-- ============================================================================
-- Event log context: raw log lines surrounding a blocked event.
-- Stored separately so the events table stays lean and context
-- can be lazy-loaded in the UI.
-- ============================================================================
CREATE TABLE IF NOT EXISTS event_log_context (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    event_id        VARCHAR(255) NOT NULL,
    line_idx        INT NOT NULL,
    raw             TEXT NOT NULL,
    parser          VARCHAR(255),
    is_trigger      TINYINT(1) NOT NULL DEFAULT 0,
    repeat_count    INT NOT NULL DEFAULT 1,
    first_ts        VARCHAR(64),
    last_ts         VARCHAR(64),
    INDEX idx_elc_event_id (event_id),
    CONSTRAINT fk_elc_event FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- App settings: key-value store for server configuration
-- ============================================================================
CREATE TABLE IF NOT EXISTS app_settings (
    `key`           VARCHAR(64) NOT NULL PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed default settings
INSERT IGNORE INTO app_settings (`key`, value, updated_at) VALUES
    ('setup_complete', 'false', '1970-01-01T00:00:00Z'),
    ('host_events_retention_days', '30', '1970-01-01T00:00:00Z'),
    ('fleet_block_ttl_seconds', '86400', '1970-01-01T00:00:00Z');

-- ============================================================================
-- Users table: dashboard operators
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(255) NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            VARCHAR(50) NOT NULL DEFAULT 'viewer',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at   DATETIME,
    display_name    VARCHAR(128) NOT NULL DEFAULT '',
    theme           VARCHAR(16) NOT NULL DEFAULT 'dark',
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until    DATETIME NULL,
    onboarding_dismissed TINYINT(1) NOT NULL DEFAULT 0,
    brand_beam_enabled TINYINT(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- API Keys table: bearer tokens for node authentication
-- ============================================================================
CREATE TABLE IF NOT EXISTS api_keys (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    key_hash        VARCHAR(255) NOT NULL UNIQUE,
    key_prefix      VARCHAR(255) NOT NULL,
    label           VARCHAR(255) NOT NULL,
    role            VARCHAR(32) NOT NULL DEFAULT 'agent',
    node_id_restriction VARCHAR(255),
    is_active       INT NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at    DATETIME,
    created_by      INT,
    host_id         VARCHAR(64),
    CONSTRAINT fk_api_keys_created_by FOREIGN KEY (created_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Nodes table: auto-registered node registry
-- ============================================================================
CREATE TABLE IF NOT EXISTS nodes (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    node_id         VARCHAR(255) NOT NULL UNIQUE,
    display_name    VARCHAR(255) NOT NULL DEFAULT '',
    first_seen_at   VARCHAR(255) NOT NULL,
    last_event_at   VARCHAR(255),
    total_events    INT NOT NULL DEFAULT 0,
    last_geo_data   TEXT NOT NULL DEFAULT ('{}'),
    -- last_block_list moved to node_blocks table
    last_whitelist  TEXT NOT NULL DEFAULT ('[]'),
    last_feeds      TEXT NOT NULL DEFAULT ('[]'),
    last_counters   TEXT NOT NULL DEFAULT ('[]'),
    last_host_info  TEXT NOT NULL DEFAULT ('{}')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Node Blocks table: indexed block list entries pushed by the daemon
-- ============================================================================
CREATE TABLE IF NOT EXISTS node_blocks (
    node_id     VARCHAR(255) NOT NULL,
    ip          VARCHAR(45) NOT NULL,
    reason      VARCHAR(255) NOT NULL DEFAULT '',
    blocked_at  DOUBLE NOT NULL,
    expires_at  DOUBLE NOT NULL,
    strike      INT NOT NULL DEFAULT 1,
    PRIMARY KEY (node_id, ip),
    INDEX idx_nb_ip (ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Audit Log table
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    timestamp       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor           VARCHAR(255) NOT NULL,
    actor_ip        VARCHAR(255),
    action_type     VARCHAR(255) NOT NULL,
    target          VARCHAR(255),
    details         TEXT NOT NULL DEFAULT ('{}')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE audit_log ADD INDEX IF NOT EXISTS idx_audit_timestamp (timestamp);
ALTER TABLE audit_log ADD INDEX IF NOT EXISTS idx_audit_action_type (action_type);

-- ============================================================================
-- Pending Commands table
-- ============================================================================
CREATE TABLE IF NOT EXISTS pending_commands (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    command_id      VARCHAR(255) NOT NULL UNIQUE,
    node_id         VARCHAR(255) NOT NULL,
    command_type    VARCHAR(255) NOT NULL,
    payload         TEXT NOT NULL DEFAULT ('{}'),
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at DATETIME,
    result          TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE pending_commands ADD INDEX IF NOT EXISTS idx_commands_node_id (node_id);
ALTER TABLE pending_commands ADD INDEX IF NOT EXISTS idx_commands_status (status);

-- ============================================================================
-- IP Rules table: tracks whitelist/blacklist entries managed from the dashboard
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_rules (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    rule_type       VARCHAR(50) NOT NULL,
    entry           VARCHAR(255) NOT NULL,
    reason          TEXT NOT NULL DEFAULT (''),
    created_by      VARCHAR(255) NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active       INT NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE ip_rules ADD INDEX IF NOT EXISTS idx_ip_rules_type (rule_type);
ALTER TABLE ip_rules ADD INDEX IF NOT EXISTS idx_ip_rules_active (is_active);

-- ============================================================================
-- Feed Catalog table: centrally managed threat intelligence feeds
-- ============================================================================
CREATE TABLE IF NOT EXISTS feed_catalog (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(255) NOT NULL UNIQUE,
    url             TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT (''),
    format          VARCHAR(50) NOT NULL DEFAULT 'plain',
    refresh_seconds INT NOT NULL DEFAULT 3600,
    category        VARCHAR(255) NOT NULL DEFAULT 'general',
    is_default      INT NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by      VARCHAR(255) NOT NULL DEFAULT 'system'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE feed_catalog ADD INDEX IF NOT EXISTS idx_feed_catalog_category (category);

-- ============================================================================
-- Counter Snapshots table: historical time-series counter data from heartbeats
-- ============================================================================
CREATE TABLE IF NOT EXISTS counter_snapshots (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    node_id     VARCHAR(255) NOT NULL,
    timestamp   VARCHAR(255) NOT NULL,
    set_name    VARCHAR(255) NOT NULL,
    chain       VARCHAR(255) NOT NULL DEFAULT '',
    family      VARCHAR(255) NOT NULL DEFAULT '',
    packets     INT NOT NULL DEFAULT 0,
    bytes       BIGINT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE counter_snapshots ADD INDEX IF NOT EXISTS idx_cs_node_set_ts (node_id, set_name, timestamp);
ALTER TABLE counter_snapshots ADD INDEX IF NOT EXISTS idx_cs_timestamp (timestamp);

-- ============================================================================
-- Enrollment Requests table: tracks agent enrollment lifecycle
-- ============================================================================
CREATE TABLE IF NOT EXISTS enrollment_requests (
    id                    INT AUTO_INCREMENT PRIMARY KEY,
    node_id               VARCHAR(255) NOT NULL,
    hostname              VARCHAR(255) NOT NULL,
    source_ip             VARCHAR(255),
    source                VARCHAR(64) NOT NULL DEFAULT 'agent',
    status                VARCHAR(50) NOT NULL DEFAULT 'pending',
    requested_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decided_at            DATETIME,
    decided_by            VARCHAR(255),
    api_key_id            INT,
    credentials_retrieved INT NOT NULL DEFAULT 0,
    pending_token         VARCHAR(255),
    host_id               VARCHAR(64),
    CONSTRAINT fk_enrollment_api_key FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE enrollment_requests ADD INDEX IF NOT EXISTS idx_enrollment_node_id (node_id);
ALTER TABLE enrollment_requests ADD INDEX IF NOT EXISTS idx_enrollment_status (status);

-- ============================================================================
-- Enrollment Settings table: server-wide enrollment configuration
-- ============================================================================
CREATE TABLE IF NOT EXISTS enrollment_settings (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    setting_key   VARCHAR(255) NOT NULL UNIQUE,
    setting_value TEXT NOT NULL,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by    VARCHAR(255) NOT NULL DEFAULT 'system'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Fleet Blocks table: active fleet-wide blocklist
-- ============================================================================
CREATE TABLE IF NOT EXISTS fleet_blocks (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    fleet_block_id  VARCHAR(255) NOT NULL UNIQUE,
    source_ip       VARCHAR(255) NOT NULL,
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    first_reported_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_renewed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_at     DATETIME,
    expires_at      DATETIME NOT NULL,
    reporting_node_count INT NOT NULL DEFAULT 1,
    originating_node_id VARCHAR(255) NOT NULL,
    event_type      VARCHAR(255) NOT NULL,
    detection_rule  VARCHAR(255) NOT NULL DEFAULT '',
    reason          TEXT NOT NULL DEFAULT (''),
    ttl_seconds     INT NOT NULL DEFAULT 3600
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE fleet_blocks ADD INDEX IF NOT EXISTS idx_fleet_blocks_source_ip (source_ip);
ALTER TABLE fleet_blocks ADD INDEX IF NOT EXISTS idx_fleet_blocks_status (status);
ALTER TABLE fleet_blocks ADD INDEX IF NOT EXISTS idx_fleet_blocks_expires (expires_at);

-- ============================================================================
-- Fleet Block Reports table: individual node reports for corroboration tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS fleet_block_reports (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    source_ip       VARCHAR(255) NOT NULL,
    node_id         VARCHAR(255) NOT NULL,
    event_type      VARCHAR(255) NOT NULL,
    detection_rule  VARCHAR(255) NOT NULL DEFAULT '',
    block_ttl_seconds INT NOT NULL DEFAULT 3600,
    reported_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    fleet_block_id  VARCHAR(255),
    event_id        VARCHAR(255) NOT NULL DEFAULT '',
    CONSTRAINT fk_fbr_fleet_block FOREIGN KEY (fleet_block_id) REFERENCES fleet_blocks(fleet_block_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE fleet_block_reports ADD INDEX IF NOT EXISTS idx_fbr_source_ip (source_ip);
ALTER TABLE fleet_block_reports ADD INDEX IF NOT EXISTS idx_fbr_node_id (node_id);
ALTER TABLE fleet_block_reports ADD INDEX IF NOT EXISTS idx_fbr_reported (reported_at);
CREATE UNIQUE INDEX idx_fbr_ip_node ON fleet_block_reports(source_ip, node_id);

-- ============================================================================
-- Fleet Allowlist table: global allow-list for fleet blocklist
-- ============================================================================
CREATE TABLE IF NOT EXISTS fleet_allowlist (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    entry       VARCHAR(255) NOT NULL UNIQUE,
    reason      TEXT NOT NULL DEFAULT (''),
    created_by  VARCHAR(255) NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active   INT NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE fleet_allowlist ADD INDEX IF NOT EXISTS idx_fleet_al_active (is_active);

-- ============================================================================
-- Fleet Config table: propagation configuration (key-value)
-- ============================================================================
CREATE TABLE IF NOT EXISTS fleet_config (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    config_key    VARCHAR(255) NOT NULL UNIQUE,
    config_value  TEXT NOT NULL,
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by    VARCHAR(255) NOT NULL DEFAULT 'system'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Detection Rules: brute force type
-- ============================================================================
CREATE TABLE IF NOT EXISTS detection_rules_brute_force (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(255) NOT NULL UNIQUE,
    event_type      VARCHAR(255) NOT NULL,
    max_attempts    INT NOT NULL,
    window_seconds  INT NOT NULL,
    parser          VARCHAR(255) NOT NULL,
    enabled         INT NOT NULL DEFAULT 1,
    is_template     INT NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by      VARCHAR(255) NOT NULL DEFAULT 'system'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Detection Rules: custom regex type
-- ============================================================================
CREATE TABLE IF NOT EXISTS detection_rules_custom (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(255) NOT NULL UNIQUE,
    event_type      VARCHAR(255) NOT NULL,
    regex           TEXT NOT NULL,
    log_sources     TEXT NOT NULL DEFAULT ('["*"]'),
    max_attempts    INT NOT NULL,
    window_seconds  INT NOT NULL,
    enabled         INT NOT NULL DEFAULT 1,
    is_template     INT NOT NULL DEFAULT 0,
    pack_name       VARCHAR(255) NOT NULL DEFAULT '',
    tags            TEXT NOT NULL DEFAULT ('[]'),
    sigma_id        VARCHAR(64) NOT NULL DEFAULT '',
    sigma_status    VARCHAR(32) NOT NULL DEFAULT '',
    content_hash    TEXT NOT NULL DEFAULT (''),
    user_modified   INT NOT NULL DEFAULT 0,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by      VARCHAR(255) NOT NULL DEFAULT 'system'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Detection Rules: revision counter (single-row)
-- ============================================================================
CREATE TABLE IF NOT EXISTS detection_rules_revision (
    id              INT NOT NULL PRIMARY KEY,
    revision        INT NOT NULL DEFAULT 0,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT chk_revision_id CHECK (id = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Detection Rules: correlation (multi-signal) type
-- ============================================================================
CREATE TABLE IF NOT EXISTS detection_rules_correlation (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(255) NOT NULL UNIQUE,
    event_type      VARCHAR(255) NOT NULL,
    min_categories  INT NOT NULL DEFAULT 3,
    window_seconds  INT NOT NULL DEFAULT 600,
    enabled         INT NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by      VARCHAR(255) NOT NULL DEFAULT 'system'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Configuration Profiles table: centralized agent configuration templates
-- ============================================================================
CREATE TABLE IF NOT EXISTS config_profiles (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    name_lower      VARCHAR(255) NOT NULL UNIQUE,
    description     TEXT NOT NULL DEFAULT (''),
    version         INT NOT NULL DEFAULT 1,
    settings        TEXT NOT NULL DEFAULT ('{}'),
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by      VARCHAR(255) NOT NULL,
    is_active       INT NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE config_profiles ADD INDEX IF NOT EXISTS idx_config_profiles_active (is_active);
ALTER TABLE config_profiles ADD INDEX IF NOT EXISTS idx_config_profiles_created (created_at);

-- ============================================================================
-- Configuration Version History table: tracks profile changes over time
-- ============================================================================
CREATE TABLE IF NOT EXISTS config_version_history (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    profile_id      INT NOT NULL,
    version         INT NOT NULL,
    previous_settings TEXT NOT NULL DEFAULT ('{}'),
    new_settings    TEXT NOT NULL DEFAULT ('{}'),
    changed_by      VARCHAR(255) NOT NULL,
    changed_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    change_reason   TEXT NOT NULL,
    CONSTRAINT fk_cvh_profile FOREIGN KEY (profile_id) REFERENCES config_profiles(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE config_version_history ADD INDEX IF NOT EXISTS idx_cvh_profile_id (profile_id);
ALTER TABLE config_version_history ADD INDEX IF NOT EXISTS idx_cvh_version (profile_id, version);

-- ============================================================================
-- Configuration Assignments table: maps profiles to agents or groups
-- ============================================================================
CREATE TABLE IF NOT EXISTS config_assignments (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    node_id         VARCHAR(255),
    group_id        INT,
    profile_id      INT NOT NULL,
    assigned_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by     VARCHAR(255) NOT NULL,
    is_active       INT NOT NULL DEFAULT 1,
    CONSTRAINT fk_ca_profile FOREIGN KEY (profile_id) REFERENCES config_profiles(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE config_assignments ADD INDEX IF NOT EXISTS idx_ca_node_id (node_id);
ALTER TABLE config_assignments ADD INDEX IF NOT EXISTS idx_ca_group_id (group_id);
ALTER TABLE config_assignments ADD INDEX IF NOT EXISTS idx_ca_profile_id (profile_id);
ALTER TABLE config_assignments ADD INDEX IF NOT EXISTS idx_ca_active (is_active);

-- ============================================================================
-- Agent Groups table: logical grouping of agents for bulk assignment
-- ============================================================================
CREATE TABLE IF NOT EXISTS agent_groups (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(255) NOT NULL UNIQUE,
    description     TEXT NOT NULL DEFAULT (''),
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by      VARCHAR(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Agent Group Members table: maps agents to groups
-- ============================================================================
CREATE TABLE IF NOT EXISTS agent_group_members (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    group_id        INT NOT NULL,
    node_id         VARCHAR(255) NOT NULL,
    added_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    added_by        VARCHAR(255) NOT NULL,
    UNIQUE KEY uk_agm_group_node (group_id, node_id),
    CONSTRAINT fk_agm_group FOREIGN KEY (group_id) REFERENCES agent_groups(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE agent_group_members ADD INDEX IF NOT EXISTS idx_agm_group_id (group_id);
ALTER TABLE agent_group_members ADD INDEX IF NOT EXISTS idx_agm_node_id (node_id);

-- ============================================================================
-- Configuration Rollouts table: tracks staged/canary rollout state
-- ============================================================================
CREATE TABLE IF NOT EXISTS config_rollouts (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    profile_id      INT NOT NULL,
    target_version  INT NOT NULL,
    policy          VARCHAR(50) NOT NULL DEFAULT 'immediate',
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    canary_nodes    TEXT NOT NULL DEFAULT ('[]'),
    current_percentage INT NOT NULL DEFAULT 100,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by      VARCHAR(255) NOT NULL,
    completed_at    DATETIME,
    failure_count   INT NOT NULL DEFAULT 0,
    success_count   INT NOT NULL DEFAULT 0,
    total_targeted  INT NOT NULL DEFAULT 0,
    CONSTRAINT fk_cr_profile FOREIGN KEY (profile_id) REFERENCES config_profiles(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE config_rollouts ADD INDEX IF NOT EXISTS idx_cr_profile_id (profile_id);
ALTER TABLE config_rollouts ADD INDEX IF NOT EXISTS idx_cr_status (status);

-- ============================================================================
-- Configuration Agent Status table: per-agent config state for rollout tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS config_agent_status (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    node_id         VARCHAR(255) NOT NULL UNIQUE,
    profile_id      INT,
    acknowledged_version INT,
    last_check_in   DATETIME,
    management_mode VARCHAR(50) NOT NULL DEFAULT 'standalone',
    config_status   VARCHAR(50) NOT NULL DEFAULT 'unknown',
    last_failure_reason TEXT,
    agent_version   VARCHAR(255),
    health_uptime   INT,
    health_active_rules INT,
    health_blocked_ips INT,
    CONSTRAINT fk_cas_profile FOREIGN KEY (profile_id) REFERENCES config_profiles(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE config_agent_status ADD INDEX IF NOT EXISTS idx_cas_node_id (node_id);
ALTER TABLE config_agent_status ADD INDEX IF NOT EXISTS idx_cas_profile_id (profile_id);

-- ============================================================================
-- IP Intelligence table: aggregated threat intelligence per IP
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_intel (
    id                        INT AUTO_INCREMENT PRIMARY KEY,
    ip_address                VARCHAR(45) NOT NULL UNIQUE,
    ip_version                VARCHAR(2) NOT NULL,
    first_seen_at             VARCHAR(255) NOT NULL,
    last_seen_at              VARCHAR(255) NOT NULL,
    last_blocked_at           VARCHAR(255),
    total_times_seen          INT NOT NULL DEFAULT 0,
    total_times_blocked       INT NOT NULL DEFAULT 0,
    total_reporting_nodes     INT NOT NULL DEFAULT 0,
    total_attack_events       INT NOT NULL DEFAULT 0,
    repeat_offender           INT NOT NULL DEFAULT 0,
    first_reporting_node      VARCHAR(128) NOT NULL,
    most_recent_reporting_node VARCHAR(128) NOT NULL,
    reporting_node_list       TEXT NOT NULL,
    geo_country               VARCHAR(2),
    asn                       BIGINT,
    isp_organization          VARCHAR(256),
    reputation_score          DOUBLE,
    threat_tags               TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE ip_intel ADD INDEX IF NOT EXISTS idx_ip_intel_last_seen (last_seen_at);
ALTER TABLE ip_intel ADD INDEX IF NOT EXISTS idx_ip_intel_times_seen (total_times_seen);
ALTER TABLE ip_intel ADD INDEX IF NOT EXISTS idx_ip_intel_repeat (repeat_offender);
ALTER TABLE ip_intel ADD INDEX IF NOT EXISTS idx_ip_intel_geo (geo_country);

-- ============================================================================
-- IP Intelligence Events table: individual sighting/block events per IP
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_intel_events (
    id                INT AUTO_INCREMENT PRIMARY KEY,
    ip_address        VARCHAR(45) NOT NULL,
    node_id           VARCHAR(128) NOT NULL,
    event_type        VARCHAR(64) NOT NULL,
    event_kind        VARCHAR(10) NOT NULL,
    timestamp         VARCHAR(255) NOT NULL,
    detection_rule    VARCHAR(128) NOT NULL DEFAULT '',
    block_ttl_seconds INT NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE ip_intel_events ADD INDEX IF NOT EXISTS idx_ip_intel_events_ip (ip_address);
ALTER TABLE ip_intel_events ADD INDEX IF NOT EXISTS idx_ip_intel_events_ts (timestamp);
ALTER TABLE ip_intel_events ADD INDEX IF NOT EXISTS idx_ip_intel_events_ip_ts (ip_address, timestamp);

-- ============================================================================
-- Seed Data
-- ============================================================================

-- Detection rules revision seed
INSERT IGNORE INTO detection_rules_revision (id, revision) VALUES (1, 0);

-- Default correlation rule seed
INSERT IGNORE INTO detection_rules_correlation (name, event_type, min_categories, window_seconds) VALUES ('recon_correlation', 'RECON_CORRELATION', 3, 600);

-- Enrollment settings seed
INSERT IGNORE INTO enrollment_settings (setting_key, setting_value) VALUES ('enrollment_enabled', 'false');
INSERT IGNORE INTO enrollment_settings (setting_key, setting_value) VALUES ('enrollment_mode', 'manual_approval');
INSERT IGNORE INTO enrollment_settings (setting_key, setting_value) VALUES ('enrollment_token', '');
INSERT IGNORE INTO enrollment_settings (setting_key, setting_value) VALUES ('allow_unrestricted_api_keys', 'true');

-- Fleet config seed
INSERT IGNORE INTO fleet_config (config_key, config_value) VALUES ('corroboration_threshold', '1');
INSERT IGNORE INTO fleet_config (config_key, config_value) VALUES ('corroboration_window_seconds', '1h');
INSERT IGNORE INTO fleet_config (config_key, config_value) VALUES ('fleet_block_ttl_seconds', '1h');
INSERT IGNORE INTO fleet_config (config_key, config_value) VALUES ('max_fleet_blocks_per_hour', '100');
INSERT IGNORE INTO fleet_config (config_key, config_value) VALUES ('max_reports_per_node_per_hour', '50');
INSERT IGNORE INTO fleet_config (config_key, config_value) VALUES ('propagation_paused', 'false');
INSERT IGNORE INTO fleet_config (config_key, config_value) VALUES ('excluded_event_types', '[]');
INSERT IGNORE INTO fleet_config (config_key, config_value) VALUES ('reaper_interval_seconds', '86400');
INSERT IGNORE INTO fleet_config (config_key, config_value) VALUES ('expired_block_retention_seconds', '1d');
INSERT IGNORE INTO fleet_config (config_key, config_value) VALUES ('fleet_recidive_tiers', '[86400, 259200, 604800, 2592000]');
INSERT IGNORE INTO fleet_config (config_key, config_value) VALUES ('fleet_recidive_decay_seconds', '30d');

-- Saved queries for Query Explorer
CREATE TABLE IF NOT EXISTS saved_queries (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    name        VARCHAR(255) NOT NULL,
    query       TEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_sq_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Alert Rules table: per-user and global alerting rules
CREATE TABLE IF NOT EXISTS alert_rules (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT,
    name            VARCHAR(255) NOT NULL,
    query           TEXT,
    check_name      VARCHAR(255),
    operator        VARCHAR(4) NOT NULL CHECK(operator IN ('>', '<', '==', '>=', '<=')),
    threshold       DOUBLE NOT NULL,
    resolve_threshold DOUBLE,
    severity        VARCHAR(8) NOT NULL CHECK(severity IN ('warning', 'critical')),
    for_duration    INT NOT NULL DEFAULT 0,
    cooldown_secs   INT,
    interval_secs   INT NOT NULL DEFAULT 60,
    tags            TEXT,
    enabled         TINYINT(1) NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_alert_rules_enabled (enabled),
    INDEX idx_alert_rules_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Notification Channels table: Slack, email, webhook, PagerDuty configs
CREATE TABLE IF NOT EXISTS notification_channels (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    type            VARCHAR(16) NOT NULL,
    config          TEXT NOT NULL DEFAULT '{}',
    enabled         TINYINT(1) NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_notification_channels_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Rule-Channel associations (many-to-many)
CREATE TABLE IF NOT EXISTS rule_notification_channels (
    rule_id         INT NOT NULL,
    channel_id      INT NOT NULL,
    PRIMARY KEY (rule_id, channel_id),
    FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,
    FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Alert Silences table: maintenance windows and suppression
CREATE TABLE IF NOT EXISTS alert_silences (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    matchers        TEXT NOT NULL DEFAULT '[]',
    rule_id         INT,
    starts_at       DATETIME NOT NULL,
    ends_at         DATETIME NOT NULL,
    reason          TEXT NOT NULL,
    created_by      INT NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id),
    INDEX idx_alert_silences_active (starts_at, ends_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Alert Eval Lock table: singleton row for distributed eval coordination
CREATE TABLE IF NOT EXISTS alert_eval_lock (
    id              INT PRIMARY KEY,
    locked_by       VARCHAR(255),
    locked_at       DATETIME,
    expires_at      DATETIME,
    last_eval_at    DATETIME
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO alert_eval_lock (id, locked_by, locked_at, expires_at, last_eval_at)
VALUES (1, NULL, NULL, NULL, NULL);

-- Monitoring Groups: named groups with label matchers for instance targeting
CREATE TABLE IF NOT EXISTS monitoring_groups (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    match_labels    TEXT NOT NULL DEFAULT '[]',
    match_any       TINYINT(1) NOT NULL DEFAULT 0,
    enabled         TINYINT(1) NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_monitoring_groups_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Group Alert Conditions: predefined metric checks per group
CREATE TABLE IF NOT EXISTS group_alert_conditions (
    id                INT AUTO_INCREMENT PRIMARY KEY,
    group_id          INT NOT NULL,
    name              VARCHAR(255) NOT NULL,
    metric_type       VARCHAR(50) NOT NULL,
    metric_params     TEXT NOT NULL DEFAULT '{}',
    target_labels     TEXT,
    operator          VARCHAR(4) NOT NULL,
    threshold         DOUBLE NOT NULL,
    resolve_threshold DOUBLE,
    severity          VARCHAR(8) NOT NULL DEFAULT 'warning',
    for_duration      INT NOT NULL DEFAULT 0,
    cooldown_secs     INT,
    interval_secs     INT NOT NULL DEFAULT 60,
    last_eval_at      DATETIME,
    enabled           TINYINT(1) NOT NULL DEFAULT 1,
    created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES monitoring_groups(id) ON DELETE CASCADE,
    INDEX idx_group_alert_conditions_group (group_id),
    INDEX idx_group_alert_conditions_type (metric_type),
    INDEX idx_group_alert_conditions_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Alert Events table: individual firing/resolved/acknowledged events
CREATE TABLE IF NOT EXISTS alert_events (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    rule_id         INT,
    entity_id       INT,
    group_condition_id INT,
    labels          TEXT NOT NULL DEFAULT '{}',
    value           DOUBLE NOT NULL,
    state           VARCHAR(16) NOT NULL DEFAULT 'firing',
    fired_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at     DATETIME,
    acknowledged_by INT,
    notified_at     DATETIME,
    FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,
    FOREIGN KEY (group_condition_id) REFERENCES group_alert_conditions(id) ON DELETE CASCADE,
    FOREIGN KEY (acknowledged_by) REFERENCES users(id),
    INDEX idx_alert_events_state (state),
    INDEX idx_alert_events_rule (rule_id),
    INDEX idx_alert_events_entity (entity_id),
    INDEX idx_alert_events_group_condition (group_condition_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Group-Condition-Channel associations (many-to-many)
CREATE TABLE IF NOT EXISTS group_condition_channels (
    condition_id  INT NOT NULL,
    channel_id    INT NOT NULL,
    PRIMARY KEY (condition_id, channel_id),
    FOREIGN KEY (condition_id) REFERENCES group_alert_conditions(id) ON DELETE CASCADE,
    FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Feed catalog seed
INSERT IGNORE INTO feed_catalog (name, url, description, format, refresh_seconds, category, is_default, created_by) VALUES ('firehol_level1', 'https://iplists.firehol.org/files/firehol_level1.netset', 'FireHOL Level 1 — verified high-confidence blocklist aggregated from multiple sources. Very low false-positive rate.', 'cidr', 21600, 'aggregated', 1, 'system');
INSERT IGNORE INTO feed_catalog (name, url, description, format, refresh_seconds, category, is_default, created_by) VALUES ('firehol_level2', 'https://iplists.firehol.org/files/firehol_level2.netset', 'FireHOL Level 2 — broader coverage than Level 1, includes more sources. Slightly higher false-positive risk.', 'cidr', 21600, 'aggregated', 0, 'system');
INSERT IGNORE INTO feed_catalog (name, url, description, format, refresh_seconds, category, is_default, created_by) VALUES ('spamhaus_drop', 'https://www.spamhaus.org/drop/drop.txt', 'Spamhaus DROP — hijacked netblocks controlled by spammers and cyber criminals (includes former EDROP ranges). Zero false-positive rate.', 'cidr', 43200, 'hijacked', 1, 'system');
INSERT IGNORE INTO feed_catalog (name, url, description, format, refresh_seconds, category, is_default, created_by) VALUES ('abuse_ch_feodo', 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'abuse.ch Feodo Tracker — C2 botnet IPs (Emotet, Dridex, TrickBot). Updated frequently.', 'plain', 3600, 'botnet', 1, 'system');
INSERT IGNORE INTO feed_catalog (name, url, description, format, refresh_seconds, category, is_default, created_by) VALUES ('abuse_ch_sslbl', 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt', 'abuse.ch SSLBL — IPs associated with malicious SSL certificates used by botnets.', 'plain', 3600, 'botnet', 0, 'system');
INSERT IGNORE INTO feed_catalog (name, url, description, format, refresh_seconds, category, is_default, created_by) VALUES ('blocklist_de', 'https://lists.blocklist.de/lists/all.txt', 'Blocklist.de — IPs reported for SSH, mail, and web attacks by a large sensor network.', 'plain', 3600, 'attacks', 0, 'system');
INSERT IGNORE INTO feed_catalog (name, url, description, format, refresh_seconds, category, is_default, created_by) VALUES ('ci_army', 'https://cinsscore.com/list/ci-badguys.txt', 'CI Army — collective intelligence badlist from the CINS Score project.', 'plain', 7200, 'attacks', 0, 'system');
INSERT IGNORE INTO feed_catalog (name, url, description, format, refresh_seconds, category, is_default, created_by) VALUES ('et_compromised', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'Emerging Threats — known compromised hosts actively participating in attacks.', 'plain', 7200, 'compromised', 0, 'system');
INSERT IGNORE INTO feed_catalog (name, url, description, format, refresh_seconds, category, is_default, created_by) VALUES ('dshield_top20', 'https://feeds.dshield.org/block.txt', 'DShield — SANS ISC top attacking subnets based on global sensor data.', 'cidr', 86400, 'attacks', 0, 'system');
INSERT IGNORE INTO feed_catalog (name, url, description, format, refresh_seconds, category, is_default, created_by) VALUES ('tor_exit_nodes', 'https://check.torproject.org/torbulkexitlist', 'Tor exit nodes — useful for blocking or flagging anonymous traffic. Use with caution as it blocks legitimate Tor users.', 'plain', 3600, 'anonymizers', 0, 'system');
INSERT IGNORE INTO feed_catalog (name, url, description, format, refresh_seconds, category, is_default, created_by) VALUES ('binarydefense', 'https://binarydefense.com/banlist.txt', 'Binary Defense — artillery honeypot IPs observed actively scanning and attacking.', 'plain', 7200, 'attacks', 0, 'system');

-- ============================================================================
-- Logfile Watches table: WebUI-configured log file monitoring for agents
-- ============================================================================
CREATE TABLE IF NOT EXISTS logfile_watches (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    agent_id        VARCHAR(36) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    path            TEXT NOT NULL,
    pattern         TEXT NOT NULL,
    alert_on_match  TINYINT(1) NOT NULL DEFAULT 1,
    enabled         TINYINT(1) NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    created_by      INT,
    UNIQUE KEY uq_lw_agent_name (agent_id, name),
    INDEX idx_lw_agent (agent_id),
    INDEX idx_lw_enabled (enabled),
    FOREIGN KEY (created_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Assets table: canonical inventory record for all infrastructure
-- Each row represents a discovered asset (host, VM, container, etc.) with a
-- permanent UUID asset_id that outlives any external identifier.
-- ============================================================================
CREATE TABLE IF NOT EXISTS assets (
    asset_id         CHAR(36) PRIMARY KEY,
    asset_type       VARCHAR(32) NOT NULL DEFAULT 'host',
    display_name     VARCHAR(255) NOT NULL,
    parent_id        CHAR(36),
    metadata         TEXT NOT NULL DEFAULT ('{}'),
    labels           TEXT NOT NULL DEFAULT ('{}'),
    first_seen_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at     DATETIME,
    status           VARCHAR(16) NOT NULL DEFAULT 'active',
    created_by_source VARCHAR(64) NOT NULL DEFAULT 'agent',
    FOREIGN KEY (parent_id) REFERENCES assets(asset_id),
    INDEX idx_assets_type (asset_type),
    INDEX idx_assets_parent (parent_id),
    INDEX idx_assets_status (status),
    INDEX idx_assets_source (created_by_source),
    INDEX idx_assets_last_seen (last_seen_at),
    INDEX idx_assets_display_name (display_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Asset Aliases table: maps external identifiers to canonical asset_id.
-- Every identifier a discovery source reports (machine-id, hostname, MAC,
-- VMID, instance-id) is stored here for entity resolution.
-- ============================================================================
CREATE TABLE IF NOT EXISTS asset_aliases (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    asset_id         CHAR(36) NOT NULL,
    alias_type       VARCHAR(64) NOT NULL,
    alias_value      VARCHAR(255) NOT NULL,
    source           VARCHAR(64) NOT NULL,
    confidence       TINYINT NOT NULL DEFAULT 100,
    first_claimed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_confirmed_at DATETIME,
    UNIQUE KEY idx_aa_type_value (alias_type, alias_value),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,
    INDEX idx_aa_asset (asset_id),
    INDEX idx_aa_value (alias_value)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Asset Relationships table: graph edges between assets.
-- Represents RUNS_ON, BELONGS_TO, DEPENDS_ON, CONNECTS_TO, etc.
-- ============================================================================
CREATE TABLE IF NOT EXISTS asset_relationships (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    source_asset_id  CHAR(36) NOT NULL,
    target_asset_id  CHAR(36) NOT NULL,
    relationship     VARCHAR(32) NOT NULL,
    metadata         TEXT NOT NULL DEFAULT ('{}'),
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY idx_ar_src_tgt_rel (source_asset_id, target_asset_id, relationship),
    FOREIGN KEY (source_asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,
    FOREIGN KEY (target_asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,
    INDEX idx_ar_target (target_asset_id),
    INDEX idx_ar_relationship (relationship)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Host events table: stores host-level process creation detections (auditd pipeline)
-- ============================================================================
CREATE TABLE IF NOT EXISTS host_events (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    hostname        VARCHAR(255) NOT NULL,
    timestamp       VARCHAR(64)  NOT NULL,
    event_type      VARCHAR(128) NOT NULL,
    rule_name       VARCHAR(128) NOT NULL,
    pid             INT          NOT NULL,
    ppid            INT          NOT NULL,
    exe             VARCHAR(1024) NOT NULL,
    command_line    TEXT         NOT NULL,
    uid             INT          NOT NULL,
    auid            BIGINT       NOT NULL,
    raw_line        TEXT         NOT NULL,
    node_id         VARCHAR(128) NOT NULL,
    ingested_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_host_events_hostname (hostname),
    INDEX idx_host_events_timestamp (timestamp),
    INDEX idx_host_events_node_id (node_id),
    INDEX idx_host_events_hostname_timestamp (hostname, timestamp),
    INDEX idx_host_events_ingested_at (ingested_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
