use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default)]
    pub server: ServerConfig,

    #[serde(default)]
    pub agent: AgentSettings,

    #[serde(default)]
    pub log_level: String,

    #[serde(default = "default_log_retention_days")]
    pub log_retention_days: u64,

    #[serde(default)]
    pub collectors: CollectorsConfig,

    #[serde(default)]
    pub buffer: BufferConfig,

    #[serde(default)]
    pub transport: TransportConfig,

    #[serde(default)]
    pub worker: WorkerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_server_url")]
    pub url: String,

    #[serde(default)]
    pub api_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentSettings {
    #[serde(default)]
    pub agent_id: String,

    #[serde(default)]
    pub hostname_override: String,

    #[serde(default)]
    pub labels: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CollectorsConfig {
    #[serde(default)]
    pub cpu: CollectorEntry,

    #[serde(default)]
    pub memory: CollectorEntry,

    #[serde(default)]
    pub disk: DiskCollectorConfig,

    #[serde(default)]
    pub network: NetworkCollectorConfig,

    #[serde(default)]
    pub systemd: SystemdCollectorConfig,

    #[serde(default)]
    pub process: ProcessCollectorConfig,

    #[serde(default)]
    pub psi: CollectorEntry,

    #[serde(default)]
    pub procfs: ProcfsCollectorConfig,

    #[serde(default)]
    pub loadavg: CollectorEntry,

    #[serde(default)]
    pub swap: CollectorEntry,

    #[serde(default)]
    pub logfile: LogfileCollectorConfig,

    #[serde(default)]
    pub exec: ExecCollectorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecCollectorConfig {
    #[serde(default = "default_disabled")]
    pub enabled: bool,

    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    #[serde(default)]
    pub timeout_secs: u64,

    #[serde(default)]
    pub scripts: Vec<ExecScriptDef>,
}

impl Default for ExecCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 300,
            timeout_secs: 30,
            scripts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecScriptDef {
    pub name: String,
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogfileCollectorConfig {
    #[serde(default = "default_disabled")]
    pub enabled: bool,

    #[serde(default = "default_logfile_interval")]
    pub interval_secs: u64,

    #[serde(default = "default_logfile_state_path")]
    pub state_path: String,

    #[serde(default)]
    pub watches: Vec<LogWatchDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogWatchDef {
    pub name: String,
    pub path: String,
    pub pattern: String,

    #[serde(default)]
    pub alert_on_match: bool,
}

fn default_logfile_interval() -> u64 {
    10
}

fn default_logfile_state_path() -> String {
    "/var/lib/vespid-agent/logfile-state.json".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcfsCollectorConfig {
    #[serde(default = "default_disabled")]
    pub enabled: bool,

    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    #[serde(default)]
    pub metrics: Vec<ProcfsMetricDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcfsMetricDef {
    pub name: String,
    pub path: String,

    #[serde(default = "default_parse_strategy")]
    pub parse: String,

    #[serde(default)]
    pub key: String,
}

impl Default for ProcfsCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 60,
            metrics: Vec::new(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorEntry {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskCollectorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    #[serde(default)]
    pub exclude_mounts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCollectorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    #[serde(default)]
    pub exclude_interfaces: Vec<String>,

    #[serde(default = "default_interface_speed_mbps")]
    pub default_interface_speed_mbps: u64,
}

fn default_interface_speed_mbps() -> u64 {
    1000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemdCollectorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    #[serde(default)]
    pub watch_units: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessCollectorConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    #[serde(default = "default_top_n")]
    pub top_n: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferConfig {
    #[serde(default = "default_buffer_path")]
    pub path: String,

    #[serde(default = "default_max_total_size")]
    pub max_total_size: u64,

    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,

    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,

    #[serde(default = "default_retry_backoff")]
    pub retry_backoff: Vec<u64>,
}

fn default_server_url() -> String {
    "https://localhost:8443".into()
}

fn default_enabled() -> bool {
    true
}

fn default_disabled() -> bool {
    false
}

fn default_interval_secs() -> u64 {
    60
}

fn default_top_n() -> usize {
    20
}

fn default_parse_strategy() -> String {
    "value".into()
}

fn default_buffer_path() -> String {
    "/var/lib/vespid-agent/buffer".into()
}

fn default_max_total_size() -> u64 {
    64 * 1024 * 1024
}

fn default_max_file_size() -> u64 {
    8 * 1024 * 1024
}

fn default_batch_size() -> usize {
    500
}

fn default_flush_interval_secs() -> u64 {
    30
}

fn default_request_timeout_secs() -> u64 {
    30
}

fn default_retry_backoff() -> Vec<u64> {
    vec![1, 5, 15, 60, 300]
}

fn default_log_retention_days() -> u64 {
    30
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            agent: AgentSettings::default(),
            log_level: String::new(),
            log_retention_days: default_log_retention_days(),
            collectors: CollectorsConfig::default(),
            buffer: BufferConfig::default(),
            transport: TransportConfig::default(),
            worker: WorkerConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            url: default_server_url(),
            api_key: String::new(),
        }
    }
}

impl Default for CollectorEntry {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            interval_secs: default_interval_secs(),
        }
    }
}

impl Default for DiskCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            interval_secs: default_interval_secs(),
            exclude_mounts: Vec::new(),
        }
    }
}

impl Default for NetworkCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            interval_secs: default_interval_secs(),
            exclude_interfaces: vec![
                "lo".into(),
                "tunl0".into(),
                "sit0".into(),
                "gre0".into(),
                "gretap0".into(),
                "erspan0".into(),
                "ip6tnl0".into(),
                "ip6gre0".into(),
                "bonding_masters".into(),
            ],
            default_interface_speed_mbps: default_interface_speed_mbps(),
        }
    }
}

impl Default for SystemdCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            interval_secs: default_interval_secs(),
            watch_units: Vec::new(),
        }
    }
}

impl Default for ProcessCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 120,
            top_n: default_top_n(),
        }
    }
}

impl Default for LogfileCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_logfile_interval(),
            state_path: default_logfile_state_path(),
            watches: Vec::new(),
        }
    }
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            path: default_buffer_path(),
            max_total_size: default_max_total_size(),
            max_file_size: default_max_file_size(),
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            batch_size: default_batch_size(),
            flush_interval_secs: default_flush_interval_secs(),
            request_timeout_secs: default_request_timeout_secs(),
            retry_backoff: default_retry_backoff(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    #[serde(default = "default_worker_capabilities")]
    pub capabilities: Vec<String>,

    #[serde(default)]
    pub labels: std::collections::HashMap<String, String>,

    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,

    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capabilities: default_worker_capabilities(),
            labels: std::collections::HashMap::new(),
            max_concurrent: default_max_concurrent(),
            poll_interval_secs: default_poll_interval(),
        }
    }
}

fn default_worker_capabilities() -> Vec<String> {
    vec!["http".into(), "icmp".into(), "tcp".into(), "dns".into()]
}

fn default_max_concurrent() -> usize {
    10
}

fn default_poll_interval() -> u64 {
    5
}

impl AgentConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read config file: {}", path.display()))?;
            let config: Self = serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
            Ok(config)
        } else {
            tracing::warn!(
                "Config file not found at {}, using defaults",
                path.display()
            );
            Ok(Self::default())
        }
    }

    pub fn resolve_hostname(&self) -> String {
        if !self.agent.hostname_override.is_empty() {
            return self.agent.hostname_override.clone();
        }
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".into())
    }
}
