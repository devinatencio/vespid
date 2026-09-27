//! Configuration for the enrollment client.

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentConfig {
    /// Base URL of the server (e.g. `https://vespid.example.com`).
    /// Trailing `/api/v1/...` paths are stripped automatically.
    pub server_url: String,

    /// Stable node_id for this agent. Mints a UUIDv4 on first run if
    /// empty.
    pub node_id: String,

    /// Display name (defaults to the system hostname).
    pub display_name: String,

    /// Path to the persisted credentials file. Defaults to
    /// `/var/lib/vespid-agent/credentials.json`.
    pub credentials_path: std::path::PathBuf,

    /// Initial poll interval for manual-approval mode (seconds).
    pub poll_initial_secs: u64,

    /// Max poll interval for manual-approval mode (seconds).
    pub poll_max_secs: u64,

    /// HTTP request timeout (seconds).
    pub request_timeout_secs: u64,

    /// Whether to verify the server's TLS certificate.
    pub tls_verify: bool,

    /// Optional client certificate (PEM path) for mTLS.
    pub tls_client_cert: Option<String>,
    pub tls_client_key: Option<String>,
}

impl EnrollmentConfig {
    /// Strip `/api/v1/...` suffix from ``server_url`` if present.
    pub fn base_url(&self) -> String {
        let url = self.server_url.trim_end_matches('/');
        if let Some(idx) = url.find("/api/v1") {
            url[..idx].trim_end_matches('/').to_string()
        } else {
            url.to_string()
        }
    }

    pub fn poll_initial(&self) -> Duration {
        Duration::from_secs(self.poll_initial_secs)
    }

    pub fn poll_max(&self) -> Duration {
        Duration::from_secs(self.poll_max_secs)
    }
}

impl Default for EnrollmentConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            node_id: String::new(),
            display_name: String::new(),
            credentials_path: std::path::PathBuf::from("/var/lib/vespid-agent/credentials.json"),
            poll_initial_secs: 30,
            poll_max_secs: 300,
            request_timeout_secs: 30,
            tls_verify: true,
            tls_client_cert: None,
            tls_client_key: None,
        }
    }
}
