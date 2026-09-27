//! Persistent credentials record. Mirrors the Python security agent's
//! `credentials.json` shape.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credentials {
    pub api_key: String,
    pub server_url: String,
    pub node_id: String,

    #[serde(default)]
    pub asset_id: String,

    /// Server-minted host identifier. Stable across security-agent and
    /// monitor-agent keys on the same physical host. Empty for older
    /// records.
    #[serde(default)]
    pub host_id: String,

    /// ISO-8601 timestamp of the most recent enrollment / rotation.
    pub enrolled_at: DateTime<Utc>,
}

impl Credentials {
    /// Load credentials from disk. Returns Ok(None) if the file is
    /// missing or unreadable. Returns Err only on JSON parse errors
    /// for a present-but-malformed file.
    pub fn load(path: &Path) -> crate::Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(path)?;
        if content.trim().is_empty() {
            return Ok(None);
        }
        let creds: Credentials = serde_json::from_str(&content)
            .map_err(|e| crate::EnrollmentError::InvalidCredentials(e.to_string()))?;
        if creds.api_key.is_empty() || creds.node_id.is_empty() {
            return Ok(None);
        }
        Ok(Some(creds))
    }

    /// Atomically persist credentials to disk with mode 0600.
    pub fn save(&self, path: &Path) -> crate::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;

        // Write to a temp file, set permissions, then rename.
        let mut tmp = path.to_path_buf();
        tmp.set_extension("json.tmp");
        std::fs::write(&tmp, json.as_bytes())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&tmp, perms)?;
        }

        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}
