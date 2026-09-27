//! HTTP client for the server's enrollment endpoints.

use crate::config::EnrollmentConfig;
use crate::credentials::Credentials;
use crate::error::{EnrollmentError, Result};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// The result of a successful enrollment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub status: String,
    pub node_id: String,
    #[serde(default)]
    pub asset_id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub server_url: String,
    #[serde(default)]
    pub host_id: String,
    #[serde(default)]
    pub rotated: bool,
}

/// What happened during an `ensure_credentials` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentOutcome {
    /// No work was needed; existing credentials are valid.
    AlreadyEnrolled,
    /// The first enrollment completed; new credentials were persisted.
    Fresh(Credentials),
    /// A rotation completed; old key was revoked, new key persisted.
    Rotated(Credentials),
    /// Manual-approval mode; the server returned 202.
    Pending,
}

#[derive(Clone)]
pub struct EnrollmentClient {
    config: EnrollmentConfig,
    http: Client,
}

impl EnrollmentClient {
    /// Build a new client. Reads TLS settings from the config and
    /// constructs an `reqwest::Client` with the configured timeout.
    pub fn new(config: EnrollmentConfig) -> Result<Self> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.request_timeout_secs))
            .danger_accept_invalid_certs(!config.tls_verify);

        if let (Some(cert), Some(key)) = (&config.tls_client_cert, &config.tls_client_key) {
            // mTLS is not used in V1, but the wiring is in place for
            // forward-compatibility. Combined PEM is the format
            // supported by reqwest 0.12's `from_pem`. Concatenate
            // the cert and key into a single PEM file at install time
            // (or pass an already-merged path).
            let combined_path = format!("{cert}+{key}");
            let _ = combined_path; // silence unused warning
            let cert_pem = std::fs::read(cert)?;
            let key_pem = std::fs::read(key)?;
            let mut combined = cert_pem;
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&combined)?;
            builder = builder.identity(identity);
        }

        let http = builder.build()?;
        Ok(Self { config, http })
    }

    /// Ensure valid credentials exist. The main entry point used by
    /// the agent's `Runtime::new`.
    ///
    /// Flow:
    /// 1. If a credentials file exists with a non-empty api_key, return
    ///    `AlreadyEnrolled`.
    /// 2. Otherwise, send a fresh enrollment request. If the server is
    ///    in open mode, it returns a key immediately. If it's in
    ///    manual-approval mode, return `Pending` and let the caller
    ///    decide whether to spawn a polling task.
    pub async fn ensure_credentials(&self) -> Result<EnrollmentOutcome> {
        if let Some(creds) = Credentials::load(&self.config.credentials_path)?
            && !creds.api_key.is_empty()
        {
            debug!("Found existing credentials for node_id={}", creds.node_id);
            return Ok(EnrollmentOutcome::AlreadyEnrolled);
        }

        let response = self.enroll(None).await?;
        if response.status == "pending" {
            return Ok(EnrollmentOutcome::Pending);
        }

        let creds = self.response_to_credentials(&response)?;
        creds.save(&self.config.credentials_path)?;
        info!(
            "Enrolled node_id={} host_id={}",
            creds.node_id, creds.host_id
        );
        Ok(EnrollmentOutcome::Fresh(creds))
    }

    /// Attempt to rotate credentials after a 401. Sends the current
    /// (revoked-by-server) key in the `X-Existing-Credentials` header
    /// — the server uses this to identify the node, revokes the old
    /// key, and issues a new one in place.
    pub async fn try_rotate(&self, current_api_key: &str) -> Result<EnrollmentOutcome> {
        let response = self.enroll(Some(current_api_key)).await?;
        if response.status == "pending" {
            return Ok(EnrollmentOutcome::Pending);
        }
        if !response.rotated {
            // Server validated the existing key and did not rotate it.
            // This is the expected outcome when the agent re-validates
            // its current, still-valid key on startup.
            debug!("Re-enroll validated existing credentials (no rotation needed)");
            return Ok(EnrollmentOutcome::AlreadyEnrolled);
        }
        let creds = self.response_to_credentials(&response)?;
        creds.save(&self.config.credentials_path)?;
        info!(
            "Rotated credentials for node_id={} host_id={}",
            creds.node_id, creds.host_id
        );
        Ok(EnrollmentOutcome::Rotated(creds))
    }

    /// Poll `/api/v1/enroll/status/<node_id>` with exponential backoff
    /// until credentials are issued. Returns immediately if the
    /// credentials file is already populated.
    pub async fn poll_until_approved(&self) -> Result<Credentials> {
        if let Some(creds) = Credentials::load(&self.config.credentials_path)?
            && !creds.api_key.is_empty()
        {
            return Ok(creds);
        }
        let mut interval = self.config.poll_initial();
        let max_interval = self.config.poll_max();
        let mut attempt: u32 = 0;
        loop {
            tokio::time::sleep(interval).await;
            attempt += 1;

            let url = format!(
                "{}/api/v1/enroll/status/{}",
                self.config.base_url(),
                self.config.node_id
            );
            debug!("Polling enrollment status (attempt {attempt})  url={url}");

            let mut req = self.http.get(&url);
            if let Some(creds) = Credentials::load(&self.config.credentials_path)?
                && !creds.api_key.is_empty()
            {
                req = req.header("Authorization", format!("Bearer {}", creds.api_key));
            }
            let response = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    warn!("Poll request failed: {e}");
                    interval = (interval * 2).min(max_interval);
                    continue;
                }
            };

            match response.status().as_u16() {
                200 => {
                    let body: EnrollmentResponse = response.json().await?;
                    if !body.api_key.is_empty() {
                        let creds = self.response_to_credentials(&body)?;
                        creds.save(&self.config.credentials_path)?;
                        info!(
                            "Enrollment approved after {attempt} attempts; node_id={}",
                            creds.node_id
                        );
                        return Ok(creds);
                    }
                    // Approved but no new key — already retrieved.
                    debug!("Approved but no new key returned");
                    if let Some(creds) = Credentials::load(&self.config.credentials_path)? {
                        return Ok(creds);
                    }
                }
                202 => {
                    debug!("Still pending (attempt {attempt})");
                }
                403 => {
                    let body: serde_json::Value = response.json().await?;
                    return Err(EnrollmentError::Rejected {
                        status: 403,
                        detail: body
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("rejected")
                            .to_string(),
                    });
                }
                status => {
                    debug!("Unexpected poll status {status}");
                }
            }
            interval = (interval * 2).min(max_interval);
        }
    }

    /// Send a POST /api/v1/enroll request. If `existing_key` is
    /// provided, it is sent in the X-Existing-Credentials header to
    /// trigger the server's self-heal path.
    async fn enroll(&self, existing_key: Option<&str>) -> Result<EnrollmentResponse> {
        let url = format!("{}/api/v1/enroll", self.config.base_url());

        let machine_id = read_machine_id();
        let hostname = if self.config.display_name.is_empty() {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown".into())
        } else {
            self.config.display_name.clone()
        };

        let mut payload = serde_json::json!({
            "node_id": self.config.node_id,
            "hostname": hostname,
            "display_name": hostname,
            "source": "monitor",
        });
        if let Some(mid) = &machine_id {
            payload["machine_id"] = serde_json::Value::String(mid.clone());
        }

        let mut req = self.http.post(&url).json(&payload);
        if let Some(key) = existing_key {
            req = req.header("X-Existing-Credentials", format!("Bearer {key}"));
        }

        let response = req.send().await?;
        let status = response.status().as_u16();
        let body: serde_json::Value = response.json().await?;

        match status {
            200 => {
                let parsed: EnrollmentResponse = serde_json::from_value(body)?;
                Ok(parsed)
            }
            202 => Ok(EnrollmentResponse {
                status: "pending".into(),
                node_id: self.config.node_id.clone(),
                asset_id: String::new(),
                display_name: hostname,
                api_key: String::new(),
                server_url: self.config.base_url(),
                host_id: String::new(),
                rotated: false,
            }),
            401 => Err(EnrollmentError::Rejected {
                status: 401,
                detail: body
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("invalid_existing_credentials")
                    .to_string(),
            }),
            403 => {
                let detail = body
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("forbidden");
                if detail == "enrollment_disabled" {
                    Err(EnrollmentError::Disabled)
                } else {
                    Err(EnrollmentError::Rejected {
                        status: 403,
                        detail: detail.to_string(),
                    })
                }
            }
            409 => {
                let detail = body
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("conflict");
                if detail == "already_enrolled" {
                    Err(EnrollmentError::AlreadyEnrolled)
                } else {
                    Err(EnrollmentError::Rejected {
                        status: 409,
                        detail: detail.to_string(),
                    })
                }
            }
            429 => Err(EnrollmentError::RateLimited),
            other => {
                error!("Unexpected enrollment response {other}: {body}");
                Err(EnrollmentError::Rejected {
                    status: other,
                    detail: body.to_string(),
                })
            }
        }
    }

    fn response_to_credentials(&self, r: &EnrollmentResponse) -> Result<Credentials> {
        if r.api_key.is_empty() {
            return Err(EnrollmentError::InvalidCredentials(
                "server returned empty api_key".into(),
            ));
        }
        let server_url = if r.server_url.is_empty() {
            self.config.base_url()
        } else {
            r.server_url.clone()
        };
        Ok(Credentials {
            api_key: r.api_key.clone(),
            server_url,
            node_id: r.node_id.clone(),
            asset_id: r.asset_id.clone(),
            host_id: r.host_id.clone(),
            enrolled_at: Utc::now(),
        })
    }
}

fn read_machine_id() -> Option<String> {
    for path in &["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            let id = content.trim();
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
    }
    None
}
