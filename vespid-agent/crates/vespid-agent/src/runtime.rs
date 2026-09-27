use crate::collectors::{CollectorContext, Collectors};
use crate::config::AgentConfig;
use crate::transport::Shipper;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use vespid_agent_enroll::{Credentials, EnrollmentClient, EnrollmentConfig, EnrollmentOutcome};

pub struct Runtime {
    config: AgentConfig,
    agent_id: String,
    hostname: String,
    machine_id: Option<String>,
    cpu_model: Option<String>,
    virt_type: Option<String>,
    cancel: CancellationToken,
}

pub async fn get_or_generate_agent_id(config: &AgentConfig) -> anyhow::Result<String> {
    if !config.agent.agent_id.is_empty() {
        return Ok(config.agent.agent_id.clone());
    }

    let state_dir = std::path::Path::new("/var/lib/vespid-agent");
    std::fs::create_dir_all(state_dir)?;
    let id_file = state_dir.join("agent_id");

    if id_file.exists() {
        let id = std::fs::read_to_string(&id_file)?.trim().to_string();
        if !id.is_empty() {
            return Ok(id);
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    std::fs::write(&id_file, &id)?;
    tracing::info!("Generated new agent ID: {id}");
    Ok(id)
}

fn get_machine_id() -> Option<String> {
    let paths = ["/etc/machine-id", "/var/lib/dbus/machine-id"];
    for path in &paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            let id = content.trim().to_string();
            if !id.is_empty() {
                return Some(id);
            }
        }
    }
    None
}

fn get_cpu_model() -> Option<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in cpuinfo.lines() {
        if let Some(stripped) = line.strip_prefix("model name")
            && let Some(value) = stripped.split(':').nth(1)
        {
            let model = value.trim().to_string();
            if !model.is_empty() {
                return Some(model);
            }
        }
    }
    None
}

fn get_virt_type() -> Option<String> {
    let dmi_path = "/sys/class/dmi/id/product_name";
    if let Ok(content) = std::fs::read_to_string(dmi_path) {
        let name = content.trim().to_lowercase();
        let hints = [
            "kvm",
            "qemu",
            "vmware",
            "virtualbox",
            "virtual machine",
            "hvm domu",
            "xen",
            "bochs",
            "openstack",
            "nutanix",
        ];
        for hint in &hints {
            if name.contains(hint) {
                return Some("vm".into());
            }
        }
        if !name.is_empty() && name != "system product name" {
            return Some("host".into());
        }
    }
    None
}

/// Ensure the agent has a valid API key. If the YAML config has
/// ``server.api_key: ""`` (the default) and no ``credentials.json`` is
/// present, run enrollment. If the server is in manual-approval mode
/// the runtime spawns a background poller that updates the shared
/// ``api_key`` once the operator approves.
async fn ensure_api_key(
    config: &AgentConfig,
    agent_id: &str,
    hostname: &str,
    cancel: CancellationToken,
    api_key: Arc<Mutex<Option<String>>>,
) -> anyhow::Result<()> {
    // Fast path: explicit API key in YAML.
    if !config.server.api_key.trim().is_empty() {
        *api_key.lock().await = Some(config.server.api_key.clone());
        return Ok(());
    }

    let credentials_path = std::path::PathBuf::from("/var/lib/vespid-agent/credentials.json");

    let enroll_config = EnrollmentConfig {
        server_url: config.server.url.clone(),
        node_id: agent_id.to_string(),
        display_name: hostname.to_string(),
        credentials_path: credentials_path.clone(),
        ..Default::default()
    };

    let client = EnrollmentClient::new(enroll_config.clone())
        .map_err(|e| anyhow::anyhow!("failed to build enrollment client: {e}"))?;

    // If credentials.json exists, try to validate the key by re-enrolling.
    // If the server says the key is invalid, delete the file and start fresh.
    if let Some(creds) = Credentials::load(&credentials_path)
        .map_err(|e| anyhow::anyhow!("failed to load credentials: {e}"))?
        && !creds.api_key.is_empty()
    {
        tracing::info!(
            "Validating existing credentials for node_id={}",
            creds.node_id
        );
        // Try to enroll with the existing key. The server will:
        // - Return 200 with a new key if the old one was revoked (auto-rotate)
        // - Return 409 if the enrollment is already approved and key is valid
        // - Return 401 if the key is completely invalid
        // - Return 202 if manual approval is needed
        match client.try_rotate(&creds.api_key).await {
            Ok(EnrollmentOutcome::Rotated(new_creds)) => {
                tracing::info!("Credentials rotated; old key was revoked");
                *api_key.lock().await = Some(new_creds.api_key);
                return Ok(());
            }
            Ok(EnrollmentOutcome::AlreadyEnrolled) => {
                // Server says we're already enrolled - key might be valid
                // but we can't be sure until we try to use it.
                // Trust it for now; the shipper will retry on 401.
                tracing::info!("Credentials validated (already enrolled)");
                *api_key.lock().await = Some(creds.api_key);
                return Ok(());
            }
            Ok(EnrollmentOutcome::Pending) => {
                tracing::warn!("Existing credentials invalid; enrollment pending approval");
                // Delete stale credentials and re-enroll
                let _ = std::fs::remove_file(&credentials_path);
            }
            Ok(EnrollmentOutcome::Fresh(new_creds)) => {
                tracing::info!("Got fresh credentials (old key was invalid)");
                *api_key.lock().await = Some(new_creds.api_key);
                return Ok(());
            }
            Err(e) => {
                tracing::warn!("Credential validation failed: {e}; re-enrolling");
                // Delete stale credentials and re-enroll
                let _ = std::fs::remove_file(&credentials_path);
            }
        }
    }

    // No valid credentials - run fresh enrollment
    match client.ensure_credentials().await {
        Ok(EnrollmentOutcome::AlreadyEnrolled) => {
            // Shouldn't happen after the check above, but handle it
            if let Some(creds) = Credentials::load(&credentials_path)
                .map_err(|e| anyhow::anyhow!("failed to load credentials: {e}"))?
            {
                *api_key.lock().await = Some(creds.api_key);
                return Ok(());
            }
            tracing::warn!("Credentials file missing; spawning poller");
        }
        Ok(EnrollmentOutcome::Fresh(creds)) => {
            tracing::info!(
                "Enrolled fresh API key  host_id={} node_id={}",
                creds.host_id,
                creds.node_id
            );
            *api_key.lock().await = Some(creds.api_key);
            return Ok(());
        }
        Ok(EnrollmentOutcome::Rotated(creds)) => {
            tracing::info!(
                "Rotated existing API key  host_id={} node_id={}",
                creds.host_id,
                creds.node_id
            );
            *api_key.lock().await = Some(creds.api_key);
            return Ok(());
        }
        Ok(EnrollmentOutcome::Pending) => {
            tracing::warn!("Enrollment pending operator approval.");
        }
        Err(e) => {
            return Err(anyhow::anyhow!("enrollment failed: {e}"));
        }
    }

    // Spawn a background poller that updates the shared api_key
    // once approval lands. The shipper will wait until the key
    // is available before sending metrics.
    let poll_config = enroll_config;
    let poll_agent_id = agent_id.to_string();
    tokio::spawn(async move {
        let client = match EnrollmentClient::new(poll_config.clone()) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to build poll client: {e}");
                return;
            }
        };
        let mut backoff = poll_config.poll_initial();
        let max_backoff = poll_config.poll_max();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            match client.poll_until_approved().await {
                Ok(creds) => {
                    tracing::info!(
                        "Background enrollment approved for node_id={}",
                        poll_agent_id
                    );
                    // Update the shared API key so the shipper
                    // can start sending metrics.
                    *api_key.lock().await = Some(creds.api_key);
                    return;
                }
                Err(e) => {
                    tracing::debug!("Background enrollment poll failed: {e}");
                }
            }
            backoff = (backoff * 2).min(max_backoff);
        }
    });
    Ok(())
}

impl Runtime {
    pub async fn new(
        config: AgentConfig,
        agent_id: String,
        hostname: String,
    ) -> anyhow::Result<Self> {
        let machine_id = get_machine_id();
        let cpu_model = get_cpu_model();
        let virt_type = get_virt_type();
        Ok(Self {
            config,
            agent_id,
            hostname,
            machine_id,
            cpu_model,
            virt_type,
            cancel: CancellationToken::new(),
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let (_metric_tx, metric_rx) = mpsc::channel::<vespid_agent_common::Metric>(2000);
        let metric_tx = _metric_tx;

        // Shared API key state — the background poller will update this
        // once enrollment is approved.
        let api_key = Arc::new(Mutex::new(None::<String>));

        // Resolve the API key — either from the YAML config or via
        // auto-enrollment. If pending, the poller updates the shared state.
        ensure_api_key(
            &self.config,
            &self.agent_id,
            &self.hostname,
            self.cancel.clone(),
            api_key.clone(),
        )
        .await?;

        let has_key = api_key.lock().await.is_some();
        if !has_key {
            tracing::info!(
                "Enrollment pending; collectors running, metrics buffered \
                 until operator approves."
            );
        }

        let agent_version = env!("CARGO_PKG_VERSION").to_string();
        let shipper = Shipper::new(
            self.config.server.url.clone(),
            api_key.clone(),
            self.agent_id.clone(),
            self.hostname.clone(),
            self.machine_id.clone(),
            self.cpu_model.clone(),
            self.virt_type.clone(),
            agent_version,
            self.config.transport.clone(),
            metric_rx,
            self.cancel.clone(),
        );

        shipper.spawn();

        let context = Arc::new(CollectorContext {
            hostname: self.hostname.clone(),
            agent_id: self.agent_id.clone(),
            server_url: self.config.server.url.clone(),
            api_key: self.config.server.api_key.clone(),
        });

        let collectors = Collectors::new(
            self.config.collectors.clone(),
            context,
            metric_tx,
            self.cancel.clone(),
        );

        Self::spawn_watchdog(self.cancel.clone());

        tracing::info!(
            "Agent started  agent_id={} hostname={} server={}",
            self.agent_id,
            self.hostname,
            self.config.server.url
        );

        let collectors_task = tokio::spawn(async move { collectors.run().await });

        tokio::select! {
            _ = collectors_task => {
                tracing::debug!("Collectors completed");
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutdown signal received");
            }
            _ = async {
                if let Ok(mut sigterm) = tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate()
                ) {
                    sigterm.recv().await;
                    tracing::info!("SIGTERM received");
                }
            } => {}
        }

        self.cancel.cancel();
        tracing::info!("Waiting for tasks to complete...");
        tokio::time::sleep(Duration::from_secs(2)).await;

        Ok(())
    }

    fn spawn_watchdog(cancel: CancellationToken) {
        let usec = match std::env::var("WATCHDOG_USEC") {
            Ok(v) => match v.parse::<u64>() {
                Ok(n) if n > 0 => n,
                _ => return,
            },
            _ => return,
        };

        let interval = Duration::from_micros(usec / 2);
        tracing::debug!(
            "Systemd watchdog enabled  interval={}ms",
            interval.as_millis()
        );

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(interval) => {
                        if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]) {
                            tracing::warn!("Watchdog notify failed: {e}");
                        }
                    }
                }
            }
        });
    }
}
