pub mod checks;
pub mod executor;
pub mod poller;
pub mod registration;

use crate::config::AgentConfig;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub struct WorkerRuntime {
    config: AgentConfig,
    agent_id: String,
    hostname: String,
    cancel: CancellationToken,
}

impl WorkerRuntime {
    pub async fn new(
        config: AgentConfig,
        agent_id: String,
        hostname: String,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            agent_id,
            hostname,
            cancel: CancellationToken::new(),
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        if !self.config.worker.enabled {
            tracing::warn!("Worker mode selected but worker.enabled is false in config");
            return Ok(());
        }

        let server_url = self.config.server.url.clone();
        let api_key = self.config.server.api_key.clone();
        let agent_id = self.agent_id.clone();
        let hostname = self.hostname.clone();
        let capabilities = self.config.worker.capabilities.clone();
        let labels = self.config.worker.labels.clone();
        let max_concurrent = self.config.worker.max_concurrent;

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(
                self.config.transport.request_timeout_secs,
            ))
            .build()?;

        tracing::info!(
            "Worker mode starting  agent_id={agent_id} hostname={hostname} capabilities={capabilities:?} labels={labels:?} max_concurrent={max_concurrent}"
        );

        let worker_id = agent_id.clone();
        let reg_worker_id = worker_id.clone();
        let reg_server = server_url.clone();
        let reg_api_key = api_key.clone();
        let reg_hostname = hostname.clone();
        let reg_capabilities = capabilities.clone();
        let reg_labels = labels.clone();
        let reg_max = max_concurrent;
        let reg_cancel = self.cancel.clone();
        let reg_client = http_client.clone();

        let reg_handle = tokio::spawn(async move {
            registration::run_heartbeat(
                reg_worker_id,
                reg_server,
                reg_api_key,
                reg_hostname,
                reg_capabilities,
                reg_labels,
                reg_max,
                reg_cancel,
                reg_client,
            )
            .await;
        });

        let poll_server = server_url.clone();
        let poll_api_key = api_key.clone();
        let poll_worker_id = worker_id.clone();
        let poll_max = max_concurrent;
        let poll_client = http_client.clone();
        let poll_cancel = self.cancel.clone();

        let poll_handle = tokio::spawn(async move {
            poller::run_poller(
                poll_worker_id,
                poll_server,
                poll_api_key,
                poll_max,
                poll_cancel,
                poll_client,
            )
            .await;
        });

        tokio::select! {
            _ = reg_handle => {
                tracing::debug!("Registration task completed");
            }
            _ = poll_handle => {
                tracing::debug!("Poller task completed");
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
        tokio::time::sleep(Duration::from_secs(2)).await;
        tracing::info!("Worker shutting down");
        Ok(())
    }
}
