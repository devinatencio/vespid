use crate::config::TransportConfig;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use vespid_agent_common::Metric;
use vespid_agent_enroll::{EnrollmentClient, EnrollmentConfig, EnrollmentOutcome};

pub struct Shipper {
    server_url: String,
    /// The current API key, shared with the background enrollment poller.
    /// The poller updates this when the operator approves enrollment.
    /// The shipper waits until it is ``Some(...)`` before sending metrics.
    api_key: Arc<Mutex<Option<String>>>,
    agent_id: String,
    hostname: String,
    machine_id: Option<String>,
    cpu_model: Option<String>,
    virt_type: Option<String>,
    agent_version: String,
    config: TransportConfig,
    metric_rx: mpsc::Receiver<Metric>,
    cancel: CancellationToken,
}

impl Shipper {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_url: String,
        api_key: Arc<Mutex<Option<String>>>,
        agent_id: String,
        hostname: String,
        machine_id: Option<String>,
        cpu_model: Option<String>,
        virt_type: Option<String>,
        agent_version: String,
        config: TransportConfig,
        metric_rx: mpsc::Receiver<Metric>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            server_url,
            api_key,
            agent_id,
            hostname,
            machine_id,
            cpu_model,
            virt_type,
            agent_version,
            config,
            metric_rx,
            cancel,
        }
    }

    pub fn spawn(mut self) {
        tokio::spawn(async move {
            if let Err(e) = self.run().await {
                tracing::error!("Shipper fatal error: {e}");
            }
        });
    }

    /// Wait for the API key to become available. Returns the key string.
    /// Logs periodically while waiting so the operator can see progress.
    async fn wait_for_api_key(&self) -> String {
        let mut logged = false;
        loop {
            {
                let key = self.api_key.lock().await;
                if let Some(ref k) = *key {
                    if !logged {
                        tracing::info!("API key available; starting metric ingest.");
                    }
                    return k.clone();
                }
            }
            if !logged {
                tracing::info!("Waiting for enrollment approval before sending metrics...");
                logged = true;
            }
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    return String::new();
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
        }
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        let client = Client::builder()
            .timeout(Duration::from_secs(self.config.request_timeout_secs))
            .build()?;

        let mut encoder = vespid_agent_common::metrics::BatchEncoder::new(self.config.batch_size);
        let flush_interval = Duration::from_secs(self.config.flush_interval_secs);

        let mut retry_count: usize = 0;
        let write_url = format!(
            "{}/api/v1/metrics/write",
            self.server_url.trim_end_matches('/')
        );

        tracing::info!(
            "Shipper started  target={write_url} agent_id={} batch_size={} flush_interval={}s",
            self.agent_id,
            self.config.batch_size,
            self.config.flush_interval_secs,
        );

        let mut buffer_manager = crate::buffer::BufferManager::new(
            "/var/lib/vespid-agent/buffer".into(),
            64 * 1024 * 1024,
            8 * 1024 * 1024,
        )?;

        // Wait for the API key before doing anything. Collectors are
        // still running and feeding metrics into the channel/encoder,
        // so they'll accumulate while we wait.
        let api_key_str = self.wait_for_api_key().await;
        if api_key_str.is_empty() {
            tracing::info!("Shipper shutting down while waiting for API key.");
            return Ok(());
        }

        self.replay_buffer(&client, &write_url, &mut buffer_manager)
            .await?;

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    tracing::info!("Shipper shutting down, flushing remaining metrics");
                    if !encoder.is_empty() {
                        self.flush_and_send(&client, &write_url, &mut encoder, &mut retry_count, &mut buffer_manager).await;
                    }
                    break;
                }
                Some(metric) = self.metric_rx.recv() => {
                    if !encoder.add(metric) {
                        self.flush_and_send(&client, &write_url, &mut encoder, &mut retry_count, &mut buffer_manager).await;
                    }
                }
                _ = tokio::time::sleep(flush_interval) => {
                    if !encoder.is_empty() {
                        self.flush_and_send(&client, &write_url, &mut encoder, &mut retry_count, &mut buffer_manager).await;
                    }
                }
            }
        }

        Ok(())
    }

    async fn flush_and_send(
        &mut self,
        client: &Client,
        url: &str,
        encoder: &mut vespid_agent_common::metrics::BatchEncoder,
        retry_count: &mut usize,
        buffer_manager: &mut crate::buffer::BufferManager,
    ) {
        match encoder.encode() {
            Ok(batch) => {
                if batch.is_empty() {
                    return;
                }
                tracing::info!(
                    "Sending batch  {} metrics, {} bytes  → {}",
                    batch.metric_count,
                    batch.compressed_size,
                    url
                );
                self.send_batch(client, url, &batch, retry_count, buffer_manager)
                    .await;
            }
            Err(e) => {
                tracing::error!("Failed to encode batch: {e}");
            }
        }
    }

    async fn send_batch(
        &mut self,
        client: &Client,
        url: &str,
        batch: &vespid_agent_common::metrics::EncodedBatch,
        retry_count: &mut usize,
        _buffer_manager: &mut crate::buffer::BufferManager,
    ) {
        loop {
            let api_key = self.api_key.lock().await.clone().unwrap_or_default();
            let mut request = client
                .post(url)
                .header("Authorization", format!("Bearer {api_key}"))
                .header("X-Agent-ID", &self.agent_id)
                .header("X-Hostname", &self.hostname)
                .header("X-Agent-Version", &self.agent_version)
                .header(
                    "Content-Type",
                    vespid_agent_common::metrics::REMOTE_WRITE_CONTENT_TYPE,
                )
                .header(
                    "Content-Encoding",
                    vespid_agent_common::metrics::REMOTE_WRITE_CONTENT_ENCODING,
                );
            if let Some(ref mid) = self.machine_id {
                request = request.header("X-Machine-ID", mid);
            }
            if let Some(ref vt) = self.virt_type {
                request = request.header("X-Virt-Type", vt);
            }
            if let Some(ref cpu) = self.cpu_model {
                request = request.header("X-CPU-Model", cpu);
            }
            match request.body(batch.data.clone()).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(
                        "Shipped {} metrics ({} bytes)  ✓",
                        batch.metric_count,
                        batch.compressed_size
                    );
                    *retry_count = 0;
                    return;
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    tracing::warn!("Server returned {status}: {body}");

                    if status.as_u16() == 401 && !api_key.is_empty() {
                        // Try to self-heal via the enrollment server.
                        if self.try_rotate(&api_key).await {
                            // New key loaded. Retry the batch on the
                            // same loop iteration (the next send_batch
                            // call will pick it up).
                            tracing::info!(
                                "Retrying after rotation: {} metrics queued",
                                batch.metric_count
                            );
                            return;
                        } else {
                            tracing::error!(
                                "401 from server and rotation failed; \
                                 dropping {} metrics",
                                batch.metric_count
                            );
                            return;
                        }
                    }

                    if status.is_client_error() {
                        return;
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to send metrics: {e}");
                }
            }

            *retry_count += 1;
            let delay_idx = (*retry_count - 1).min(self.config.retry_backoff.len() - 1);
            let delay = self.config.retry_backoff[delay_idx];
            tracing::info!(
                "Retry {} in {}s ({} metrics buffered)",
                retry_count,
                delay,
                batch.metric_count
            );

            tokio::time::sleep(Duration::from_secs(delay)).await;
        }
    }

    /// Attempt to rotate the API key by re-enrolling with the old one
    /// in the ``X-Existing-Credentials`` header. On success, swap the
    /// in-memory key and return ``true``.
    async fn try_rotate(&self, current_key: &str) -> bool {
        let enroll_config = EnrollmentConfig {
            server_url: self.server_url.clone(),
            node_id: self.agent_id.clone(),
            display_name: self.hostname.clone(),
            credentials_path: std::path::PathBuf::from("/var/lib/vespid-agent/credentials.json"),
            ..Default::default()
        };
        let client = match EnrollmentClient::new(enroll_config) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to build enrollment client for rotation: {e}");
                return false;
            }
        };
        match client.try_rotate(current_key).await {
            Ok(EnrollmentOutcome::Rotated(creds)) => {
                let mut key = self.api_key.lock().await;
                *key = Some(creds.api_key.clone());
                tracing::info!(
                    "API key rotated; host_id={} node_id={}",
                    creds.host_id,
                    creds.node_id
                );
                true
            }
            Ok(_) => {
                tracing::warn!("Re-enroll did not trigger rotation; keeping current key");
                false
            }
            Err(e) => {
                tracing::error!("Rotation failed: {e}");
                false
            }
        }
    }

    async fn replay_buffer(
        &mut self,
        client: &Client,
        url: &str,
        buffer_manager: &mut crate::buffer::BufferManager,
    ) -> anyhow::Result<()> {
        let entries = buffer_manager.read_all()?;
        if entries.is_empty() {
            return Ok(());
        }

        tracing::debug!("Replaying {} buffered metric entries", entries.len());

        for entry in &entries {
            let batch = vespid_agent_common::metrics::EncodedBatch {
                data: bytes::Bytes::from(entry.clone()),
                compressed_size: entry.len(),
                metric_count: 1,
            };

            let mut rcount: usize = 0;
            self.send_batch(client, url, &batch, &mut rcount, buffer_manager)
                .await;
        }

        buffer_manager.clear()?;
        tracing::info!("Buffer replay complete");
        Ok(())
    }
}
