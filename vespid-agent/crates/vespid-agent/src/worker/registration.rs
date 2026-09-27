use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[allow(clippy::too_many_arguments)]
pub async fn run_heartbeat(
    worker_id: String,
    server_url: String,
    api_key: String,
    hostname: String,
    capabilities: Vec<String>,
    labels: HashMap<String, String>,
    max_concurrent: usize,
    cancel: CancellationToken,
    client: Client,
) {
    let register_url = format!(
        "{}/api/v1/workers/register",
        server_url.trim_end_matches('/')
    );

    let running_jobs: usize = 0;

    let header_value = format!("Bearer {api_key}");

    let version = env!("CARGO_PKG_VERSION").to_string();

    let body = serde_json::json!({
        "worker_id": worker_id,
        "hostname": hostname,
        "version": version,
        "capabilities": capabilities,
        "labels": labels,
        "max_concurrent": max_concurrent,
        "running_jobs": running_jobs,
        "status": "online",
    });

    tracing::info!("Registering worker  url={register_url}");

    match client
        .post(&register_url)
        .header("Authorization", &header_value)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!("Worker registered successfully");
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!("Worker registration failed: {status} — {body}");
        }
        Err(e) => {
            tracing::warn!("Worker registration network error: {e}");
        }
    }

    let mut interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                let drain_body = serde_json::json!({
                    "worker_id": worker_id,
                    "hostname": hostname,
                    "version": version,
                    "capabilities": capabilities,
                    "labels": labels,
                    "max_concurrent": 0,
                    "running_jobs": running_jobs,
                    "status": "offline",
                });
                let _ = client
                    .post(&register_url)
                    .header("Authorization", &header_value)
                    .header("Content-Type", "application/json")
                    .json(&drain_body)
                    .send()
                    .await;
                tracing::debug!("Worker sent offline heartbeat");
                break;
            }
            _ = interval.tick() => {
                let body = serde_json::json!({
                    "worker_id": worker_id,
                    "hostname": hostname,
                    "version": version,
                    "capabilities": capabilities,
                    "labels": labels,
                    "max_concurrent": max_concurrent,
                    "running_jobs": running_jobs,
                    "status": "online",
                });

                match client
                    .post(&register_url)
                    .header("Authorization", &header_value)
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        tracing::debug!("Worker heartbeat ok");
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        tracing::debug!("Worker heartbeat response: {status} — {body}");
                    }
                    Err(e) => {
                        tracing::debug!("Worker heartbeat network error: {e}");
                    }
                }
            }
        }
    }
}
