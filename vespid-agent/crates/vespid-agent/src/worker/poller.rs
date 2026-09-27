use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::checks;
use super::executor::{CheckJob, CheckResult};

pub async fn run_poller(
    worker_id: String,
    server_url: String,
    api_key: String,
    max_concurrent: usize,
    cancel: CancellationToken,
    client: Client,
) {
    let jobs_url = format!(
        "{}/api/v1/workers/{worker_id}/jobs",
        server_url.trim_end_matches('/')
    );
    let result_url = format!(
        "{}/api/v1/workers/{worker_id}/jobs",
        server_url.trim_end_matches('/')
    );

    let header_value = format!("Bearer {api_key}");
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let poll_interval = Duration::from_secs(5);

    tracing::info!("Worker poller started  jobs_url={jobs_url} max_concurrent={max_concurrent}");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("Poller shutting down");
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                let jobs = match fetch_jobs(&client, &jobs_url, &header_value).await {
                    Ok(j) => j,
                    Err(e) => {
                        tracing::debug!("Failed to fetch jobs: {e}");
                        continue;
                    }
                };

                if jobs.is_empty() {
                    continue;
                }

                tracing::debug!("Fetched {} jobs", jobs.len());

                for job in jobs {
                    let permit = semaphore.clone().acquire_owned().await;
                    if permit.is_err() {
                        break;
                    }
                    let permit = permit.unwrap();

                    let client = client.clone();
                    let result_url = result_url.clone();
                    let header_value = header_value.clone();
                    let job_id = job.job_id;

                    tokio::spawn(async move {
                        let _permit = permit;

                        let result = execute_job(&job).await;
                        let mut final_result = result;
                        final_result.job_id = job_id;

                        post_result(&client, &result_url, &header_value, job_id, &final_result).await;
                    });
                }
            }
        }
    }
}

async fn fetch_jobs(
    client: &Client,
    url: &str,
    auth: &str,
) -> Result<Vec<CheckJob>, reqwest::Error> {
    let resp = client
        .get(url)
        .header("Authorization", auth)
        .send()
        .await?
        .error_for_status()?;

    #[derive(serde::Deserialize)]
    struct JobsResponse {
        jobs: Vec<CheckJob>,
    }

    let body: JobsResponse = resp.json().await?;
    Ok(body.jobs)
}

async fn execute_job(job: &CheckJob) -> CheckResult {
    let executor = checks::get_executor_for(&job.check_type);
    tracing::info!(target: "job", "[{}] {} {} target={}", job.job_id, job.check_type, job.check_name, job.target);
    let result = match executor {
        Some(e) => {
            e.execute(&job.target, &job.check_config, job.timeout_secs, job.job_id)
                .await
        }
        None => CheckResult {
            job_id: job.job_id,
            success: false,
            duration_ms: 0,
            status_code: None,
            error_message: Some(format!("unknown check type: {}", job.check_type)),
            details: None,
        },
    };
    tracing::info!(
        target: "job",
        "[{}] done success={} duration={}ms{}",
        job.job_id,
        result.success,
        result.duration_ms,
        result.error_message.as_ref().map(|e| format!(" error={}", e)).unwrap_or_default(),
    );
    result
}

async fn post_result(
    client: &Client,
    base_url: &str,
    auth: &str,
    job_id: i64,
    result: &CheckResult,
) {
    let url = format!("{base_url}/{job_id}/result");

    match client
        .post(&url)
        .header("Authorization", auth)
        .header("Content-Type", "application/json")
        .json(result)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!("Posted result for job {job_id}");
        }
        Ok(resp) => {
            tracing::warn!("Failed to post result for job {job_id}: {resp:?}");
        }
        Err(e) => {
            tracing::warn!("Error posting result for job {job_id}: {e}");
        }
    }
}
