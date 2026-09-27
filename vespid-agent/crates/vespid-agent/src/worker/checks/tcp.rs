use async_trait::async_trait;
use std::time::Instant;
use tokio::net::TcpStream;
use tracing;

use super::super::executor::{CheckExecutor, CheckResult};

pub struct TcpExecutor;

#[async_trait]
impl CheckExecutor for TcpExecutor {
    fn check_type(&self) -> &'static str {
        "tcp"
    }

    async fn execute(
        &self,
        target: &str,
        config: &serde_json::Value,
        timeout_secs: u64,
        job_id: i64,
    ) -> CheckResult {
        let start = Instant::now();

        let (host, port) = parse_target(target, config);
        tracing::debug!("[{job_id}] TCP check: connect {host}:{port}");

        let timeout = std::time::Duration::from_secs(timeout_secs);

        match tokio::time::timeout(timeout, TcpStream::connect(&format!("{host}:{port}"))).await {
            Ok(Ok(_stream)) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                tracing::debug!(
                    "[{job_id}] TCP result: {host}:{port} -> connected in {duration_ms}ms"
                );
                let details = serde_json::json!({
                    "host": host,
                    "port": port,
                    "connect_time_ms": duration_ms,
                });

                if let Some(max_conn) = config.get("max_connect_ms").and_then(|v| v.as_u64())
                    && duration_ms > max_conn
                {
                    return CheckResult {
                        job_id: 0,
                        success: false,
                        duration_ms,
                        status_code: Some(port),
                        error_message: Some(format!(
                            "connect time {duration_ms}ms exceeds threshold {max_conn}ms"
                        )),
                        details: Some(details),
                    };
                }

                CheckResult {
                    job_id: 0,
                    success: true,
                    duration_ms,
                    status_code: Some(port),
                    error_message: None,
                    details: Some(details),
                }
            }
            Ok(Err(e)) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                tracing::debug!(
                    "[{job_id}] TCP result: {host}:{port} -> connection refused ({e}) in {duration_ms}ms"
                );
                CheckResult {
                    job_id: 0,
                    success: false,
                    duration_ms,
                    status_code: Some(port),
                    error_message: Some(format!("connection refused: {e}")),
                    details: Some(serde_json::json!({"host": host, "port": port})),
                }
            }
            Err(_) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                tracing::debug!(
                    "[{job_id}] TCP result: {host}:{port} -> timeout in {duration_ms}ms"
                );
                CheckResult {
                    job_id: 0,
                    success: false,
                    duration_ms,
                    status_code: Some(port),
                    error_message: Some("timeout".into()),
                    details: Some(serde_json::json!({"host": host, "port": port})),
                }
            }
        }
    }
}

fn parse_target(target: &str, config: &serde_json::Value) -> (String, u16) {
    if let Some(colon) = target.rfind(':')
        && target[colon + 1..].chars().all(|c| c.is_ascii_digit())
    {
        let host = target[..colon]
            .trim_end_matches('[')
            .trim_start_matches('[');
        let port: u16 = target[colon + 1..].parse().unwrap_or(0);
        if port > 0 {
            return (host.to_string(), port);
        }
    }

    let port = config
        .get("port")
        .and_then(|v| v.as_u64())
        .map(|p| p as u16)
        .unwrap_or(443);

    (target.to_string(), port)
}
