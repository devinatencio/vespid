use async_trait::async_trait;
use std::time::Instant;
use tokio::process::Command;
use tracing;

use super::super::executor::{CheckExecutor, CheckResult};

pub struct IcmpExecutor;

#[async_trait]
impl CheckExecutor for IcmpExecutor {
    fn check_type(&self) -> &'static str {
        "icmp"
    }

    async fn execute(
        &self,
        target: &str,
        _config: &serde_json::Value,
        timeout_secs: u64,
        job_id: i64,
    ) -> CheckResult {
        let start = Instant::now();

        let timeout_str = timeout_secs.to_string();
        tracing::debug!("[{job_id}] ICMP check: ping -c 1 -W {timeout_str} {target}");

        let output = match Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg(&timeout_str)
            .arg(target)
            .output()
            .await
        {
            Ok(o) => o,
            Err(e) => {
                return CheckResult {
                    job_id: 0,
                    success: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    status_code: None,
                    error_message: Some(format!("failed to run ping: {e}")),
                    details: None,
                };
            }
        };

        let duration_ms = start.elapsed().as_millis() as u64;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() {
            let rtt = parse_rtt(&stdout);
            tracing::debug!("[{job_id}] ICMP result: {target} -> rtt={rtt:?}ms in {duration_ms}ms");
            let mut details = serde_json::json!({"raw_stdout": stdout.to_string()});
            if let Some(r) = rtt {
                details["rtt_avg_ms"] = serde_json::json!(r);
            }

            if let (Some(r), Some(max_rtt)) =
                (rtt, _config.get("max_rtt_ms").and_then(|v| v.as_f64()))
                && r > max_rtt
            {
                return CheckResult {
                    job_id: 0,
                    success: false,
                    duration_ms,
                    status_code: None,
                    error_message: Some(format!("RTT {r}ms exceeds threshold {max_rtt}ms")),
                    details: Some(details),
                };
            }

            CheckResult {
                job_id: 0,
                success: true,
                duration_ms,
                status_code: None,
                error_message: None,
                details: Some(details),
            }
        } else {
            let err = if stderr.is_empty() {
                stdout.trim().to_string()
            } else {
                stderr.trim().to_string()
            };
            let err_msg = if err.is_empty() {
                "ping failed".into()
            } else {
                err.clone()
            };
            tracing::debug!(
                "[{job_id}] ICMP result: {target} -> FAILED ({err_msg}) in {duration_ms}ms"
            );
            CheckResult {
                job_id: 0,
                success: false,
                duration_ms,
                status_code: None,
                error_message: Some(err_msg),
                details: Some(serde_json::json!({"raw_stdout": stdout.to_string()})),
            }
        }
    }
}

fn parse_rtt(stdout: &str) -> Option<f64> {
    for line in stdout.lines() {
        if line.contains("rtt min/avg/max/mdev") {
            let parts: Vec<&str> = line.split('=').collect();
            if parts.len() >= 2 {
                let stats: Vec<&str> = parts[1].trim().split('/').collect();
                if stats.len() >= 4 {
                    return stats[1].parse::<f64>().ok();
                }
            }
        }
    }
    None
}
