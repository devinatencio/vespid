use async_trait::async_trait;
use std::time::Instant;
use tokio::process::Command;
use tracing;

use super::super::executor::{CheckExecutor, CheckResult};

pub struct DnsExecutor;

#[async_trait]
impl CheckExecutor for DnsExecutor {
    fn check_type(&self) -> &'static str {
        "dns"
    }

    async fn execute(
        &self,
        target: &str,
        config: &serde_json::Value,
        timeout_secs: u64,
        job_id: i64,
    ) -> CheckResult {
        let start = Instant::now();

        let timeout_str = timeout_secs.to_string();
        let nameserver = config
            .get("nameserver")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mut cmd = Command::new("dig");
        cmd.arg("+short")
            .arg(format!("+timeout={}", timeout_str))
            .arg(target);

        if let Some(ns) = config.get("nameserver").and_then(|v| v.as_str()) {
            cmd.arg(format!("@{}", ns));
        }

        tracing::debug!("[{job_id}] DNS check: {target} type=A nameserver={nameserver}");
        tracing::debug!(
            "[{job_id}] DNS check command: dig +short +timeout={timeout_str} {target} {ns}",
            ns = if nameserver.is_empty() {
                String::new()
            } else {
                format!("@{nameserver}")
            }
        );

        let output = match cmd.output().await {
            Ok(o) => o,
            Err(e) => {
                return CheckResult {
                    job_id: 0,
                    success: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    status_code: None,
                    error_message: Some(format!("failed to run dig: {e}")),
                    details: None,
                };
            }
        };

        let duration_ms = start.elapsed().as_millis() as u64;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let answers: Vec<&str> = stdout
            .lines()
            .filter(|l| !l.is_empty() && !l.contains(";;"))
            .collect();

        tracing::debug!(
            "[{job_id}] DNS result: {target} -> {} answers in {duration_ms}ms",
            answers.len()
        );
        tracing::debug!("[{job_id}] DNS answers: {:?}", answers);

        if answers.is_empty() {
            let msg = if !stderr.is_empty() {
                stderr.trim().to_string()
            } else {
                "no records found".into()
            };
            CheckResult {
                job_id: 0,
                success: false,
                duration_ms,
                status_code: None,
                error_message: Some(msg),
                details: Some(serde_json::json!({"raw_stdout": stdout.trim()})),
            }
        } else {
            let details = serde_json::json!({
                "answers": answers,
                "answer_count": answers.len(),
            });

            if let Some(expected) = config.get("expected_value").and_then(|v| v.as_str()) {
                let found = answers.iter().any(|a| a.trim() == expected.trim());
                if !found {
                    return CheckResult {
                        job_id: 0,
                        success: false,
                        duration_ms,
                        status_code: None,
                        error_message: Some(format!(
                            "expected value '{expected}' not found in DNS answers"
                        )),
                        details: Some(details),
                    };
                }
            }

            CheckResult {
                job_id: 0,
                success: true,
                duration_ms,
                status_code: None,
                error_message: None,
                details: Some(details),
            }
        }
    }
}
