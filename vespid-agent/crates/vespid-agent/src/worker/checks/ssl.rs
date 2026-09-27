use async_trait::async_trait;
use chrono::NaiveDateTime;
use std::time::Instant;
use tokio::process::Command;
use tracing;

use super::super::executor::{CheckExecutor, CheckResult};

pub struct SslExecutor;

#[async_trait]
impl CheckExecutor for SslExecutor {
    fn check_type(&self) -> &'static str {
        "ssl"
    }

    async fn execute(
        &self,
        target: &str,
        config: &serde_json::Value,
        _timeout_secs: u64,
        job_id: i64,
    ) -> CheckResult {
        let start = Instant::now();

        let host = target
            .strip_prefix("https://")
            .or_else(|| target.strip_prefix("http://"))
            .unwrap_or(target)
            .trim_end_matches('/');
        let port = config.get("port").and_then(|v| v.as_u64()).unwrap_or(443);
        let sni = config.get("sni").and_then(|v| v.as_str()).unwrap_or(host);
        let check_chain = config
            .get("check_chain")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let connect_str = format!("{}:{}", host, port);
        tracing::debug!(
            "[{job_id}] SSL check: host={host}, port={port}, sni={sni}, check_chain={check_chain}"
        );

        let mut cmd = Command::new("openssl");
        cmd.arg("s_client")
            .arg("-connect")
            .arg(&connect_str)
            .arg("-servername")
            .arg(sni);

        if check_chain {
            cmd.arg("-verify_return_error");
            cmd.arg("-verify").arg("5");
        }

        cmd.arg("-CApath").arg("/etc/ssl/certs");

        cmd.arg("-no_ign_eof");

        tracing::debug!(
            "[{job_id}] SSL check command: openssl s_client -connect {connect_str} -servername {sni} -CApath /etc/ssl/certs -no_ign_eof"
        );

        let mut child = match cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return CheckResult {
                    job_id: 0,
                    success: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    status_code: None,
                    error_message: Some(format!("failed to run openssl: {e}")),
                    details: None,
                };
            }
        };

        if let Some(stdin) = child.stdin.as_mut() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write(b"\n").await;
            let _ = stdin.flush().await;
        }
        drop(child.stdin.take());

        let output = match child.wait_with_output().await {
            Ok(o) => o,
            Err(e) => {
                return CheckResult {
                    job_id: 0,
                    success: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    status_code: None,
                    error_message: Some(format!("openssl process error: {e}")),
                    details: None,
                };
            }
        };

        let duration_ms = start.elapsed().as_millis() as u64;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{}\n{}", stdout, stderr);

        tracing::debug!("[{job_id}] SSL check openssl stdout:\n{stdout}");
        if !stderr.trim().is_empty() {
            tracing::debug!("[{job_id}] SSL check openssl stderr:\n{stderr}");
        }

        if output.status.code() == Some(2) {
            return CheckResult {
                job_id: 0,
                success: false,
                duration_ms,
                status_code: None,
                error_message: Some("openssl not found or failed to execute".into()),
                details: None,
            };
        }

        let has_verify_error =
            combined.contains("verify error:num=") && !combined.contains("verify error:num=0");
        let exit_ok = output.status.success();

        let subject = extract_field(&combined, "subject=");
        let issuer = extract_field(&combined, "issuer=");
        let not_before = extract_field_flex(&combined, "NotBefore");
        let not_after = extract_field_flex(&combined, "NotAfter");

        let days_remaining = parse_days_remaining(&not_after);

        let chain_valid = if check_chain {
            exit_ok && !has_verify_error
        } else {
            true
        };

        let mut chain_error = None;
        if check_chain && (!exit_ok || has_verify_error) {
            let err_line = combined
                .lines()
                .find(|l| l.contains("verify error:num=") && !l.contains("verify error:num=0"))
                .unwrap_or("unknown verification error");
            chain_error = Some(clean_error(err_line));
        }

        let success = days_remaining.map(|d| d > 0).unwrap_or(false) && chain_valid;

        tracing::debug!(
            "[{job_id}] SSL check result: host={host}, success={success}, days_remaining={days_remaining:?}, \
             chain_valid={chain_valid}, subject={subject:?}, issuer={issuer:?}, duration_ms={duration_ms}"
        );

        let mut details = serde_json::json!({
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "days_remaining": days_remaining,
            "chain_valid": chain_valid,
        });

        if let Some(ref e) = chain_error {
            details["chain_error"] = serde_json::json!(e);
        }

        if !success {
            if !chain_valid {
                return CheckResult {
                    job_id: 0,
                    success: false,
                    duration_ms,
                    status_code: None,
                    error_message: chain_error
                        .or(Some("certificate chain validation failed".into())),
                    details: Some(details),
                };
            }
            if let Some(0) | Some(-1i64..) = days_remaining {
                return CheckResult {
                    job_id: 0,
                    success: false,
                    duration_ms,
                    status_code: None,
                    error_message: Some("certificate has expired".into()),
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

fn extract_field(output: &str, field: &str) -> String {
    output
        .lines()
        .find(|l| l.trim().starts_with(field))
        .map(|l| {
            let val = l.trim_start().strip_prefix(field).unwrap_or("").trim();
            val.trim_end_matches(',').trim().to_string()
        })
        .unwrap_or_default()
}

fn parse_days_remaining(date_str: &str) -> Option<i64> {
    let date_str = date_str.trim();
    if date_str.is_empty() {
        return None;
    }
    let formats = &[
        "%b %d %H:%M:%S %Y GMT",
        "%b %e %H:%M:%S %Y GMT",
        "%b %d %H:%M:%S %Y",
        "%b %e %H:%M:%S %Y",
    ];
    let parsed = formats
        .iter()
        .find_map(|fmt| NaiveDateTime::parse_from_str(date_str, fmt).ok());
    match parsed {
        Some(dt) => {
            let now = chrono::Utc::now().naive_utc();
            Some((dt - now).num_days())
        }
        None => None,
    }
}

fn clean_error(s: &str) -> String {
    let s = s.trim();
    if let Some(idx) = s.find("verify error:") {
        let start = idx + "verify error:".len();
        s[start..].trim().to_string()
    } else {
        s.to_string()
    }
}

fn extract_field_flex(output: &str, field: &str) -> String {
    for line in output.lines() {
        if let Some(idx) = line.find(field) {
            let after_field = &line[idx + field.len()..];
            if let Some(colon_idx) = after_field.find(':') {
                return after_field[colon_idx + 1..]
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches(',')
                    .trim()
                    .to_string();
            }
        }
    }
    String::new()
}
