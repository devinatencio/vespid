use async_trait::async_trait;
use regex::Regex;
use std::time::Instant;
use tracing;

use super::super::executor::{CheckExecutor, CheckResult};

pub struct HttpExecutor;

#[async_trait]
impl CheckExecutor for HttpExecutor {
    fn check_type(&self) -> &'static str {
        "http"
    }

    async fn execute(
        &self,
        target: &str,
        config: &serde_json::Value,
        timeout_secs: u64,
        job_id: i64,
    ) -> CheckResult {
        let start = Instant::now();

        let base_url = if target.starts_with("http://") || target.starts_with("https://") {
            target.to_string()
        } else {
            format!("https://{target}")
        };

        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(false)
            .cookie_store(true)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                return CheckResult {
                    job_id: 0,
                    success: false,
                    duration_ms: start.elapsed().as_millis() as u64,
                    status_code: None,
                    error_message: Some(format!("client build error: {e}")),
                    details: None,
                };
            }
        };

        if let Some(steps) = config.get("steps").and_then(|v| v.as_array())
            && !steps.is_empty()
        {
            return self
                .execute_steps(
                    &client,
                    &base_url,
                    steps,
                    config,
                    timeout_secs,
                    start,
                    job_id,
                )
                .await;
        }

        self.execute_single(&client, &base_url, config, start, job_id)
            .await
    }
}

impl HttpExecutor {
    #[allow(clippy::too_many_arguments)]
    async fn execute_steps(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        steps: &[serde_json::Value],
        config: &serde_json::Value,
        timeout_secs: u64,
        start: Instant,
        job_id: i64,
    ) -> CheckResult {
        let mut current_url = base_url.to_string();
        let mut step_results: Vec<serde_json::Value> = Vec::new();
        let mut overall_success = true;
        let mut first_status_code: Option<u16> = None;
        let mut last_error: Option<String> = None;

        tracing::debug!(
            "[{job_id}] HTTP stepped check: {} steps for {}",
            steps.len(),
            base_url
        );

        for (i, step) in steps.iter().enumerate() {
            let step_start = Instant::now();

            let step_url = step.get("url").and_then(|v| v.as_str());
            let url = if let Some(u) = step_url {
                if u.starts_with("http://") || u.starts_with("https://") {
                    u.to_string()
                } else {
                    let base = url::Url::parse(&current_url)
                        .unwrap_or_else(|_| url::Url::parse("about:blank").unwrap());
                    match base.join(u) {
                        Ok(resolved) => resolved.to_string(),
                        Err(_) => u.to_string(),
                    }
                }
            } else {
                current_url.clone()
            };

            let method = step.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
            let expected_status = step
                .get("expect_status")
                .and_then(|v| v.as_str())
                .unwrap_or("200-399");

            let mut req_builder = match method.to_uppercase().as_str() {
                "POST" => client.post(&url),
                "PUT" => client.put(&url),
                "DELETE" => client.delete(&url),
                "PATCH" => client.patch(&url),
                _ => client.get(&url),
            };

            if let Some(headers) = step.get("headers").and_then(|v| v.as_object()) {
                for (key, val) in headers {
                    if let Some(v) = val.as_str() {
                        req_builder = req_builder.header(key.as_str(), resolve_env_vars(v));
                    }
                }
            }

            if let Some(body) = step.get("body").and_then(|v| v.as_str()) {
                req_builder = req_builder.body(resolve_env_vars(body));
            }

            let step_name = step.get("name").and_then(|v| v.as_str()).unwrap_or("");

            tracing::debug!(
                "[{job_id}] HTTP step {}: {method} {url} (step_name={step_name:?})",
                i + 1
            );

            match req_builder.send().await {
                Ok(resp) => {
                    let status_code = resp.status().as_u16();
                    if first_status_code.is_none() {
                        first_status_code = Some(status_code);
                    }

                    let status_ok = match_status(status_code, expected_status);
                    let response_url = resp.url().to_string();
                    current_url = response_url.clone();

                    let mut step_detail = serde_json::json!({
                        "step": i + 1,
                        "name": step_name,
                        "method": method,
                        "url": url,
                        "status_code": status_code,
                        "duration_ms": step_start.elapsed().as_millis() as u64,
                    });

                    if !status_ok {
                        overall_success = false;
                        let msg = format!(
                            "step {} HTTP {status_code} (expected {expected_status})",
                            i + 1
                        );
                        step_detail["error"] = serde_json::json!(msg.clone());
                        step_detail["success"] = serde_json::json!(false);
                        step_results.push(step_detail);
                        last_error = Some(msg);
                        break;
                    }

                    let body_match = step.get("body_match").and_then(|v| v.as_str());
                    if let Some(expected) = body_match {
                        match resp.text().await {
                            Ok(body) => {
                                let found = body.contains(expected);
                                step_detail["body_match"] = serde_json::json!(found);
                                if !found {
                                    overall_success = false;
                                    let msg = format!(
                                        "step {} body does not contain expected text: {expected}",
                                        i + 1
                                    );
                                    step_detail["error"] = serde_json::json!(msg.clone());
                                    step_detail["success"] = serde_json::json!(false);
                                    step_results.push(step_detail);
                                    last_error = Some(msg);
                                    break;
                                }
                            }
                            Err(e) => {
                                overall_success = false;
                                let msg =
                                    format!("step {} failed to read response body: {e}", i + 1);
                                step_detail["error"] = serde_json::json!(msg.clone());
                                step_detail["success"] = serde_json::json!(false);
                                step_results.push(step_detail);
                                last_error = Some(msg);
                                break;
                            }
                        }
                    }

                    step_detail["success"] = serde_json::json!(true);
                    step_results.push(step_detail);
                }
                Err(e) => {
                    overall_success = false;
                    let is_timeout = e.is_timeout();
                    let msg = if is_timeout {
                        format!("step {} timeout", i + 1)
                    } else {
                        format!("step {} error: {e}", i + 1)
                    };
                    step_results.push(serde_json::json!({
                        "step": i + 1,
                        "name": step_name,
                        "method": method,
                        "url": url,
                        "duration_ms": step_start.elapsed().as_millis() as u64,
                        "success": false,
                        "error": msg.clone(),
                    }));
                    last_error = Some(msg);
                    break;
                }
            }

            let total_elapsed = start.elapsed().as_secs();
            if total_elapsed >= timeout_secs {
                overall_success = false;
                last_error = Some(format!("overall timeout after {total_elapsed}s"));
                break;
            }
        }

        let total_ms = start.elapsed().as_millis() as u64;
        let mut details = serde_json::json!({
            "steps": step_results,
            "total_steps": steps.len(),
            "completed_steps": step_results.len(),
        });

        if let Some(max_dur) = config.get("max_duration_ms").and_then(|v| v.as_u64()) {
            details["max_duration_ms_exceeded"] = serde_json::json!(total_ms > max_dur);
        }

        CheckResult {
            job_id: 0,
            success: overall_success,
            duration_ms: total_ms,
            status_code: first_status_code,
            error_message: last_error,
            details: Some(details),
        }
    }

    async fn execute_single(
        &self,
        client: &reqwest::Client,
        url: &str,
        config: &serde_json::Value,
        start: Instant,
        job_id: i64,
    ) -> CheckResult {
        tracing::debug!("[{job_id}] HTTP check: GET {url}");
        match client.get(url).send().await {
            Ok(resp) => {
                let status_code = resp.status().as_u16();
                let duration_ms = start.elapsed().as_millis() as u64;
                tracing::debug!(
                    "[{job_id}] HTTP result: GET {url} -> {status_code} in {duration_ms}ms"
                );

                let expected_status_range = config
                    .get("expected_status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("200-399");

                let status_ok = match_status(status_code, expected_status_range);
                let success = status_ok;

                let mut details = serde_json::json!({
                    "status_code": status_code,
                    "response_time_ms": duration_ms,
                });

                if !status_ok {
                    return CheckResult {
                        job_id: 0,
                        success: false,
                        duration_ms,
                        status_code: Some(status_code),
                        error_message: Some(format!(
                            "HTTP {status_code} (expected {expected_status_range})"
                        )),
                        details: Some(details),
                    };
                }

                let body_match = config.get("body_match").and_then(|v| v.as_str());
                if let Some(expected) = body_match {
                    match resp.text().await {
                        Ok(body) => {
                            let found = body.contains(expected);
                            details["body_match"] = serde_json::json!(found);
                            if !found {
                                return CheckResult {
                                    job_id: 0,
                                    success: false,
                                    duration_ms,
                                    status_code: Some(status_code),
                                    error_message: Some(format!(
                                        "body does not contain expected text: {expected}"
                                    )),
                                    details: Some(details),
                                };
                            }
                        }
                        Err(e) => {
                            return CheckResult {
                                job_id: 0,
                                success: false,
                                duration_ms,
                                status_code: Some(status_code),
                                error_message: Some(format!("failed to read response body: {e}")),
                                details: Some(details),
                            };
                        }
                    }
                }

                if let Some(max_dur) = config.get("max_duration_ms").and_then(|v| v.as_u64())
                    && duration_ms > max_dur
                {
                    details["max_duration_ms_exceeded"] = serde_json::json!(true);
                    return CheckResult {
                        job_id: 0,
                        success: false,
                        duration_ms,
                        status_code: Some(status_code),
                        error_message: Some(format!(
                            "response time {duration_ms}ms exceeds threshold {max_dur}ms"
                        )),
                        details: Some(details),
                    };
                }

                CheckResult {
                    job_id: 0,
                    success,
                    duration_ms,
                    status_code: Some(status_code),
                    error_message: None,
                    details: Some(details),
                }
            }
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let is_timeout = e.is_timeout();
                CheckResult {
                    job_id: 0,
                    success: false,
                    duration_ms,
                    status_code: None,
                    error_message: Some(if is_timeout {
                        "timeout".to_string()
                    } else {
                        format!("{e}")
                    }),
                    details: None,
                }
            }
        }
    }
}

fn match_status(status: u16, spec: &str) -> bool {
    for part in spec.split(',') {
        let part = part.trim();
        if let Some(hyphen) = part.find('-') {
            let low: u16 = match part[..hyphen].trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let high: u16 = match part[hyphen + 1..].trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            if status >= low && status <= high {
                return true;
            }
        } else {
            let exact: u16 = match part.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            if status == exact {
                return true;
            }
        }
    }
    false
}

fn resolve_env_vars(s: &str) -> String {
    let re = Regex::new(r"\$\$|\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)").unwrap();
    let result = re.replace_all(s, |caps: &regex::Captures| {
        if caps.get(0).map(|m| m.as_str() == "$$").unwrap_or(false) {
            return "$".to_string();
        }
        let var_name = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map(|m| m.as_str())
            .unwrap_or("");
        std::env::var(var_name)
            .unwrap_or_else(|_| caps.get(0).map(|m| m.as_str()).unwrap_or("").to_string())
    });
    result.to_string()
}
