use crate::collectors::Collector;
use crate::config::{CollectorsConfig, ExecScriptDef};
use std::process::Command;
use std::time::{Duration, Instant};
use vespid_agent_common::{Metric, MetricLabel, MetricSample};

pub struct ExecCollector {
    local_scripts: Vec<ExecScriptDef>,
    timeout_secs: u64,
    server_url: String,
    api_key: String,
    agent_id: String,
    hostname: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ServerScript {
    name: String,
    command: String,
    #[serde(default = "default_timeout")]
    timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}

impl ExecCollector {
    pub fn new(
        config: &CollectorsConfig,
        server_url: String,
        api_key: String,
        agent_id: String,
        hostname: String,
    ) -> Self {
        Self {
            local_scripts: config.exec.scripts.clone(),
            timeout_secs: config.exec.timeout_secs,
            server_url,
            api_key,
            agent_id,
            hostname,
        }
    }

    fn run_command(command_str: &str, _timeout_secs: u64, name: &str) -> ScriptResult {
        let start = Instant::now();
        let parts: Vec<&str> = command_str.split_whitespace().collect();
        if parts.is_empty() {
            return ScriptResult {
                name: name.to_string(),
                exit_code: 127,
                output: String::from("error: empty command"),
                duration_ms: 0,
            };
        }

        let mut cmd = Command::new(parts[0]);
        if parts.len() > 1 {
            cmd.args(&parts[1..]);
        }

        match cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
        {
            Ok(output) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let exit_code = output.status.code().unwrap_or(-1);
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

                let combined = if stderr.is_empty() {
                    stdout.clone()
                } else if stdout.is_empty() {
                    stderr.clone()
                } else {
                    format!("{stdout}\n{stderr}")
                };

                ScriptResult {
                    name: name.to_string(),
                    exit_code,
                    output: combined,
                    duration_ms,
                }
            }
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                ScriptResult {
                    name: name.to_string(),
                    exit_code: -1,
                    output: format!("error: {e}"),
                    duration_ms,
                }
            }
        }
    }

    fn run_script(def: &ExecScriptDef, timeout_secs: u64) -> ScriptResult {
        let command_str = def.command.join(" ");
        Self::run_command(&command_str, timeout_secs, &def.name)
    }

    pub fn metrics_from_result(result: &ScriptResult) -> Vec<Metric> {
        let prefix = "vespid_monitor_exec";
        let mut metrics = Vec::new();

        metrics.push(Metric {
            labels: vec![
                MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_exit_code"),
                },
                MetricLabel {
                    name: "name".into(),
                    value: result.name.clone(),
                },
            ],
            sample: MetricSample {
                value: result.exit_code as f64,
                timestamp_ms: 0,
            },
        });

        metrics.push(Metric {
            labels: vec![
                MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_duration_ms"),
                },
                MetricLabel {
                    name: "name".into(),
                    value: result.name.clone(),
                },
            ],
            sample: MetricSample {
                value: result.duration_ms as f64,
                timestamp_ms: 0,
            },
        });

        metrics
    }

    fn post_check_result(&self, result: &ScriptResult) {
        let url = format!(
            "{}/api/v1/metrics/checks",
            self.server_url.trim_end_matches('/')
        );

        let body = serde_json::json!({
            "name": result.name,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "exit_code": result.exit_code,
            "output": result.output,
            "duration_ms": result.duration_ms,
        });

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build();

        match client {
            Ok(client) => {
                let resp = client
                    .post(&url)
                    .header("Authorization", format!("Bearer {}", self.api_key))
                    .header("Content-Type", "application/json")
                    .json(&body)
                    .send();

                match resp {
                    Ok(r) if r.status().is_success() => {
                        tracing::debug!(
                            "Check '{}' reported (exit={})",
                            result.name,
                            result.exit_code
                        );
                    }
                    Ok(r) => {
                        tracing::warn!(
                            "Check '{}' report failed: HTTP {}",
                            result.name,
                            r.status()
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Check '{}' report connection error: {}", result.name, e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Check '{}' HTTP client error: {}", result.name, e);
            }
        }
    }

    fn fetch_server_scripts(&self) -> Vec<ServerScript> {
        let url = format!(
            "{}/api/v1/agent/{}/exec-scripts",
            self.server_url.trim_end_matches('/'),
            self.agent_id
        );

        let client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let resp = match client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!("Failed to fetch exec scripts: {}", e);
                return Vec::new();
            }
        };

        if !resp.status().is_success() {
            tracing::debug!("Exec scripts endpoint returned {}", resp.status());
            return Vec::new();
        }

        let body: serde_json::Value = match resp.json() {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("Failed to parse exec scripts response: {}", e);
                return Vec::new();
            }
        };

        let scripts_raw = match body.get("scripts").and_then(|s| s.as_array()) {
            Some(arr) => arr,
            None => return Vec::new(),
        };

        let mut scripts = Vec::new();
        for s in scripts_raw {
            if let (Some(name), Some(command)) = (
                s.get("name").and_then(|n| n.as_str()),
                s.get("command").and_then(|c| c.as_str()),
            ) {
                let timeout = s.get("timeout_secs").and_then(|t| t.as_u64()).unwrap_or(30);
                scripts.push(ServerScript {
                    name: name.to_string(),
                    command: command.to_string(),
                    timeout_secs: timeout,
                });
            }
        }

        scripts
    }
}

impl Collector for ExecCollector {
    fn name(&self) -> &'static str {
        "exec"
    }

    fn default_interval(&self) -> Duration {
        Duration::from_secs(300)
    }

    fn enabled(&self, config: &CollectorsConfig) -> bool {
        config.exec.enabled
    }

    fn collect(&self) -> Vec<Metric> {
        let mut metrics = Vec::new();

        // Run local scripts
        for def in &self.local_scripts {
            let result = Self::run_script(def, self.timeout_secs);

            if result.exit_code != 0 {
                tracing::warn!(
                    "Check '{}' failed (exit={}, {}ms): {}",
                    result.name,
                    result.exit_code,
                    result.duration_ms,
                    result.output.lines().next().unwrap_or("(no output)")
                );
                self.post_check_result(&result);
            } else {
                tracing::debug!("Check '{}' ok ({}ms)", result.name, result.duration_ms);
                self.post_check_result(&result);
            }

            metrics.extend(Self::metrics_from_result(&result));
        }

        // Fetch and run server-defined scripts
        let server_scripts = self.fetch_server_scripts();
        if !server_scripts.is_empty() {
            tracing::debug!(
                "Running {} server-defined exec scripts",
                server_scripts.len()
            );
        }
        for server_script in &server_scripts {
            let result = Self::run_command(
                &server_script.command,
                server_script.timeout_secs,
                &server_script.name,
            );

            if result.exit_code != 0 {
                tracing::warn!(
                    "Server check '{}' failed (exit={}, {}ms): {}",
                    result.name,
                    result.exit_code,
                    result.duration_ms,
                    result.output.lines().next().unwrap_or("(no output)")
                );
            } else {
                tracing::debug!(
                    "Server check '{}' ok ({}ms)",
                    result.name,
                    result.duration_ms
                );
            }
            self.post_check_result(&result);
            metrics.extend(Self::metrics_from_result(&result));
        }

        metrics
    }
}

pub struct ScriptResult {
    pub name: String,
    pub exit_code: i32,
    pub output: String,
    pub duration_ms: u64,
}
