use crate::collectors::Collector;
use crate::config::{CollectorsConfig, LogWatchDef};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use vespid_agent_common::{Metric, MetricLabel, MetricSample};

pub struct LogfileCollector {
    yaml_watches: Vec<CompiledWatch>,
    server_url: String,
    api_key: String,
    agent_id: String,
    hostname: String,
    state_path: PathBuf,
    state: Mutex<Option<PersistedState>>,
    server_cache: Mutex<Option<(Vec<CompiledWatch>, Instant)>>,
}

#[derive(Clone)]
struct CompiledWatch {
    def: LogWatchDef,
    regex: Regex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedState {
    version: u32,
    watches: HashMap<String, WatchFileState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WatchFileState {
    inode: u64,
    position: u64,
    matched: bool,
    total_matches: u64,
    last_match_text: String,
}

fn default_state_path() -> PathBuf {
    PathBuf::from("/var/lib/vespid-agent/logfile-state.json")
}

impl LogfileCollector {
    pub fn new(
        config: &CollectorsConfig,
        server_url: String,
        api_key: String,
        agent_id: String,
        hostname: String,
    ) -> Self {
        let yaml_watches: Vec<CompiledWatch> = config
            .logfile
            .watches
            .iter()
            .filter_map(|w| {
                let name = w.name.clone();
                match Regex::new(&w.pattern) {
                    Ok(re) => Some(CompiledWatch {
                        def: w.clone(),
                        regex: re,
                    }),
                    Err(e) => {
                        tracing::warn!("Invalid regex pattern for logfile watch '{name}': {e}");
                        None
                    }
                }
            })
            .collect();

        let state_path = if config.logfile.state_path.is_empty() {
            default_state_path()
        } else {
            PathBuf::from(&config.logfile.state_path)
        };

        Self {
            yaml_watches,
            server_url,
            api_key,
            agent_id,
            hostname,
            state_path,
            state: Mutex::new(None),
            server_cache: Mutex::new(None),
        }
    }

    fn get_inode(meta: &fs::Metadata) -> u64 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            meta.ino()
        }
        #[cfg(not(unix))]
        {
            let _ = meta;
            0
        }
    }

    fn load_state(&self) -> PersistedState {
        match fs::read_to_string(&self.state_path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(state) => state,
                Err(e) => {
                    tracing::warn!("Failed to parse logfile state file: {e}");
                    PersistedState {
                        version: 1,
                        watches: HashMap::new(),
                    }
                }
            },
            Err(_) => PersistedState {
                version: 1,
                watches: HashMap::new(),
            },
        }
    }

    fn save_state(&self, state: &PersistedState) {
        if let Some(parent) = self.state_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(state) {
            Ok(content) => {
                if let Err(e) = fs::write(&self.state_path, &content) {
                    tracing::warn!("Failed to write logfile state: {e}");
                }
            }
            Err(e) => tracing::warn!("Failed to serialize logfile state: {e}"),
        }
    }

    fn get_all_watches(&self) -> Vec<CompiledWatch> {
        let mut watches: Vec<CompiledWatch> = Vec::new();
        let mut server_names: std::collections::HashSet<String> = std::collections::HashSet::new();

        if let Some(server_watches) = self.get_server_watches() {
            for w in server_watches {
                server_names.insert(w.def.name.clone());
                watches.push(w);
            }
        }

        for w in &self.yaml_watches {
            if !server_names.contains(&w.def.name) {
                watches.push(CompiledWatch {
                    def: w.def.clone(),
                    regex: w.regex.clone(),
                });
            }
        }

        watches
    }

    fn get_server_watches(&self) -> Option<Vec<CompiledWatch>> {
        let mut cache = self.server_cache.lock().unwrap();
        if let Some((ref watches, ref fetch_time)) = *cache
            && fetch_time.elapsed() < Duration::from_secs(60)
        {
            return Some(watches.clone());
        }

        match self.fetch_watches_from_server() {
            Ok(watches) => {
                *cache = Some((watches.clone(), Instant::now()));
                Some(watches)
            }
            Err(e) => {
                tracing::debug!("Failed to fetch logfile watches from server: {e}");
                cache.as_ref().map(|(w, _)| w.clone())
            }
        }
    }

    fn fetch_watches_from_server(&self) -> Result<Vec<CompiledWatch>, String> {
        let url = format!(
            "{}/api/v1/agent/{}/logfile-watches",
            self.server_url.trim_end_matches('/'),
            self.agent_id
        );

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;

        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send()
            .map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }

        #[derive(Deserialize)]
        struct ServerResponse {
            watches: Vec<LogWatchDef>,
        }

        let body: ServerResponse = resp.json().map_err(|e| e.to_string())?;

        let compiled: Vec<CompiledWatch> = body
            .watches
            .into_iter()
            .filter_map(|def| {
                let name = def.name.clone();
                match Regex::new(&def.pattern) {
                    Ok(re) => Some(CompiledWatch { def, regex: re }),
                    Err(e) => {
                        tracing::warn!("Invalid regex pattern from server for watch '{name}': {e}");
                        None
                    }
                }
            })
            .collect();

        Ok(compiled)
    }

    fn post_check_result(&self, name: &str, exit_code: i32, output: &str) {
        let url = format!(
            "{}/api/v1/metrics/checks",
            self.server_url.trim_end_matches('/')
        );

        let body = serde_json::json!({
            "name": name,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "exit_code": exit_code,
            "output": output,
            "duration_ms": 0,
        });

        let client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to create HTTP client for check result: {e}");
                return;
            }
        };

        match client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
        {
            Ok(r) if r.status().is_success() => {
                tracing::debug!("Logfile check '{name}' reported (exit={exit_code})");
            }
            Ok(r) => {
                tracing::warn!("Logfile check '{name}' report failed: HTTP {}", r.status());
            }
            Err(e) => {
                tracing::warn!("Logfile check '{name}' report error: {e}");
            }
        }
    }

    fn process_watch(
        watch: &CompiledWatch,
        watch_state: &mut WatchFileState,
        prefix: &str,
    ) -> (Vec<Metric>, Option<(i32, String)>) {
        let mut metrics = Vec::new();

        let meta = match fs::metadata(&watch.def.path) {
            Ok(m) => m,
            Err(_) => return (metrics, None),
        };

        let current_inode = Self::get_inode(&meta);
        let file_size = meta.len();

        if current_inode != watch_state.inode {
            tracing::debug!(
                "Log file {} rotated or created (inode changed)",
                watch.def.path
            );
            watch_state.position = 0;
            watch_state.inode = current_inode;
        } else if watch_state.position > file_size {
            tracing::debug!("Log file {} truncated", watch.def.path);
            watch_state.position = 0;
        }

        let file = match fs::File::open(&watch.def.path) {
            Ok(f) => f,
            Err(_) => return (metrics, None),
        };

        let mut reader = BufReader::new(file);
        if watch_state.position > 0 && reader.seek(SeekFrom::Start(watch_state.position)).is_err() {
            return (metrics, None);
        }

        let mut found_match = false;
        let mut last_match = String::new();

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if watch.regex.is_match(trimmed) {
                        found_match = true;
                        watch_state.total_matches += 1;
                        last_match = trimmed.to_string();

                        metrics.push(Metric {
                            labels: vec![
                                MetricLabel {
                                    name: "__name__".into(),
                                    value: format!("{prefix}_matches_total"),
                                },
                                MetricLabel {
                                    name: "name".into(),
                                    value: watch.def.name.clone(),
                                },
                                MetricLabel {
                                    name: "file".into(),
                                    value: watch.def.path.clone(),
                                },
                                MetricLabel {
                                    name: "pattern".into(),
                                    value: watch.def.pattern.clone(),
                                },
                            ],
                            sample: MetricSample {
                                value: 1.0,
                                timestamp_ms: 0,
                            },
                        });
                    }
                }
                Err(_) => break,
            }
        }

        watch_state.position = reader.stream_position().unwrap_or(file_size);

        let check_event = if found_match && !watch_state.matched {
            watch_state.matched = true;
            watch_state.last_match_text = last_match.clone();
            Some((1, last_match))
        } else if !found_match && watch_state.matched {
            watch_state.matched = false;
            let clear_text = format!(
                "Logfile '{}' returned to clean state (no more pattern matches)",
                watch.def.path
            );
            Some((0, clear_text))
        } else {
            None
        };

        metrics.push(Metric {
            labels: vec![
                MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_state"),
                },
                MetricLabel {
                    name: "name".into(),
                    value: watch.def.name.clone(),
                },
                MetricLabel {
                    name: "file".into(),
                    value: watch.def.path.clone(),
                },
                MetricLabel {
                    name: "pattern".into(),
                    value: watch.def.pattern.clone(),
                },
            ],
            sample: MetricSample {
                value: if watch_state.matched { 1.0 } else { 0.0 },
                timestamp_ms: 0,
            },
        });

        (metrics, check_event)
    }
}

impl Collector for LogfileCollector {
    fn name(&self) -> &'static str {
        "logfile"
    }

    fn default_interval(&self) -> Duration {
        Duration::from_secs(10)
    }

    fn enabled(&self, config: &CollectorsConfig) -> bool {
        config.logfile.enabled
    }

    fn collect(&self) -> Vec<Metric> {
        let prefix = "vespid_monitor_logfile";
        let mut metrics = Vec::new();

        let watches = self.get_all_watches();
        if watches.is_empty() {
            return metrics;
        }

        let mut state = self.state.lock().unwrap();
        let persisted = state.get_or_insert_with(|| self.load_state());

        for watch in &watches {
            let watch_state = persisted
                .watches
                .entry(watch.def.name.clone())
                .or_insert_with(|| WatchFileState {
                    inode: 0,
                    position: 0,
                    matched: false,
                    total_matches: 0,
                    last_match_text: String::new(),
                });

            let (watch_metrics, check) = Self::process_watch(watch, watch_state, prefix);
            metrics.extend(watch_metrics);

            if let Some((exit_code, output)) = check
                && watch.def.alert_on_match
            {
                self.post_check_result(&watch.def.name, exit_code, &output);
            }
        }

        self.save_state(persisted);

        metrics
    }
}
