use crate::collectors::Collector;
use crate::config::CollectorsConfig;
use std::collections::HashMap;
use std::time::Duration;
use vespid_agent_common::{Metric, MetricLabel, MetricSample};

pub struct SwapCollector;

impl SwapCollector {
    fn read_raw(path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    pub fn parse(content: &str) -> HashMap<String, u64> {
        let mut map = HashMap::new();
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let key = parts[0].trim_end_matches(':').to_string();
            let value: u64 = match parts[1].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            map.insert(key, value);
        }
        map
    }

    pub fn metrics_from_map(meminfo: &HashMap<String, u64>) -> Vec<Metric> {
        let prefix = "vespid_monitor_swap";
        let mut metrics = Vec::new();

        let total = meminfo.get("SwapTotal").copied().unwrap_or(0) * 1024;
        let free = meminfo.get("SwapFree").copied().unwrap_or(0) * 1024;
        let cached = meminfo.get("SwapCached").copied().unwrap_or(0) * 1024;
        let used = total.saturating_sub(free + cached);
        let used_percent = if total > 0 {
            (used as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        metrics.push(Metric {
            labels: vec![MetricLabel {
                name: "__name__".into(),
                value: format!("{prefix}_total_bytes"),
            }],
            sample: MetricSample {
                value: total as f64,
                timestamp_ms: 0,
            },
        });
        metrics.push(Metric {
            labels: vec![MetricLabel {
                name: "__name__".into(),
                value: format!("{prefix}_free_bytes"),
            }],
            sample: MetricSample {
                value: free as f64,
                timestamp_ms: 0,
            },
        });
        metrics.push(Metric {
            labels: vec![MetricLabel {
                name: "__name__".into(),
                value: format!("{prefix}_used_bytes"),
            }],
            sample: MetricSample {
                value: used as f64,
                timestamp_ms: 0,
            },
        });
        metrics.push(Metric {
            labels: vec![MetricLabel {
                name: "__name__".into(),
                value: format!("{prefix}_used_percent"),
            }],
            sample: MetricSample {
                value: used_percent,
                timestamp_ms: 0,
            },
        });
        metrics.push(Metric {
            labels: vec![MetricLabel {
                name: "__name__".into(),
                value: format!("{prefix}_cached_bytes"),
            }],
            sample: MetricSample {
                value: cached as f64,
                timestamp_ms: 0,
            },
        });

        metrics
    }
}

impl Collector for SwapCollector {
    fn name(&self) -> &'static str {
        "swap"
    }
    fn default_interval(&self) -> Duration {
        Duration::from_secs(60)
    }
    fn enabled(&self, config: &CollectorsConfig) -> bool {
        config.swap.enabled
    }

    fn collect(&self) -> Vec<Metric> {
        let Some(content) = Self::read_raw("/proc/meminfo") else {
            return Vec::new();
        };
        let map = Self::parse(&content);
        Self::metrics_from_map(&map)
    }
}
