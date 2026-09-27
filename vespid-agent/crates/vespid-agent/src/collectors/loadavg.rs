use crate::collectors::Collector;
use crate::config::CollectorsConfig;
use std::time::Duration;
use vespid_agent_common::{Metric, MetricLabel, MetricSample};

pub struct LoadavgCollector;

impl Collector for LoadavgCollector {
    fn name(&self) -> &'static str {
        "loadavg"
    }

    fn default_interval(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn enabled(&self, config: &CollectorsConfig) -> bool {
        config.loadavg.enabled
    }

    fn collect(&self) -> Vec<Metric> {
        let content = match std::fs::read_to_string("/proc/loadavg") {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() < 3 {
            return Vec::new();
        }

        let load1: f64 = parts[0].parse().unwrap_or(0.0);
        let load5: f64 = parts[1].parse().unwrap_or(0.0);
        let load15: f64 = parts[2].parse().unwrap_or(0.0);

        let prefix = "vespid_monitor_loadavg";

        vec![
            Metric {
                labels: vec![MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_1min"),
                }],
                sample: MetricSample {
                    value: load1,
                    timestamp_ms: 0,
                },
            },
            Metric {
                labels: vec![MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_5min"),
                }],
                sample: MetricSample {
                    value: load5,
                    timestamp_ms: 0,
                },
            },
            Metric {
                labels: vec![MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_15min"),
                }],
                sample: MetricSample {
                    value: load15,
                    timestamp_ms: 0,
                },
            },
        ]
    }
}
