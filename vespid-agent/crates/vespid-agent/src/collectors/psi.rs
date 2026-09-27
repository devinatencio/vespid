use crate::collectors::Collector;
use crate::config::CollectorsConfig;
use std::collections::HashMap;
use std::time::Duration;
use vespid_agent_common::{Metric, MetricLabel, MetricSample};

pub struct PsiCollector;

#[derive(Debug)]
pub struct PsiLine {
    avg10: f64,
    avg60: f64,
    avg300: f64,
    total: u64,
}

impl PsiCollector {
    fn read_raw(path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    pub fn parse_psi(content: &str) -> HashMap<String, PsiLine> {
        let mut map = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() != 2 {
                continue;
            }

            let key = parts[0].to_string();
            let rest = parts[1];

            let mut avg10 = 0.0f64;
            let mut avg60 = 0.0f64;
            let mut avg300 = 0.0f64;
            let mut total = 0u64;

            for token in rest.split_whitespace() {
                if let Some(val) = token.strip_prefix("avg10=") {
                    avg10 = val.parse().unwrap_or(0.0);
                } else if let Some(val) = token.strip_prefix("avg60=") {
                    avg60 = val.parse().unwrap_or(0.0);
                } else if let Some(val) = token.strip_prefix("avg300=") {
                    avg300 = val.parse().unwrap_or(0.0);
                } else if let Some(val) = token.strip_prefix("total=") {
                    total = val.parse().unwrap_or(0);
                }
            }

            map.insert(
                key,
                PsiLine {
                    avg10,
                    avg60,
                    avg300,
                    total,
                },
            );
        }

        map
    }

    pub fn metrics_from_map(
        map: &HashMap<String, PsiLine>,
        resource: &str,
        prefix: &str,
    ) -> Vec<Metric> {
        let mut metrics = Vec::new();

        for (level, psi) in map {
            let labels = vec![
                MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_avg10"),
                },
                MetricLabel {
                    name: "resource".into(),
                    value: resource.into(),
                },
                MetricLabel {
                    name: "level".into(),
                    value: level.clone(),
                },
            ];

            metrics.push(Metric {
                labels: labels.clone(),
                sample: MetricSample {
                    value: psi.avg10,
                    timestamp_ms: 0,
                },
            });

            let labels_60 = vec![
                MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_avg60"),
                },
                MetricLabel {
                    name: "resource".into(),
                    value: resource.into(),
                },
                MetricLabel {
                    name: "level".into(),
                    value: level.clone(),
                },
            ];
            metrics.push(Metric {
                labels: labels_60,
                sample: MetricSample {
                    value: psi.avg60,
                    timestamp_ms: 0,
                },
            });

            let labels_300 = vec![
                MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_avg300"),
                },
                MetricLabel {
                    name: "resource".into(),
                    value: resource.into(),
                },
                MetricLabel {
                    name: "level".into(),
                    value: level.clone(),
                },
            ];
            metrics.push(Metric {
                labels: labels_300,
                sample: MetricSample {
                    value: psi.avg300,
                    timestamp_ms: 0,
                },
            });

            let labels_total = vec![
                MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_total"),
                },
                MetricLabel {
                    name: "resource".into(),
                    value: resource.into(),
                },
                MetricLabel {
                    name: "level".into(),
                    value: level.clone(),
                },
            ];
            metrics.push(Metric {
                labels: labels_total,
                sample: MetricSample {
                    value: psi.total as f64,
                    timestamp_ms: 0,
                },
            });
        }

        metrics
    }
}

impl Collector for PsiCollector {
    fn name(&self) -> &'static str {
        "psi"
    }

    fn default_interval(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn enabled(&self, config: &CollectorsConfig) -> bool {
        config.psi.enabled
    }

    fn collect(&self) -> Vec<Metric> {
        let mut metrics = Vec::new();
        let prefix = "vespid_monitor_psi";

        let resources = [
            ("cpu", "/proc/pressure/cpu"),
            ("memory", "/proc/pressure/memory"),
            ("io", "/proc/pressure/io"),
        ];

        for (resource, path) in resources {
            if let Some(content) = Self::read_raw(path) {
                let map = Self::parse_psi(&content);
                metrics.extend(Self::metrics_from_map(&map, resource, prefix));
            }
        }

        metrics
    }
}
