use crate::collectors::Collector;
use crate::config::{CollectorsConfig, ProcfsMetricDef};
use std::time::Duration;
use vespid_agent_common::{Metric, MetricLabel, MetricSample};

pub struct ProcfsCollector {
    metrics_defs: Vec<ProcfsMetricDef>,
}

impl ProcfsCollector {
    pub fn new(config: &CollectorsConfig) -> Self {
        Self {
            metrics_defs: config.procfs.metrics.clone(),
        }
    }

    fn read_file(path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn parse_value(content: &str, strategy: &str, key: &str) -> Option<f64> {
        let content = content.trim();
        if content.is_empty() {
            return None;
        }

        match strategy {
            "value" => content.parse().ok(),

            "first_field" => content
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok()),

            "line_count" => Some(content.lines().count() as f64),

            "snmp" => {
                if key.is_empty() {
                    return None;
                }
                let mut section = "";
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if !line.contains(':') {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if !parts.is_empty() {
                            section = parts[0].trim_end_matches(':');
                        }
                        continue;
                    }
                    let parts: Vec<&str> = line.splitn(2, ':').collect();
                    if parts.len() != 2 {
                        continue;
                    }
                    let section_key = parts[0].trim();
                    let full_key = format!("{section}.{section_key}");
                    if full_key != key && section_key != key {
                        continue;
                    }
                    let values: Vec<&str> = parts[1].split_whitespace().collect();
                    if values.is_empty() {
                        continue;
                    }
                    return values[0].parse().ok();
                }
                None
            }

            _ => content.parse().ok(),
        }
    }

    fn collect_one(def: &ProcfsMetricDef) -> Option<Metric> {
        let content = Self::read_file(&def.path)?;
        let value = Self::parse_value(&content, &def.parse, &def.key)?;

        let mut labels = vec![
            MetricLabel {
                name: "__name__".into(),
                value: def.name.clone(),
            },
            MetricLabel {
                name: "path".into(),
                value: def.path.clone(),
            },
        ];
        if !def.key.is_empty() {
            labels.push(MetricLabel {
                name: "key".into(),
                value: def.key.clone(),
            });
        }

        Some(Metric {
            labels,
            sample: MetricSample {
                value,
                timestamp_ms: 0,
            },
        })
    }
}

impl Collector for ProcfsCollector {
    fn name(&self) -> &'static str {
        "procfs"
    }

    fn default_interval(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn enabled(&self, config: &CollectorsConfig) -> bool {
        config.procfs.enabled && !config.procfs.metrics.is_empty()
    }

    fn collect(&self) -> Vec<Metric> {
        self.metrics_defs
            .iter()
            .filter_map(Self::collect_one)
            .collect()
    }
}
