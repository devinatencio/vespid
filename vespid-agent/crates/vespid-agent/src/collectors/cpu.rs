use crate::collectors::Collector;
use crate::config::CollectorsConfig;
use std::time::Duration;
use vespid_agent_common::{Metric, MetricLabel, MetricSample};

pub struct CpuCollector;

impl CpuCollector {
    fn read_raw(path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    pub fn parse(content: &str) -> Vec<CpuStat> {
        let mut stats = Vec::new();

        for line in content.lines() {
            if !line.starts_with("cpu") {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 8 {
                continue;
            }

            let cpu = parts[0].to_string();
            if cpu == "cpu" {
                continue;
            }

            let Ok(user) = parts[1].parse::<u64>() else {
                continue;
            };
            let Ok(nice) = parts[2].parse::<u64>() else {
                continue;
            };
            let Ok(system) = parts[3].parse::<u64>() else {
                continue;
            };
            let Ok(idle) = parts[4].parse::<u64>() else {
                continue;
            };
            let Ok(iowait) = parts[5].parse::<u64>() else {
                continue;
            };
            let Ok(irq) = parts[6].parse::<u64>() else {
                continue;
            };
            let Ok(softirq) = parts[7].parse::<u64>() else {
                continue;
            };
            let steal: u64 = parts.get(8).and_then(|s| s.parse().ok()).unwrap_or(0);

            stats.push(CpuStat {
                cpu,
                user,
                nice,
                system,
                idle,
                iowait,
                irq,
                softirq,
                steal,
            });
        }

        stats
    }

    pub fn metrics_from_stats(stats: &[CpuStat]) -> Vec<Metric> {
        let mut metrics = Vec::new();
        let prefix = "vespid_monitor_cpu";

        for stat in stats {
            let total = stat.user
                + stat.nice
                + stat.system
                + stat.idle
                + stat.iowait
                + stat.irq
                + stat.softirq
                + stat.steal;
            if total == 0 {
                continue;
            }

            let labels = |name: &str| {
                vec![
                    MetricLabel {
                        name: "__name__".into(),
                        value: name.into(),
                    },
                    MetricLabel {
                        name: "cpu".into(),
                        value: stat.cpu.clone(),
                    },
                ]
            };

            metrics.push(Metric {
                labels: labels(&format!("{prefix}_user_seconds_total")),
                sample: MetricSample {
                    value: stat.user as f64 / 100.0,
                    timestamp_ms: 0,
                },
            });
            metrics.push(Metric {
                labels: labels(&format!("{prefix}_system_seconds_total")),
                sample: MetricSample {
                    value: stat.system as f64 / 100.0,
                    timestamp_ms: 0,
                },
            });
            metrics.push(Metric {
                labels: labels(&format!("{prefix}_iowait_seconds_total")),
                sample: MetricSample {
                    value: stat.iowait as f64 / 100.0,
                    timestamp_ms: 0,
                },
            });
            metrics.push(Metric {
                labels: labels(&format!("{prefix}_idle_seconds_total")),
                sample: MetricSample {
                    value: stat.idle as f64 / 100.0,
                    timestamp_ms: 0,
                },
            });
            metrics.push(Metric {
                labels: labels(&format!("{prefix}_steal_seconds_total")),
                sample: MetricSample {
                    value: stat.steal as f64 / 100.0,
                    timestamp_ms: 0,
                },
            });
        }

        metrics
    }
}

impl Collector for CpuCollector {
    fn name(&self) -> &'static str {
        "cpu"
    }
    fn default_interval(&self) -> Duration {
        Duration::from_secs(60)
    }
    fn enabled(&self, config: &CollectorsConfig) -> bool {
        config.cpu.enabled
    }

    fn collect(&self) -> Vec<Metric> {
        let Some(content) = Self::read_raw("/proc/stat") else {
            return Vec::new();
        };
        let stats = Self::parse(&content);
        Self::metrics_from_stats(&stats)
    }
}

#[derive(Debug, PartialEq)]
pub struct CpuStat {
    pub cpu: String,
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}
