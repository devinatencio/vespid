use crate::collectors::Collector;
use crate::config::CollectorsConfig;
use std::time::Duration;
use vespid_agent_common::{Metric, MetricLabel, MetricSample};

pub struct NetworkCollector {
    exclude_interfaces: Vec<String>,
    fallback_speed_mbps: u64,
}

#[derive(Debug, PartialEq)]
pub struct NetDevStat {
    pub iface: String,
    pub bytes_recv: u64,
    pub packets_recv: u64,
    pub errors_recv: u64,
    pub drops_recv: u64,
    pub bytes_sent: u64,
    pub packets_sent: u64,
    pub errors_sent: u64,
    pub drops_sent: u64,
    pub speed_bps: u64,
}

impl NetworkCollector {
    pub fn new(config: &CollectorsConfig) -> Self {
        Self {
            exclude_interfaces: config.network.exclude_interfaces.clone(),
            fallback_speed_mbps: config.network.default_interface_speed_mbps,
        }
    }

    fn read_raw(path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    pub fn parse(content: &str, fallback_speed_mbps: u64) -> Vec<NetDevStat> {
        let mut stats = Vec::new();

        for line in content.lines().skip(2) {
            let line = line.trim();
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 {
                continue;
            }

            let iface = parts[0].trim().to_string();
            let values: Vec<&str> = parts[1].split_whitespace().collect();
            if values.len() < 10 {
                continue;
            }

            let bytes_recv: u64 = values[0].parse().unwrap_or(0);
            let packets_recv: u64 = values[1].parse().unwrap_or(0);
            let errors_recv: u64 = values[2].parse().unwrap_or(0);
            let drops_recv: u64 = values[3].parse().unwrap_or(0);
            let bytes_sent: u64 = values[8].parse().unwrap_or(0);
            let packets_sent: u64 = values[9].parse().unwrap_or(0);
            let errors_sent: u64 = values[10].parse().unwrap_or(0);
            let drops_sent: u64 = values[11].parse().unwrap_or(0);

            let speed_bps = read_interface_speed_bps(&iface, fallback_speed_mbps);

            stats.push(NetDevStat {
                iface,
                bytes_recv,
                packets_recv,
                errors_recv,
                drops_recv,
                bytes_sent,
                packets_sent,
                errors_sent,
                drops_sent,
                speed_bps,
            });
        }

        stats
    }

    pub fn metrics_from_stats(stats: &[NetDevStat], exclude: &[String]) -> Vec<Metric> {
        let mut metrics = Vec::new();
        let prefix = "vespid_monitor_network";

        for stat in stats {
            if stat.iface == "lo" || exclude.contains(&stat.iface) {
                continue;
            }

            let label = |name: &str| {
                vec![
                    MetricLabel {
                        name: "__name__".into(),
                        value: name.into(),
                    },
                    MetricLabel {
                        name: "interface".into(),
                        value: stat.iface.clone(),
                    },
                ]
            };

            metrics.push(Metric {
                labels: label(&format!("{prefix}_bytes_sent_total")),
                sample: MetricSample {
                    value: stat.bytes_sent as f64,
                    timestamp_ms: 0,
                },
            });
            metrics.push(Metric {
                labels: label(&format!("{prefix}_bytes_recv_total")),
                sample: MetricSample {
                    value: stat.bytes_recv as f64,
                    timestamp_ms: 0,
                },
            });
            metrics.push(Metric {
                labels: label(&format!("{prefix}_packets_sent_total")),
                sample: MetricSample {
                    value: stat.packets_sent as f64,
                    timestamp_ms: 0,
                },
            });
            metrics.push(Metric {
                labels: label(&format!("{prefix}_packets_recv_total")),
                sample: MetricSample {
                    value: stat.packets_recv as f64,
                    timestamp_ms: 0,
                },
            });
            metrics.push(Metric {
                labels: label(&format!("{prefix}_errors_sent_total")),
                sample: MetricSample {
                    value: stat.errors_sent as f64,
                    timestamp_ms: 0,
                },
            });
            metrics.push(Metric {
                labels: label(&format!("{prefix}_errors_recv_total")),
                sample: MetricSample {
                    value: stat.errors_recv as f64,
                    timestamp_ms: 0,
                },
            });
            metrics.push(Metric {
                labels: label(&format!("{prefix}_drops_sent_total")),
                sample: MetricSample {
                    value: stat.drops_sent as f64,
                    timestamp_ms: 0,
                },
            });
            metrics.push(Metric {
                labels: label(&format!("{prefix}_drops_recv_total")),
                sample: MetricSample {
                    value: stat.drops_recv as f64,
                    timestamp_ms: 0,
                },
            });
            if stat.speed_bps > 0 {
                metrics.push(Metric {
                    labels: label(&format!("{prefix}_speed_bps")),
                    sample: MetricSample {
                        value: stat.speed_bps as f64,
                        timestamp_ms: 0,
                    },
                });
            }
        }

        metrics
    }
}

fn read_interface_speed_bps(iface: &str, fallback_mbps: u64) -> u64 {
    let path = format!("/sys/class/net/{iface}/speed");
    if let Ok(content) = std::fs::read_to_string(&path)
        && let Ok(mbps_signed) = content.trim().parse::<i64>()
        && mbps_signed > 0
    {
        return (mbps_signed as u64) * 1_000_000;
    }
    if fallback_mbps > 0 {
        fallback_mbps * 1_000_000
    } else {
        0
    }
}

impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }
    fn default_interval(&self) -> Duration {
        Duration::from_secs(60)
    }
    fn enabled(&self, config: &CollectorsConfig) -> bool {
        config.network.enabled
    }

    fn collect(&self) -> Vec<Metric> {
        let Some(content) = Self::read_raw("/proc/net/dev") else {
            return Vec::new();
        };
        let stats = Self::parse(&content, self.fallback_speed_mbps);
        Self::metrics_from_stats(&stats, &self.exclude_interfaces)
    }
}
