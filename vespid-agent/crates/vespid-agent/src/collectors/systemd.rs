use crate::collectors::Collector;
use crate::config::CollectorsConfig;
use std::process::Command;
use std::time::Duration;
use vespid_agent_common::{Metric, MetricLabel, MetricSample};

pub struct SystemdCollector {
    watch_units: Vec<String>,
}

#[derive(Debug)]
struct UnitState {
    name: String,
    active: bool,
    sub_state: String,
}

impl SystemdCollector {
    pub fn new(config: &CollectorsConfig) -> Self {
        Self {
            watch_units: config.systemd.watch_units.clone(),
        }
    }

    fn list_units(&self) -> Vec<UnitState> {
        let mut units = Vec::new();

        let output = match Command::new("systemctl")
            .args(["list-units", "--all", "--no-legend", "--type=service"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return units,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let name = parts[0].trim_end_matches(".service").to_string();
            let load = parts[1];
            let active = parts[2];
            let sub = parts[3];

            if load == "not-found" {
                continue;
            }

            let is_active = active == "active";
            let sub_state = sub.to_string();

            if !is_active && !self.watch_units.contains(&name) {
                continue;
            }

            units.push(UnitState {
                name,
                active: is_active,
                sub_state,
            });
        }

        units
    }
}

impl Collector for SystemdCollector {
    fn name(&self) -> &'static str {
        "systemd"
    }

    fn default_interval(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn enabled(&self, config: &CollectorsConfig) -> bool {
        config.systemd.enabled
    }

    fn collect(&self) -> Vec<Metric> {
        let mut metrics = Vec::new();
        let prefix = "vespid_monitor_systemd";

        for unit in self.list_units() {
            metrics.push(Metric {
                labels: vec![
                    MetricLabel {
                        name: "__name__".into(),
                        value: format!("{prefix}_unit_active"),
                    },
                    MetricLabel {
                        name: "unit".into(),
                        value: unit.name.clone(),
                    },
                    MetricLabel {
                        name: "sub_state".into(),
                        value: unit.sub_state.clone(),
                    },
                ],
                sample: MetricSample {
                    value: if unit.active { 1.0 } else { 0.0 },
                    timestamp_ms: 0,
                },
            });
        }

        metrics
    }
}
