pub mod cpu;
pub mod disk;
pub mod exec;
pub mod loadavg;
pub mod logfile;
pub mod memory;
pub mod network;
pub mod process;
pub mod procfs;
pub mod psi;
pub mod swap;
pub mod systemd;

use crate::config::CollectorsConfig;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vespid_agent_common::Metric;

pub struct CollectorContext {
    pub hostname: String,
    pub agent_id: String,
    pub server_url: String,
    pub api_key: String,
}

pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    fn default_interval(&self) -> Duration;
    fn enabled(&self, config: &CollectorsConfig) -> bool;
    fn collect(&self) -> Vec<Metric>;
}

pub struct Collectors {
    config: CollectorsConfig,
    context: Arc<CollectorContext>,
    metric_tx: mpsc::Sender<Metric>,
    cancel: CancellationToken,
}

impl Collectors {
    pub fn new(
        config: CollectorsConfig,
        context: Arc<CollectorContext>,
        metric_tx: mpsc::Sender<Metric>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            config,
            context,
            metric_tx,
            cancel,
        }
    }

    fn build_collectors(&self) -> Vec<Box<dyn Collector>> {
        let mut collectors: Vec<Box<dyn Collector>> = Vec::new();

        let cpu = cpu::CpuCollector;
        if cpu.enabled(&self.config) {
            collectors.push(Box::new(cpu));
        }

        let memory = memory::MemoryCollector;
        if memory.enabled(&self.config) {
            collectors.push(Box::new(memory));
        }

        let disk = disk::DiskCollector::new(&self.config);
        if disk.enabled(&self.config) {
            collectors.push(Box::new(disk));
        }

        let network = network::NetworkCollector::new(&self.config);
        if network.enabled(&self.config) {
            collectors.push(Box::new(network));
        }

        let systemd = systemd::SystemdCollector::new(&self.config);
        if systemd.enabled(&self.config) {
            collectors.push(Box::new(systemd));
        }

        let process = process::ProcessCollector::new(&self.config);
        if process.enabled(&self.config) {
            collectors.push(Box::new(process));
        }

        let psi = psi::PsiCollector;
        if psi.enabled(&self.config) {
            collectors.push(Box::new(psi));
        }

        let loadavg = loadavg::LoadavgCollector;
        if loadavg.enabled(&self.config) {
            collectors.push(Box::new(loadavg));
        }

        let swap = swap::SwapCollector;
        if swap.enabled(&self.config) {
            collectors.push(Box::new(swap));
        }

        let logfile = logfile::LogfileCollector::new(
            &self.config,
            self.context.server_url.clone(),
            self.context.api_key.clone(),
            self.context.agent_id.clone(),
            self.context.hostname.clone(),
        );
        if logfile.enabled(&self.config) {
            collectors.push(Box::new(logfile));
        }

        let procfs = procfs::ProcfsCollector::new(&self.config);
        if procfs.enabled(&self.config) {
            collectors.push(Box::new(procfs));
        }

        let exec = exec::ExecCollector::new(
            &self.config,
            self.context.server_url.clone(),
            self.context.api_key.clone(),
            self.context.agent_id.clone(),
            self.context.hostname.clone(),
        );
        if exec.enabled(&self.config) {
            collectors.push(Box::new(exec));
        }

        collectors
    }

    pub async fn run(&self) {
        let collectors: Vec<_> = self
            .build_collectors()
            .into_iter()
            .map(|c| {
                let interval = c.default_interval();
                (c, interval)
            })
            .collect();

        if collectors.is_empty() {
            tracing::warn!("No collectors enabled");
            return;
        }

        tracing::info!("Starting {} collectors", collectors.len());

        let mut handles = Vec::new();

        for (collector, interval) in collectors {
            let tx = self.metric_tx.clone();
            let cancel = self.cancel.clone();
            let agent_id = self.context.agent_id.clone();
            let hostname = self.context.hostname.clone();
            let collector_name = collector.name().to_string();

            let handle = tokio::spawn(async move {
                let mut interval_timer = tokio::time::interval(interval);
                interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = interval_timer.tick() => {
                            let now = Utc::now();
                            let mut metrics = collector.collect();
                            let count = metrics.len();

                            for metric in &mut metrics {
                                if !metric.labels.iter().any(|l| l.name == "agent_id") {
                                    metric.labels.push(vespid_agent_common::MetricLabel {
                                        name: "agent_id".into(),
                                        value: agent_id.clone(),
                                    });
                                }
                                if !metric.labels.iter().any(|l| l.name == "hostname") {
                                    metric.labels.push(vespid_agent_common::MetricLabel {
                                        name: "hostname".into(),
                                        value: hostname.clone(),
                                    });
                                }
                                metric.sample.timestamp_ms = now.timestamp_millis();
                            }

                            for metric in metrics {
                                if tx.send(metric).await.is_err() {
                                    break;
                                }
                            }
                            tracing::debug!("{}: collected {} metrics", collector_name, count);
                        }
                    }
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }
    }
}
