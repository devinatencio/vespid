use crate::collectors::Collector;
use crate::config::CollectorsConfig;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use vespid_agent_common::{Metric, MetricLabel, MetricSample};

pub struct ProcessCollector {
    top_n: usize,
    prev_ticks: Mutex<HashMap<i32, u64>>,
}

#[derive(Debug, Clone)]
pub struct ProcStat {
    pub pid: i32,
    pub comm: String,
    pub state: char,
    #[allow(dead_code)]
    pub ppid: i32,
    pub utime: u64,
    pub stime: u64,
    pub cutime: u64,
    pub cstime: u64,
    pub rss_pages: u64,
    #[allow(dead_code)]
    pub threads: u64,
    #[allow(dead_code)]
    pub starttime: u64,
}

impl ProcessCollector {
    pub fn new(config: &CollectorsConfig) -> Self {
        Self {
            top_n: config.process.top_n,
            prev_ticks: Mutex::new(HashMap::new()),
        }
    }

    fn read_proc() -> Vec<ProcStat> {
        let mut procs = Vec::new();
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return procs;
        };

        for entry in dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let Ok(pid) = name_str.parse::<i32>() else {
                continue;
            };

            let path = entry.path().join("stat");
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };

            if let Some(stat) = Self::parse_stat_line(&content, pid) {
                procs.push(stat);
            }
        }

        procs
    }

    pub fn parse_stat_line(line: &str, pid: i32) -> Option<ProcStat> {
        let paren_close = line.rfind(')')?;
        let comm = &line[line.find('(')? + 1..paren_close];
        let rest = &line[paren_close + 2..];

        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() < 22 {
            return None;
        }

        let state = fields[0].chars().next()?;
        let ppid: i32 = fields[1].parse().ok()?;
        let utime: u64 = fields[11].parse().ok()?;
        let stime: u64 = fields[12].parse().ok()?;
        let cutime: u64 = fields[13].parse().ok()?;
        let cstime: u64 = fields[14].parse().ok()?;
        let threads: u64 = fields[17].parse().ok()?;
        let starttime: u64 = fields[19].parse().ok()?;
        let rss_pages: u64 = fields[21].parse().ok()?;

        Some(ProcStat {
            pid,
            comm: comm.to_string(),
            state,
            ppid,
            utime,
            stime,
            cutime,
            cstime,
            rss_pages,
            threads,
            starttime,
        })
    }

    pub fn metrics_from_procs(&self, procs: &[ProcStat], prefix: &str) -> Vec<Metric> {
        let mut metrics = Vec::new();
        let page_size = 4096u64;

        let mut running = 0u64;
        let mut sleeping = 0u64;
        let mut zombies = 0u64;
        let mut stopped = 0u64;
        let mut total = 0u64;

        for p in procs {
            total += 1;
            match p.state {
                'R' => running += 1,
                'S' | 'D' => sleeping += 1,
                'Z' => zombies += 1,
                'T' => stopped += 1,
                _ => {}
            }
        }

        metrics.push(Metric {
            labels: vec![MetricLabel {
                name: "__name__".into(),
                value: format!("{prefix}_count_total"),
            }],
            sample: MetricSample {
                value: total as f64,
                timestamp_ms: 0,
            },
        });
        metrics.push(Metric {
            labels: vec![
                MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_running"),
                },
                MetricLabel {
                    name: "state".into(),
                    value: "running".into(),
                },
            ],
            sample: MetricSample {
                value: running as f64,
                timestamp_ms: 0,
            },
        });
        metrics.push(Metric {
            labels: vec![
                MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_sleeping"),
                },
                MetricLabel {
                    name: "state".into(),
                    value: "sleeping".into(),
                },
            ],
            sample: MetricSample {
                value: sleeping as f64,
                timestamp_ms: 0,
            },
        });
        metrics.push(Metric {
            labels: vec![
                MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_zombies"),
                },
                MetricLabel {
                    name: "state".into(),
                    value: "zombies".into(),
                },
            ],
            sample: MetricSample {
                value: zombies as f64,
                timestamp_ms: 0,
            },
        });
        metrics.push(Metric {
            labels: vec![
                MetricLabel {
                    name: "__name__".into(),
                    value: format!("{prefix}_stopped"),
                },
                MetricLabel {
                    name: "state".into(),
                    value: "stopped".into(),
                },
            ],
            sample: MetricSample {
                value: stopped as f64,
                timestamp_ms: 0,
            },
        });

        let mut prev = self.prev_ticks.lock().unwrap();
        let mut cpu_deltas: Vec<(i32, String, u64)> = Vec::new();

        for p in procs {
            let total_ticks = p.utime + p.stime + p.cutime + p.cstime;
            let prev_ticks = prev.get(&p.pid).copied().unwrap_or(total_ticks);
            let delta = total_ticks.saturating_sub(prev_ticks);
            prev.insert(p.pid, total_ticks);

            cpu_deltas.push((p.pid, p.comm.clone(), delta));
        }

        prev.retain(|pid, _| procs.iter().any(|p| p.pid == *pid));

        cpu_deltas.sort_by_key(|x| std::cmp::Reverse(x.2));
        for (i, (pid, comm, delta)) in cpu_deltas.iter().take(self.top_n).enumerate() {
            metrics.push(Metric {
                labels: vec![
                    MetricLabel {
                        name: "__name__".into(),
                        value: format!("{prefix}_cpu_ticks_delta"),
                    },
                    MetricLabel {
                        name: "pid".into(),
                        value: pid.to_string(),
                    },
                    MetricLabel {
                        name: "comm".into(),
                        value: comm.clone(),
                    },
                    MetricLabel {
                        name: "rank".into(),
                        value: (i + 1).to_string(),
                    },
                ],
                sample: MetricSample {
                    value: *delta as f64,
                    timestamp_ms: 0,
                },
            });
        }

        let mut mem_sorted: Vec<_> = procs.iter().collect();
        mem_sorted.sort_by_key(|x| std::cmp::Reverse(x.rss_pages));
        for (i, p) in mem_sorted.iter().take(self.top_n).enumerate() {
            metrics.push(Metric {
                labels: vec![
                    MetricLabel {
                        name: "__name__".into(),
                        value: format!("{prefix}_resident_bytes"),
                    },
                    MetricLabel {
                        name: "pid".into(),
                        value: p.pid.to_string(),
                    },
                    MetricLabel {
                        name: "comm".into(),
                        value: p.comm.clone(),
                    },
                    MetricLabel {
                        name: "rank".into(),
                        value: (i + 1).to_string(),
                    },
                ],
                sample: MetricSample {
                    value: (p.rss_pages * page_size) as f64,
                    timestamp_ms: 0,
                },
            });
        }

        metrics.push(Metric {
            labels: vec![MetricLabel {
                name: "__name__".into(),
                value: format!("{prefix}_zombies_count"),
            }],
            sample: MetricSample {
                value: zombies as f64,
                timestamp_ms: 0,
            },
        });

        metrics
    }
}

impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "process"
    }

    fn default_interval(&self) -> Duration {
        Duration::from_secs(120)
    }

    fn enabled(&self, config: &CollectorsConfig) -> bool {
        config.process.enabled
    }

    fn collect(&self) -> Vec<Metric> {
        let procs = Self::read_proc();
        self.metrics_from_procs(&procs, "vespid_monitor_process")
    }
}
