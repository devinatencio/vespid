use crate::collectors::Collector;
use crate::config::CollectorsConfig;
use std::collections::HashMap;
use std::time::Duration;
use vespid_agent_common::{Metric, MetricLabel, MetricSample};

pub struct DiskCollector {
    exclude_mounts: Vec<String>,
}

impl DiskCollector {
    pub fn new(config: &CollectorsConfig) -> Self {
        Self {
            exclude_mounts: config.disk.exclude_mounts.clone(),
        }
    }

    fn should_exclude(&self, mountpoint: &str, fstype: &str) -> bool {
        let always_exclude = [
            "tmpfs",
            "devtmpfs",
            "devfs",
            "cgroup",
            "cgroup2",
            "proc",
            "sysfs",
            "securityfs",
            "debugfs",
            "tracefs",
            "fusectl",
            "configfs",
            "pstore",
            "bpf",
            "hugetlbfs",
            "mqueue",
            "ramfs",
            "overlay",
            "squashfs",
        ];

        if always_exclude.contains(&fstype) {
            return true;
        }

        for pattern in &self.exclude_mounts {
            if let Some(prefix) = pattern.strip_suffix('*') {
                if mountpoint.starts_with(prefix) {
                    return true;
                }
            } else if mountpoint == *pattern {
                return true;
            }
        }

        false
    }

    fn read_mounts_and_usage(&self) -> Vec<MountInfo> {
        let mut mounts = Vec::new();
        let content = match std::fs::read_to_string("/proc/self/mountinfo") {
            Ok(c) => c,
            Err(_) => return mounts,
        };

        let mut seen_devices = std::collections::HashSet::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            let dev_id = parts[2];
            let (major_str, _) = match dev_id.split_once(':') {
                Some(pair) => pair,
                None => continue,
            };
            let major: u32 = match major_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Skip virtual filesystems (major == 0)
            if major == 0 {
                continue;
            }

            // Field 4 is mountpoint
            let mountpoint = parts[4].to_string();

            // Find the `-` separator to get fstype and source
            let sep_pos = match parts.iter().position(|&s| s == "-") {
                Some(p) => p,
                None => continue,
            };

            if sep_pos + 3 >= parts.len() {
                continue;
            }

            let fstype = parts[sep_pos + 1].to_string();
            let device = parts[sep_pos + 2].to_string();

            if self.should_exclude(&mountpoint, &fstype) {
                continue;
            }

            // Deduplicate by device ID (major:minor)
            if !seen_devices.insert(dev_id.to_string()) {
                continue;
            }

            mounts.push(MountInfo {
                device,
                mountpoint,
                fstype,
            });
        }

        mounts
    }

    fn read_diskstats() -> Option<HashMap<String, DiskIoStat>> {
        let content = std::fs::read_to_string("/proc/diskstats").ok()?;
        let mut map = HashMap::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 14 {
                continue;
            }

            let device = parts[2].to_string();
            let read_complete: u64 = parts[3].parse().ok()?;
            let read_sectors: u64 = parts[5].parse().ok()?;
            let write_complete: u64 = parts[7].parse().ok()?;
            let write_sectors: u64 = parts[9].parse().ok()?;
            let io_ms: u64 = parts[12].parse().ok()?;

            map.insert(
                device,
                DiskIoStat {
                    read_bytes: read_sectors * 512,
                    write_bytes: write_sectors * 512,
                    read_ops: read_complete,
                    write_ops: write_complete,
                    io_time_ms: io_ms,
                },
            );
        }

        Some(map)
    }
}

impl Collector for DiskCollector {
    fn name(&self) -> &'static str {
        "disk"
    }

    fn default_interval(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn enabled(&self, config: &CollectorsConfig) -> bool {
        config.disk.enabled
    }

    fn collect(&self) -> Vec<Metric> {
        let mut metrics = Vec::new();
        let prefix = "vespid_monitor_disk";

        for mount in self.read_mounts_and_usage() {
            let Ok(mpath) = std::ffi::CString::new(mount.mountpoint.as_bytes()) else {
                continue;
            };

            unsafe {
                let mut stat: libc::statvfs = std::mem::zeroed();
                if libc::statvfs(mpath.as_ptr(), &mut stat) != 0 {
                    continue;
                }

                #[allow(clippy::useless_conversion)]
                let total = u64::from(stat.f_blocks) * stat.f_frsize;
                #[allow(clippy::useless_conversion)]
                let available = u64::from(stat.f_bavail) * stat.f_frsize;
                #[allow(clippy::useless_conversion)]
                let used = total.saturating_sub(u64::from(stat.f_bfree) * stat.f_frsize);
                let used_percent = if total > 0 {
                    (used as f64 / total as f64) * 100.0
                } else {
                    0.0
                };

                let inodes_total = stat.f_files;
                let inodes_free = stat.f_ffree;
                let inodes_used = inodes_total.saturating_sub(inodes_free);
                let inodes_used_percent = if inodes_total > 0 {
                    (inodes_used as f64 / inodes_total as f64) * 100.0
                } else {
                    0.0
                };

                let _labels = [
                    MetricLabel {
                        name: "device".into(),
                        value: mount.device.clone(),
                    },
                    MetricLabel {
                        name: "mountpoint".into(),
                        value: mount.mountpoint.clone(),
                    },
                    MetricLabel {
                        name: "fstype".into(),
                        value: mount.fstype.clone(),
                    },
                ];

                metrics.push(Metric {
                    labels: vec![
                        MetricLabel {
                            name: "__name__".into(),
                            value: format!("{prefix}_total_bytes"),
                        },
                        MetricLabel {
                            name: "device".into(),
                            value: mount.device.clone(),
                        },
                        MetricLabel {
                            name: "mountpoint".into(),
                            value: mount.mountpoint.clone(),
                        },
                        MetricLabel {
                            name: "fstype".into(),
                            value: mount.fstype.clone(),
                        },
                    ],
                    sample: MetricSample {
                        value: total as f64,
                        timestamp_ms: 0,
                    },
                });

                metrics.push(Metric {
                    labels: vec![
                        MetricLabel {
                            name: "__name__".into(),
                            value: format!("{prefix}_used_bytes"),
                        },
                        MetricLabel {
                            name: "device".into(),
                            value: mount.device.clone(),
                        },
                        MetricLabel {
                            name: "mountpoint".into(),
                            value: mount.mountpoint.clone(),
                        },
                        MetricLabel {
                            name: "fstype".into(),
                            value: mount.fstype.clone(),
                        },
                    ],
                    sample: MetricSample {
                        value: used as f64,
                        timestamp_ms: 0,
                    },
                });

                metrics.push(Metric {
                    labels: vec![
                        MetricLabel {
                            name: "__name__".into(),
                            value: format!("{prefix}_available_bytes"),
                        },
                        MetricLabel {
                            name: "device".into(),
                            value: mount.device.clone(),
                        },
                        MetricLabel {
                            name: "mountpoint".into(),
                            value: mount.mountpoint.clone(),
                        },
                        MetricLabel {
                            name: "fstype".into(),
                            value: mount.fstype.clone(),
                        },
                    ],
                    sample: MetricSample {
                        value: available as f64,
                        timestamp_ms: 0,
                    },
                });

                metrics.push(Metric {
                    labels: vec![
                        MetricLabel {
                            name: "__name__".into(),
                            value: format!("{prefix}_used_percent"),
                        },
                        MetricLabel {
                            name: "device".into(),
                            value: mount.device.clone(),
                        },
                        MetricLabel {
                            name: "mountpoint".into(),
                            value: mount.mountpoint.clone(),
                        },
                        MetricLabel {
                            name: "fstype".into(),
                            value: mount.fstype.clone(),
                        },
                    ],
                    sample: MetricSample {
                        value: used_percent,
                        timestamp_ms: 0,
                    },
                });

                metrics.push(Metric {
                    labels: vec![
                        MetricLabel {
                            name: "__name__".into(),
                            value: format!("{prefix}_inodes_used_percent"),
                        },
                        MetricLabel {
                            name: "device".into(),
                            value: mount.device,
                        },
                        MetricLabel {
                            name: "mountpoint".into(),
                            value: mount.mountpoint,
                        },
                        MetricLabel {
                            name: "fstype".into(),
                            value: mount.fstype,
                        },
                    ],
                    sample: MetricSample {
                        value: inodes_used_percent,
                        timestamp_ms: 0,
                    },
                });
            }
        }

        if let Some(diskstats) = Self::read_diskstats() {
            for (device, stat) in diskstats {
                metrics.push(Metric {
                    labels: vec![
                        MetricLabel {
                            name: "__name__".into(),
                            value: format!("{prefix}_read_bytes_total"),
                        },
                        MetricLabel {
                            name: "device".into(),
                            value: device.clone(),
                        },
                    ],
                    sample: MetricSample {
                        value: stat.read_bytes as f64,
                        timestamp_ms: 0,
                    },
                });
                metrics.push(Metric {
                    labels: vec![
                        MetricLabel {
                            name: "__name__".into(),
                            value: format!("{prefix}_write_bytes_total"),
                        },
                        MetricLabel {
                            name: "device".into(),
                            value: device.clone(),
                        },
                    ],
                    sample: MetricSample {
                        value: stat.write_bytes as f64,
                        timestamp_ms: 0,
                    },
                });
                metrics.push(Metric {
                    labels: vec![
                        MetricLabel {
                            name: "__name__".into(),
                            value: format!("{prefix}_read_ops_total"),
                        },
                        MetricLabel {
                            name: "device".into(),
                            value: device.clone(),
                        },
                    ],
                    sample: MetricSample {
                        value: stat.read_ops as f64,
                        timestamp_ms: 0,
                    },
                });
                metrics.push(Metric {
                    labels: vec![
                        MetricLabel {
                            name: "__name__".into(),
                            value: format!("{prefix}_write_ops_total"),
                        },
                        MetricLabel {
                            name: "device".into(),
                            value: device.clone(),
                        },
                    ],
                    sample: MetricSample {
                        value: stat.write_ops as f64,
                        timestamp_ms: 0,
                    },
                });
                metrics.push(Metric {
                    labels: vec![
                        MetricLabel {
                            name: "__name__".into(),
                            value: format!("{prefix}_io_time_ms_total"),
                        },
                        MetricLabel {
                            name: "device".into(),
                            value: device,
                        },
                    ],
                    sample: MetricSample {
                        value: stat.io_time_ms as f64,
                        timestamp_ms: 0,
                    },
                });
            }
        }

        metrics
    }
}

#[derive(Debug)]
struct MountInfo {
    device: String,
    mountpoint: String,
    fstype: String,
}

#[derive(Debug)]
struct DiskIoStat {
    read_bytes: u64,
    write_bytes: u64,
    read_ops: u64,
    write_ops: u64,
    io_time_ms: u64,
}
