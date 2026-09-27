use vespid_agent::collectors::cpu::CpuCollector;
use vespid_agent::collectors::memory::MemoryCollector;
use vespid_agent::collectors::network::NetworkCollector;
use vespid_agent::collectors::swap::SwapCollector;

macro_rules! fixture {
    ($name:expr) => {
        include_str!(concat!("fixtures/", $name))
    };
}

#[test]
fn cpu_parse_real_stats() {
    let content = fixture!("proc_stat");
    let stats = CpuCollector::parse(content);
    assert!(!stats.is_empty(), "should parse at least one CPU core");

    let cpu0 = stats
        .iter()
        .find(|s| s.cpu == "cpu0")
        .expect("should have cpu0");
    assert!(cpu0.idle > 0, "cpu0 should have idle time");
    assert!(cpu0.user > 0);
    assert!(cpu0.system > 0);

    for s in &stats {
        assert_ne!(s.cpu, "cpu", "should skip aggregate cpu line");
    }

    let metrics = CpuCollector::metrics_from_stats(&stats);
    assert_eq!(metrics.len(), stats.len() * 5, "5 metrics per core");

    let idle_metric = metrics
        .iter()
        .find(|m| {
            m.labels
                .iter()
                .any(|l| l.name == "__name__" && l.value.contains("idle"))
        })
        .expect("should have idle metric");
    assert!(
        idle_metric.sample.value > 0.0,
        "idle value should be positive"
    );
}

#[test]
fn memory_parse_real_meminfo() {
    let content = fixture!("proc_meminfo");
    let map = MemoryCollector::parse(content);

    assert!(map.contains_key("MemTotal"), "should have MemTotal");
    assert!(map.contains_key("MemAvailable"), "should have MemAvailable");
    assert!(map.contains_key("SwapTotal"), "should have SwapTotal");

    let total_kb = map["MemTotal"];
    assert!(total_kb > 0, "total memory should be > 0");

    let metrics = MemoryCollector::metrics_from_map(&map);
    assert_eq!(metrics.len(), 11, "11 memory metrics");

    let used_pct = metrics
        .iter()
        .find(|m| {
            m.labels
                .iter()
                .any(|l| l.name == "__name__" && l.value.contains("used_percent"))
        })
        .expect("should have used_percent metric");
    assert!(used_pct.sample.value > 0.0);
    assert!(used_pct.sample.value <= 100.0);
}

#[test]
fn memory_used_percent_reasonable() {
    let content = fixture!("proc_meminfo");
    let map = MemoryCollector::parse(content);
    let metrics = MemoryCollector::metrics_from_map(&map);

    let total_bytes = map["MemTotal"] * 1024;
    let used_pct = metrics
        .iter()
        .find(|m| {
            m.labels
                .iter()
                .any(|l| l.name == "__name__" && l.value == "vespid_monitor_memory_used_percent")
        })
        .expect("used_percent missing");
    let used_bytes = metrics
        .iter()
        .find(|m| {
            m.labels
                .iter()
                .any(|l| l.name == "__name__" && l.value == "vespid_monitor_memory_used_bytes")
        })
        .expect("used_bytes missing");

    assert!(used_pct.sample.value > 0.0);
    assert!(used_pct.sample.value < 100.0);
    assert!(used_bytes.sample.value > 0.0);
    assert!(used_bytes.sample.value < total_bytes as f64);
}

#[test]
fn network_parse_real_dev() {
    let content = fixture!("proc_net_dev");
    let stats = NetworkCollector::parse(content, 1000);
    assert!(!stats.is_empty(), "should have at least one interface");

    let lo = stats
        .iter()
        .find(|s| s.iface == "lo")
        .expect("should have loopback");
    assert!(lo.bytes_recv > 0, "loopback should have receive traffic");
    assert!(lo.bytes_sent > 0, "loopback should have send traffic");

    let metrics = NetworkCollector::metrics_from_stats(&stats, &["lo".into()]);
    assert!(
        !metrics.is_empty(),
        "should have metrics after excluding lo"
    );

    for m in &metrics {
        let has_interface = m
            .labels
            .iter()
            .any(|l| l.name == "interface" && l.value != "lo");
        assert!(
            has_interface,
            "should have non-lo interface label: {:?}",
            m.labels
        );
    }
}

#[test]
fn cpu_no_aggregate_line() {
    let content = fixture!("proc_stat");
    let stats = CpuCollector::parse(content);

    let has_aggregate = stats.iter().any(|s| s.cpu == "cpu");
    assert!(!has_aggregate, "aggregate 'cpu' line must be excluded");
}

#[test]
fn memory_swap_handling() {
    let content = fixture!("proc_meminfo");
    let map = MemoryCollector::parse(content);
    let metrics = MemoryCollector::metrics_from_map(&map);

    let swap_total = metrics.iter().find(|m| {
        m.labels
            .iter()
            .any(|l| l.name == "__name__" && l.value.contains("swap_total"))
    });
    assert!(swap_total.is_some(), "should have swap_total_bytes metric");

    let swap_used = metrics.iter().find(|m| {
        m.labels
            .iter()
            .any(|l| l.name == "__name__" && l.value.contains("swap_used_percent"))
    });
    assert!(swap_used.is_some(), "should have swap_used_percent metric");
    assert!(swap_used.unwrap().sample.value >= 0.0);
}

#[test]
fn swap_parse_and_metrics() {
    let content = "MemTotal:        7668564 kB\nMemFree:         3220396 kB\nMemAvailable:    6374076 kB\nSwapTotal:       2097152 kB\nSwapFree:        1048576 kB\nSwapCached:       524288 kB\n";
    let map = SwapCollector::parse(content);

    assert!(map.contains_key("SwapTotal"), "should have SwapTotal");
    assert!(map.contains_key("SwapFree"), "should have SwapFree");
    assert!(map.contains_key("SwapCached"), "should have SwapCached");

    let metrics = SwapCollector::metrics_from_map(&map);
    assert_eq!(metrics.len(), 5, "5 swap metrics");

    let total = metrics
        .iter()
        .find(|m| {
            m.labels
                .iter()
                .any(|l| l.name == "__name__" && l.value.contains("swap_total"))
        })
        .expect("should have swap_total_bytes");
    assert!(total.sample.value > 0.0, "swap total should be positive");

    let used_pct = metrics
        .iter()
        .find(|m| {
            m.labels
                .iter()
                .any(|l| l.name == "__name__" && l.value.contains("swap_used_percent"))
        })
        .expect("should have swap_used_percent metric");
    assert!(used_pct.sample.value >= 0.0);
    assert!(used_pct.sample.value <= 100.0);

    let free = metrics
        .iter()
        .find(|m| {
            m.labels
                .iter()
                .any(|l| l.name == "__name__" && l.value.contains("swap_free_bytes"))
        })
        .expect("should have swap_free_bytes");
    assert!(free.sample.value > 0.0, "swap free should be positive");

    let cached = metrics
        .iter()
        .find(|m| {
            m.labels
                .iter()
                .any(|l| l.name == "__name__" && l.value.contains("swap_cached_bytes"))
        })
        .expect("should have swap_cached_bytes");
    assert!(cached.sample.value > 0.0, "swap cached should be positive");

    let used = metrics
        .iter()
        .find(|m| {
            m.labels
                .iter()
                .any(|l| l.name == "__name__" && l.value == "vespid_monitor_swap_used_bytes")
        })
        .expect("should have swap_used_bytes");
    assert_eq!(
        used.sample.value,
        (2097152u64 - 1048576 - 524288) as f64 * 1024.0,
        "swap_used = total - free - cached (in bytes)"
    );
}

#[test]
fn swap_zero_when_no_swap() {
    let content =
        "MemTotal:       100000 kB\nMemFree:         50000 kB\nMemAvailable:    60000 kB\n";
    let map = SwapCollector::parse(content);
    let metrics = SwapCollector::metrics_from_map(&map);

    let total = metrics
        .iter()
        .find(|m| {
            m.labels
                .iter()
                .any(|l| l.name == "__name__" && l.value.contains("swap_total"))
        })
        .expect("should have swap_total_bytes");
    assert_eq!(
        total.sample.value, 0.0,
        "swap total should be 0 when no swap"
    );

    let used_pct = metrics
        .iter()
        .find(|m| {
            m.labels
                .iter()
                .any(|l| l.name == "__name__" && l.value.contains("swap_used_percent"))
        })
        .expect("should have swap_used_percent");
    assert_eq!(
        used_pct.sample.value, 0.0,
        "swap used percent should be 0 when no swap"
    );
}
