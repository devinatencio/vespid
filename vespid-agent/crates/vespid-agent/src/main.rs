use clap::Parser;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use vespid_agent::config;
use vespid_agent::runtime;
use vespid_agent::worker;
#[derive(Parser)]
#[command(name = "vespid-agent")]
#[command(about = "Vespid Monitor system metrics collection agent")]
struct Cli {
    #[arg(short, long, default_value = "system")]
    mode: String,

    #[arg(short, long, default_value = "/etc/vespid-agent/agent.yaml")]
    config: PathBuf,

    #[arg(long, default_value = "info")]
    log_level: String,

    #[arg(long, default_value = "/var/log/vespid-agent/agent.log")]
    log_file: PathBuf,
}

fn setup_logging(level: &str, log_file: &Path, log_retention_days: u64) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("vespid_agent={level}")));

    let use_color = std::io::stdout().is_terminal();

    // Best-effort: make sure the log directory exists. Under the systemd unit
    // this is handled by LogsDirectory=; this covers manual runs.
    let log_dir = log_file.parent().unwrap_or_else(|| Path::new("/var/log"));
    let _ = std::fs::create_dir_all(log_dir);

    let prefix = log_file
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("agent.log"))
        .to_string_lossy()
        .into_owned();

    // Build the rolling file appender without panicking. If the directory is
    // missing or not writable we fall back to stdout/journald instead of
    // aborting the daemon.
    let file_layer = match tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(prefix)
        .build(log_dir)
    {
        Ok(appender) => {
            let (non_blocking, guard) = tracing_appender::non_blocking(appender);
            // Keep the background writer alive for the process lifetime.
            std::mem::forget(guard);
            Some(
                fmt::layer()
                    .with_ansi(false)
                    .with_target(false)
                    .with_writer(non_blocking),
            )
        }
        Err(e) => {
            eprintln!(
                "warning: file logging to {} disabled ({e}); logging to stdout only",
                log_file.display()
            );
            None
        }
    };

    let file_logging_enabled = file_layer.is_some();

    let registry = tracing_subscriber::registry()
        .with(fmt::layer().with_ansi(use_color).with_target(false))
        .with(filter);

    if let Some(layer) = file_layer {
        registry.with(layer).init();
    } else {
        registry.init();
    }

    if file_logging_enabled {
        spawn_log_pruning(log_file, log_retention_days);
    }
}

/// tracing-appender rotates daily (prefix.YYYY-MM-DD) but never prunes old
/// files, so without this the log directory grows forever. A background task
/// removes rotated files older than `log_retention_days` (0 disables pruning).
fn spawn_log_pruning(log_file: &Path, log_retention_days: u64) {
    if log_retention_days == 0 {
        return;
    }

    let dir = log_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/var/log"));
    let prefix = log_file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "agent.log".into());

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 60 * 60));
        loop {
            interval.tick().await;
            prune_old_log_files(&dir, &prefix, log_retention_days);
        }
    });
}

/// Remove daily-rotated files (`prefix.YYYY-MM-DD`) older than `retention_days`.
/// `retention_days == 0` disables pruning.
fn prune_old_log_files(dir: &Path, prefix: &str, retention_days: u64) {
    if retention_days == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let cutoff = chrono::Utc::now().date_naive() - chrono::Duration::days(retention_days as i64);
    let file_prefix = format!("{prefix}.");

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(date_str) = name.strip_prefix(&file_prefix) else {
            continue;
        };
        let Ok(date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") else {
            continue;
        };
        if date < cutoff {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => tracing::debug!("Pruned old log file {}", entry.path().display()),
                Err(e) => tracing::warn!(
                    "Failed to prune old log file {}: {e}",
                    entry.path().display()
                ),
            }
        }
    }
}

fn print_banner(mode: &str) {
    let version = env!("CARGO_PKG_VERSION");
    eprintln!(
        r#"
  _   _ ___  ______   __  __     _      _                    __
 | | | |/ _ \ |  _ \  |  \/  |   / \    | |  _ __  ___  _ __  \ \   / /
 | |_| | | | || |_) | | |\/| |  / _ \   | | | '__|/ _ \| '_ \  \ \ / /
 |  _  | |_| ||  _ <  | |  | | / ___ \  | | | |  |  __/| | | |  \ V /
 |_| |_|\___/ |_| \_\ |_|  |_|_/     \_| |_|_|    \___||_| |_|   \_/
 ─────────────────────────────────────────────────────────────────────
  mode={}  version={}
  ─────────────────────────────────────────────────────────────────────
"#,
        mode, version
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = config::AgentConfig::load(&cli.config)?;

    let log_level = if cli.log_level == "info" && !config.log_level.is_empty() {
        &config.log_level
    } else {
        &cli.log_level
    };
    setup_logging(log_level, &cli.log_file, config.log_retention_days);
    print_banner(&cli.mode);
    tracing::info!("Vespid Agent starting  mode={}", cli.mode);
    tracing::info!("Configuration loaded from {}", cli.config.display());

    let agent_id = runtime::get_or_generate_agent_id(&config).await?;
    tracing::info!("Agent ID: {agent_id}");

    let hostname = config.resolve_hostname();
    tracing::info!("Hostname: {hostname}");

    match cli.mode.as_str() {
        "worker" => {
            let worker = worker::WorkerRuntime::new(config, agent_id, hostname).await?;
            worker.run().await?;
        }
        _ => {
            let running = runtime::Runtime::new(config, agent_id, hostname).await?;
            running.run().await?;
        }
    }

    tracing::info!("Vespid Agent shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("vespid-agent-log-test-{}-{id}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp log dir");
        dir
    }

    fn write_file(dir: &Path, name: &str) {
        fs::write(dir.join(name), "test\n").expect("write log file");
    }

    #[test]
    fn prunes_files_older_than_retention() {
        let dir = test_dir();
        // Derive dates from "now" so the test does not expire over time.
        let today = chrono::Utc::now().date_naive();
        let old_name = format!(
            "agent.log.{}",
            (today - chrono::Duration::days(60)).format("%Y-%m-%d")
        );
        let recent_name = format!(
            "agent.log.{}",
            (today - chrono::Duration::days(5)).format("%Y-%m-%d")
        );
        let unrelated_name = format!(
            "unrelated.log.{}",
            (today - chrono::Duration::days(60)).format("%Y-%m-%d")
        );

        write_file(&dir, "agent.log");
        write_file(&dir, &old_name);
        write_file(&dir, &recent_name);
        write_file(&dir, &unrelated_name);

        prune_old_log_files(&dir, "agent.log", 30);

        assert!(dir.join("agent.log").exists(), "current file kept");
        assert!(!dir.join(&old_name).exists(), "old rotated file pruned");
        assert!(dir.join(&recent_name).exists(), "recent file kept");
        assert!(
            dir.join(&unrelated_name).exists(),
            "unrelated files untouched"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retention_zero_disables_pruning() {
        let dir = test_dir();
        write_file(&dir, "agent.log.2020-01-01");

        prune_old_log_files(&dir, "agent.log", 0);

        assert!(dir.join("agent.log.2020-01-01").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ignores_non_dated_files() {
        let dir = test_dir();
        write_file(&dir, "agent.log.bak");

        prune_old_log_files(&dir, "agent.log", 30);

        assert!(dir.join("agent.log.bak").exists());
        fs::remove_dir_all(&dir).ok();
    }
}
