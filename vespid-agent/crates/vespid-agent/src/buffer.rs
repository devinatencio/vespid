use anyhow::Context;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

pub struct BufferManager {
    dir: PathBuf,
    max_total_size: u64,
    max_file_size: u64,
    current_file_index: u64,
}

#[allow(dead_code)]
impl BufferManager {
    pub fn new(dir: PathBuf, max_total_size: u64, max_file_size: u64) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create buffer directory: {}", dir.display()))?;

        let mut mgr = Self {
            dir,
            max_total_size,
            max_file_size,
            current_file_index: 0,
        };
        mgr.find_current_index();
        Ok(mgr)
    }

    fn find_current_index(&mut self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };

        let mut max_idx: u64 = 0;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(rest) = name
                .strip_prefix("buffer_")
                .and_then(|s| s.strip_suffix(".jsonl"))
                && let Ok(idx) = rest.parse::<u64>()
            {
                max_idx = max_idx.max(idx + 1);
            }
        }
        self.current_file_index = max_idx;
    }

    pub fn write(&mut self, metrics_json: &str) -> anyhow::Result<()> {
        let path = self.current_file_path();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("Failed to open buffer file: {}", path.display()))?;

        writeln!(file, "{metrics_json}")
            .with_context(|| format!("Failed to write buffer entry: {}", path.display()))?;

        file.sync_all()?;

        if let Ok(meta) = std::fs::metadata(&path)
            && meta.len() >= self.max_file_size
        {
            self.current_file_index += 1;
        }

        self.enforce_total_size()?;
        Ok(())
    }

    pub fn read_all(&self) -> anyhow::Result<Vec<String>> {
        let mut entries = Vec::new();
        let Ok(dir_entries) = std::fs::read_dir(&self.dir) else {
            return Ok(entries);
        };

        let mut files: Vec<_> = dir_entries.flatten().collect();
        files.sort_by_key(|f| f.file_name());

        for entry in files {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("buffer_") || !name.ends_with(".jsonl") {
                continue;
            }

            let file = match std::fs::File::open(entry.path()) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                if !line.trim().is_empty() {
                    entries.push(line);
                }
            }
        }

        Ok(entries)
    }

    pub fn clear(&self) -> anyhow::Result<()> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Ok(());
        };

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("buffer_") && name.ends_with(".jsonl") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(())
    }

    fn current_file_path(&self) -> PathBuf {
        self.dir
            .join(format!("buffer_{:06}.jsonl", self.current_file_index))
    }

    fn enforce_total_size(&self) -> anyhow::Result<()> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Ok(());
        };

        let mut files: Vec<_> = entries.flatten().collect();
        files.sort_by_key(|f| f.file_name());

        let mut total: u64 = 0;
        let mut sizes: Vec<(PathBuf, u64)> = Vec::new();

        for entry in &files {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("buffer_") || !name.ends_with(".jsonl") {
                continue;
            }
            if let Ok(meta) = std::fs::metadata(entry.path()) {
                total += meta.len();
                sizes.push((entry.path(), meta.len()));
            }
        }

        while total > self.max_total_size {
            if let Some((path, size)) = sizes.first() {
                tracing::warn!(
                    "Buffer total size ({}MB) exceeds limit ({}MB), removing oldest file",
                    total / (1024 * 1024),
                    self.max_total_size / (1024 * 1024)
                );
                let _ = std::fs::remove_file(path);
                total = total.saturating_sub(*size);
                sizes.remove(0);
            } else {
                break;
            }
        }

        Ok(())
    }
}
