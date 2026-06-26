use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use evident_crypto::hash;
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::writer::audit_log_path_buf;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub prev_hash: String,
    pub action: String,
    pub file_hash: String,
    pub ts: String,
    pub entry_hash: String,
}

fn compute_entry_hash(seq: u64, prev_hash: &str, action: &str, file_hash: &str, ts: &str) -> String {
    let input = format!("{seq}:{prev_hash}:{action}:{file_hash}:{ts}");
    hash::sha256_hex(input.as_bytes())
}

fn ensure_evident_dir() -> Result<PathBuf> {
    let path = audit_log_path_buf()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    Ok(path)
}

fn read_last_valid_entry(path: &PathBuf) -> Result<Option<AuditEntry>> {
    if !path.exists() {
        return Ok(None);
    }

    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut last_valid = None;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(trimmed) {
            last_valid = Some(entry);
        }
    }

    Ok(last_valid)
}

fn audit_lock_path(path: &Path) -> PathBuf {
    path.with_extension("lock")
}

fn with_audit_lock<T>(path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let lock_path = audit_lock_path(path);
    let lock_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("open lock {}", lock_path.display()))?;
    lock_file
        .try_lock_exclusive()
        .map_err(|_| anyhow!("audit.jsonl locked by another process"))?;

    f()
}

fn atomic_append_line(path: &Path, line: &str) -> Result<()> {
    with_audit_lock(path, || {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("audit log has no parent directory"))?;
        fs::create_dir_all(parent)?;

        let mut existing = String::new();
        if path.exists() {
            existing = fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
        }

        let temp_path = parent.join(format!(".audit.jsonl.{}.tmp", std::process::id()));

        {
            let mut temp = File::create(&temp_path)
                .with_context(|| format!("create temp {}", temp_path.display()))?;
            if !existing.is_empty() {
                temp.write_all(existing.as_bytes())?;
                if !existing.ends_with('\n') {
                    temp.write_all(b"\n")?;
                }
            }
            writeln!(temp, "{line}")?;
            temp.sync_all()?;
        }

        fs::rename(&temp_path, path).with_context(|| {
            format!(
                "atomic rename {} -> {}",
                temp_path.display(),
                path.display()
            )
        })?;

        Ok(())
    })
}

pub fn append(action: &str, file_hash: &str) -> Result<u64> {
    let path = ensure_evident_dir()?;
    let last = read_last_valid_entry(&path)?;

    let (seq, prev_hash) = match last {
        Some(entry) => (entry.seq + 1, entry.entry_hash),
        None => (1, GENESIS_HASH.to_string()),
    };

    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let entry_hash = compute_entry_hash(seq, &prev_hash, action, file_hash, &ts);

    let entry = AuditEntry {
        seq,
        prev_hash,
        action: action.to_string(),
        file_hash: file_hash.to_string(),
        ts,
        entry_hash: entry_hash.clone(),
    };

    let line = serde_json::to_string(&entry)?;
    atomic_append_line(&path, &line)?;

    Ok(seq)
}

pub fn head_hash() -> Result<String> {
    let path = audit_log_path_buf()?;
    match read_last_valid_entry(&path)? {
        Some(entry) => Ok(entry.entry_hash),
        None => Ok(GENESIS_HASH.to_string()),
    }
}

pub fn verify_chain() -> Result<(bool, Option<u64>)> {
    let path = audit_log_path_buf()?;
    if !path.exists() {
        return Ok((true, None));
    }

    let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut count = 0u64;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let entry: AuditEntry = serde_json::from_str(trimmed)
            .map_err(|e| anyhow!("invalid audit entry JSON: {e}"))?;

        if entry.prev_hash != expected_prev {
            return Ok((false, Some(entry.seq)));
        }

        let recomputed = compute_entry_hash(
            entry.seq,
            &entry.prev_hash,
            &entry.action,
            &entry.file_hash,
            &entry.ts,
        );
        if recomputed != entry.entry_hash {
            return Ok((false, Some(entry.seq)));
        }

        expected_prev = entry.entry_hash.clone();
        count = entry.seq;
    }

    let _ = count;
    Ok((true, None))
}

pub fn read_all_entries() -> Result<Vec<AuditEntry>> {
    let path = audit_log_path_buf()?;
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(trimmed) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

pub fn entry_count() -> Result<u64> {
    let entries = read_all_entries()?;
    Ok(entries.len() as u64)
}
