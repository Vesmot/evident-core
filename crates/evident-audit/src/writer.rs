use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use serde_json::Value;

fn audit_log_path() -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("home directory not found"))?;
    Ok(home.join(".evident").join("audit.jsonl"))
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Единственная точка append-записи в audit chain.
pub struct AuditWriter;

#[derive(Debug)]
pub struct AuditError {
    message: String,
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AuditError {}

impl AuditWriter {
    pub fn append(event: &Value) -> Result<(), AuditError> {
        Self::append_internal(event).map_err(|e| AuditError {
            message: e.to_string(),
        })
    }

    pub fn last_chain_hash() -> String {
        let path = match audit_log_path() {
            Ok(p) => p,
            Err(_) => return GENESIS_HASH.to_string(),
        };
        if !path.exists() {
            return GENESIS_HASH.to_string();
        }

        let file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => return GENESIS_HASH.to_string(),
        };

        let reader = BufReader::new(file);
        let mut last_hash = GENESIS_HASH.to_string();

        for line in reader.lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if let Some(h) = v.get("entry_hash").and_then(|x| x.as_str()) {
                    last_hash = h.to_string();
                } else if let Some(h) = v.get("chain_hash").and_then(|x| x.as_str()) {
                    last_hash = h.to_string();
                } else if let Some(h) = v.get("envelope_hash").and_then(|x| x.as_str()) {
                    last_hash = h.to_string();
                } else if let Some(h) = v.get("hash").and_then(|x| x.as_str()) {
                    last_hash = h.to_string();
                } else if let Some(h) = v.get("event_hash").and_then(|x| x.as_str()) {
                    last_hash = h.to_string();
                }
            }
        }

        last_hash
    }

    fn append_internal(event: &Value) -> anyhow::Result<()> {
        let path = audit_log_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let line = serde_json::to_string(event)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        writeln!(file, "{line}")?;
        file.sync_all()?;
        Ok(())
    }
}

pub fn audit_log_path_buf() -> anyhow::Result<PathBuf> {
    audit_log_path()
}
