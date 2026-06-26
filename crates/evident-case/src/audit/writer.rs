use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;

/// Non-crypto global event journal. Does not participate in case hash validation.
pub struct GlobalAuditWriter {
    path: PathBuf,
}

impl GlobalAuditWriter {
    pub fn new(root: &Path) -> Self {
        Self {
            path: root.join("audit.jsonl"),
        }
    }

    pub fn append(&self, event: &Value) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let line = serde_json::to_string(event)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("open {}", self.path.display()))?;
        writeln!(file, "{line}")?;
        file.sync_all()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
