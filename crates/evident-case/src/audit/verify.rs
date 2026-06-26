use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};

/// Structural check only: each line must be valid JSON. No cryptographic validation.
pub fn verify_global_audit_readable(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        serde_json::from_str::<serde_json::Value>(trimmed)
            .map_err(|e| anyhow::anyhow!("invalid JSON at line {}: {e}", idx + 1))?;
    }

    Ok(())
}
