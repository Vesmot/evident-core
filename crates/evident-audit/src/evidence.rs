use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct EvidencePack {
    pub version: String,
    pub file_name: String,
    pub file_hash: String,
    pub sealed_at: String,
    pub sealed_at_unix: i64,
    pub signer: SignerInfo,
    pub tsa: TsaInfo,
    pub audit: AuditRef,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignerInfo {
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TsaInfo {
    pub status: String,
    pub provider: Option<String>,
    pub tsr_b64: Option<String>,
    pub verified_time: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditRef {
    pub seq: u64,
    pub chain_hash: String,
}

impl EvidencePack {
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let json = fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        let pack: Self = serde_json::from_str(&json)
            .with_context(|| format!("parse evidence pack {}", path.display()))?;
        if pack.version != "1" {
            anyhow::bail!("unsupported evidence pack version: {}", pack.version);
        }
        Ok(pack)
    }
}
