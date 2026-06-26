use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GitInfo {
    pub commit: String,
    pub branch: String,
    pub tag: Option<String>,
    pub dirty: bool,
    pub repo: Option<String>,
    pub ci: Option<CiInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CiInfo {
    pub provider: String,
    pub run_id: Option<String>,
    pub workflow: Option<String>,
}

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
    #[serde(default)]
    pub git: Option<GitInfo>,
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

#[cfg(test)]
mod tests {
    use super::EvidencePack;

    #[test]
    fn deserializes_without_git_field() {
        let json = r#"{
            "version": "1",
            "file_name": "test.txt",
            "file_hash": "abc",
            "sealed_at": "2026-06-26T10:00:00Z",
            "sealed_at_unix": 1782477600,
            "signer": { "public_key": "00", "signature": "00" },
            "tsa": { "status": "skipped" },
            "audit": { "seq": 1, "chain_hash": "00" }
        }"#;

        let pack: EvidencePack = serde_json::from_str(json).expect("parse legacy pack");
        assert!(pack.git.is_none());
    }
}
