use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::audit::hash::{canonical_json_bytes, CaseChainLinker, ChainLinker};

pub const STATUS_VALID: &str = "VALID";
pub const STATUS_INVALID: &str = "INVALID";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub case_id: String,
    pub root_hash: String,
    pub last_hash: String,
    pub event_count: u64,
    pub status: String,
}

impl Manifest {
    pub fn genesis(case_id: &str) -> Self {
        let genesis = CaseChainLinker::genesis_hash();
        Self {
            case_id: case_id.to_string(),
            root_hash: genesis.clone(),
            last_hash: genesis,
            event_count: 0,
            status: STATUS_VALID.to_string(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        canonical_json_bytes(&value)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json).with_context(|| format!("write manifest {}", path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let json = fs::read_to_string(path)
            .with_context(|| format!("read manifest {}", path.display()))?;
        let manifest: Self = serde_json::from_str(&json)
            .with_context(|| format!("parse manifest {}", path.display()))?;
        Ok(manifest)
    }
}
