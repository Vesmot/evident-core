use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const ENGINE_VERSION: &str = "1";
pub const HASH_SCHEMA: &str = "case-hash-v1";
pub const CANONICAL_JSON: &str = "sorted-keys-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseMeta {
    pub case_id: String,
    pub engine_version: String,
    pub hash_schema: String,
    pub canonical_json: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CaseMeta {
    pub fn new(case_id: &str) -> Self {
        let now = Utc::now();
        Self {
            case_id: case_id.to_string(),
            engine_version: ENGINE_VERSION.to_string(),
            hash_schema: HASH_SCHEMA.to_string(),
            canonical_json: CANONICAL_JSON.to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json).with_context(|| format!("write meta {}", path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let json = fs::read_to_string(path)
            .with_context(|| format!("read meta {}", path.display()))?;
        let meta: Self = serde_json::from_str(&json)
            .with_context(|| format!("parse meta {}", path.display()))?;
        Ok(meta)
    }
}
