use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::audit::hash::{canonical_json_bytes, CaseChainLinker, ChainLinker};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub data: Value,
    pub prev_hash: String,
    pub current_hash: String,
}

#[derive(Debug, Clone)]
pub struct CaseChain {
    pub case_id: String,
    pub last_hash: String,
    chain_path: PathBuf,
}

impl CaseChain {
    pub fn open(case_dir: &Path, case_id: &str) -> Result<Self> {
        fs::create_dir_all(case_dir.join("evidence"))?;
        let chain_path = case_dir.join("chain.jsonl");
        let last_hash = read_last_hash(&chain_path)?;
        Ok(Self {
            case_id: case_id.to_string(),
            last_hash,
            chain_path,
        })
    }

    pub fn append_event(&mut self, event_type: &str, data: Value) -> Result<CaseEvent> {
        let data_bytes = canonical_json_bytes(&data)?;
        let prev_hash = self.last_hash.clone();
        let current_hash = CaseChainLinker::compute_hash(&data_bytes, &prev_hash);

        let event = CaseEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            data,
            prev_hash,
            current_hash: current_hash.clone(),
        };

        append_event_line(&self.chain_path, &event)?;
        self.last_hash = current_hash;
        Ok(event)
    }

    pub fn verify_chain(&self) -> Result<(bool, Option<usize>)> {
        if !self.chain_path.exists() {
            return Ok((true, None));
        }

        let file = File::open(&self.chain_path)
            .with_context(|| format!("open {}", self.chain_path.display()))?;
        let reader = BufReader::new(file);

        let mut expected_prev = CaseChainLinker::genesis_hash();
        let mut index = 0usize;

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let event: CaseEvent = serde_json::from_str(trimmed)
                .map_err(|e| anyhow!("invalid chain event JSON: {e}"))?;

            if event.prev_hash != expected_prev {
                return Ok((false, Some(index)));
            }

            let data_bytes = canonical_json_bytes(&event.data)?;
            if !CaseChainLinker::verify(&event.prev_hash, &event.current_hash, &data_bytes) {
                return Ok((false, Some(index)));
            }

            expected_prev = event.current_hash.clone();
            index += 1;
        }

        Ok((true, None))
    }

    pub fn event_count(&self) -> Result<usize> {
        Ok(read_all_events(&self.chain_path)?.len())
    }

    pub fn root_hash(&self) -> Result<String> {
        let events = read_all_events(&self.chain_path)?;
        if let Some(first) = events.first() {
            Ok(first.current_hash.clone())
        } else {
            Ok(CaseChainLinker::genesis_hash())
        }
    }

    pub fn chain_path(&self) -> &Path {
        &self.chain_path
    }
}

fn read_last_hash(path: &Path) -> Result<String> {
    let events = read_all_events(path)?;
    if let Some(last) = events.last() {
        Ok(last.current_hash.clone())
    } else {
        Ok(CaseChainLinker::genesis_hash())
    }
}

fn read_all_events(path: &Path) -> Result<Vec<CaseEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event: CaseEvent = serde_json::from_str(trimmed)?;
        events.push(event);
    }

    Ok(events)
}

fn append_event_line(path: &Path, event: &CaseEvent) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("chain path has no parent"))?;
    fs::create_dir_all(parent)?;

    let lock_path = parent.join(format!("{}.chain.lock", path.file_name().unwrap_or_default().to_string_lossy()));
    let lock_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("open lock {}", lock_path.display()))?;
    lock_file
        .try_lock_exclusive()
        .map_err(|_| anyhow!("chain locked by another process"))?;

    let line = serde_json::to_string(event)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    writeln!(file, "{line}")?;
    file.sync_all()?;
    Ok(())
}
