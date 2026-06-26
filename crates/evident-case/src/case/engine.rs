use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::audit::hash::{CaseChainLinker, ChainLinker};
use crate::audit::writer::GlobalAuditWriter;
use crate::case::chain::CaseChain;
use crate::case::manifest::{Manifest, ManifestStatus};
use crate::crypto::signer::{load_signature, save_signature, sign_manifest, verify_manifest_signature};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaseVerifyStatus {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseVerifyResult {
    pub case_id: String,
    pub status: CaseVerifyStatus,
    pub failed_at: Option<usize>,
    pub reason: Option<String>,
}

pub struct CaseEngine {
    root: PathBuf,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl CaseEngine {
    pub fn new(root: impl AsRef<Path>, signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            root: root.as_ref().to_path_buf(),
            signing_key,
            verifying_key,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn create_case(&self, case_id: &str) -> Result<PathBuf> {
        let case_dir = self.case_dir(case_id);
        if case_dir.exists() {
            return Err(anyhow!("case already exists: {case_id}"));
        }

        fs::create_dir_all(case_dir.join("evidence"))?;

        let _chain = CaseChain::open(&case_dir, case_id)?;
        let manifest = Manifest::new(case_id);
        manifest.save(&case_dir.join("manifest.json"))?;

        let sig = sign_manifest(&manifest, &self.signing_key)?;
        save_signature(&case_dir.join("signature.sig"), &sig)?;

        GlobalAuditWriter::new(&self.root).append(&json!({
            "action": "case_create",
            "case_id": case_id,
            "ts": chrono::Utc::now().to_rfc3339(),
        }))?;

        Ok(case_dir)
    }

    pub fn append_event(
        &self,
        case_id: &str,
        event_type: &str,
        data: serde_json::Value,
    ) -> Result<()> {
        let case_dir = self.case_dir(case_id);
        if !case_dir.exists() {
            return Err(anyhow!("case not found: {case_id}"));
        }

        let mut chain = CaseChain::open(&case_dir, case_id)?;
        chain.append_event(event_type, data.clone())?;

        let manifest = self.build_manifest(&chain, &case_dir)?;
        manifest.save(&case_dir.join("manifest.json"))?;

        let sig = sign_manifest(&manifest, &self.signing_key)?;
        save_signature(&case_dir.join("signature.sig"), &sig)?;

        GlobalAuditWriter::new(&self.root).append(&json!({
            "action": "case_append",
            "case_id": case_id,
            "event_type": event_type,
            "ts": chrono::Utc::now().to_rfc3339(),
        }))?;

        Ok(())
    }

    pub fn verify_case(&self, case_id: &str) -> Result<CaseVerifyResult> {
        let case_dir = self.case_dir(case_id);
        if !case_dir.exists() {
            return Ok(CaseVerifyResult {
                case_id: case_id.to_string(),
                status: CaseVerifyStatus::Invalid,
                failed_at: None,
                reason: Some("case not found".to_string()),
            });
        }

        let chain = CaseChain::open(&case_dir, case_id)?;
        let (chain_ok, failed_at) = chain.verify_chain()?;
        if !chain_ok {
            return Ok(CaseVerifyResult {
                case_id: case_id.to_string(),
                status: CaseVerifyStatus::Invalid,
                failed_at,
                reason: Some("hash chain verification failed".to_string()),
            });
        }

        let events = chain.event_count()?;
        if events > 0 {
            let all = read_chain_events(chain.chain_path())?;
            if all[0].prev_hash != CaseChainLinker::genesis_hash() {
                return Ok(CaseVerifyResult {
                    case_id: case_id.to_string(),
                    status: CaseVerifyStatus::Invalid,
                    failed_at: Some(0),
                    reason: Some("genesis rule violated".to_string()),
                });
            }
        }

        let manifest_path = case_dir.join("manifest.json");
        let manifest = Manifest::load(&manifest_path)?;
        let expected = self.build_manifest(&chain, &case_dir)?;

        if manifest.root_hash != expected.root_hash
            || manifest.last_hash != expected.last_hash
            || manifest.event_count != expected.event_count
        {
            return Ok(CaseVerifyResult {
                case_id: case_id.to_string(),
                status: CaseVerifyStatus::Invalid,
                failed_at: None,
                reason: Some("manifest inconsistent with chain".to_string()),
            });
        }

        let sig_path = case_dir.join("signature.sig");
        let sig_bytes = load_signature(&sig_path)?;
        if !verify_manifest_signature(&manifest, &sig_bytes, &self.verifying_key) {
            return Ok(CaseVerifyResult {
                case_id: case_id.to_string(),
                status: CaseVerifyStatus::Invalid,
                failed_at: None,
                reason: Some("manifest signature invalid".to_string()),
            });
        }

        Ok(CaseVerifyResult {
            case_id: case_id.to_string(),
            status: CaseVerifyStatus::Valid,
            failed_at: None,
            reason: None,
        })
    }

    fn case_dir(&self, case_id: &str) -> PathBuf {
        self.root.join("cases").join(case_id)
    }

    fn build_manifest(&self, chain: &CaseChain, case_dir: &Path) -> Result<Manifest> {
        let manifest_path = case_dir.join("manifest.json");
        let created_at = if manifest_path.exists() {
            Manifest::load(&manifest_path)?.created_at
        } else {
            chrono::Utc::now()
        };

        let event_count = chain.event_count()? as u64;
        let root_hash = chain.root_hash()?;
        Ok(Manifest {
            case_id: chain.case_id.clone(),
            root_hash,
            last_hash: chain.last_hash.clone(),
            status: ManifestStatus::Valid,
            event_count,
            created_at,
        })
    }
}

fn read_chain_events(path: &Path) -> Result<Vec<crate::case::chain::CaseEvent>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        events.push(serde_json::from_str(trimmed)?);
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_engine() -> (tempfile::TempDir, CaseEngine) {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let engine = CaseEngine::new(dir.path(), key);
        (dir, engine)
    }

    #[test]
    fn create_append_and_verify_case() {
        let (_dir, engine) = test_engine();
        engine.create_case("case-a").unwrap();

        for i in 0..5 {
            engine
                .append_event("case-a", "document_added", json!({ "doc": i }))
                .unwrap();
        }

        let result = engine.verify_case("case-a").unwrap();
        assert_eq!(result.status, CaseVerifyStatus::Valid);
        assert!(result.failed_at.is_none());
    }

    #[test]
    fn tampered_event_marks_case_invalid() {
        let (dir, engine) = test_engine();
        engine.create_case("case-b").unwrap();
        engine
            .append_event("case-b", "note", json!({ "n": 1 }))
            .unwrap();

        let chain_path = dir.path().join("cases/case-b/chain.jsonl");
        let content = fs::read_to_string(&chain_path).unwrap();
        let tampered = content.replace("\"n\":1", "\"n\":999");
        fs::write(&chain_path, tampered).unwrap();

        let result = engine.verify_case("case-b").unwrap();
        assert_eq!(result.status, CaseVerifyStatus::Invalid);
    }

    #[test]
    fn cases_are_isolated() {
        let (_dir, engine) = test_engine();
        engine.create_case("good").unwrap();
        engine.create_case("bad").unwrap();

        engine
            .append_event("good", "evt", json!({ "ok": true }))
            .unwrap();
        engine
            .append_event("bad", "evt", json!({ "ok": true }))
            .unwrap();

        let chain_path = engine.root().join("cases/bad/chain.jsonl");
        let content = fs::read_to_string(&chain_path).unwrap();
        fs::write(&chain_path, content.replace("true", "false")).unwrap();

        assert_eq!(
            engine.verify_case("bad").unwrap().status,
            CaseVerifyStatus::Invalid
        );
        assert_eq!(
            engine.verify_case("good").unwrap().status,
            CaseVerifyStatus::Valid
        );
    }
}
