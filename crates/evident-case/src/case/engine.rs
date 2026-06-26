use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{json, Value};

use crate::audit::verify::{self, CaseVerifyResult};
use crate::audit::writer::GlobalAuditWriter;
use crate::case::chain::CaseChain;
use crate::case::manifest::Manifest;
use crate::case::meta::CaseMeta;
use crate::crypto::signer::{save_signature, sign_manifest};

pub const DEFAULT_ROOT: &str = "/var/lib/evident";

pub use crate::audit::verify::CaseVerifyResult as CaseVerifyOutput;

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

    pub fn with_default_root(signing_key: SigningKey) -> Self {
        Self::new(DEFAULT_ROOT, signing_key)
    }

    pub fn default_root() -> PathBuf {
        PathBuf::from(DEFAULT_ROOT)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn create_case(&self, case_id: &str) -> Result<()> {
        let case_dir = self.case_dir(case_id);
        if case_dir.exists() {
            return Err(anyhow!("case already exists: {case_id}"));
        }

        fs::create_dir_all(case_dir.join("evidence"))?;

        let meta = CaseMeta::new(case_id);
        meta.save(&case_dir.join("meta.json"))?;

        let _chain = CaseChain::open(&case_dir, case_id)?;

        let manifest = Manifest::genesis(case_id);
        manifest.save(&case_dir.join("manifest.json"))?;

        let sig = sign_manifest(&manifest, &self.signing_key)?;
        save_signature(&case_dir.join("signature.sig"), &sig)?;

        let _ = GlobalAuditWriter::new(&self.root).append(&json!({
            "action": "case_create",
            "case_id": case_id,
            "ts": chrono::Utc::now().to_rfc3339(),
        }));

        Ok(())
    }

    pub fn append_event(
        &self,
        case_id: &str,
        event_type: &str,
        data: Value,
    ) -> Result<String> {
        let case_dir = self.case_dir(case_id);
        if !case_dir.exists() {
            return Err(anyhow!("case not found: {case_id}"));
        }

        let meta_path = case_dir.join("meta.json");
        let mut meta = CaseMeta::load(&meta_path)?;
        meta.touch();
        meta.save(&meta_path)?;

        let mut chain = CaseChain::open(&case_dir, case_id)?;
        let event = chain.append_event(event_type, data.clone())?;

        let manifest = verify::build_manifest_from_chain(&chain)?;
        manifest.save(&case_dir.join("manifest.json"))?;

        let sig = sign_manifest(&manifest, &self.signing_key)?;
        save_signature(&case_dir.join("signature.sig"), &sig)?;

        let _ = GlobalAuditWriter::new(&self.root).append(&json!({
            "action": "case_append",
            "case_id": case_id,
            "event_type": event_type,
            "current_hash": event.current_hash,
            "ts": chrono::Utc::now().to_rfc3339(),
        }));

        Ok(event.current_hash)
    }

    pub fn verify_case(&self, case_id: &str) -> Result<CaseVerifyResult> {
        let case_dir = self.case_dir(case_id);
        if !case_dir.exists() {
            return Ok(CaseVerifyResult {
                status: verify::VERIFY_INVALID.to_string(),
                failed_at: None,
                reason: Some("case not found".to_string()),
            });
        }

        Ok(verify::verify_case(&case_dir, &self.verifying_key))
    }

    fn case_dir(&self, case_id: &str) -> PathBuf {
        self.root.join("cases").join(case_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::fs;

    fn test_engine() -> (tempfile::TempDir, CaseEngine) {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut OsRng);
        let engine = CaseEngine::new(dir.path(), key);
        (dir, engine)
    }

    #[test]
    fn happy_path_ten_events() {
        let (_dir, engine) = test_engine();
        engine.create_case("happy").unwrap();

        for i in 0..10 {
            let hash = engine
                .append_event("happy", "document_added", json!({ "doc": i }))
                .unwrap();
            assert_eq!(hash.len(), 64);
        }

        let result = engine.verify_case("happy").unwrap();
        assert_eq!(result.status, verify::VERIFY_VALID);
    }

    #[test]
    fn tampered_chain_is_invalid() {
        let (dir, engine) = test_engine();
        engine.create_case("tamper").unwrap();
        engine
            .append_event("tamper", "note", json!({ "n": 1 }))
            .unwrap();

        let chain_path = dir.path().join("cases/tamper/chain.jsonl");
        let content = fs::read_to_string(&chain_path).unwrap();
        fs::write(&chain_path, content.replace("\"n\":1", "\"n\":999")).unwrap();

        let result = engine.verify_case("tamper").unwrap();
        assert_eq!(result.status, verify::VERIFY_INVALID);
    }

    #[test]
    fn cases_are_isolated() {
        let (dir, engine) = test_engine();
        engine.create_case("good").unwrap();
        engine.create_case("bad").unwrap();

        engine
            .append_event("good", "evt", json!({ "ok": true }))
            .unwrap();
        engine
            .append_event("bad", "evt", json!({ "ok": true }))
            .unwrap();

        let chain_path = dir.path().join("cases/bad/chain.jsonl");
        let content = fs::read_to_string(&chain_path).unwrap();
        fs::write(&chain_path, content.replace("true", "false")).unwrap();

        assert_eq!(
            engine.verify_case("bad").unwrap().status,
            verify::VERIFY_INVALID
        );
        assert_eq!(
            engine.verify_case("good").unwrap().status,
            verify::VERIFY_VALID
        );
    }
}
