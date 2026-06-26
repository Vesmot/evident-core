use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use ed25519_dalek::VerifyingKey;
use serde::Serialize;

use crate::audit::hash::{CaseChainLinker, ChainLinker};
use crate::case::chain::CaseChain;
use crate::case::manifest::{Manifest, STATUS_VALID};
use crate::case::meta::CaseMeta;
use crate::crypto::signer::{load_signature, verify_manifest_signature};

pub const VERIFY_VALID: &str = "VALID";
pub const VERIFY_INVALID: &str = "INVALID";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaseVerifyResult {
    pub status: String,
    pub failed_at: Option<u64>,
    pub reason: Option<String>,
}

pub fn verify_case(case_dir: &Path, verifying_key: &VerifyingKey) -> CaseVerifyResult {
    let meta_path = case_dir.join("meta.json");
    if !meta_path.exists() {
        return invalid(None, "meta.json not found");
    }

    let meta = match CaseMeta::load(&meta_path) {
        Ok(m) => m,
        Err(e) => return invalid(None, &format!("meta.json load failed: {e}")),
    };

    let chain = match CaseChain::open(case_dir, &meta.case_id) {
        Ok(c) => c,
        Err(e) => return invalid(None, &format!("chain open failed: {e}")),
    };

    let (chain_ok, failed_at) = match chain.verify_chain() {
        Ok(v) => v,
        Err(e) => return invalid(None, &format!("chain read failed: {e}")),
    };
    if !chain_ok {
        return invalid(failed_at, "hash chain verification failed");
    }

    if chain.event_count().unwrap_or(0) > 0 {
        if let Ok(events) = chain.read_events() {
            if events
                .first()
                .map(|e| e.prev_hash != CaseChainLinker::genesis_hash())
                .unwrap_or(false)
            {
                return invalid(Some(0), "genesis rule violated");
            }
        }
    }

    let manifest_path = case_dir.join("manifest.json");
    let manifest = match Manifest::load(&manifest_path) {
        Ok(m) => m,
        Err(e) => return invalid(None, &format!("manifest load failed: {e}")),
    };

    let expected = match build_manifest_from_chain(&chain) {
        Ok(m) => m,
        Err(e) => return invalid(None, &format!("manifest rebuild failed: {e}")),
    };

    if manifest.root_hash != expected.root_hash
        || manifest.last_hash != expected.last_hash
        || manifest.event_count != expected.event_count
    {
        return invalid(None, "manifest inconsistent with chain");
    }

    let sig_path = case_dir.join("signature.sig");
    let sig_bytes = match load_signature(&sig_path) {
        Ok(s) => s,
        Err(e) => return invalid(None, &format!("signature load failed: {e}")),
    };

    if !verify_manifest_signature(&manifest, &sig_bytes, verifying_key) {
        return invalid(None, "manifest signature invalid");
    }

    if manifest.status != STATUS_VALID {
        return invalid(None, "manifest status is not VALID");
    }

    CaseVerifyResult {
        status: VERIFY_VALID.to_string(),
        failed_at: None,
        reason: None,
    }
}

pub fn build_manifest_from_chain(chain: &CaseChain) -> anyhow::Result<Manifest> {
    Ok(Manifest {
        case_id: chain.case_id.clone(),
        root_hash: chain.root_hash()?,
        last_hash: chain.last_hash.clone(),
        event_count: chain.event_count()? as u64,
        status: STATUS_VALID.to_string(),
    })
}

/// Structural check only — never used in case cryptographic verification.
pub fn verify_global_audit_readable(path: &Path) -> bool {
    if !path.exists() {
        return true;
    }

    let Ok(file) = File::open(path) else {
        return false;
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        let Ok(line) = line else {
            return false;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if serde_json::from_str::<serde_json::Value>(trimmed).is_err() {
            return false;
        }
    }

    true
}

fn invalid(failed_at: Option<u64>, reason: &str) -> CaseVerifyResult {
    CaseVerifyResult {
        status: VERIFY_INVALID.to_string(),
        failed_at,
        reason: Some(reason.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::engine::CaseEngine;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use serde_json::json;
    use std::fs;

    fn engine() -> (tempfile::TempDir, CaseEngine) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let key = SigningKey::generate(&mut OsRng);
        (dir, CaseEngine::new(root, key))
    }

    #[test]
    fn audit_log_deletion_does_not_affect_validity() {
        let (dir, engine) = engine();
        engine.create_case("iso").unwrap();
        engine
            .append_event("iso", "evt", json!({ "n": 1 }))
            .unwrap();

        let audit = dir.path().join("audit.jsonl");
        if audit.exists() {
            fs::remove_file(audit).unwrap();
        }

        let result = engine.verify_case("iso").unwrap();
        assert_eq!(result.status, VERIFY_VALID);
    }

    #[test]
    fn tampered_manifest_fails_signature() {
        let (dir, engine) = engine();
        engine.create_case("sig").unwrap();
        engine
            .append_event("sig", "evt", json!({ "x": 1 }))
            .unwrap();

        let manifest_path = dir.path().join("cases/sig/manifest.json");
        let mut manifest = Manifest::load(&manifest_path).unwrap();
        manifest.status = "TAMPERED".to_string();
        manifest.save(&manifest_path).unwrap();

        let result = engine.verify_case("sig").unwrap();
        assert_eq!(result.status, VERIFY_INVALID);
    }
}
