use std::env;
use std::fs;
use std::path::PathBuf;

use chrono::Utc;
use evident_audit::chain;
use evident_audit::evidence::{AuditRef, EvidencePack, SignerInfo, TsaInfo};
use evident_crypto::file_signer::{sign_evidence, verify_evidence};
use evident_crypto::hash;
use evident_crypto::key_store;
use evident_tsa::{TsaConfig, TsaStatus};

fn evident_dir(home: &std::path::Path) -> PathBuf {
    home.join(".evident")
}

#[test]
fn round_trip_seal_and_verify() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let home = temp.path().to_path_buf();
    let previous_home = env::var("HOME").ok();
    env::set_var("HOME", &home);

    let result = (|| -> anyhow::Result<()> {
        let file_path = home.join("test.txt");
        fs::write(&file_path, "test content")?;

        let pin = b"test123";
        key_store::init(pin)?;
        chain::append("key_init", "")?;

        let file_hash = hash::sha256_file(&file_path)?;
        let file_hash_hex = hex::encode(file_hash);
        let (signing_key, verifying_key) = key_store::signing_key_and_verifying(pin)?;
        let pubkey_bytes = verifying_key.to_bytes();
        let sealed_at_unix = Utc::now().timestamp();
        let sealed_at = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let signature = sign_evidence(&signing_key, &file_hash, sealed_at_unix, &pubkey_bytes);

        let audit_seq = chain::append("seal", &file_hash_hex)?;
        let audit_chain_hash = chain::head_hash()?;

        let pack = EvidencePack {
            version: "1".to_string(),
            file_name: "test.txt".to_string(),
            file_hash: file_hash_hex.clone(),
            sealed_at: sealed_at.clone(),
            sealed_at_unix,
            signer: SignerInfo {
                public_key: hex::encode(pubkey_bytes),
                signature: hex::encode(signature.to_bytes()),
            },
            tsa: TsaInfo {
                status: "skipped".to_string(),
                provider: None,
                tsr_b64: None,
                verified_time: None,
            },
            audit: AuditRef {
                seq: audit_seq,
                chain_hash: audit_chain_hash,
            },
            git: None,
        };

        let proof_path = file_path.with_extension("evident");
        pack.save(&proof_path)?;

        assert!(verify_evidence(
            &verifying_key,
            &file_hash,
            sealed_at_unix,
            &pubkey_bytes,
            &signature,
        ));

        fs::write(&file_path, "test content\nmodified")?;
        let modified_hash = hash::sha256_file(&file_path)?;
        assert_ne!(hex::encode(modified_hash), pack.file_hash);

        let (ok, broken) = chain::verify_chain()?;
        assert!(ok);
        assert!(broken.is_none());

        assert!(evident_dir(&home).join("key.enc").exists());
        assert!(evident_dir(&home).join("audit.jsonl").exists());

        Ok(())
    })();

    if let Some(prev) = previous_home {
        env::set_var("HOME", prev);
    } else {
        env::remove_var("HOME");
    }

    result
}

#[test]
fn tsa_skipped_when_no_network_urls_fail() {
    let file_hash = hash::sha256(b"test");
    let result = evident_tsa::seal(
        &file_hash,
        &TsaConfig {
            urls: vec!["http://127.0.0.1:1".to_string()],
        },
    );
    assert_eq!(result.status, TsaStatus::Skipped);
}
