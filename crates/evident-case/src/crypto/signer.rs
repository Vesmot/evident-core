use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::case::manifest::Manifest;

pub fn sign_manifest(manifest: &Manifest, signing_key: &SigningKey) -> Result<Vec<u8>> {
    let bytes = manifest.canonical_bytes()?;
    let sig = signing_key.sign(&bytes);
    Ok(sig.to_bytes().to_vec())
}

pub fn verify_manifest_signature(
    manifest: &Manifest,
    signature_bytes: &[u8; 64],
    verifying_key: &VerifyingKey,
) -> bool {
    let Ok(bytes) = manifest.canonical_bytes() else {
        return false;
    };
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key.verify_strict(&bytes, &signature).is_ok()
}

pub fn load_signature(path: &std::path::Path) -> Result<[u8; 64]> {
    let hex_str = std::fs::read_to_string(path)
        .with_context(|| format!("read signature {}", path.display()))?;
    let bytes = hex::decode(hex_str.trim())
        .with_context(|| format!("decode signature {}", path.display()))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))
}

pub fn save_signature(path: &std::path::Path, signature: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, hex::encode(signature))?;
    Ok(())
}
