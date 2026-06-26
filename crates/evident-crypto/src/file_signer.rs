use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::canonical;

pub fn sign_evidence(
    signing_key: &SigningKey,
    file_hash: &[u8; 32],
    sealed_at_unix: i64,
    pubkey: &[u8; 32],
) -> Signature {
    let message = canonical::signature_message(file_hash, sealed_at_unix, pubkey);
    signing_key.sign(&message)
}

pub fn verify_evidence(
    verifying_key: &VerifyingKey,
    file_hash: &[u8; 32],
    sealed_at_unix: i64,
    pubkey: &[u8; 32],
    signature: &Signature,
) -> bool {
    let message = canonical::signature_message(file_hash, sealed_at_unix, pubkey);
    verifying_key.verify_strict(&message, signature).is_ok()
}

pub fn parse_verifying_key(pubkey_bytes: &[u8; 32]) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(pubkey_bytes).map_err(|e| anyhow::anyhow!("invalid public key: {e}"))
}

pub fn parse_signature(signature_bytes: &[u8; 64]) -> Signature {
    Signature::from_bytes(signature_bytes)
}
