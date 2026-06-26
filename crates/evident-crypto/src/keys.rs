use ed25519_dalek::{Signature, VerifyingKey};

pub fn verify_signature(
    public_key_bytes: &[u8; 32],
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> bool {
    let pub_key = match VerifyingKey::from_bytes(public_key_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let signature = Signature::from_bytes(signature_bytes);

    pub_key.verify_strict(message, &signature).is_ok()
}
