use crate::hash;

pub const SIGNATURE_DOMAIN: &[u8] = b"EVIDENT-v1";

/// Binary canonical message: SHA256(domain || file_hash || sealed_at_unix || pubkey)
/// `sealed_at_unix` is encoded as little-endian i64 (8 bytes).
pub fn signature_message(
    file_hash: &[u8; 32],
    sealed_at_unix: i64,
    pubkey: &[u8; 32],
) -> [u8; 32] {
    let ts_bytes = sealed_at_unix.to_le_bytes();
    let mut buf = [0u8; SIGNATURE_DOMAIN.len() + 32 + 8 + 32];
    let mut off = 0;

    buf[off..off + SIGNATURE_DOMAIN.len()].copy_from_slice(SIGNATURE_DOMAIN);
    off += SIGNATURE_DOMAIN.len();
    buf[off..off + 32].copy_from_slice(file_hash);
    off += 32;
    buf[off..off + 8].copy_from_slice(&ts_bytes);
    off += 8;
    buf[off..off + 32].copy_from_slice(pubkey);

    hash::sha256(&buf)
}
