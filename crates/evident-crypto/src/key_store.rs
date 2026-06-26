use std::fs;
use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const VAULT_VERSION: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SEED_LEN: usize = 32;
const KDF_M_COST: u32 = 65536;
const KDF_T_COST: u32 = 3;
const KDF_P_COST: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfParams {
    m: u32,
    t: u32,
    p: u32,
}

impl KdfParams {
    fn default_v1() -> Self {
        Self {
            m: KDF_M_COST,
            t: KDF_T_COST,
            p: KDF_P_COST,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    v: u32,
    kdf: String,
    kdf_params: KdfParams,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn evident_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("home directory not found"))?;
    Ok(home.join(".evident"))
}

pub fn vault_path() -> Result<PathBuf> {
    Ok(evident_dir()?.join("key.enc"))
}

fn derive_key(
    pin: &[u8],
    salt: &[u8; SALT_LEN],
    kdf_params: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(kdf_params.m, kdf_params.t, kdf_params.p, Some(32))
        .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kdf_key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(pin, salt, kdf_key.as_mut())
        .map_err(|e| anyhow!("argon2 hash failed: {e}"))?;
    Ok(kdf_key)
}

fn encrypt_seed(
    seed: &[u8; SEED_LEN],
    kdf_key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(kdf_key)
        .map_err(|e| anyhow!("invalid AES key: {e}"))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, seed.as_ref())
        .map_err(|e| anyhow!("AES-GCM encrypt failed: {e}"))
}

fn decrypt_seed(
    ciphertext: &[u8],
    kdf_key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<Zeroizing<[u8; SEED_LEN]>> {
    let cipher = Aes256Gcm::new_from_slice(kdf_key)
        .map_err(|e| anyhow!("invalid AES key: {e}"))?;
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("vault decryption failed (wrong PIN or corrupted vault)"))?;
    let seed_bytes: [u8; SEED_LEN] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid seed length in vault"))?;
    Ok(Zeroizing::new(seed_bytes))
}

pub fn init(pin: &[u8]) -> Result<()> {
    let path = vault_path()?;
    if path.exists() {
        return Err(anyhow!("vault already exists at {}", path.display()));
    }

    let dir = evident_dir()?;
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    OsRng.fill_bytes(seed.as_mut());

    let kdf_params = KdfParams::default_v1();
    let kdf_key: [u8; 32] = *derive_key(pin, &salt, &kdf_params)?;
    let ciphertext = encrypt_seed(&seed, &kdf_key, &nonce)?;

    let vault = VaultFile {
        v: VAULT_VERSION,
        kdf: "argon2id".to_string(),
        kdf_params,
        salt: BASE64.encode(salt),
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(&ciphertext),
    };

    let json = serde_json::to_string_pretty(&vault)?;
    fs::write(&path, json).with_context(|| format!("write vault {}", path.display()))?;

    Ok(())
}

pub fn load(pin: &[u8]) -> Result<SigningKey> {
    let path = vault_path()?;
    let json = fs::read_to_string(&path)
        .with_context(|| format!("read vault {}", path.display()))?;
    let vault: VaultFile = serde_json::from_str(&json)?;

    if vault.v != VAULT_VERSION {
        return Err(anyhow!("unsupported vault version: {}", vault.v));
    }
    if vault.kdf != "argon2id" {
        return Err(anyhow!("unsupported KDF: {}", vault.kdf));
    }

    let salt_vec = BASE64
        .decode(&vault.salt)
        .map_err(|e| anyhow!("invalid vault salt: {e}"))?;
    let nonce_vec = BASE64
        .decode(&vault.nonce)
        .map_err(|e| anyhow!("invalid vault nonce: {e}"))?;
    let ciphertext = BASE64
        .decode(&vault.ciphertext)
        .map_err(|e| anyhow!("invalid vault ciphertext: {e}"))?;

    let salt: [u8; SALT_LEN] = salt_vec
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid salt length"))?;
    let nonce: [u8; NONCE_LEN] = nonce_vec
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid nonce length"))?;

    let kdf_key: [u8; 32] = *derive_key(pin, &salt, &vault.kdf_params)?;
    let seed = decrypt_seed(&ciphertext, &kdf_key, &nonce)?;
    let signing_key = SigningKey::from_bytes(&seed);
    Ok(signing_key)
}

pub fn signing_key_and_verifying(
    pin: &[u8],
) -> Result<(SigningKey, ed25519_dalek::VerifyingKey)> {
    let signing_key = load(pin)?;
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key, verifying_key))
}

pub fn vault_exists() -> bool {
    vault_path()
        .map(|p| p.exists())
        .unwrap_or(false)
}

pub fn read_vault_public_hint(pin: &[u8]) -> Result<[u8; 32]> {
    let signing_key = load(pin)?;
    Ok(signing_key.verifying_key().to_bytes())
}
