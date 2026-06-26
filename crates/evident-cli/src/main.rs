use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use clap::{Parser, Subcommand};
use evident_audit::chain::{self, AuditEntry};
use evident_audit::evidence::{AuditRef, EvidencePack, SignerInfo, TsaInfo};
use evident_crypto::file_signer::{parse_signature, parse_verifying_key, verify_evidence};
use evident_crypto::hash;
use evident_crypto::key_store;
use evident_tsa::{seal, TsaConfig, TsaResult, TsaStatus};
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "evident", about = "Evident evidence management CLI")]
struct Cli {
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    Seal {
        file: PathBuf,
        #[arg(long)]
        no_tsa: bool,
    },
    Verify {
        file: PathBuf,
        #[arg(long)]
        proof: Option<PathBuf>,
    },
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    Init,
}

#[derive(Subcommand)]
enum AuditCommands {
    Log,
    Verify,
}

#[derive(Serialize)]
struct KeyInitOutput {
    public_key: String,
}

#[derive(Serialize)]
struct SealOutput {
    proof_path: String,
    tsa_status: String,
    tsa_provider: Option<String>,
    audit_seq: u64,
}

#[derive(Serialize)]
struct VerifyOutput {
    file_integrity: bool,
    signature_valid: bool,
    tsa_status: String,
    tsa_provider: Option<String>,
    sealed_at: String,
    signer_prefix: String,
}

#[derive(Serialize)]
struct AuditLogEntry {
    seq: u64,
    action: String,
    file_hash_preview: String,
    ts: String,
}

#[derive(Serialize)]
struct AuditLogOutput {
    entries: Vec<AuditLogEntry>,
}

#[derive(Serialize)]
struct AuditVerifyOutput {
    ok: bool,
    entry_count: u64,
    broken_at: Option<u64>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Key { command } => match command {
            KeyCommands::Init => cmd_key_init(cli.json),
        },
        Commands::Seal { file, no_tsa } => cmd_seal(&file, no_tsa, cli.json),
        Commands::Verify { file, proof } => cmd_verify(&file, proof.as_deref(), cli.json),
        Commands::Audit { command } => match command {
            AuditCommands::Log => cmd_audit_log(cli.json),
            AuditCommands::Verify => cmd_audit_verify(cli.json),
        },
    }
}

fn read_pin(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    let pin = rpassword::prompt_password(prompt)?;
    Ok(Zeroizing::new(pin.into_bytes()))
}

fn parse_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| format!("decode {label} hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must be {N} bytes"))
}

fn cmd_key_init(json: bool) -> Result<u8> {
    if key_store::vault_exists() {
        return Err(anyhow!("vault already exists; refusing to overwrite"));
    }

    let pin = read_pin("Enter PIN: ")?;
    let confirm = read_pin("Confirm PIN: ")?;
    if pin.as_slice() != confirm.as_slice() {
        return Err(anyhow!("PIN confirmation does not match"));
    }

    key_store::init(pin.as_slice())?;
    chain::append("key_init", "")?;

    let (_, verifying_key) = key_store::signing_key_and_verifying(pin.as_slice())?;
    let public_key = hex::encode(verifying_key.to_bytes());

    if json {
        let out = KeyInitOutput { public_key };
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("Key initialized. Public key: {public_key}");
    }

    Ok(0)
}

fn cmd_seal(file: &Path, no_tsa: bool, json: bool) -> Result<u8> {
    if !file.exists() {
        return Err(anyhow!("file not found: {}", file.display()));
    }

    let file_hash = hash::sha256_file(file)?;
    let file_hash_hex = hex::encode(file_hash);

    let pin = read_pin("Enter PIN: ")?;
    let (signing_key, verifying_key) = key_store::signing_key_and_verifying(pin.as_slice())?;
    let pubkey_bytes = verifying_key.to_bytes();
    let pubkey_hex = hex::encode(pubkey_bytes);

    let sealed_at_unix = Utc::now().timestamp();
    let sealed_at = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let signature = evident_crypto::file_signer::sign_evidence(
        &signing_key,
        &file_hash,
        sealed_at_unix,
        &pubkey_bytes,
    );
    let signature_hex = hex::encode(signature.to_bytes());

    let tsa_result = if no_tsa {
        TsaResult {
            status: TsaStatus::Skipped,
            provider: None,
            tsr_data: None,
            verified_time: None,
            error: None,
        }
    } else {
        seal(&file_hash, &TsaConfig::default())
    };

    let audit_seq = chain::append("seal", &file_hash_hex)?;
    let audit_chain_hash = chain::head_hash()?;

    let (tsa_status, tsa_provider, tsr_b64, verified_time) = tsa_fields(&tsa_result);

    let pack = EvidencePack {
        version: "1".to_string(),
        file_name: file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string(),
        file_hash: file_hash_hex,
        sealed_at: sealed_at.clone(),
        sealed_at_unix,
        signer: SignerInfo {
            public_key: pubkey_hex,
            signature: signature_hex,
        },
        tsa: TsaInfo {
            status: tsa_status.clone(),
            provider: tsa_provider.clone(),
            tsr_b64,
            verified_time,
        },
        audit: AuditRef {
            seq: audit_seq,
            chain_hash: audit_chain_hash,
        },
    };

    let proof_path = file.with_extension("evident");
    pack.save(&proof_path)?;

    if json {
        let out = SealOutput {
            proof_path: proof_path.display().to_string(),
            tsa_status,
            tsa_provider,
            audit_seq,
        };
        println!("{}", serde_json::to_string(&out)?);
    } else {
        let tsa_line = format_tsa_line(&tsa_result);
        println!("SEALED: {}", proof_path.display());
        println!("TSA:    {tsa_line}");
        println!("seq:    {audit_seq}");
    }

    Ok(0)
}

fn cmd_verify(file: &Path, proof: Option<&Path>, json: bool) -> Result<u8> {
    let proof_path = proof
        .map(PathBuf::from)
        .unwrap_or_else(|| file.with_extension("evident"));

    if !file.exists() {
        return Err(anyhow!("file not found: {}", file.display()));
    }
    if !proof_path.exists() {
        return Err(anyhow!("proof not found: {}", proof_path.display()));
    }

    let pack = EvidencePack::load(&proof_path)?;
    let file_hash = hash::sha256_file(file)?;
    let file_hash_hex = hex::encode(file_hash);
    let file_ok = file_hash_hex == pack.file_hash;

    let pubkey_bytes: [u8; 32] = parse_hex_array(&pack.signer.public_key, "public key")?;
    let signature_bytes: [u8; 64] = parse_hex_array(&pack.signer.signature, "signature")?;
    let verifying_key = parse_verifying_key(&pubkey_bytes)?;
    let signature = parse_signature(&signature_bytes);

    let sig_ok = verify_evidence(
        &verifying_key,
        &file_hash,
        pack.sealed_at_unix,
        &pubkey_bytes,
        &signature,
    );

    let tsa_status = pack.tsa.status.clone();
    let tsa_provider = pack.tsa.provider.clone();
    let signer_prefix = if pack.signer.public_key.len() >= 16 {
        format!("{}...", &pack.signer.public_key[..16])
    } else {
        pack.signer.public_key.clone()
    };

    if json {
        let out = VerifyOutput {
            file_integrity: file_ok,
            signature_valid: sig_ok,
            tsa_status,
            tsa_provider,
            sealed_at: pack.sealed_at.clone(),
            signer_prefix,
        };
        println!("{}", serde_json::to_string(&out)?);
    } else {
        let file_label = if file_ok { "VALID" } else { "INVALID" };
        let sig_label = if sig_ok { "VALID" } else { "INVALID" };
        let status = if file_ok && sig_ok { "OK" } else { "FAIL" };
        let tsa_line = format_tsa_status(&tsa_status, tsa_provider.as_deref());

        println!("[{status}] File integrity: {file_label}");
        println!("[{status}] Signature:      {sig_label}");
        println!("[--]   TSA:            {tsa_line}");
        println!("[--]   Sealed at:      {}", pack.sealed_at);
        println!("[--]   Signer:         {signer_prefix}");
    }

    if file_ok && sig_ok {
        Ok(0)
    } else {
        Ok(1)
    }
}

fn cmd_audit_log(json: bool) -> Result<u8> {
    let entries = chain::read_all_entries()?;
    let start = entries.len().saturating_sub(20);

    if json {
        let out_entries: Vec<AuditLogEntry> = entries[start..]
            .iter()
            .map(format_log_entry)
            .collect();
        let out = AuditLogOutput {
            entries: out_entries,
        };
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("seq | action    | file_hash                         | ts");
        for entry in &entries[start..] {
            let formatted = format_log_entry(entry);
            println!(
                "{} | {:9} | {:33} | {}",
                formatted.seq, formatted.action, formatted.file_hash_preview, formatted.ts
            );
        }
    }

    Ok(0)
}

fn cmd_audit_verify(json: bool) -> Result<u8> {
    let (ok, broken_at) = chain::verify_chain()?;
    let entry_count = chain::entry_count()?;

    if json {
        let out = AuditVerifyOutput {
            ok,
            entry_count,
            broken_at,
        };
        println!("{}", serde_json::to_string(&out)?);
    } else if ok {
        println!("Chain OK ({entry_count} entries)");
    } else if let Some(seq) = broken_at {
        println!("Chain BROKEN at seq {seq}");
    } else {
        println!("Chain BROKEN");
    }

    if ok {
        Ok(0)
    } else {
        Ok(1)
    }
}

fn format_log_entry(entry: &AuditEntry) -> AuditLogEntry {
    let file_hash_preview = if entry.file_hash.is_empty() {
        "—".to_string()
    } else if entry.file_hash.len() > 16 {
        format!("{}...", &entry.file_hash[..16])
    } else {
        entry.file_hash.clone()
    };

    AuditLogEntry {
        seq: entry.seq,
        action: entry.action.clone(),
        file_hash_preview,
        ts: entry.ts.clone(),
    }
}

fn tsa_fields(tsa_result: &TsaResult) -> (String, Option<String>, Option<String>, Option<String>) {
    match tsa_result.status {
        TsaStatus::Anchored => (
            "anchored".to_string(),
            tsa_result.provider.clone(),
            tsa_result
                .tsr_data
                .as_ref()
                .map(|d| BASE64.encode(d)),
            tsa_result.verified_time.clone(),
        ),
        TsaStatus::Skipped | TsaStatus::Failed => (
            "skipped".to_string(),
            None,
            None,
            None,
        ),
    }
}

fn format_tsa_line(tsa_result: &TsaResult) -> String {
    match tsa_result.status {
        TsaStatus::Anchored => {
            let provider = tsa_result.provider.as_deref().unwrap_or("unknown");
            format!("anchored ({provider})")
        }
        TsaStatus::Skipped | TsaStatus::Failed => "skipped".to_string(),
    }
}

fn format_tsa_status(status: &str, provider: Option<&str>) -> String {
    if status == "anchored" {
        format!("anchored ({})", provider.unwrap_or("unknown"))
    } else {
        "skipped".to_string()
    }
}