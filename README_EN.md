# Evident

Cryptographic file integrity and audit-trail engine.

Evident creates immutable proof that a file existed at a specific point in time:
Ed25519 signature + RFC 3161 timestamp (TSA).

## What is Evident

> Cryptographic file integrity and audit-trail engine.

## Installation

```bash
cargo install --git https://github.com/Vesmot/evident-core --bin evident
```

### From source

```bash
git clone https://github.com/Vesmot/evident-core
cd evident-core
cargo build --release
# binary: target/release/evident
```

## Core commands

```bash
evident seal file.pdf
evident verify file.pdf
evident inspect file.evident
```

## Output types

- `.evident` proof artifact (JSON evidence pack)
- verification status (exit code 0 = valid, 1 = failed check, 2 = system error)
- audit metadata in `~/.evident/audit.jsonl`

## Quick start

```bash
# 1. Initialize key vault (once)
evident key init

# 2. Seal a file
evident seal document.pdf

# 3. Verify
evident verify document.pdf

# 4. Inspect proof artifact
evident inspect document.evident

# 5. Human-readable reports (Russian)
evident seal document.pdf --report
evident verify document.pdf --report
```

## Commands

| Command | Description |
|---|---|
| `evident key init` | Create encrypted key vault |
| `evident seal <file>` | Seal file (signature + TSA) |
| `evident seal <file> --no-tsa` | Seal without TSA (offline) |
| `evident seal <file> --git` | Include Git context in proof |
| `evident seal <file> --report` | Print seal attestation report |
| `evident verify <file>` | Verify file integrity and signature |
| `evident verify <file> --report` | Print verification report |
| `evident inspect <proof>` | Show `.evident` file contents |
| `evident audit log` | Show audit journal |
| `evident audit verify` | Verify audit chain integrity |

## Flags

| Flag | Description |
|---|---|
| `--no-tsa` | Skip TSA request |
| `--git` | Add Git commit/branch to proof |
| `--report` | Human-readable report (Russian) |
| `--json` | JSON output for scripts and CI |
| `--proof <path>` | Explicit path to `.evident` file |

## Proof format

File `<document>.evident` — JSON evidence pack:

```json
{
  "version": "1",
  "file_name": "document.pdf",
  "file_hash": "<sha256-hex>",
  "sealed_at": "<ISO8601 UTC>",
  "sealed_at_unix": 1234567890,
  "signer": {
    "public_key": "<hex>",
    "signature": "<hex>"
  },
  "tsa": {
    "status": "anchored",
    "provider": "FreeTSA",
    "tsr_b64": "<base64>",
    "verified_time": "<ISO8601>"
  },
  "audit": {
    "seq": 1,
    "chain_hash": "<hex>"
  }
}
```

## Storage

| Path | Description |
|---|---|
| `~/.evident/key.enc` | Encrypted vault (Argon2id + AES-256-GCM) |
| `~/.evident/audit.jsonl` | Append-only audit journal |
| `<file>.evident` | Proof artifact next to source file |

## TSA providers

Default: FreeTSA (`https://freetsa.org/tsr`).
Fallback: DigiCert.

## Cryptography

- Signature: Ed25519 (ed25519-dalek 2.1)
- Hash: SHA-256
- KDF: Argon2id (m=65536, t=3, p=1)
- Vault encryption: AES-256-GCM
- Timestamp: RFC 3161

## Version history

| Version | Changes |
|---|---|
| v1.0 | Production baseline: inspect, error model, public release |
| v0.6 | `--version`, documentation |
| v0.5 | `--report` on verify |
| v0.4 | `--report` on seal |
| v0.3 | Git attestation overlay |
| v0.2 | RFC3161 DER, TSA anchoring |
| v0.1 | vault, seal, verify, audit chain |
