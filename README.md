# Evident-Core

Evident-Core is a cryptographic CLI tool for file notarization.

It provides:
- Ed25519 digital signatures
- Optional RFC3161 timestamping (TSA)
- Append-only audit chain
- Encrypted local key vault

## Components

- **evident-cli** — command line interface
- **evident-crypto** — cryptographic primitives (Ed25519, Argon2id, AES-256-GCM)
- **evident-tsa** — RFC3161 timestamping layer with fallback
- **evident-audit** — audit trail and evidence packaging

## Quick Start

```bash
# Initialize key vault
evident key init

# Seal a file
evident seal document.pdf

# Verify integrity
evident verify document.pdf

# View audit log
evident audit
Status
v0.1-stable — stable cryptographic baseline

✅ Argon2id + AES-256-GCM vault with KDF parameters

✅ Ed25519 signatures with verify_strict

✅ RFC3161 TSA with automatic fallback

✅ Append-only audit chain with file locking

✅ Binary canonical format with Unix timestamp

License
MIT
