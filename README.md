# Evident-Core

**Deterministic file integrity and audit-trail engine.**

Evident-Core is a lightweight, offline-first cryptographic tool for:
- **Sealing** files with SHA-256 + Ed25519 signatures
- **Timestamping** via RFC 3161 TSA (FreeTSA, DigiCert)
- **Verifying** integrity without cloud dependencies
- **Auditing** every operation in an append-only chain

## Quick Start

```bash
# Install
cargo install --git https://github.com/Vesmot/evident-core

# Seal a file
evident seal document.pdf --report

# Verify
evident verify document.pdf --report
Features
Offline-first — No cloud required

Audit-ready — Every operation logged

Cryptographic proof — SHA-256 + Ed25519 + RFC 3161

Zero-trust — Verification requires no trust in the system

Documentation
Strategy — Product and go-to-market strategy

Changelog — Version history

License
MIT
