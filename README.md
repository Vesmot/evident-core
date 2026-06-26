[![CI](https://github.com/Vesmot/evident-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Vesmot/evident-core/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/Vesmot/evident-core/releases/tag/v1.0.0)


# Evident-Core

**Deterministic file integrity and audit-trail engine.**

Evident-Core is a lightweight, offline-first cryptographic tool for:
- **Sealing** files with SHA-256 + Ed25519 signatures
- **Timestamping** via RFC 3161 TSA (FreeTSA, DigiCert)
- **Verifying** integrity without cloud dependencies
- **Auditing** every operation in an append-only chain

## Quick Start

## Demo

```bash
# Seal a file
$ evident seal document.pdf --report
Enter PIN: 
SEALED: document.evident
TSA:    anchored (FreeTSA)
seq:    1

═══════════════════════════════════════════════════
         СВИДЕТЕЛЬСТВО О КРИПТОЗАПИСИ              
═══════════════════════════════════════════════════
Документ : document.pdf
Хэш      : a1fff0ffefb9eace...
Подписан : 2026-06-26T11:13:40Z
TSA      : подтверждено (FreeTSA)
═══════════════════════════════════════════════════

# Verify
$ evident verify document.pdf --report
[OK] File integrity: VALID
[OK] Signature:      VALID
[--]   TSA:            anchored (FreeTSA)

═══════════════════════════════════════════════════
Результат   : ЦЕЛОСТНОСТЬ ПОДТВЕРЖДЕНА
═══════════════════════════════════════════════════
```

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

## Roadmap

- [ ] `cargo install` from crates.io
- [ ] GitHub Actions integration
- [ ] Enterprise TSA (DigiCert, Sectigo)
- [ ] Blockchain timestamping
- [ ] GUI desktop app (egui)
- [ ] CI/CD badge with test coverage

License
MIT
