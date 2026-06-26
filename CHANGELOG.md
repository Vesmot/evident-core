# Changelog

## [0.1-stable] - 2026-06-26

### Added
- Initial release of Evident-Core
- Ed25519 key generation and signing
- Argon2id key derivation with persisted KDF parameters
- AES-256-GCM encrypted key vault
- RFC3161 timestamping with fallback support
- Append-only audit chain with evidence packaging
- Binary canonical format: `EVIDENT-v1 || hash || sealed_at_unix || pubkey`
- File locking for concurrent audit writes

### Changed
- `verify_strict` for all Ed25519 verification paths
- `sealed_at_unix` as i64 LE in canonical blob
- EvidencePack with both `sealed_at` (ISO) and `sealed_at_unix` (i64)

### Security
- KDF parameters stored in vault for future migration
- Exclusive file lock on audit operations
- No hardcoded cryptographic parameters

### CLI Commands
- `evident key init` — initialize key vault
- `evident seal <file>` — seal file with optional TSA
- `evident verify <file>` — verify integrity and signature
- `evident audit` — view audit trail
