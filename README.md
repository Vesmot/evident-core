# If any cryptographic or audit invariant cannot be guaranteed deterministically, fail build.

## evident-core v0.1

Secure evidence management: Ed25519 signatures, encrypted key vault, TSA anchoring, append-only audit chain.

### Build

```bash
cargo build --release
```

### Commands

- `evident key init` — create encrypted vault at `~/.evident/key.enc`
- `evident seal <file> [--no-tsa]` — seal file, write `<file>.evident`
- `evident verify <file> [--proof <path>]` — verify integrity and signature
- `evident audit log` — show last 20 audit entries
- `evident audit verify` — verify audit chain integrity

All commands support `--json` for machine-readable output.

### Cryptographic invariants

1. Signature covers `SHA256(domain || file_hash || sealed_at || pubkey)` with `domain = b"EVIDENT-v1"`
2. `sealed_at`: RFC3339 UTC, second precision (`%Y-%m-%dT%H:%M:%SZ`)
3. Audit chain independent of TSA failures
4. TSA failure → `skipped`, not a hard error
5. Hashes are `[u8;32]` internally, hex in JSON
6. Vault stores seed `[u8;32]`, not SigningKey bytes
7. No `key.pub` — public key derived from seed via PIN
8. Verify uses public key from `.evident` file, PIN not required
