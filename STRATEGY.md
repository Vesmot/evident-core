# Evident — Product & Go-to-Market Strategy

## 1. Core Positioning

**Evident is a deterministic integrity primitive for digital artifacts.**

- Not a "trust system"
- Not a "blockchain product"
- Not a "legal proof generator"

It is:
- A cryptographic file integrity engine
- Deterministic, verifiable, offline-first
- A building block for compliance and audit systems

---

## 2. Product Architecture
┌─────────────────────────────────────────────┐
│ evident-core │
│ (integrity engine) │
├─────────────────────────────────────────────┤
│ CLI │ Library │ Adapters │
│ evident │ core-lib │ GitHub Actions │
└─────────────────────────────────────────────┘

text

**Core contract:**
- SHA-256 + Ed25519 + RFC 3161 TSA
- Append-only audit chain
- Deterministic .evident format
- Offline-first (no cloud dependency)

---

## 3. Go-to-Market Phases

### Phase 0: Product Hardening (0–14 days)
**Goal:** Make `evident-core` stable, spec-locked, and production-ready.

- [ ] Finalize `.evident` v1 format
- [ ] CLI stable (`seal`, `verify`, `audit`, `--report`)
- [ ] TSA: FreeTSA (default) + fallback
- [ ] GitHub Actions CI
- [ ] `cargo install` works
- [ ] CHANGELOG.md up to date

**Deliverable:**
- `evident-core` v0.6
- Public GitHub repository

---

### Phase 1: Public Signal (2–4 weeks)
**Goal:** Establish presence without overpromising.

- [ ] English README (global)
- [ ] Russian README (localization)
- [ ] Minimal landing page (GitHub Pages)
- [ ] `--version` shows build info
- [ ] First external user (developer)

**Positioning:**
> "Cryptographic file integrity tool"

**No:**
- Enterprise claims
- Legal promises
- Compliance guarantees

---

### Phase 2: Distribution Hook (4–8 weeks)
**Goal:** Product-led growth through GitHub integration.

- [ ] `notary-github` GitHub App
- [ ] GitHub Actions workflow
- [ ] Sealed artifacts in CI
- [ ] Auto-verification in PRs

**Target:** Developers who want auditability

**Price:** Free for open source, $29/mo for orgs

---

### Phase 3: Enterprise Later (Optional)
**Condition:** Usage + traction + real cases

- [ ] Compliance framing (HIPAA, SOX, FDA)
- [ ] SOC2 readiness
- [ ] Paid enterprise integrations
- [ ] Consulting (LIMS, SAP, legal)

---

## 4. Principles

### 1. Determinism over marketing
The code must be boring, stable, and predictable.

### 2. Offline-first
No cloud dependency. Works in air-gapped environments.

### 3. Adapters, not rewriting
Core stays stable. Integrations are separate products.

### 4. Product-led growth
Value first. Enterprise narrative later.

### 5. No legal promises
"Tamper-evident audit evidence" → not "court proof"

---

## 5. Decision Register

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-06-26 | Focus on `evident-core` before GitHub App | Core stability > distribution |
| 2026-06-26 | English README as primary | Global audience |
| 2026-06-26 | GUI via egui (not Tauri) | Clean Rust, no WebView |
| 2026-06-26 | FreeTSA default, enterprise TSA later | Simplicity first |

---

## 6. Success Metrics

| Phase | Metric |
|-------|--------|
| Phase 0 | `cargo install` works |
| Phase 1 | 10 GitHub stars |
| Phase 2 | 10 users (outside self) |
| Phase 3 | 1 paid enterprise contract |

---

## 7. Anti-Goals (What we are NOT doing)

- ❌ Building a "trust layer for court"
- ❌ Entering pharma in 2026
- ❌ Selling compliance without traction
- ❌ Rewriting the core for marketing
- ❌ Tauri GUI (egui only)
