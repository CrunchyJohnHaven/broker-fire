# Changelog

All notable changes to `@credexai/broker-fire` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-13

### Added

- `brokerFire(req)` — the deterministic 11-stage broker-fire evaluator. Returns `{outcome, state, reasons}`. Outcomes: `allow`, `deny`, `indeterminate`. State machine: `RECEIVED → IDENTITY_BOUND → INTENT_BOUND → CUSTODY_BOUND → POLICY_ALLOWED → WITNESS_BOUND → GRANT_VERIFIED → EPOCH_FRESH → IDEMPOTENCY_OK → PRE_COMMITTED → RECEIPTED` (or `DENIED_BEFORE_FIRE` / `RECOVERY_REQUIRED`).
- `denyEnvelope(actionName, result)` — shapes a broker-fire deny into a uniform error envelope for callers.
- `strictModeEnabled()` — checks `BROKER_FIRE_STRICT=1` migration dial.
- `canonicalHash(value)` — canonical-JSON SHA-256 hasher with **byte-identical parity** between Python and TypeScript across 20 test vectors. Rejects floats, non-NFC strings, duplicate keys, non-string keys. Sorts object keys by Unicode code-point order. Arrays preserve insertion order.
- `CanonicalJSONError` — thrown by `canonicalHash` with a typed `code` field on rule violations.
- 15 broker-fire e2e cases covering: panic stop, untrusted authority, raw secret output, missing witness on live financial, idempotency replay, cross-tenant violation, revocation epoch stale, side effect before pre-commit, witness summary mismatch, native message bypass, provider receipt unverified (indeterminate), missing post-commit (indeterminate), grant intent mismatch, valid metadata path, valid live financial path with witness.
- 20 canonical-hash parity vectors covering: simple objects, nested objects, key-order invariance, NFC unicode, booleans/null, empty containers, large integers, deep nesting, emoji, spaces in values, float rejection, non-NFC rejection, integer differences, array order differences, single-field perturbation, added field, string case sensitivity.
- Apache-2.0 license.
- GitHub Actions CI on `push` and `pull_request`. Runs `npm install && npm run build && npm test` on Ubuntu 24.04 / Node 20.
- Zero runtime dependencies. Three devDependencies (typescript, tsx, @types/node).

### What this version proves

Eleven cryptographic and structural invariants every AI-agent side effect must satisfy to fire. The proofs run as falsifiable synthetic gates with explicit deny reason codes — no "the model judged it" anywhere in the chain.

### What this version does NOT do

- Real Ed25519 signature verification. Synthetic only (HMAC-SHA-256 placeholder).
- Real audit-chain anchoring (Sigstore Rekor). Contract proven, integration pending.
- Real WebAuthn server-side ceremony validation.
- Real SPIRE workload attestation.
- Real KMS-backed key derivation.
- Live-money readiness. The upstream `ai_money_safety_gate` correctly reports `BLOCKED_REAL_FUNDS` until L3 capped-live tests pass.

These are integration work **on top of** this library, not changes inside it.

### Provenance

The synthetic gates upstream (Python) pass identical contracts. Cross-language parity is enforced by the canonical-hash test vector matrix. Full operational context lives at https://technosocialism.ai/diligence and https://technosocialism.ai/demo.

[0.1.0]: https://github.com/CrunchyJohnHaven/broker-fire/releases/tag/v0.1.0
