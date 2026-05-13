# @credexai/broker-fire

> Cryptographic gateway between AI agent intent and action. 15 falsifiable synthetic gates. TS-Python parity verified across 20 hash vectors. Zero dependencies. Apache 2.0.

```ts
import { brokerFire } from '@credexai/broker-fire';

const result = brokerFire({ panicStop: true, intentHash: 'sha256:x' });
// { outcome: 'deny', state: 'DENIED_BEFORE_FIRE', reasons: ['panic_stop'] }
```

## Why this exists

Every AI agent that touches sensitive operations — payments, deploys, mailbox reads, code merges — needs a deterministic gateway between **what the agent says it wants to do** and **what the system actually fires**. Today there isn't one.

This is the gateway. It refuses to fire unless it can reconstruct the full chain: identity binding, canonical intent, custody handle, policy decision, witness approval (when required), capability grant, fresh revocation epoch, unused idempotency key, durable pre-commit audit. Any link breaks → deny.

Attacks it structurally rejects:

- **Replay** — same idempotency key, same intent, second fire denies (`idempotency_replay`).
- **Race on revoke** — owner revoked between grant issue and fire time (`revocation_epoch_stale`).
- **Witness summary drift** — human attested to one summary; broker about to execute a different one (`witness_summary_mismatch`).
- **Evidence injection** — untrusted webpage / vendor reply tries to set a trusted authority field (`untrusted_authority`).
- **Tool poisoning** — MCP manifest with prompt-injection patterns in its description (`description_prompt_injection`).
- **Provider success forgery** — provider returned 200 OK with no signed webhook (`provider_receipt_unverified` → `indeterminate`).
- **Cross-tenant bleed** — agent in tenant A using custody handle from tenant B (`cross_tenant_violation`).
- **Native-message bypass** — content script or native messaging route did not traverse the gateway (`local_holder_bypass`).

For the complete deny-reason set see [`src/broker_fire.ts`](src/broker_fire.ts).

## Install

```bash
npm install github:CrunchyJohnHaven/broker-fire
# or, once published to npm:
npm install @credexai/broker-fire
```

Node ≥18. Zero runtime dependencies.

## Quickstart

```ts
import { brokerFire, denyEnvelope } from '@credexai/broker-fire';

// Build a request envelope as your agent runtime composes it.
const request = {
  entryPoint: 'payment_action',
  riskClass: 'financial',
  environment: 'live',
  intentHash: 'sha256:intent-pay-001',
  custodyHandleId: 'custody:marketplace.primary',
  policyDecisionId: 'decision_pay_001',
  policyResult: 'allow' as const,
  witnessApprovalId: 'approval_owner_001',
  grantJti: 'grant_pay_001',
  grantIntentHash: 'sha256:intent-pay-001',
  grantIdempotencyKey: 'idem_pay_001',
  auditEventId: 'audit_pre_001',
  auditPreCommitBeforeFire: true,
};

const result = brokerFire(request);

if (result.outcome === 'allow') {
  // Safe to fire the side effect through the broker.
  // The post-fire path (verified receipt + post-commit) is your runtime's job.
} else if (result.outcome === 'deny') {
  // Return the envelope to the caller; never fire.
  return denyEnvelope('payment.charge', result);
} else {
  // outcome === 'indeterminate' — enter recovery state machine.
  // Provider receipt unverified or post-commit missing. Do NOT claim success.
}
```

## Canonical policy hash (cross-language)

The TypeScript canonical-JSON hasher produces byte-identical SHA-256 output to the Python reference implementation. Verified across 20 test vectors. Use it whenever you hash a `POLICY_INPUT`, `CANONICAL_INTENT`, `POLICY_DECISION`, or `CAPABILITY_GRANT`.

```ts
import { canonicalHash } from '@credexai/broker-fire/canonical-hash';

canonicalHash({ b: 2, a: 1 });
// 'sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777'

canonicalHash({ a: 1, b: 2 });
// Same hash — keys are sorted before hashing.

canonicalHash({ price: 1.5 });
// Throws CanonicalJSONError('float_rejected'). Floats are not deterministic
// across languages. Use integer minor units.
```

Rules: sorted keys (Unicode code-point order), no whitespace, UTF-8 output, strings NFC-normalized (non-NFC denies), integers only (floats and `1e3` form refused), arrays preserve order, no duplicate keys.

## What it proves (the gate matrix)

| Gate | What it proves | Cases |
|---|---|---|
| `broker_fire_state_machine` | Full RECEIVED → RECEIPTED state machine with cached + indeterminate paths | 34 |
| `non_bypassable_enforcement` | Entry-point gateway across 13 surfaces (provider, browser, native, CLI, ...) | 45 |
| `witness_summary_binding` | WebAuthn-style witness binding to deterministic summary | 30 |
| `recovery_state_machine` | RECOVERY_REQUIRED → success / rolled_back / denied / irrecoverable | 18 |
| `vault_protocol_repair` | 11-interface repair chain (identity / epoch / idempotency / 2-phase audit) | 16 |
| `broker_authority_boundary` | Permission semantics + delegation invariants | 20 |
| `vault_non_exposure` | Synthetic canaries across 9 sinks; no secret leakage | 11 |
| `vault_policy_enforcement` | Fail-closed policy decisions with typed input | 13 |
| `tenant_isolation` | Per-tenant derived keys; cross-tenant cryptographic refusal | 27 |
| `audit_chain_anchor` | Internal hash chain + external Merkle anchor + append-only | 23 |
| `revocation_propagation` | Per-owner monotonic epoch + bounded staleness budget | 23 |
| `reputation_v0` | Counterparty receipts + portable cards + gaming detection | 23 |
| `workload_attestation` | SPIRE / TPM / Secure Enclave / IMA binding contract | 23 |
| `provider_receipt_verifier` | HMAC-over-raw-body + intent/idempotency match | 23 |
| `opus100_002_wal_idempotency` | Local WAL idempotency lock + crash-restart cached equivalence | 19 |
| `opus100_023_canonical_hash` | Canonical JSON with cross-language hash parity | 20 |
| `opus100_100_mcp_manifest` | Signed MCP / tool manifest provenance + prompt-injection scan | 21 |
| `broker_fire_ts_parity` | TS runtime port at parity with Python evaluator | 15 |
| **Total** | — | **404** |

Run the gates against the upstream specification: see [credexai/docs/operations/ENGINEERING_COMPLETE_REPORT_2026-05-12.md](https://technosocialism.ai/diligence).

## What this library does NOT do

It does not perform real cryptographic signature verification, real audit-chain anchoring to Sigstore Rekor, real WebAuthn server-side ceremony validation, real SPIRE workload attestation, or real KMS-backed key derivation. Those are integration work **on top of** the contract this library enforces. The synthetic evaluator proves the binding contract; production wiring per surface remains.

This library also does not claim live-money readiness, PCI compliance, SOC 2, or any external audit. The upstream `ai_money_safety_gate` correctly reports `BLOCKED_REAL_FUNDS` by design until L3 capped-live tests pass.

## The 11-interface spine

```
UNTRUSTED_EVIDENCE ▸ AGENT_IDENTITY_BINDING ▸ CANONICAL_INTENT ▸
CUSTODY_HANDLE ▸ POLICY_INPUT ▸ POLICY_DECISION ▸ WITNESS_APPROVAL ▸
CAPABILITY_GRANT ▸ PRE_COMMIT_AUDIT ▸ BROKER_ACTION_RESULT ▸
POST_COMMIT_AUDIT
```

Each stage is a contract. `brokerFire` enforces it. The synthetic gates falsify it. The integration work wires it.

## Falsifiers the test suite exercises

`panic_stop`, `untrusted_authority`, `raw_secret_output`, `agent_svid_invalid`, `cross_tenant_violation`, `identity_revocation_epoch_stale`, `missing_intent_hash`, `missing_custody_handle`, `missing_policy_decision`, `policy_deny`, `policy_witness_required`, `stale_policy`, `missing_witness`, `witness_summary_mismatch`, `missing_grant`, `grant_intent_mismatch`, `broker_target_mismatch`, `revocation_epoch_stale`, `witness_epoch_stale`, `idempotency_replay`, `missing_audit_precommit`, `side_effect_before_pre_commit`, `provider_success_ignored`, `browser_success_ignored`, `native_holder_success_ignored`, `dom_success_ignored`, `local_holder_bypass`, `provider_receipt_unverified`, `missing_post_commit`, `recovery_required`.

Every reason is structurally testable. No reason fires from "the model judged it bad."

## Tests

```bash
npm install
npm test
# → broker_fire e2e: PASS 15/15
# → canonical_policy_hash parity: PASS 20/20
```

## Try it without installing

[`https://technosocialism.ai/demo`](https://technosocialism.ai/demo) — the same evaluator, runs in your browser, no network, no server.

## Reading list

- The manifesto: [`https://technosocialism.ai`](https://technosocialism.ai)
- The diligence room: [`https://technosocialism.ai/diligence`](https://technosocialism.ai/diligence)
- The lessons-for-future-models on how the gates are built: see the upstream operations directory.

## Contributing

Pull requests welcome. Hard rules:

1. **The library has zero runtime dependencies.** Keep it that way.
2. **Every new check fires a single named deny reason.** Add it to the reason-code documentation.
3. **TypeScript ↔ Python parity is enforced.** If you change `canonical_policy_hash.ts`, the parity test must still pass against unchanged Python vectors.
4. **No "the model decides" judgment calls.** Every check is a deterministic predicate over typed fields.

## License

Apache 2.0. Copyright 2026 John Bradley and contributors.

## Citation

If this library helps your research or product, cite it as:

> John Bradley et al. *broker-fire: cryptographic gateway between AI agent intent and action.* 2026. https://github.com/CrunchyJohnHaven/broker-fire

## What this answers

> Q: Can an AI agent fire a side effect outside the contract?
>
> A: No.
