/**
 * broker_fire_e2e.ts — end-to-end parity test between the TS broker_fire
 * runtime and the Python synthetic gate.
 *
 * Run: `tsx test/broker_fire_e2e.ts`
 * Exit 0 = all assertions pass; non-zero = failures listed.
 *
 * This test does NOT contact the network, the vault store, or any
 * provider. It exercises the broker_fire contract under representative
 * cases drawn from the same taxonomy as the Python gates.
 */

import { brokerFire, denyEnvelope, strictModeEnabled } from '../src/broker_fire.js';

type Case = {
  id: string;
  expected: 'allow' | 'deny' | 'indeterminate';
  req: Parameters<typeof brokerFire>[0];
};

const cases: Case[] = [
  {
    id: 'metadata_gateway_allow',
    expected: 'allow',
    req: {
      entryPoint: 'provider_api_call',
      riskClass: 'metadata',
      intentHash: 'sha256:intent-meta',
      custodyHandleId: 'custody:vercel.primary',
      policyDecisionId: 'decision_meta',
      policyResult: 'allow',
      grantJti: 'grant_meta',
      grantIntentHash: 'sha256:intent-meta',
      auditEventId: 'audit_meta',
    },
  },
  {
    id: 'live_financial_witnessed_allow',
    expected: 'allow',
    req: {
      entryPoint: 'payment_action',
      riskClass: 'financial',
      environment: 'live',
      intentHash: 'sha256:intent-pay-ok',
      custodyHandleId: 'custody:marketplace.primary',
      policyDecisionId: 'decision_pay_ok',
      policyResult: 'allow',
      witnessApprovalId: 'approval_john',
      grantJti: 'grant_pay_ok',
      grantIntentHash: 'sha256:intent-pay-ok',
      auditEventId: 'audit_pay_ok',
    },
  },
  {
    id: 'panic_stop_deny',
    expected: 'deny',
    req: { panicStop: true, intentHash: 'sha256:x' },
  },
  {
    id: 'untrusted_authority_deny',
    expected: 'deny',
    req: { untrustedSetsTrustedFields: true, intentHash: 'sha256:x' },
  },
  {
    id: 'raw_secret_output_deny',
    expected: 'deny',
    req: { rawSecretOutputRequested: true, intentHash: 'sha256:x' },
  },
  {
    id: 'live_financial_no_witness_deny',
    expected: 'deny',
    req: {
      entryPoint: 'payment_action',
      riskClass: 'financial',
      environment: 'live',
      intentHash: 'sha256:intent-pay',
      custodyHandleId: 'custody:marketplace.primary',
      policyDecisionId: 'decision_pay',
      policyResult: 'allow',
      grantJti: 'grant_pay',
      grantIntentHash: 'sha256:intent-pay',
      auditEventId: 'audit_pay',
    },
  },
  {
    id: 'grant_intent_mismatch_deny',
    expected: 'deny',
    req: {
      entryPoint: 'provider_api_call',
      riskClass: 'metadata',
      intentHash: 'sha256:intent-final',
      custodyHandleId: 'custody:vercel.primary',
      policyDecisionId: 'decision_mm',
      policyResult: 'allow',
      grantJti: 'grant_mm',
      grantIntentHash: 'sha256:intent-old',
      auditEventId: 'audit_mm',
    },
  },
  {
    id: 'cross_tenant_violation_deny',
    expected: 'deny',
    req: {
      entryPoint: 'provider_api_call',
      riskClass: 'metadata',
      tenantId: 'tenant_a',
      custodyTenantId: 'tenant_b',
      intentHash: 'sha256:intent-cross',
      custodyHandleId: 'custody:other-tenant.primary',
      policyDecisionId: 'decision_cross',
      policyResult: 'allow',
      grantJti: 'grant_cross',
      grantIntentHash: 'sha256:intent-cross',
      auditEventId: 'audit_cross',
    },
  },
  {
    id: 'idempotency_replay_deny',
    expected: 'deny',
    req: {
      entryPoint: 'provider_api_call',
      riskClass: 'metadata',
      intentHash: 'sha256:intent-replay',
      custodyHandleId: 'custody:vercel.primary',
      policyDecisionId: 'decision_replay',
      policyResult: 'allow',
      grantJti: 'grant_replay',
      grantIntentHash: 'sha256:intent-replay',
      grantIdempotencyKey: 'idem_001',
      consumedIdempotencyKeys: ['idem_001'],
      auditEventId: 'audit_replay',
    },
  },
  {
    id: 'revocation_epoch_stale_deny',
    expected: 'deny',
    req: {
      entryPoint: 'provider_api_call',
      riskClass: 'metadata',
      intentHash: 'sha256:intent-rev',
      custodyHandleId: 'custody:vercel.primary',
      policyDecisionId: 'decision_rev',
      policyResult: 'allow',
      grantJti: 'grant_rev',
      grantIntentHash: 'sha256:intent-rev',
      grantRevocationEpochAtGrant: 7,
      currentRevocationEpoch: 8,
      identityRevocationEpochSeen: 8,
      auditEventId: 'audit_rev',
    },
  },
  {
    id: 'side_effect_before_pre_commit_deny',
    expected: 'deny',
    req: {
      entryPoint: 'provider_api_call',
      riskClass: 'metadata',
      intentHash: 'sha256:intent-late',
      custodyHandleId: 'custody:vercel.primary',
      policyDecisionId: 'decision_late',
      policyResult: 'allow',
      grantJti: 'grant_late',
      grantIntentHash: 'sha256:intent-late',
      auditEventId: 'audit_late',
      auditPreCommitBeforeFire: false,
    },
  },
  {
    id: 'witness_summary_mismatch_deny',
    expected: 'deny',
    req: {
      entryPoint: 'payment_action',
      riskClass: 'financial',
      environment: 'live',
      intentHash: 'sha256:intent-wm',
      custodyHandleId: 'custody:marketplace.primary',
      policyDecisionId: 'decision_wm',
      policyResult: 'allow',
      witnessApprovalId: 'approval_x',
      witnessSummaryHashMatches: false,
      grantJti: 'grant_wm',
      grantIntentHash: 'sha256:intent-wm',
      auditEventId: 'audit_wm',
    },
  },
  {
    id: 'native_message_bypass_deny',
    expected: 'deny',
    req: {
      entryPoint: 'native_message',
      riskClass: 'secret',
      environment: 'live',
      gatewayTraversed: false,
      intentHash: 'sha256:intent-nm',
      custodyHandleId: 'custody:host.native',
      policyDecisionId: 'decision_nm',
      policyResult: 'allow',
      witnessApprovalId: 'approval_john',
      grantJti: 'grant_nm',
      grantIntentHash: 'sha256:intent-nm',
      auditEventId: 'audit_nm',
    },
  },
  {
    id: 'provider_receipt_unverified_indeterminate',
    expected: 'indeterminate',
    req: {
      entryPoint: 'payment_action',
      riskClass: 'financial',
      environment: 'live',
      intentHash: 'sha256:intent-pruv',
      custodyHandleId: 'custody:marketplace.primary',
      policyDecisionId: 'decision_pruv',
      policyResult: 'allow',
      witnessApprovalId: 'approval_john',
      grantJti: 'grant_pruv',
      grantIntentHash: 'sha256:intent-pruv',
      auditEventId: 'audit_pruv',
      providerReceiptVerified: false,
    },
  },
  {
    id: 'missing_post_commit_indeterminate',
    expected: 'indeterminate',
    req: {
      entryPoint: 'provider_api_call',
      riskClass: 'metadata',
      intentHash: 'sha256:intent-mpc',
      custodyHandleId: 'custody:vercel.primary',
      policyDecisionId: 'decision_mpc',
      policyResult: 'allow',
      grantJti: 'grant_mpc',
      grantIntentHash: 'sha256:intent-mpc',
      auditEventId: 'audit_mpc',
      postCommitPresent: false,
    },
  },
];

function main(): number {
  const failures: { id: string; expected: string; actual: string; reasons: string[] }[] = [];
  for (const c of cases) {
    const result = brokerFire(c.req);
    if (result.outcome !== c.expected) {
      failures.push({
        id: c.id,
        expected: c.expected,
        actual: result.outcome,
        reasons: result.reasons,
      });
    }
  }

  const total = cases.length;
  const passed = total - failures.length;
  console.log(`broker_fire e2e: ${failures.length ? 'FAIL' : 'PASS'} ${passed}/${total}`);
  console.log(`strict_mode_enabled: ${strictModeEnabled()}`);

  for (const c of cases) {
    const result = brokerFire(c.req);
    const status = result.outcome === c.expected ? 'PASS' : 'FAIL';
    const reasons = result.reasons.length ? result.reasons.join(',') : 'none';
    console.log(`${status} ${c.id}: expected=${c.expected} actual=${result.outcome} reasons=${reasons}`);
  }

  if (failures.length) {
    console.log('\nFailures:');
    for (const f of failures) {
      console.log(`  ${f.id}: expected=${f.expected} actual=${f.actual} reasons=${f.reasons.join(',')}`);
    }
    return 1;
  }

  // Smoke-test the deny envelope helper.
  const denyResult = brokerFire({ panicStop: true, intentHash: 'sha256:x' });
  const envelope = denyEnvelope('test.action', denyResult);
  if (envelope.code !== 'BROKER_FIRE_DENIED') {
    console.log(`FAIL deny_envelope_code: ${envelope.code}`);
    return 1;
  }
  console.log('PASS deny_envelope_smoke');

  return 0;
}

process.exit(main());
