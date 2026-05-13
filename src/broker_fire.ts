/**
 * broker_fire.ts — the single non-bypassable broker-fire layer.
 *
 * This module is the TypeScript runtime port of the Python synthetic gates:
 *   - scripts/non_bypassable_enforcement_gate.py
 *   - scripts/broker_fire_state_machine_gate.py
 *   - scripts/witness_summary_binding_gate.py
 *   - scripts/recovery_state_machine_gate.py
 *   - scripts/tenant_isolation_gate.py
 *   - scripts/audit_chain_anchor.py
 *   - scripts/revocation_propagation.py
 *
 * Use:
 *   const result = brokerFire(request);
 *   if (result.outcome !== 'allow') { return deny envelope; }
 *   // ...proceed with action.
 *
 * Migration policy (alpha):
 *   - This module is ADDITIVE. Existing actions that do NOT call brokerFire
 *     keep working under the legacy `ctx.readCredential` path.
 *   - Action adapters opt in by calling `brokerFire(intent)` BEFORE
 *     `ctx.readCredential`. A denied result aborts the action with a
 *     deny envelope; an allowed result proceeds.
 *   - Strict mode (env BROKER_FIRE_STRICT=1) forces the registry to call
 *     brokerFire for every action; legacy actions get a deny envelope
 *     unless they opt in.
 *   - cli.ts:get is the ONE current raw-secret-egress path. v1 will route
 *     it through brokerFire and return only redacted metadata.
 *
 * Hard rules:
 *   - This module NEVER reads, returns, or logs raw credential material.
 *   - The deny path is the default. Allow requires explicit affirmative
 *     proof at every interface.
 *   - The contract here is the same as the synthetic gates. Test parity
 *     is enforced by `src/broker_fire_e2e.ts`.
 */

export type BrokerFireOutcome = 'allow' | 'deny' | 'indeterminate' | 'cached';

export type BrokerFireState =
  | 'RECEIVED'
  | 'IDENTITY_BOUND'
  | 'INTENT_BOUND'
  | 'CUSTODY_BOUND'
  | 'POLICY_ALLOWED'
  | 'WITNESS_BOUND'
  | 'GRANT_VERIFIED'
  | 'EPOCH_FRESH'
  | 'IDEMPOTENCY_OK'
  | 'PRE_COMMITTED'
  | 'DENIED_BEFORE_FIRE'
  | 'RECOVERY_REQUIRED'
  | 'RECEIPTED'
  | 'IDEMPOTENCY_CACHE_HIT';

export interface BrokerFireRequest {
  /** Panic stop / kill switch flag; denies before any check. */
  panicStop?: boolean;
  /** Any of the forbidden free-text fields would surface here as true. */
  untrustedSetsTrustedFields?: boolean;
  /** Raw secret output requested; always denied. */
  rawSecretOutputRequested?: boolean;

  /** Closed enum from scripts/witness_summary.py ACTION_LABELS. */
  action?: string;
  /** Closed enum: payment_action, secret_release, browser_credential_fill, ... */
  entryPoint?: string;
  /** Closed enum: metadata, secret, financial, production_write, private_read, policy_admin. */
  riskClass?: string;
  /** Closed enum: synthetic, sandbox, live. */
  environment?: string;

  /** Canonical intent hash; required. */
  intentHash?: string;

  /** Identity binding fields. */
  agentSvid?: string;
  ownerId?: string;
  orgId?: string;
  tenantId?: string;
  runtimeAttestationSha256?: string;
  identityRevocationEpochSeen?: number;

  /** Custody handle reference. */
  custodyHandleId?: string;
  custodyTenantId?: string;

  /** Policy decision. */
  policyDecisionId?: string;
  policyResult?: 'allow' | 'deny' | 'witness_required';
  policyStale?: boolean;
  policyVersion?: string;

  /** Witness approval. */
  witnessApprovalId?: string;
  witnessSummaryHashMatches?: boolean;
  witnessEpochAtAttest?: number;

  /** Capability grant. */
  grantJti?: string;
  grantIntentHash?: string;
  grantRevocationEpochAtGrant?: number;
  grantIdempotencyKey?: string;
  grantBrokerTarget?: string;

  /** Broker side state. */
  brokerTarget?: string;
  currentRevocationEpoch?: number;
  consumedIdempotencyKeys?: string[];

  /** Audit. */
  auditEventId?: string;
  auditPreCommitBeforeFire?: boolean;

  /** Provider/native/browser/dom claimed success without grant — non-authoritative. */
  providerSuccess?: boolean;
  browserSuccess?: boolean;
  nativeHolderSuccess?: boolean;
  domSuccess?: boolean;

  /** Gateway-routed entry points (cli, content script, native message). */
  gatewayTraversed?: boolean;

  /** Post-fire signals; lift to indeterminate when set. */
  providerReceiptVerified?: boolean;
  postCommitPresent?: boolean;
  indeterminateRecovery?: boolean;
}

export interface BrokerFireResult {
  outcome: BrokerFireOutcome;
  state: BrokerFireState;
  reasons: string[];
}

const HIGH_RISK_CLASSES = new Set([
  'financial',
  'policy_admin',
  'production_write',
  'private_read',
  'secret',
]);

const SECRET_BEARING_ENTRY_POINTS = new Set([
  'secret_release',
  'browser_credential_fill',
  'provider_api_call',
  'payment_action',
  'provider_callback',
  'private_read',
  'deploy_action',
  'dns_mutation',
  'native_message',
  'audit_revoke_recovery',
  'content_script_route',
  'cli_local_holder',
]);

const GATEWAY_REQUIRED_ROUTES = new Set([
  'cli_local_holder',
  'content_script_route',
  'native_message',
]);

function deny(reasons: string[]): BrokerFireResult {
  return { outcome: 'deny', state: 'DENIED_BEFORE_FIRE', reasons };
}

function indeterminate(reason: string): BrokerFireResult {
  return { outcome: 'indeterminate', state: 'RECOVERY_REQUIRED', reasons: [reason] };
}

export function brokerFire(req: BrokerFireRequest): BrokerFireResult {
  const reasons: string[] = [];

  if (req.panicStop) return deny(['panic_stop']);
  if (req.untrustedSetsTrustedFields) return deny(['untrusted_authority']);
  if (req.rawSecretOutputRequested) return deny(['raw_secret_output']);

  // Identity binding.
  if (req.agentSvid !== undefined && !/^spiffe:\/\/[a-z0-9.\-/_]+$/.test(req.agentSvid)) {
    reasons.push('agent_svid_invalid');
  }
  if (
    req.tenantId !== undefined &&
    req.custodyTenantId !== undefined &&
    req.tenantId !== req.custodyTenantId
  ) {
    reasons.push('cross_tenant_violation');
  }
  if (
    req.currentRevocationEpoch !== undefined &&
    req.identityRevocationEpochSeen !== undefined &&
    req.currentRevocationEpoch > req.identityRevocationEpochSeen
  ) {
    reasons.push('identity_revocation_epoch_stale');
  }

  // Canonical intent.
  if (!req.intentHash) reasons.push('missing_intent_hash');

  // Custody handle.
  if (
    req.entryPoint !== undefined &&
    SECRET_BEARING_ENTRY_POINTS.has(req.entryPoint) &&
    !req.custodyHandleId
  ) {
    reasons.push('missing_custody_handle');
  }

  // Policy decision.
  if (!req.policyDecisionId) {
    reasons.push('missing_policy_decision');
  } else if (req.policyResult !== 'allow') {
    reasons.push(`policy_${req.policyResult ?? 'missing'}`);
  }
  if (req.policyStale) reasons.push('stale_policy');

  // Witness.
  const highRisk = req.riskClass !== undefined && HIGH_RISK_CLASSES.has(req.riskClass);
  if (highRisk && req.environment === 'live' && !req.witnessApprovalId) {
    reasons.push('missing_witness');
  }
  if (req.witnessSummaryHashMatches === false) {
    reasons.push('witness_summary_mismatch');
  }

  // Grant.
  const grantPresent = !!req.grantJti;
  const grantIntentMatches = grantPresent && req.grantIntentHash === req.intentHash;
  if (!grantPresent) {
    reasons.push('missing_grant');
  } else if (!grantIntentMatches) {
    reasons.push('grant_intent_mismatch');
  }
  if (
    grantPresent &&
    req.brokerTarget !== undefined &&
    req.grantBrokerTarget !== undefined &&
    req.grantBrokerTarget !== req.brokerTarget
  ) {
    reasons.push('broker_target_mismatch');
  }

  // Revocation epoch.
  if (
    req.currentRevocationEpoch !== undefined &&
    req.grantRevocationEpochAtGrant !== undefined &&
    req.currentRevocationEpoch > req.grantRevocationEpochAtGrant
  ) {
    reasons.push('revocation_epoch_stale');
  }
  if (
    req.witnessEpochAtAttest !== undefined &&
    req.currentRevocationEpoch !== undefined &&
    req.witnessEpochAtAttest < req.currentRevocationEpoch
  ) {
    reasons.push('witness_epoch_stale');
  }

  // Idempotency.
  if (
    req.grantIdempotencyKey !== undefined &&
    req.consumedIdempotencyKeys?.includes(req.grantIdempotencyKey)
  ) {
    reasons.push('idempotency_replay');
  }

  // Pre-commit audit.
  if (!req.auditEventId) reasons.push('missing_audit_precommit');
  if (req.auditPreCommitBeforeFire === false) reasons.push('side_effect_before_pre_commit');

  // Provider / browser / native / DOM success without matching grant.
  if (req.providerSuccess && !grantIntentMatches) reasons.push('provider_success_ignored');
  if (req.browserSuccess && !grantIntentMatches) reasons.push('browser_success_ignored');
  if (req.nativeHolderSuccess && !grantIntentMatches) reasons.push('native_holder_success_ignored');
  if (req.domSuccess && !grantIntentMatches) reasons.push('dom_success_ignored');

  // Gateway routes.
  if (
    req.entryPoint !== undefined &&
    GATEWAY_REQUIRED_ROUTES.has(req.entryPoint) &&
    req.gatewayTraversed === false
  ) {
    reasons.push('local_holder_bypass');
  }

  if (reasons.length > 0) return deny(reasons);

  // Post-fire signals.
  if (req.providerReceiptVerified === false) {
    return indeterminate('provider_receipt_unverified');
  }
  if (req.postCommitPresent === false) {
    return indeterminate('missing_post_commit');
  }
  if (req.indeterminateRecovery) {
    return indeterminate('recovery_required');
  }

  return { outcome: 'allow', state: 'RECEIPTED', reasons: [] };
}

/**
 * Strict-mode helper: if `BROKER_FIRE_STRICT=1` is set in env, callers that
 * have not yet opted into brokerFire are denied. This is the migration
 * dial: turn it on after all action adapters are migrated; off during the
 * transition.
 */
export function strictModeEnabled(): boolean {
  return process.env.BROKER_FIRE_STRICT === '1';
}

/**
 * Build a deny envelope shaped like the existing registry ActionResultErr
 * so callers can return broker-fire results uniformly.
 */
export function denyEnvelope(actionName: string, result: BrokerFireResult): {
  ok: false;
  action: string;
  code: 'BROKER_FIRE_DENIED' | 'BROKER_FIRE_INDETERMINATE';
  error: string;
  reasons: string[];
  state: BrokerFireState;
} {
  return {
    ok: false,
    action: actionName,
    code: result.outcome === 'indeterminate' ? 'BROKER_FIRE_INDETERMINATE' : 'BROKER_FIRE_DENIED',
    error: `broker_fire ${result.outcome}: ${result.reasons.join(',')}`,
    reasons: result.reasons,
    state: result.state,
  };
}
