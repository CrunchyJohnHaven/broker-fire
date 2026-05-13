/**
 * canonical_policy_hash.ts — TypeScript port of
 * `scripts/opus100_023_canonical_policy_hash.py`.
 *
 * Identical rules; identical output. Cross-language parity is verified by
 * `canonical_policy_hash_parity_test.ts` against the shared vector JSONL.
 *
 * R1. Object keys sorted by Unicode code-point order.
 * R2. No whitespace between tokens.
 * R3. UTF-8 encoded byte output.
 * R4. Strings NFC-normalized; non-NFC input → REJECT.
 * R5. Integers: bare digits, no leading zeros (except literal 0).
 * R6. Floats: REJECTED entirely.
 * R7. Booleans: lowercase true / false.
 * R8. Null: literal null.
 * R9. Arrays preserve insertion order.
 * R10. No duplicate keys at any depth.
 */

import { createHash } from 'node:crypto';

export type Canonical =
  | null
  | boolean
  | number
  | string
  | Canonical[]
  | { [key: string]: Canonical };

export class CanonicalJSONError extends Error {
  code: string;
  context: Record<string, unknown>;
  constructor(code: string, context: Record<string, unknown> = {}) {
    super(`${code}: ${JSON.stringify(context)}`);
    this.code = code;
    this.context = context;
  }
}

const INT_PATTERN = /^-?(0|[1-9][0-9]*)$/;

function isPlainObject(value: unknown): value is Record<string, Canonical> {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function canonicalize(value: unknown, path: string = '$'): string {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new CanonicalJSONError('float_rejected', { at: path, value: String(value) });
    }
    if (!Number.isInteger(value)) {
      throw new CanonicalJSONError('float_rejected', { at: path, value });
    }
    return String(value);
  }

  if (typeof value === 'string') {
    const normalized = value.normalize('NFC');
    if (normalized !== value) {
      throw new CanonicalJSONError('non_nfc_string', { at: path });
    }
    return JSON.stringify(normalized);
  }

  if (Array.isArray(value)) {
    const items = value.map((v, i) => canonicalize(v, `${path}[${i}]`));
    return '[' + items.join(',') + ']';
  }

  if (isPlainObject(value)) {
    const keys = Object.keys(value);
    for (const k of keys) {
      const nk = k.normalize('NFC');
      if (nk !== k) throw new CanonicalJSONError('non_nfc_key', { at: path });
    }
    // Duplicate-key check: JS object literal cannot truly hold duplicates,
    // but we still surface any post-NFC collision.
    const counts: Record<string, number> = {};
    for (const k of keys) counts[k] = (counts[k] || 0) + 1;
    const dup = Object.entries(counts).filter(([, c]) => c > 1).map(([k]) => k);
    if (dup.length > 0) throw new CanonicalJSONError('duplicate_key', { at: path, keys: dup });
    const sorted = [...keys].sort();
    const parts = sorted.map(k => {
      const kv = JSON.stringify(k);
      const v = canonicalize((value as Record<string, unknown>)[k], `${path}.${k}`);
      return `${kv}:${v}`;
    });
    return '{' + parts.join(',') + '}';
  }

  throw new CanonicalJSONError('unknown_type', { at: path, type: typeof value });
}

export function canonicalJSON(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

export function canonicalHash(value: unknown): string {
  const text = canonicalize(value);
  const hash = createHash('sha256').update(Buffer.from(text, 'utf-8')).digest('hex');
  return `sha256:${hash}`;
}
