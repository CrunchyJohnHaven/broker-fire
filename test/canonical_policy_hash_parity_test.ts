/**
 * canonical_policy_hash_parity_test.ts
 *
 * Cross-language parity test for OPUS100-021 + 023 + 093. Reads the same
 * vector JSONL the Python gate reads and verifies TypeScript produces
 * IDENTICAL canonical hashes.
 *
 * Run: tsx test/canonical_policy_hash_parity_test.ts
 * Exit 0 = parity holds; non-zero = TS and Python disagree somewhere.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { canonicalHash, CanonicalJSONError } from '../src/canonical_policy_hash.js';

type Vector =
  | { id: string; op: 'hash_equals'; expect: 'match'; input: unknown; expected_hash: string }
  | { id: string; op: 'hash_rejects'; expect: 'rejected'; input: unknown; expected_error_code: string }
  | { id: string; op: 'hash_differs'; expect: 'differs'; input_a: unknown; input_b: unknown };

function loadVectors(): Vector[] {
  const path = resolve(
    process.cwd(),
    'test/vectors/canonical_policy_hash_vectors.jsonl',
  );
  const raw = readFileSync(path, 'utf-8');
  const lines = raw.split('\n').filter(l => l.trim().length > 0);
  return lines.map((l, i) => {
    try {
      return JSON.parse(l) as Vector;
    } catch (e) {
      throw new Error(`line ${i + 1}: invalid JSON: ${(e as Error).message}`);
    }
  });
}

function evaluate(vec: Vector): { status: 'PASS' | 'FAIL'; detail: string } {
  if (vec.op === 'hash_equals') {
    try {
      const actual = canonicalHash(vec.input);
      if (actual === vec.expected_hash) {
        return { status: 'PASS', detail: actual };
      }
      return { status: 'FAIL', detail: `expected ${vec.expected_hash}, got ${actual}` };
    } catch (e) {
      const code = e instanceof CanonicalJSONError ? e.code : (e as Error).message;
      return { status: 'FAIL', detail: `unexpected reject: ${code}` };
    }
  }
  if (vec.op === 'hash_rejects') {
    try {
      const accepted = canonicalHash(vec.input);
      return { status: 'FAIL', detail: `unexpected accept: ${accepted}` };
    } catch (e) {
      if (e instanceof CanonicalJSONError) {
        if (e.code === vec.expected_error_code) return { status: 'PASS', detail: e.code };
        return { status: 'FAIL', detail: `wrong code: ${e.code}` };
      }
      return { status: 'FAIL', detail: `non-canonical error: ${(e as Error).message}` };
    }
  }
  if (vec.op === 'hash_differs') {
    try {
      const ha = canonicalHash(vec.input_a);
      const hb = canonicalHash(vec.input_b);
      if (ha !== hb) return { status: 'PASS', detail: `${ha} != ${hb}` };
      return { status: 'FAIL', detail: `collision: both ${ha}` };
    } catch (e) {
      return { status: 'FAIL', detail: `unexpected reject: ${(e as Error).message}` };
    }
  }
  return { status: 'FAIL', detail: `unknown op` };
}

function main(): number {
  const vectors = loadVectors();
  let pass = 0;
  let fail = 0;
  const failures: string[] = [];
  for (const vec of vectors) {
    const result = evaluate(vec);
    if (result.status === 'PASS') {
      pass++;
    } else {
      fail++;
      failures.push(`${vec.id}: ${result.detail}`);
    }
  }
  console.log(`canonical_policy_hash parity: ${fail === 0 ? 'PASS' : 'FAIL'} ${pass}/${pass + fail}`);
  for (const vec of vectors) {
    const result = evaluate(vec);
    console.log(`${result.status} ${vec.id} [${vec.op}]: ${result.detail.slice(0, 100)}`);
  }
  if (failures.length > 0) {
    console.log('\nFailures:');
    failures.forEach(f => console.log(`  ${f}`));
  }
  return fail === 0 ? 0 : 1;
}

process.exit(main());
