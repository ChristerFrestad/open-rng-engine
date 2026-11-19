// R-K1-BIND: J3 bit-identity, reps 0..49 (see test/r-k1-bind-lib.mjs). This file: the coverage pin and the
// randomInt/Lehmer coupon-collector entries other than entry 9.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { J3, FAST, SLOW, ENTRIES, REPS, BIND_GROUPS, bindEntry } from './r-k1-bind-lib.mjs';

test('R-K1-BIND covers all 26 entries: the file groups are disjoint, cover 0..25, and each file binds its group', () => {
  assert.equal(ENTRIES.length, 26); assert.equal(J3.results.length, 26);
  const all = Object.values(BIND_GROUPS).flat().sort((a, b) => a - b);
  assert.deepEqual(all, Array.from({ length: 26 }, (_, i) => i));
  assert.deepEqual([...FAST, ...SLOW].sort((a, b) => a - b), all);
  for (const f of Object.keys(BIND_GROUPS)) assert.match(readFileSync(new URL(f, import.meta.url), 'utf8'), f === 'r-k1-bind-entry9.test.mjs' ? /bindEntry\(9\)/ : new RegExp(`BIND_GROUPS\\['${f.replace(/\./g, '\\.')}'\\]\\) test\\(`), f);
  J3.results.forEach((r) => assert.ok(r.pvalues.length >= REPS, r.id));
});
for (const i of BIND_GROUPS['r-k1-bind.test.mjs']) test(`R-K1-BIND entry ${i} ${ENTRIES[i].id}: reps 0..${REPS - 1} bit-identical to J3`, () => bindEntry(i));
