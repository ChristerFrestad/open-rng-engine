// Entry 9 (randomInt/coupon-collector/min-0-max-4294967297): R-K1-BIND J3 bit-identity (reps 0..49) and the
// G-69 evidence-path identity, in their own file because the exact law costs minutes (test/r-k1-bind-lib.mjs).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SLOW, ENTRIES, bindEntry, identityEntry } from './r-k1-bind-lib.mjs';

test('entry 9 is the only slow entry and is the one bound here', () => { assert.deepEqual(SLOW, [9]); assert.equal(ENTRIES[9].id, 'randomInt/coupon-collector/min-0-max-4294967297'); });
test(`R-K1-BIND entry 9 ${ENTRIES[9].id}: reps 0..49 bit-identical to J3`, () => bindEntry(9));
test(`G-69 identity entry 9 ${ENTRIES[9].id}: evidence path = THE module on the same records`, () => identityEntry(9));
