// R-K1-BIND: J3 bit-identity, reps 0..49, for the duplicates entries 12..23 (see test/r-k1-bind-lib.mjs).
import { test } from 'node:test';
import { ENTRIES, REPS, BIND_GROUPS, bindEntry } from './r-k1-bind-lib.mjs';

for (const i of BIND_GROUPS['r-k1-bind-dup.test.mjs']) test(`R-K1-BIND entry ${i} ${ENTRIES[i].id}: reps 0..${REPS - 1} bit-identical to J3`, () => bindEntry(i));
