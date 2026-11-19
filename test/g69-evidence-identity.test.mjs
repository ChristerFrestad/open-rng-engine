// G-69 GM-3/GM-5: evidence path = THE module on the same real outcome records, entries other than entry 9
// (entry 9 is in test/r-k1-bind-entry9.test.mjs; see test/r-k1-bind-lib.mjs).
import { test } from 'node:test';
import { FAST, ENTRIES, identityEntry } from './r-k1-bind-lib.mjs';

for (const i of FAST) test(`G-69 identity entry ${i} ${ENTRIES[i].id}: evidence path = THE module on the same records`, () => identityEntry(i));
