// Spec F-15 (inputs/cto-g1-spec.md L58, L381): the decision-rule file is committed before the first evidence run id.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const FILE = 'verification/decision-rule-v1.md';
const tracked = execFileSync('git', ['ls-files'], { encoding: 'utf8' }).split('\n').filter(Boolean);

test('F-15: decision-rule file is tracked', () => {
  assert.ok(tracked.includes(FILE));
});

test('F-15: decision rule v1 is the HoQ-FROZEN text, byte-identical (sha256 5d09c75a, 87 lines)', () => {
  const b = readFileSync(FILE);
  assert.equal(createHash('sha256').update(b).digest('hex'), '5d09c75a0fe9ab3679166d6705ba16f6d816f61b9924b2abec735cb45f2e022f');
  assert.equal(b.toString('utf8').split('\n').length - 1, 87);
});

test('F-15: no evidence run is tracked (evidence runs must come after this file)', () => {
  const runs = tracked.filter((p) => /(^|\/)(evidence-runs?|runs)\//.test(p) || /run-id/i.test(p));
  assert.deepEqual(runs, []);
});
