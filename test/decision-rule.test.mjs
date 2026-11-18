// Spec F-15 (inputs/cto-g1-spec.md L58, L381): the decision-rule file is committed before the first evidence run id.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const FILE = 'verification/decision-rule-v1.md';
const tracked = execFileSync('git', ['ls-files'], { encoding: 'utf8' }).split('\n').filter(Boolean);

test('F-15: decision-rule file is tracked', () => {
  assert.ok(tracked.includes(FILE));
});

test('F-15: decision rule carries the frozen-rule constants from quality 3.2 / PLAN 4.4', () => {
  const s = readFileSync(FILE, 'utf8');
  for (const k of ['alpha = 0.01', 'fewer than 981 of 1,000', 'P-value_T < 0.0001', '1-5 flags', '>= 6 flags', '>= 4 flags', 'exactly once', 'NOT YET FROZEN']) {
    assert.ok(s.includes(k), k);
  }
});

test('F-15: no evidence run is tracked (evidence runs must come after this file)', () => {
  const runs = tracked.filter((p) => /(^|\/)(evidence-runs?|runs)\//.test(p) || /run-id/i.test(p));
  assert.deepEqual(runs, []);
});
