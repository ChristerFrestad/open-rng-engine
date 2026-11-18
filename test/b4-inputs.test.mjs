// B-4 inputs (CPO-R107), copied byte-identical from /workspace/rng-backup/b4-prep/ (v1.1 rewording per CTO option (a)).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const PINS = {
  'verification/k-tests-v1.1.json': 'f75299de7fa063b96e2a031ec7072ed4fe34f219a4bc04e3534125b973097c4c',
  'verification/tool-pins-v1.1.json': '605e9a9973d754b1211c3d2e6ebe5202c28ee3656c988fa0203a0d68da899f8b',
  'verification/m153-harness-mutant.md': '0b017faaecacc1cff74236b5f4d5ae1eab7bcea1ba4e76e69d2cbea92c72b275',
};

test('B-4 inputs are byte-identical (sha256)', () => {
  for (const [p, sha] of Object.entries(PINS)) assert.equal(createHash('sha256').update(readFileSync(p)).digest('hex'), sha, p);
});

test('k-tests-v1.1.json: 157 entries (R68 S19 P40 W30), unique ids, n = 1e9 everywhere', () => {
  const k = JSON.parse(readFileSync('verification/k-tests-v1.1.json', 'utf8'));
  assert.equal(k.tests.length, 157);
  const c = {}; for (const e of k.tests) c[e.family] = (c[e.family] ?? 0) + 1;
  assert.deepEqual(c, { R: 68, S: 19, P: 40, W: 30 });
  assert.equal(new Set(k.tests.map((e) => e.id)).size, 157);
  assert.ok(k.tests.every((e) => e.n === 1e9));
});

test('tool-pins-v1.1.json: the 4 tools, each with a sha256', () => {
  const t = JSON.parse(readFileSync('verification/tool-pins-v1.1.json', 'utf8'));
  assert.deepEqual(t.tools.map((x) => x.name), ['NIST STS', 'TestU01', 'Dieharder', 'PractRand']);
  for (const x of t.tools) assert.match(x.sha256, /^[0-9a-f]{64}$/, x.name);
});
