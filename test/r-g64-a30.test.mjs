// HoQ A30 (A29-1 method ruling): the paired bench estimator, load guard and verdicts in verification/bench/a30-method.mjs,
// driven with fake child runs (no real timing here). The real run is verification/bench/r-g64-a25-a30.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as M from '../verification/bench/a30-method.mjs';

const N = 7;
// a fake world: load1 values in order, and the a25/plain median_ns per call
function fake({ loads = [], a25 = () => 110, plain = () => 100, burned = 10001 } = {}) {
  const calls = []; const sleeps = []; let li = 0; let ai = 0; let pi = 0;
  return {
    calls, sleeps,
    sampleLoad: () => (li < loads.length ? loads[li++] : 1.0),
    runChild: async (which, ctx) => { calls.push({ which, ...ctx }); return which === 'a25' ? { median_ns: a25(ai++), burned } : { median_ns: plain(pi++), burned: ctx.burn }; },
    sleep: async (ms) => { sleeps.push(ms); },
  };
}
const go = (f, extra = {}) => M.runEntry({ key: 'randomInt [0,2)', N, backoffMs: 60000, ...f, ...extra });

test('A30: constants are N >= 7, limit 10%, guard load1 4.0', () => {
  assert.deepEqual({ ...M.A30 }, { N_MIN: 7, LIMIT: 0.10, GUARD_LOAD1: 4.0 });
  assert.equal(M.failCount(7), 5); assert.equal(M.failCount(8), 5); assert.equal(M.failCount(9), 6);
});
test('A30: pairs alternate ABBA (a25 first on even pairs, plain first on odd)', () => {
  assert.deepEqual([0, 1, 2, 3].map(M.pairOrder), [['a25', 'plain'], ['plain', 'a25'], ['a25', 'plain'], ['plain', 'a25']]);
  assert.throws(() => M.pairOrder(-1)); assert.throws(() => M.pairOrder(1.5));
});
test('A30: a run takes exactly N valid pairs in ABBA order; plain is burned like the last a25 child', async () => {
  const f = fake({ a25: () => 105 }); const e = await go(f);
  assert.equal(e.verdict, 'PASS');
  assert.equal(f.calls.length, 2 * N); assert.equal(e.valid, N); assert.equal(e.attempts, N);
  assert.deepEqual(f.calls.map((c) => c.which), ['a25', 'plain', 'plain', 'a25', 'a25', 'plain', 'plain', 'a25', 'a25', 'plain', 'plain', 'a25', 'a25', 'plain']);
  assert.ok(f.calls.filter((c) => c.which === 'plain').every((c) => c.burn === 10001));
  assert.deepEqual(e.pairs.map((p) => p.order), ['a25>plain', 'plain>a25', 'a25>plain', 'plain>a25', 'a25>plain', 'plain>a25', 'a25>plain']);
});
test('A30: the entry overhead is the median of the pair ratios, never a pooled median_ns', async () => {
  // a25 median_ns per pair: one huge outlier pair; pooled medians would differ from the median of ratios
  const a = [105, 106, 107, 300, 104, 103, 108]; const p = [100, 100, 100, 100, 100, 100, 100];
  const e = await go(fake({ a25: (i) => a[i], plain: (i) => p[i] }));
  assert.equal(e.verdict, 'PASS'); assert.ok(Math.abs(e.median - 0.06) < 1e-12, String(e.median));
  assert.ok(Math.abs(e.max - 2.0) < 1e-12); assert.equal(e.above, 1);
});
test('A30: PASS needs median <= 10.0% exactly; 10.04% fails (no rounding)', () => {
  assert.equal(M.entryVerdict([0.05, 0.06, 0.07, 0.10, 0.11, 0.12, 0.13], { N, attempts: 7 }).verdict, 'PASS');
  assert.equal(M.entryVerdict([0.05, 0.06, 0.07, 0.1004, 0.11, 0.12, 0.13], { N, attempts: 7 }).verdict, 'FAIL');
});
test('A30: an entry with ceil(N/2)+1 repeats above 10% fails; one fewer can pass', () => {
  const four = [0.01, 0.02, 0.03, 0.09, 0.2, 0.2, 0.2, 0.2];
  assert.equal(M.entryVerdict(four, { N: 8, attempts: 8 }).verdict, 'FAIL'); // median 14.5% anyway
  const r = M.entryVerdict([0.01, 0.02, 0.03, 0.04, 0.2, 0.2, 0.2, 0.2], { N: 8, attempts: 8 });
  assert.equal(r.above, 4); assert.equal(r.verdict, 'FAIL'); // median (0.04+0.2)/2 = 12%
  const p = M.entryVerdict([0.01, 0.02, 0.03, 0.04, 0.05, 0.2, 0.2, 0.2], { N: 8, attempts: 8 });
  assert.equal(p.above, 3); assert.equal(p.verdict, 'PASS');
});
test('A30: a pair with load1 > 4.0 is void, logged, not run, backed off, and re-run', async () => {
  const f = fake({ loads: [4.01, 3.9, 4.5, 4.0] });
  const e = await go(f, { });
  const v = e.pairs.filter((p) => p.void);
  assert.equal(v.length, 2); assert.deepEqual(v.map((p) => p.load1), [4.01, 4.5]); assert.match(v[0].reason, /load1 4.01 > 4/);
  assert.equal(f.sleeps.length, 2); assert.ok(f.sleeps.every((s) => s === 60000));
  assert.equal(e.valid, N); assert.equal(e.attempts, N + 2); assert.equal(f.calls.length, 2 * N);
  assert.equal(e.pairs.find((p) => p.load1 === 4.0).void, false); // 4.0 itself is not above the guard
});
test('A30: after 2N attempts without N valid pairs the entry is INCONCLUSIVE, never PASS', async () => {
  const f = fake({ loads: Array(2 * N - 3).fill(5), a25: () => 101 });
  const e = await go(f);
  assert.equal(e.attempts, 2 * N); assert.equal(e.valid, 3); assert.equal(e.verdict, 'INCONCLUSIVE'); assert.equal(e.median, null);
  assert.equal(e.pairs.length, 2 * N);
});
test('A30: N below 7, a guard other than 4.0, or more valid pairs than N are refused', async () => {
  await assert.rejects(go(fake(), { N: 6 }), /N >= 7/);
  await assert.rejects(go(fake(), { guard: 5 }), /guard is 4/);
  assert.throws(() => M.entryVerdict(Array(8).fill(0.01), { N, attempts: 8 }), /more than the pre-registered N=7/);
});
test('A30: the overall verdict is FAIL on any failing entry, INCONCLUSIVE on any open one, else PASS', () => {
  const e = (verdict) => ({ verdict });
  assert.equal(M.overallVerdict([e('PASS'), e('PASS')]), 'PASS');
  assert.equal(M.overallVerdict([e('PASS'), e('INCONCLUSIVE')]), 'INCONCLUSIVE');
  assert.equal(M.overallVerdict([e('INCONCLUSIVE'), e('FAIL')]), 'FAIL');
  assert.equal(M.overallVerdict([]), 'INCONCLUSIVE');
});
test('A30: the shape keys match r-g64-a25-stageA.mjs (same function text, same 24 shapes)', () => {
  const fn = (t) => t.slice(t.indexOf('function shapeKey(k) {'), t.indexOf('\n}\n', t.indexOf('function shapeKey(k) {')) + 2);
  const a = fn(readFileSync(new URL('../verification/bench/r-g64-a25-stageA.mjs', import.meta.url), 'utf8'));
  const b = fn(readFileSync(new URL('../verification/bench/a30-method.mjs', import.meta.url), 'utf8'));
  assert.ok(a.length > 50); assert.equal(b, a);
  const keys = M.shapeKeys(JSON.parse(readFileSync(new URL('../verification/k-tests-v1.1.json', import.meta.url), 'utf8')).tests);
  assert.equal(keys.length, 24); assert.equal(new Set(keys).size, 24);
});
