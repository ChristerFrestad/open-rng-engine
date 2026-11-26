// R-G64 item 2 (HoQ addendum 1 R118-4): shuffle positional statistic ((n-1)/n)·X², df (n-1)², every n.
// The calibration test (n = 5, 10^4 replications, KS against χ²_16) is what kills a raw-X² mutant
// (tools/ci/j-calib-mutants.mjs RP-*). Uniform permutations come from a seeded sha256 counter here, never the engine.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as Q from '../verification/statistic/positional-statistic.mjs';
import { ksUniform, chi2sf } from '../verification/statistic/wave1-statistic.mjs';
import * as P from '../verification/harness/run-plan.mjs';
import * as L from '../verification/harness/stream-launcher.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const K = P.loadKTests(ROOT);

// A seeded uniform source: 32-bit words from sha256(seed || block), 8 words per block; Lemire-free rejection.
function words(seed) {
  let block = 0, buf = null, i = 8;
  return () => { if (i === 8) { buf = createHash('sha256').update(`${seed}:${block++}`).digest(); i = 0; } return buf.readUInt32LE(4 * i++); };
}
function uniformBelow(next, m) { const lim = Math.floor(2 ** 32 / m) * m; for (;;) { const x = next(); if (x < lim) return x % m; } }
function perm(next, n) { const a = Array.from({ length: n }, (_, i) => i); for (let i = n - 1; i > 0; i--) { const j = uniformBelow(next, i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; }

test('raw X² is exact: (n·ΣC² - n·M²)/M equals the cell-by-cell Pearson sum', () => {
  const next = words('exact'); const n = 7, M = 300;
  const acc = Q.positionalAccumulator(n); for (let t = 0; t < M; t++) acc.add(perm(next, n));
  let x2 = 0; const E = M / n; for (const c of acc.C) x2 += (c - E) ** 2 / E;
  const st = Q.positionalStatistic(acc.C, n, M);
  assert.ok(Math.abs(st.x2_raw - x2) <= 1e-9 * x2); assert.equal(st.x2, (6 / 7) * st.x2_raw); assert.equal(st.df, 36);
  const { num, den } = Q.rawX2Exact(acc.C, n, M); assert.equal(typeof num, 'bigint'); assert.equal(den, 300n);
});

test('every shuffle positional entry in K: df = (n-1)², the scaling is (n-1)/n (n = 52 and 54 included)', async () => {
  const ents = K.filter((k) => /^shuffle\/positional\//.test(k.id));
  assert.deepEqual(ents.map((k) => k.parameters.n), [52, 54, 104, 312, 416, 1000]);
  for (const k of ents) {
    const n = k.parameters.n;
    assert.equal(k.df, (n - 1) ** 2, k.id); assert.equal(Q.df(n), k.df); assert.equal(Q.scale(n), (n - 1) / n);
    // a perfectly balanced count matrix (a Latin square repeated) has X² = 0 for every n
    const C = new Float64Array(n * n).fill(3); const st = Q.positionalStatistic(C, n, 3 * n);
    assert.equal(st.x2, 0); assert.equal(st.p, 1); assert.equal(st.scaling, `(${n - 1}/${n})`);
  }
  const plan = P.buildPlan({ runId: 'q', M: Object.fromEntries(ents.map((k) => [k.id, 10])), N: 1 });
  for (const s of plan.streams) {
    const c = await L.streamConsumers(s, { kTests: K });
    assert.equal(c.fixed.length, s.entries.filter((e) => /^shuffle\/positional\//.test(e.id)).length, s.id);
  }
});

test('counts that break the permutation constraint are refused', () => {
  const C = new Float64Array(9).fill(1); C[0] = 2;
  assert.throws(() => Q.positionalStatistic(C, 3, 3), /does not sum to M/);
  assert.throws(() => Q.positionalAccumulator(3).add([0, 1]), /not a permutation/);
});

test('large-n p-values agree with the Wilson-Hilferty normal approximation (df up to 998001)', () => {
  const Phi = (z) => 0.5 * (1 + erf(z / Math.SQRT2));
  function erf(x) { const t = 1 / (1 + 0.3275911 * Math.abs(x)); const y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-x * x); return x >= 0 ? y : -y; }
  for (const d of [2601, 96721, 998001]) for (const z of [-2, 0, 1, 3]) {
    const x = d * (1 - 2 / (9 * d) + z * Math.sqrt(2 / (9 * d))) ** 3;
    assert.ok(Math.abs(chi2sf(x, d) - (1 - Phi(z))) < 2e-3, `df ${d} z ${z}`);
  }
});

test('small-n calibration: n = 5, 10^4 replications of M = 200: ((n-1)/n)·X² is χ²_16 (KS), raw X² is not', () => {
  const next = words('calib-r118-4'); const n = 5, M = 200, R = 10000;
  const ps = [], raw = [];
  for (let r = 0; r < R; r++) {
    const acc = Q.positionalAccumulator(n); for (let t = 0; t < M; t++) acc.add(perm(next, n));
    const st = Q.positionalStatistic(acc.C, n, M);
    assert.equal(st.df, 16);
    ps.push(st.p); raw.push(chi2sf(st.x2_raw, 16));
  }
  const ks = ksUniform(ps), ksRaw = ksUniform(raw);
  assert.ok(ks.p >= 0.001, `scaled X² vs χ²_16: KS p ${ks.p} (D ${ks.D})`);
  assert.ok(ksRaw.p < 1e-6, `raw X² must fail KS vs χ²_16 (p ${ksRaw.p})`);
  const mean = ps.reduce((a, b) => a + b, 0) / R; assert.ok(Math.abs(mean - 0.5) < 0.02, `mean p ${mean}`);
});

test('part accumulators merged equal one pass (exact counts)', () => {
  const next = words('merge'); const n = 52, M = 90;
  const ps = Array.from({ length: M }, () => perm(next, n));
  const one = Q.positionalAccumulator(n); ps.forEach((x) => one.add(x));
  const parts = [ps.slice(0, 30), ps.slice(30, 60), ps.slice(60)].map((xs) => { const a = Q.positionalAccumulator(n); xs.forEach((x) => a.add(x)); return a; });
  const m = Q.positionalAccumulator(n); parts.forEach((a) => m.merge(a));
  assert.deepEqual([...m.C], [...one.C]);
  assert.deepEqual(Q.positionalStatistic(m.C, n, M), Q.positionalStatistic(one.C, n, M));
  assert.throws(() => m.merge(Q.positionalAccumulator(5)), /different n/);
});
