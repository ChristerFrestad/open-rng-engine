// R-DT-SCREEN (CPO-R116a = HoQ R-DT-SCREEN, ratified): the hard-FAIL screen in THE statistic module.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as S from '../verification/statistic/wave1-statistic.mjs';

// BigInt fixed-point natural log (scale 10^60) of a positive rational a/b: ln = 2·atanh((x-1)/(x+1)) after
// reduction by a power of two, ln 2 = 2·atanh(1/3). Truncation error < 1e-55.
const F = 10n ** 60n;
const bl = (n) => n.toString(2).length;
function atanhF(num, den) { const z = (num * F) / den; const z2 = (z * z) / F; let t = z, s = 0n; for (let n = 1n; t !== 0n; n += 2n) { s += t / n; t = (t * z2) / F; } return s; }
const LN2F = 2n * atanhF(1n, 3n);
function lnF(a, b) { const e = bl(a) - bl(b); const num = e >= 0 ? a : a << BigInt(-e); const den = e >= 0 ? b << BigInt(e) : b; return 2n * atanhF(num - den, num + den) + BigInt(e) * LN2F; }
// KL(x/M || a/b) in fixed point.
function klRefF(x, M, a, b) {
  let r = 0n;
  if (x > 0n) r += (x * lnF(x * b, M * a)) / M;
  if (x < M) r += ((M - x) * lnF((M - x) * b, M * (b - a))) / M;
  return r;
}
// Exact comparison of a double d >= 0 with a fixed-point value: d <= ref/F ?
function dblLeF(d, ref) { if (d === 0) return ref >= -1n; let e = 0; let m = d; while (!Number.isInteger(m)) { m *= 2; e += 1; } return BigInt(m) * F <= (ref + 1n) * 2n ** BigInt(e); }
const logBig = (n) => { const L = bl(n); return L <= 53 ? Math.log(Number(n)) : (L - 53) * Math.LN2 + Math.log(Number(n >> BigInt(L - 53))); };
const PS = [[1n, 2n], [1n, 3n], [1n, 7n], [3n, 1000n], [999n, 1000n], [1n, 1048576n], [5n, 11n]];

test('R-DT-SCREEN: float KL_safe never exceeds the BigInt fixed-point KL reference on the KAT grid', () => {
  let n = 0;
  for (const [a, b] of PS) for (const M of [1n, 2n, 3n, 7n, 13n, 40n, 1000n, 1000000n, 1000000000n]) {
    const mp = (M * a) / b; const xs = new Set([0n, 1n, M, M - 1n, mp, mp + 1n, mp > 0n ? mp - 1n : 0n, M / 2n, M / 3n, (M * 9n) / 10n, mp + mp / 10n + 1n, mp / 2n]);
    for (const x of xs) { if (x < 0n || x > M) continue; const d = S.klSafe(Number(x) / Number(M), Number(a) / Number(b)); assert.ok(dblLeF(d, klRefF(x, M, a, b)), `x ${x} M ${M} p ${a}/${b}: ${d}`); n++; }
  }
  assert.ok(n > 400);
  assert.equal(S.klBernoulli(0, 0.25), -Math.log1p(-0.25)); assert.equal(S.klBernoulli(1, 0.25), -Math.log(0.25));
});

test('R-DT-SCREEN: small-M KAT (M <= 40): b(x) >= the exact two-sided binomial tail 2·min(P[X<=x], P[X>=x]) for every x', () => {
  for (const [a, b] of PS) for (let m = 1; m <= 40; m++) {
    const M = BigInt(m); const c = b - a; const pm = []; let C = 1n;
    for (let j = 0n; j <= M; j++) { pm.push(C * a ** j * c ** (M - j)); C = (C * (M - j)) / (j + 1n); }
    const den = b ** M; let lo = 0n; const LO = pm.map((v) => (lo += v)); let hi = 0n; const HI = [...pm].reverse().map((v) => (hi += v)).reverse();
    for (let x = 0; x <= m; x++) {
      const tail = 2n * (LO[x] < HI[x] ? LO[x] : HI[x]);
      const logTail = tail >= den ? 0 : logBig(tail) - logBig(den);
      const logB = Math.LN2 - m * S.klSafe(x / m, Number(a) / Number(b));
      assert.ok(Math.min(logTail, Math.LN2) <= logB + 1e-12, `M ${m} x ${x} p ${a}/${b}: tail ${logTail} > b ${logB}`);
    }
  }
});

// Synthetic entry: k = 20 cells (one big cell 0.43, nineteen 0.03), M = 10^6.
const k = 20, M = 1e6;
const cells = Float64Array.from({ length: k }, (_, j) => (j === 0 ? 0.43 : 0.03));
const L = { cells, map: Int32Array.from({ length: k }, (_, j) => j) };
const nullLike = () => Array.from(cells, (p) => Math.round(M * p));
const refLogBound = (h) => { let mx = 0n; h.forEach((x, j) => { const a = j === 0 ? 43n : 3n; const v = klRefF(BigInt(x), BigInt(M), a, 100n); if (v > mx) mx = v; }); const kl = Number(mx / 10n ** 40n) / 1e20; return { lb: Math.LN2 + Math.log(k) - M * kl, mkl: M * kl }; };

test('R-DT-SCREEN: null-like vector does not HARD FAIL; gross single-cell excess and deficit do', () => {
  const h0 = nullLike(); assert.equal(S.screen(h0, L, M).hardFail, false); assert.equal(S.screen(h0, L, M).k, k);
  const up = nullLike(); up[5] += 3000; up[0] -= 3000; const r = S.screen(up, L, M);
  assert.equal(r.hardFail, true); assert.equal(r.worst, 5);
  const dn = nullLike(); dn[7] -= 3000; dn[0] += 3000; assert.equal(S.screen(dn, L, M).hardFail, true);
  const zero = nullLike(); zero[0] += zero[9]; zero[9] = 0; assert.equal(S.screen(zero, L, M).hardFail, true);
});

// Several cells moderately off: each b_i between 1e-10/k and 1e-10 (so a k-less or 2-less Bound would fail),
// but k·min b_i >= 1e-10: must NOT fail.
function moderate() {
  const target = Math.log(2 * k) - Math.log(1e-10) - 0.25; // M·KL for b_i = 1e-10/k · e^{0.25}·... below 1e-10
  const h = nullLike(); const e = h[3];
  let up = e; while (M * S.klSafe(up / M, 0.03) < target) up++;
  let dn = e; while (M * S.klSafe(dn / M, 0.03) < target) dn--;
  h[3] = up; h[4] = up; h[11] = dn; h[12] = dn; h[0] -= 2 * (up - e) + 2 * (dn - e);
  return h;
}
test('R-DT-SCREEN: several cells moderately off, none below 1e-10/k: no HARD FAIL; each b_i < 1e-10', () => {
  const h = moderate(); const r = S.screen(h, L, M);
  assert.equal(r.hardFail, false, `logBound ${r.logBound}`);
  assert.ok(r.logBound < Math.log(1e-10) + Math.LN2 - 0.05, 'fixture sits within a factor 2 of the threshold');
  for (const j of [3, 4, 11, 12]) { const b = Math.LN2 - M * S.klSafe(h[j] / M, 0.03); assert.ok(b < Math.log(1e-10) && b > Math.log(1e-10 / k), `cell ${j}: ${b}`); }
});

test('R-DT-SCREEN: logBound is conservative against the BigInt reference and no looser than the stated safety factor', () => {
  for (const h of [nullLike(), moderate(), (() => { const u = nullLike(); u[5] += 3000; u[0] -= 3000; return u; })(), (() => { const u = nullLike(); u[7] -= 2500; u[0] += 2500; return u; })()]) {
    const r = S.screen(h, L, M); const { lb, mkl } = refLogBound(h);
    assert.ok(r.logBound >= lb - 1e-9, `not conservative: ${r.logBound} < ${lb}`);
    assert.ok(r.logBound <= lb + S.SCREEN.SAFETY_REL * mkl * 1.01 + M * S.SCREEN.SAFETY_ABS + 1e-9, `too loose: ${r.logBound} vs ${lb}`);
  }
});

test('R-DT-SCREEN: threshold is strict "<" at exactly 1e-10', () => {
  assert.equal(S.SCREEN.THRESHOLD, 1e-10); assert.equal(S.SCREEN.LOG_THRESHOLD, Math.log(1e-10));
  assert.equal(S.screenFails(Math.log(1e-10)), false);
  assert.equal(S.screenFails(Math.log(1e-10) - 1e-9), true);
  assert.equal(S.screenFails(Math.log(1.5e-10)), false);
  assert.equal(S.screenFails(Math.log(0.7e-10)), true);
});
