// The 26 wave-1 EBC entries (HoQ addendum 1 A7 R-W1-METHOD at 8d1df14f) and their statistics as built on
// the labkit reference stream (verification/labkit/aes-ctr-ref.mjs). Calibration only: not an evidence run.
import { RefStream } from '../labkit/aes-ctr-ref.mjs';
import { couponLaw, dupLaw, adjacencyLawExact, lump } from './laws.mjs';

const T32 = 2 ** 32;
export const N_CAL = 1e6;        // A6: n >= 10^6 outcomes per replication
export const M_CAL_FLOOR = 200;  // and at least 200 observations
export const R_CAL = 1000;       // A6: R >= 1000 replications

// [label, r (range size), coupon d, duplicates m-base dd, u, b]
const RI = [
  ['min-0-max-2', 2, 2, 2, 20, 4096], ['min-1-max-7', 6, 6, 6, 8, 4096], ['min-1-max-38', 37, 37, 37, 4, 4096],
  ['min-1-max-53', 52, 52, 52, 4, 8192], ['min-0-max-100', 100, 100, 100, 3, 4096], ['min-0-max-2147483649', 2 ** 31 + 1, 3, 3, 13, 4096],
  ['min-0-max-4294967296', T32, 64, 2 ** 20, 1, 4096], ['min-0-max-38', 38, 38, 38, 4, 4096], ['min-0-max-54', 54, 54, 54, 4, 8448],
  ['min-0-max-4294967297', T32 + 1, 641, 6700417, 1, 8192], ['min-0-max-281474976710656', 2 ** 48, 64, 2 ** 20, 1, 4096],
];

export const ENTRIES = [];
for (const [lab, r, d] of RI) ENTRIES.push({ id: `randomInt/coupon-collector/${lab}`, kind: 'coupon', r, d });
ENTRIES.push({ id: 'shuffle/coupon-collector/lehmer-52', kind: 'coupon', r: 'lehmer', d: 52 });
for (const [lab, r, , dd, u, b] of RI) ENTRIES.push({ id: `randomInt/duplicates/${lab}`, kind: 'dup', r, dd, u, b, m: dd ** u });
ENTRIES.push({ id: 'shuffle/duplicates/lehmer-52', kind: 'dup', r: 'lehmer', dd: 2 ** 20, u: 1, b: 4096, m: 2 ** 20 });
ENTRIES.push({ id: 'shuffle/adjacency-mod4/n-52', kind: 'adj', L: 4, c: 13, lab: (v) => v % 4 });
ENTRIES.push({ id: 'shuffle/adjacency-div4/n-52', kind: 'adj', L: 13, c: 4, lab: (v) => (v / 4) | 0 });
ENTRIES.forEach((e, i) => { e.stream = i + 1; });

export const MIN_CELLS = 10;      // and doubled until the §6.1-lumped table has >= 10 cells (C-1: at M_cal the
                                  // table is coarser than at M = 10^9; d = 641 coupon is degenerate at 1561)
const lumpedCells = (e, M) => lump(lawOf(e).p, M).cells.length;
const mCache = new Map();
export function mCal(e) {
  if (mCache.has(e.id)) return mCache.get(e.id);
  const per = e.kind === 'coupon' ? e.d : e.kind === 'dup' ? e.b * e.u : 1; // minimum outcomes per observation
  let M = Math.max(Math.ceil(N_CAL / per), e.kind === 'adj' ? 0 : M_CAL_FLOOR);
  while (lumpedCells(e, M) < MIN_CELLS) M *= 2;
  mCache.set(e.id, M);
  return M;
}

export function lawOf(e) {
  if (e.kind === 'coupon') return couponLaw(e.d);
  if (e.kind === 'dup') return dupLaw(e.m, e.b);
  return adjacencyLawExact(e.L, e.c);
}

// ---- outcomes from the reference stream ----
// Forward Fisher-Yates: a = [0..51]; for i: j = i + below(52 - i), swap; pi_i = a[i]. Lehmer digit
// d_i = #{remaining cards < pi_i} (remaining tracked as two 26-bit masks). [CS-1] Entries that read only a
// prefix of the permutation draw only that prefix (distributionally identical to the full shuffle); the
// duplicates entry completes the shuffle and uses the exact BigInt rank whenever the prefix is ambiguous.
const pc = (x) => { x -= (x >>> 1) & 0x55555555; x = (x & 0x33333333) + ((x >>> 2) & 0x33333333); return (((x + (x >>> 4)) & 0x0f0f0f0f) * 0x01010101) >>> 24; };
const P = []; { let q = 1; for (let i = 0; i < 52; i++) { q *= 52 - i; P.push(q); } }
const F52 = (() => { let f = 1n; for (let i = 2n; i <= 52n; i++) f *= i; return f; })();
const FACT = (() => { const f = [1n]; for (let i = 1n; i <= 52n; i++) f.push(f.at(-1) * i); return f; })();
export const lehmerStats = { fallbacks: 0 };

export function lehmerTop20(s, a) {
  for (let i = 0; i < 52; i++) a[i] = i;
  let lo = 0x3ffffff, hi = 0x3ffffff, y = 0;
  const dig = [];
  for (let i = 0; i < 10; i++) {
    const j = i + s.below(52 - i); const t = a[i]; a[i] = a[j]; a[j] = t; const v = a[i];
    const di = v < 26 ? pc(lo & ((1 << v) - 1)) : pc(lo) + pc(hi & ((1 << (v - 26)) - 1));
    if (v < 26) lo &= ~(1 << v); else hi &= ~(1 << (v - 26));
    dig.push(di); y += di * 1048576 / P[i];
  }
  const f = y - Math.floor(y);
  if (f > 1e-9 && f < 1 - 1e-9) return Math.floor(y);
  lehmerStats.fallbacks += 1;
  for (let i = 10; i < 52; i++) {
    const j = i + s.below(52 - i); const t = a[i]; a[i] = a[j]; a[j] = t; const v = a[i];
    const di = v < 26 ? pc(lo & ((1 << v) - 1)) : pc(lo) + pc(hi & ((1 << (v - 26)) - 1));
    if (v < 26) lo &= ~(1 << v); else hi &= ~(1 << (v - 26));
    dig.push(di);
  }
  let rank = 0n; for (let i = 0; i < 52; i++) rank += BigInt(dig[i]) * FACT[51 - i];
  return Number((rank * 1048576n) / F52);
}

// One replication: returns the histogram over the raw law index (caller lumps) and the outcomes consumed.
export function replicate(e, rep, M, nRaw) {
  const s = new RefStream(e.stream, rep);
  const h = new Float64Array(nRaw); let outcomes = 0;
  const put = (k) => { h[Math.min(k, nRaw - 1)] += 1; };
  if (e.kind === 'coupon') {
    const seen = new Int32Array(e.d); let gen = 0;
    const a = new Uint8Array(52);
    const div = e.r === 'lehmer' ? 0 : e.r / e.d;
    for (let o = 0; o < M; o++) {
      gen += 1; let got = 0, t = 0;
      while (got < e.d) {
        let c;
        if (e.r === 'lehmer') c = s.below(52); // forward FY first draw: pi_0 = j = Lehmer digit 0 = floor(rank*52/52!)
        else c = Math.floor(s.below(e.r) / div);
        t += 1; if (seen[c] !== gen) { seen[c] = gen; got += 1; }
      }
      outcomes += t; put(t - e.d);
    }
    void a;
  } else if (e.kind === 'dup') {
    const stamp = new Int32Array(e.m); let gen = 0; const a = new Uint8Array(52);
    const div = e.r === 'lehmer' ? 0 : e.r / e.dd;
    for (let o = 0; o < M; o++) {
      gen += 1; let C = 0;
      for (let k = 0; k < e.b; k++) {
        let urn = 0;
        if (e.r === 'lehmer') urn = lehmerTop20(s, a);
        else for (let t = 0; t < e.u; t++) urn = urn * e.dd + Math.floor(s.below(e.r) / div);
        if (stamp[urn] === gen) C += 1; else stamp[urn] = gen;
      }
      outcomes += e.b * e.u; put(C);
    }
  } else {
    const a = new Uint8Array(52);
    for (let o = 0; o < M; o++) {
      for (let i = 0; i < 52; i++) a[i] = i;
      for (let i = 0; i < 51; i++) { const j = i + s.below(52 - i); const t = a[i]; a[i] = a[j]; a[j] = t; }
      let X = 0, prev = e.lab(a[0]);
      for (let i = 1; i < 52; i++) { const l = e.lab(a[i]); if (l === prev) X += 1; prev = l; }
      outcomes += 1; put(X);
    }
  }
  return { h, outcomes, words: s.words };
}
