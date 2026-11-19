// THE wave-1 EBC statistic (CTO batch J, G-56; HoQ addendum 1 A8; df-design-v2 §1-§3, §6). ONE module used by
// both the evidence path (verification/harness/wave1-evidence.mjs, fed collector records) and the A6
// calibration (verification/calibration/wave1-source.mjs, fed the labkit reference stream). It never draws:
// the caller injects public-call outcomes through next(). Laws are EXACT BigInt; lumping (§6.1) compares
// exactly; doubles appear only in X^2 and the chi^2 tail.
//   outcome (randomInt entries): one integer v in [min, max);
//   outcome (shuffle entries): one permutation of 52, as an array or as { card(i) } (cards read lazily).
// [CL-2] p = chi^2(df) upper tail of Pearson's X^2 (asymptotic; see R-DEEP-TAIL in the results for its size).
// [CL-3] KS p (calibration only) = asymptotic Kolmogorov series with the Stephens factor (sqrt(R)+0.12+0.11/sqrt(R)).
export const STATISTIC_ID = 'open-rng-engine/wave1-statistic/v1';

const T32 = 2 ** 32;
// [label, min, max, coupon d, duplicates base dd, u, b] (df-design-v2 §1, §2, §6.2 F-rows).
const RI = [
  ['min-0-max-2', 0, 2, 2, 2, 20, 4096], ['min-1-max-7', 1, 7, 6, 6, 8, 4096], ['min-1-max-38', 1, 38, 37, 37, 4, 4096],
  ['min-1-max-53', 1, 53, 52, 52, 4, 8192], ['min-0-max-100', 0, 100, 100, 100, 3, 4096], ['min-0-max-2147483649', 0, 2 ** 31 + 1, 3, 3, 13, 4096],
  ['min-0-max-4294967296', 0, T32, 64, 2 ** 20, 1, 4096], ['min-0-max-38', 0, 38, 38, 38, 4, 4096], ['min-0-max-54', 0, 54, 54, 54, 4, 8448],
  ['min-0-max-4294967297', 0, T32 + 1, 641, 6700417, 1, 8192], ['min-0-max-281474976710656', 0, 2 ** 48, 64, 2 ** 20, 1, 4096],
];
export const ENTRIES = [];
for (const [lab, min, max, d] of RI) ENTRIES.push({ id: `randomInt/coupon-collector/${lab}`, kind: 'coupon', min, r: max - min, d });
ENTRIES.push({ id: 'shuffle/coupon-collector/lehmer-52', kind: 'coupon', r: 'lehmer', d: 52 });
for (const [lab, min, max, , dd, u, b] of RI) ENTRIES.push({ id: `randomInt/duplicates/${lab}`, kind: 'dup', min, r: max - min, dd, u, b, m: dd ** u });
ENTRIES.push({ id: 'shuffle/duplicates/lehmer-52', kind: 'dup', r: 'lehmer', dd: 2 ** 20, u: 1, b: 4096, m: 2 ** 20 });
ENTRIES.push({ id: 'shuffle/adjacency-mod4/n-52', kind: 'adj', L: 4, c: 13, label: 'mod4' });
ENTRIES.push({ id: 'shuffle/adjacency-div4/n-52', kind: 'adj', L: 13, c: 4, label: 'div4' });
Object.freeze(ENTRIES.forEach((e) => Object.freeze(e)) ?? ENTRIES);
const LAB = { mod4: (v) => v % 4, div4: (v) => (v / 4) | 0 };

// ---------------- exact laws: { num: BigInt[], den: BigInt }, last index = exact complement tail ----------------
const TAIL_EPS = 10n ** 12n; // head cells are kept while the tail mass is >= 1e-12 (far below any 5/M cell)
export function couponLawExact(d) {
  // v[j] = number of length-t sequences over d symbols with j distinct, j < d (over d^t). P(T = t+1) =
  // v[d-1] / d^(t+1); P(T > t) = sum(v) / d^t. Stop once that tail is below 1e-12.
  const D = BigInt(d);
  let v = new Array(d).fill(0n); v[0] = 1n;
  const raw = []; let pow = 1n; // d^t
  for (let t = 0; ; t++) {
    if (t >= d - 1) raw.push(v[d - 1]);
    const w = new Array(d).fill(0n);
    for (let j = 0; j < d; j++) { const x = v[j]; if (x === 0n) continue; w[j] += x * BigInt(j); if (j + 1 < d) w[j + 1] += x * BigInt(d - j); }
    v = w; pow *= D; // now over d^(t+1)
    if (t >= d - 1 && raw.length > 2) {
      let tail = 0n; for (const x of v) tail += x;
      if (tail * TAIL_EPS < pow) {
        const num = new Array(raw.length); let g = 1n;
        for (let i = raw.length - 1; i >= 0; i--) { num[i] = raw[i] * g; g *= D; }
        num.push(tail);
        return { k0: d, num, den: pow };
      }
    }
  }
}
export function dupLawExact(m, b) {
  // w[c] = number of urn sequences of k balls with c collisions (c <= cmax); exact tail = m^b - sum.
  const lam = b * (b - 1) / (2 * m);
  const cmax = Math.floor(lam + 12 * Math.sqrt(lam) + 25);
  const Mb = BigInt(m);
  let w = new Array(cmax + 1).fill(0n); w[0] = 1n;
  for (let k = 0; k < b; k++) {
    const x = new Array(cmax + 1).fill(0n);
    for (let c = 0; c <= cmax; c++) {
      const y = w[c]; if (y === 0n) continue;
      x[c] += y * (Mb - BigInt(k - c));
      if (c < cmax) x[c + 1] += y * BigInt(k - c);
    }
    w = x;
  }
  const den = Mb ** BigInt(b);
  let s = 0n; for (const y of w) s += y;
  return { k0: 0, num: [...w, den - s], den };
}
const fact = (n) => { let f = 1n; for (let i = 2n; i <= BigInt(n); i++) f *= i; return f; };
const comb = (n, k) => (k < 0 || k > n ? 0n : fact(n) / (fact(k) * fact(n - k)));
export function adjacencyLawExact(L, c) {
  const cf = fact(c); const lab = new Map();
  for (let r = 1; r <= c; r++) for (let s = 1; s <= r; s++) {
    const v = ((r - s) % 2 ? -1n : 1n) * comb(r - 1, s - 1) * comb(c - 1, r - 1) * (cf / fact(s));
    const key = `${s},${r}`; lab.set(key, (lab.get(key) ?? 0n) + v);
  }
  let poly = new Map([['0,0', 1n]]);
  for (let a = 0; a < L; a++) {
    const nxt = new Map();
    for (const [k1, w] of poly) { const [S, R] = k1.split(',').map(Number); for (const [k2, v] of lab) { const [s, r] = k2.split(',').map(Number); const key = `${S + s},${R + r}`; nxt.set(key, (nxt.get(key) ?? 0n) + w * v); } }
    poly = nxt;
  }
  const words = new Map();
  for (const [k1, w] of poly) { const [S, R] = k1.split(',').map(Number); words.set(R, (words.get(R) ?? 0n) + w * fact(S)); }
  const n = L * c; const den = fact(n);
  const by = new Map(); let sum = 0n;
  for (const [R, w] of words) { by.set(n - R, w); sum += w; }
  if (sum !== den) throw new Error(`adjacency law does not sum to ${n}!`);
  const K = Math.max(...by.keys());
  return { k0: 0, num: Array.from({ length: K + 1 }, (_, k) => by.get(k) ?? 0n), den };
}
const lawCache = new Map();
export function lawExact(e) {
  if (!lawCache.has(e.id)) {
    const L = e.kind === 'coupon' ? couponLawExact(e.d) : e.kind === 'dup' ? dupLawExact(e.m, e.b) : adjacencyLawExact(e.L, e.c);
    let s = 0n; for (const x of L.num) { if (x < 0n) throw new Error(`${e.id}: negative law term`); s += x; }
    if (s !== L.den) throw new Error(`${e.id}: law does not sum to 1`);
    lawCache.set(e.id, Object.freeze(L));
  }
  return lawCache.get(e.id);
}

// exact num/den -> nearest double (enough bits for X^2)
export function toDouble(num, den) {
  if (num === 0n) return 0;
  const s = BigInt(Math.max(0, den.toString(2).length - num.toString(2).length + 64));
  return Number((num << s) / den) / 2 ** Number(s);
}

// §6.1 lumping, EXACT: merge from each tail while the outer cell or its inner neighbour has M*p < 5.
export function lumpExact(law, M) {
  const MB = BigInt(M); const five = 5n * law.den;
  const small = (x) => MB * x < five;
  const g = law.num.map((_, i) => [i]); const c = [...law.num];
  while (c.length > 1 && (small(c[0]) || small(c[1]))) { c[1] += c[0]; c.shift(); g[1] = [...g[0], ...g[1]]; g.shift(); }
  while (c.length > 1 && (small(c.at(-1)) || small(c.at(-2)))) { c[c.length - 2] += c.at(-1); c.pop(); g[g.length - 2].push(...g.at(-1)); g.pop(); }
  if (c.some(small)) throw new Error('lumping left a cell below 5');
  const map = new Int32Array(law.num.length); g.forEach((grp, j) => grp.forEach((i) => { map[i] = j; }));
  return { map, cellNum: c, den: law.den, cells: Float64Array.from(c, (x) => toDouble(x, law.den)) };
}

// ---------------- reductions: public-call outcomes -> one observation ----------------
const card = (perm, i) => (Array.isArray(perm) ? perm[i] : perm.card(i));
const pc = (x) => { x -= (x >>> 1) & 0x55555555; x = (x & 0x33333333) + ((x >>> 2) & 0x33333333); return (((x + (x >>> 4)) & 0x0f0f0f0f) * 0x01010101) >>> 24; };
const PFX = []; { let q = 1; for (let i = 0; i < 52; i++) { q *= 52 - i; PFX.push(q); } }
const FACT = (() => { const f = [1n]; for (let i = 1n; i <= 52n; i++) f.push(f.at(-1) * i); return f; })();
export const lehmerStats = { fallbacks: 0 };
// floor(rank * 2^20 / 52!) of a permutation (Lehmer rank); exact: 10-card float prefix, BigInt rank otherwise.
export function lehmerTop20(perm) {
  let lo = 0x3ffffff, hi = 0x3ffffff, y = 0; const dig = [];
  const digit = (v) => { const di = v < 26 ? pc(lo & ((1 << v) - 1)) : pc(lo) + pc(hi & ((1 << (v - 26)) - 1)); if (v < 26) lo &= ~(1 << v); else hi &= ~(1 << (v - 26)); return di; };
  for (let i = 0; i < 10; i++) { const di = digit(card(perm, i)); dig.push(di); y += di * 1048576 / PFX[i]; }
  const f = y - Math.floor(y);
  if (f > 1e-9 && f < 1 - 1e-9) return Math.floor(y);
  lehmerStats.fallbacks += 1;
  for (let i = 10; i < 52; i++) dig.push(digit(card(perm, i)));
  let rank = 0n; for (let i = 0; i < 52; i++) rank += BigInt(dig[i]) * FACT[51 - i];
  return Number((rank * 1048576n) / FACT[52]);
}
const unit = (e, v) => Math.floor((Number(v) - e.min) / (e.r / (e.kind === 'coupon' ? e.d : e.dd)));

// One observation from next() (each call = one public-call outcome). Returns { k, outcomes }.
export function observe(e, next) {
  if (e.kind === 'coupon') {
    const seen = new Uint8Array(e.d); let got = 0, t = 0;
    while (got < e.d) { const v = next(); const c = e.r === 'lehmer' ? card(v, 0) : unit(e, v); t += 1; if (!seen[c]) { seen[c] = 1; got += 1; } }
    return { k: t - e.d, outcomes: t };
  }
  if (e.kind === 'dup') {
    const urns = new Set(); let C = 0, t = 0;
    for (let k = 0; k < e.b; k++) {
      let urn = 0;
      if (e.r === 'lehmer') { urn = lehmerTop20(next()); t += 1; } else for (let j = 0; j < e.u; j++) { urn = urn * e.dd + unit(e, next()); t += 1; }
      if (urns.has(urn)) C += 1; else urns.add(urn);
    }
    return { k: C, outcomes: t };
  }
  const p = next(); const lab = LAB[e.label]; let X = 0, prev = lab(card(p, 0));
  for (let i = 1; i < 52; i++) { const l = lab(card(p, i)); if (l === prev) X += 1; prev = l; }
  return { k: X, outcomes: 1 };
}

// M observations -> raw-index histogram (indices past the law's tail index go to the tail cell).
export function histogram(e, M, next, nRaw = lawExact(e).num.length) {
  const h = new Float64Array(nRaw); let outcomes = 0;
  for (let o = 0; o < M; o++) { const { k, outcomes: t } = observe(e, next); h[Math.min(k, nRaw - 1)] += 1; outcomes += t; }
  return { h, outcomes };
}

// ---------------- Pearson X^2 and its chi^2 tail ----------------
function lgamma(x) {
  const g = 7, cof = [0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
  if (x < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * x)) - lgamma(1 - x);
  x -= 1; let a = cof[0]; const t = x + g + 0.5;
  for (let i = 1; i < 9; i++) a += cof[i] / (x + i);
  return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
}
export function gammaQ(a, x) {
  if (x <= 0) return 1;
  const gl = lgamma(a);
  if (x < a + 1) {
    let ap = a, sum = 1 / a, del = sum;
    for (let n = 0; n < 100000; n++) { ap += 1; del *= x / ap; sum += del; if (Math.abs(del) < Math.abs(sum) * 1e-16) break; }
    return Math.max(0, 1 - sum * Math.exp(-x + a * Math.log(x) - gl));
  }
  let b = x + 1 - a, c = 1 / 1e-300, d = 1 / b, h = d;
  for (let i = 1; i < 100000; i++) {
    const an = -i * (i - a); b += 2;
    d = an * d + b; if (Math.abs(d) < 1e-300) d = 1e-300;
    c = b + an / c; if (Math.abs(c) < 1e-300) c = 1e-300;
    d = 1 / d; const del = d * c; h *= del; if (Math.abs(del - 1) < 1e-16) break;
  }
  return Math.exp(-x + a * Math.log(x) - gl) * h;
}
export const chi2sf = (x, df) => gammaQ(df / 2, x / 2);
export function pearson(h, lumped, M) {
  const o = new Float64Array(lumped.cells.length);
  for (let i = 0; i < h.length; i++) o[lumped.map[i]] += h[i];
  let x2 = 0;
  for (let j = 0; j < o.length; j++) { const ex = M * lumped.cells[j]; x2 += (o[j] - ex) ** 2 / ex; }
  const df = o.length - 1;
  return { x2, df, p: chi2sf(x2, df) };
}
export function ksUniform(ps) {
  const s = [...ps].sort((a, b) => a - b); const n = s.length; let D = 0;
  for (let i = 0; i < n; i++) D = Math.max(D, (i + 1) / n - s[i], s[i] - i / n);
  const en = Math.sqrt(n); const lam = (en + 0.12 + 0.11 / en) * D;
  let p = 0; for (let k = 1; k <= 200; k++) { const t = 2 * (k % 2 ? 1 : -1) * Math.exp(-2 * k * k * lam * lam); p += t; if (Math.abs(t) < 1e-18) break; }
  return { D, p: Math.min(1, Math.max(0, p)) };
}
// A6 per-entry rule (HoQ addendum 1 A6, A8 R-A6n): R >= 1000, n >= 10^6 public-call outcomes per
// replication, KS p >= 0.001, flags (p < 0.01) in the equal-tail 99.9% interval [2, 22] of Bin(1000, 0.01).
export const A6 = Object.freeze({ R: 1000, N: 1e6, KS_ALPHA: 0.001, FLAG: 0.01, FLAGS: Object.freeze([2, 22]) });
export function a6Verdict(ps, minOutcomes) {
  const ks = ksUniform(ps); const flags = ps.filter((p) => p < A6.FLAG).length;
  const pass = ps.length >= A6.R && minOutcomes >= A6.N && ks.p >= A6.KS_ALPHA && flags >= A6.FLAGS[0] && flags <= A6.FLAGS[1];
  return { ks, flags, pass };
}
