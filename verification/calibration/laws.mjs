// Wave-1 null laws, lumping, chi^2 and KS for the A6 calibration (CTO commit H). Design: df-design-v2.md §1-§3
// and §6 (8d1df14f); HoQ addendum 1 A7 R-W1-METHOD.
// [CL-1] coupon and duplicates laws are double-precision occupancy DPs with positive terms only (no
//   cancellation); the gated exact BigInt tables are the design's (§1/§2) and Quant's. The duplicates DP is
//   the one HoQ reproduced exactly to 2 decimals of min E (report 5f7f4ad7 §7(e)). Adjacency is EXACT BigInt
//   (run-counting generating function, §6.3), converted to double only for the chi^2.
// [CL-2] the p-value of Pearson's X^2 uses the chi^2(df) upper tail (the statistic as designed).
// [CL-3] the KS p-value uses the asymptotic Kolmogorov series at lambda = (sqrt(R) + 0.12 + 0.11/sqrt(R))*D;
//   the A6 rule (reject at alpha = 0.001; D_crit ~= 1.949/sqrt(R) = 0.0617 at R = 1000) is applied to it.

export function couponLaw(d) {
  // P(T = k), k = d, d+1, ...; DP over the number j of distinct categories seen after t draws.
  let p = new Float64Array(d + 1); p[0] = 1;
  const cells = []; let mass = 0;
  for (let t = 0; ; t++) {
    if (t >= d - 1) {
      const pk = p[d - 1] / d; // the (t+1)-th draw is the last new one
      if (t + 1 >= d) { cells.push(pk); mass += pk; }
      if (1 - mass < 1e-13 && cells.length > 2) break;
    }
    const q = new Float64Array(d + 1);
    for (let j = 0; j < d; j++) { const w = p[j]; if (w === 0) continue; q[j] += w * j / d; q[j + 1] += w * (d - j) / d; }
    q[d] = 0; // absorbed (T reached)
    p = q;
  }
  cells.push(Math.max(0, 1 - mass)); // exact complement tail cell: T > last k
  return { k0: d, p: cells };
}

export function dupLaw(m, b) {
  const lam = b * (b - 1) / (2 * m);
  const cmax = Math.floor(lam + 12 * Math.sqrt(lam) + 25);
  let P = new Float64Array(cmax + 2); P[0] = 1;
  for (let k = 0; k < b; k++) {
    const Q = new Float64Array(cmax + 2); Q[cmax + 1] = P[cmax + 1];
    for (let c = 0; c <= cmax; c++) {
      const w = P[c]; if (w === 0) continue;
      const pc = (k - c) / m;
      Q[c] += w * (1 - pc);
      Q[c < cmax ? c + 1 : cmax + 1] += w * pc;
    }
    P = Q;
  }
  return { k0: 0, p: Array.from(P) }; // last cell: C > cmax
}

const fact = (n) => { let f = 1n; for (let i = 2n; i <= BigInt(n); i++) f *= i; return f; };
const comb = (n, k) => (k < 0 || k > n ? 0n : fact(n) / (fact(k) * fact(n - k)));

// EXACT P(X = k), X = # equal-label adjacent pairs, L labels x c copies, uniform over (Lc)! orders.
export function adjacencyLawExact(L, c) {
  const cf = fact(c);
  const lab = new Map(); // key s,r -> integer coef * c!/s!
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
  const n = L * c; const tot = fact(n);
  const num = new Map(); let sum = 0n;
  for (const [R, w] of words) { num.set(n - R, w); sum += w; } // w = arrangements incl. card identities (cf^L scaling cancels)
  if (sum !== tot) throw new Error(`adjacency law does not sum to ${n}!`);
  const K = Math.max(...num.keys());
  const p = []; for (let k = 0; k <= K; k++) p.push(Number(((num.get(k) ?? 0n) * 10n ** 30n) / tot) / 1e30);
  return { k0: 0, p, exactNum: num, total: tot };
}

// §6.1 lumping: merge from each tail while the outer cell or its inner neighbour has M*p < 5.
export function lump(p, M) {
  const g = p.map((_, i) => [i]); const c = [...p];
  while (c.length > 1 && (M * c[0] < 5 || M * c[1] < 5)) { c[1] += c[0]; c.shift(); g[1] = [...g[0], ...g[1]]; g.shift(); }
  while (c.length > 1 && (M * c.at(-1) < 5 || M * c.at(-2) < 5)) { c[c.length - 2] += c.at(-1); c.pop(); g[g.length - 2].push(...g.at(-1)); g.pop(); }
  if (!c.every((x) => M * x >= 5)) throw new Error('lumping left a cell below 5');
  const map = new Int32Array(p.length); g.forEach((grp, j) => grp.forEach((i) => { map[i] = j; }));
  return { cells: c, map };
}

function lgamma(x) {
  const g = 7, cof = [0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];
  if (x < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * x)) - lgamma(1 - x);
  x -= 1; let a = cof[0]; const t = x + g + 0.5;
  for (let i = 1; i < 9; i++) a += cof[i] / (x + i);
  return 0.5 * Math.log(2 * Math.PI) + (x + 0.5) * Math.log(t) - t + Math.log(a);
}
// Regularized upper incomplete gamma Q(a, x).
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

export function pearsonP(counts, cells, M) {
  let x2 = 0;
  for (let j = 0; j < cells.length; j++) { const e = M * cells[j]; x2 += (counts[j] - e) ** 2 / e; }
  return { x2, p: chi2sf(x2, cells.length - 1) };
}

export function ksUniform(ps) {
  const s = [...ps].sort((a, b) => a - b); const n = s.length; let D = 0;
  for (let i = 0; i < n; i++) D = Math.max(D, (i + 1) / n - s[i], s[i] - i / n);
  const en = Math.sqrt(n); const lam = (en + 0.12 + 0.11 / en) * D;
  let p = 0; for (let k = 1; k <= 200; k++) { const t = 2 * (k % 2 ? 1 : -1) * Math.exp(-2 * k * k * lam * lam); p += t; if (Math.abs(t) < 1e-18) break; }
  return { D, p: Math.min(1, Math.max(0, p)) };
}
