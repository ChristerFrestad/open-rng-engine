// R-G64 item 2 (HoQ addendum 1 R118-4; CPO routing to CTO): the shuffle positional-frequency statistic.
// Counts C[i][p] = how often item i lands at position p over M shuffles of n items (exact integers).
// Raw Pearson X² = Σ (C - M/n)² / (M/n) = (n·ΣC² - n·M²) / M, computed EXACTLY in BigInt and rounded once.
// Every row and every column of C sums to M, so the cells are not independent multinomial cells: under H0 the
// raw X² is asymptotically (n/(n-1))·χ²_{(n-1)²}. The reported statistic is ((n-1)/n)·X² with df (n-1)², for
// EVERY shuffle positional entry (n = 52, 54, 104, 312, 416, 1000; no exceptions). The raw X² is kept in the
// output for audit only and is never compared with χ². The small-n calibration test (n = 5, 10^4 replications,
// KS against χ²_16) kills a raw-X² mutant. Under R-DT the p-value may also be an exact-permutation Monte Carlo
// value, which needs no scaling; that path is not built here.
import { chi2sf, toDouble } from './wave1-statistic.mjs';

export const POSITIONAL_ID = 'open-rng-engine/positional-statistic/v1';
export const df = (n) => (n - 1) * (n - 1);
export const scale = (n) => (n - 1) / n;

// Accumulator: n×n exact counts (each < 2^53 for M <= 10^9), merged by addition in part order.
export function positionalAccumulator(n) {
  const C = new Float64Array(n * n);
  return {
    C, n,
    add(perm) {
      if (!Array.isArray(perm) || perm.length !== n) throw new Error(`positional: outcome is not a permutation of ${n}`);
      for (let p = 0; p < n; p++) C[perm[p] * n + p] += 1;
    },
    merge(o) { if (o.n !== n) throw new Error('positional: merge of a different n'); for (let i = 0; i < C.length; i++) C[i] += o.C[i]; },
  };
}

// Raw X² as an exact rational: numerator n·ΣC² - n·M², denominator M.
export function rawX2Exact(C, n, M) {
  let s = 0n, rows = new Float64Array(n), cols = new Float64Array(n);
  for (let i = 0; i < n; i++) for (let p = 0; p < n; p++) { const c = C[i * n + p]; s += BigInt(c) * BigInt(c); rows[i] += c; cols[p] += c; }
  for (let i = 0; i < n; i++) if (rows[i] !== M || cols[i] !== M) throw new Error(`positional: row/column ${i} does not sum to M=${M}`);
  const nb = BigInt(n), Mb = BigInt(M);
  return { num: nb * s - nb * Mb * Mb, den: Mb };
}

export function positionalStatistic(C, n, M) {
  const { num, den } = rawX2Exact(C, n, M);
  const raw = toDouble(num, den);
  const x2 = scale(n) * raw;
  const d = df(n);
  return { x2, df: d, p: chi2sf(x2, d), x2_raw: raw, scaling: `(${n - 1}/${n})`, outcomes: M, statistic: POSITIONAL_ID };
}
