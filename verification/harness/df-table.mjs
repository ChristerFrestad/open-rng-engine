// Rule 8 df table. Decision rule v1 (FROZEN 5d09c75a), rule 8: "The df of 72 entries are marked
// `unspecified` or `proposed` in the list. The harness fixes each df with its test code, before any data;
// df does not change K or the threshold." HoQ ruling (CTO relay, 2026-11-18 23:30 CET): the rule 8 set is
// ALL df-null entries of verification/k-tests-v1.1.json (f75299de); the count comes from that file.
// No data is collected here. Entries not yet designed stay OPEN; they are never filled with a placeholder.
import { createHash } from 'node:crypto';

export const K_TESTS_SHA256 = 'f75299de7fa063b96e2a031ec7072ed4fe34f219a4bc04e3534125b973097c4c';
export const N_OUTCOMES = 1000000000n; // rule 8: 10^9 public-call outcomes per usage

// Adjacency (HoQ ruling): the ordered pair (π[i], π[i+1]) of one shuffle of 52 takes one of
// 52 × 51 = 2652 values (two distinct items), each with probability 1/2652 under a uniform shuffle.
// One observation per shuffle at the pre-registered position i, so the 10^9 pairs are independent:
// a single multinomial goodness-of-fit over 2652 cells, df = 2652 − 1 = 2651, expected count 10^9/2652.
export const ADJACENCY_CELLS = 52 * 51;
export const ADJACENCY_DF = ADJACENCY_CELLS - 1;

// Proposed 1000/999 entries (HoQ ruling, conditions (a)-(d)): exactly 1000 contiguous bins over [0, r),
// exact BigInt cell probabilities width/r, every expected count ≥ 5 at n = 10^9, df = bins − 1.
export const BINS = 1000;
export const BINNED_DF = BINS - 1;

export function factorial(n) {
  let f = 1n;
  for (let i = 2n; i <= BigInt(n); i++) f *= i;
  return f;
}
export const LEHMER_52_SUPPORT = factorial(52); // 52!, divisible by 1000

// The df table. Keys must be df-null ids of k-tests-v1.1; values are integers.
export const DF_TABLE = Object.freeze({
  'shuffle/adjacency/n-52-i-0': ADJACENCY_DF,
  'shuffle/adjacency/n-52-i-1': ADJACENCY_DF,
  'shuffle/adjacency/n-52-i-25': ADJACENCY_DF,
  'shuffle/adjacency/n-52-i-50': ADJACENCY_DF,
  'randomInt/chi2/min-0-max-2147483649': BINNED_DF,
  'randomInt/chi2/min-0-max-4294967296': BINNED_DF,
  'randomInt/chi2/min-0-max-4294967297': BINNED_DF,
  'randomInt/chi2/min-0-max-281474976710656': BINNED_DF,
  'shuffle/chi2/lehmer-52': BINNED_DF,
});

// Binned entries: r = the size of the outcome support (randomInt span, or 52! Lehmer ranks).
export const BINNED_SUPPORT = Object.freeze({
  'randomInt/chi2/min-0-max-2147483649': 2147483649n,
  'randomInt/chi2/min-0-max-4294967296': 4294967296n,
  'randomInt/chi2/min-0-max-4294967297': 4294967297n,
  'randomInt/chi2/min-0-max-281474976710656': 281474976710656n,
  'shuffle/chi2/lehmer-52': LEHMER_52_SUPPORT,
});

// Canonical JSON of DF_TABLE (sorted keys) and its digest literal.
export function dfTableCanonical(table = DF_TABLE) {
  return JSON.stringify(Object.keys(table).sort().map((k) => [k, table[k]]));
}
export const DF_TABLE_SHA256 = '1ed710bfb77b8e2a6736407386e60b70401398e88603b97b172d8df1d3817e63';
export function sha256(s) {
  return createHash('sha256').update(s).digest('hex');
}

// Bin k covers [edge(k), edge(k+1)) with edge(k) = floor(k·r / 1000) (condition (a): contiguous, exactly 1000).
export function binEdge(k, r) {
  return (BigInt(k) * r) / BigInt(BINS);
}
export function binWidth(k, r) {
  return binEdge(k + 1, r) - binEdge(k, r);
}
// Exact probability of bin k as a BigInt fraction [width, r] (condition (b); never 1/1000 unless r | 1000·width).
export function binProbability(k, r) {
  return [binWidth(k, r), r];
}
// Bin of a value v in [0, r): the largest k with edge(k) ≤ v, i.e. ceil(1000(v+1)/r) − 1.
export function binOf(v, r) {
  if (typeof v !== 'bigint') throw new TypeError('binOf: value must be a BigInt');
  const x = v;
  if (x < 0n || x >= r) throw new RangeError('binOf: value outside [0, r)');
  return Number((BigInt(BINS) * (x + 1n) - 1n) / r);
}
// Condition (c): n·width/r ≥ 5 for every bin, checked exactly as n·width ≥ 5·r.
export function minExpectedOk(r, n = N_OUTCOMES) {
  for (let k = 0; k < BINS; k++) if (n * binWidth(k, r) < 5n * r) return false;
  return true;
}

// Lehmer rank of a permutation of 0..m-1 in BigInt: Σ c_i · (m−1−i)!, c_i = #{j > i : π[j] < π[i]}.
// Identity → 0 (bin 0); reversed → m! − 1 (bin 999 for m = 52).
export function lehmerRank(perm) {
  const m = perm.length;
  let rank = 0n;
  let f = factorial(m - 1);
  for (let i = 0; i < m; i++) {
    let c = 0n;
    for (let j = i + 1; j < m; j++) if (perm[j] < perm[i]) c += 1n;
    rank += c * f;
    if (i < m - 1) f /= BigInt(m - 1 - i);
  }
  return rank;
}

// Integrity (PH0 gate): the table, its digest, and the derivations. Returns findings; [] is green.
export function checkDfTable(kTests, { kTestsSha256, table = DF_TABLE } = {}) {
  const f = [];
  if (kTestsSha256 !== undefined && kTestsSha256 !== K_TESTS_SHA256) f.push(`k-tests sha256 ${kTestsSha256} != ${K_TESTS_SHA256}`);
  const canon = dfTableCanonical(table);
  if (sha256(canon) !== DF_TABLE_SHA256) f.push(`rule 8: df table digest ${sha256(canon)} != pinned ${DF_TABLE_SHA256}`);
  const byId = new Map(kTests.map((t) => [t.id, t]));
  for (const [id, df] of Object.entries(table)) {
    const t = byId.get(id);
    if (!t) { f.push(`rule 8: df table id ${id} is not in the K list`); continue; }
    if (t.df !== null) f.push(`rule 8: df table id ${id} already has df ${t.df} in the K list`);
    if (!Number.isSafeInteger(df) || df < 1) f.push(`rule 8: df for ${id} is not a positive integer`);
  }
  for (const id of Object.keys(table).filter((k) => k.startsWith('shuffle/adjacency/'))) {
    const t = byId.get(id);
    if (t && t.cells !== ADJACENCY_CELLS) f.push(`rule 8: ${id} cells ${t.cells} != 52×51`);
    if (table[id] !== ADJACENCY_CELLS - 1) f.push(`rule 8: ${id} df ${table[id]} != 2652 − 1`);
  }
  for (const [id, r] of Object.entries(BINNED_SUPPORT)) {
    const t = byId.get(id);
    if (t && t.proposed_cells !== BINS) f.push(`rule 8: ${id} proposed_cells ${t && t.proposed_cells} != ${BINS}`);
    if (t && t.proposed_df !== table[id]) f.push(`rule 8: ${id} df ${table[id]} != proposed_df ${t && t.proposed_df}`);
    if (table[id] !== BINS - 1) f.push(`rule 8: ${id} df ${table[id]} != bins − 1`);
    if (t && t.parameters && t.parameters.r !== undefined && BigInt(t.parameters.r) !== r) f.push(`rule 8: ${id} support ${r} != K-list r ${t.parameters.r}`);
    if (binEdge(0, r) !== 0n || binEdge(BINS, r) !== r) f.push(`rule 8: ${id} bins do not cover [0, r)`);
    let total = 0n;
    for (let k = 0; k < BINS; k++) { const w = binWidth(k, r); if (w <= 0n) f.push(`rule 8: ${id} bin ${k} empty`); total += w; }
    if (total !== r) f.push(`rule 8: ${id} bin widths sum ${total} != r`);
    if (!minExpectedOk(r)) f.push(`rule 8: ${id} has a bin with expected count < 5 at n = 10^9`);
  }
  return f;
}

// Harness readiness (evidence-run entry only, NOT the PH0 gate): every df-null entry of the K list must have
// a df after the table is applied. The open list is computed from k-tests, never hard-coded.
export function dfReadiness(kTests) {
  const nullIds = kTests.filter((t) => t.df === null).map((t) => t.id);
  const open = nullIds.filter((id) => !Number.isSafeInteger(DF_TABLE[id]));
  return { ready: open.length === 0, dfNull: nullIds.length, fixed: nullIds.length - open.length, open };
}
