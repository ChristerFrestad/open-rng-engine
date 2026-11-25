// HoQ A30 (hoq-ph1-m1-addendum-1.md L791, A29-1 method ruling): the paired estimator, load guard and verdicts for the
// A25 overhead bench. Pure logic; verification/bench/r-g64-a25-a30.mjs wires it to real child runs, and
// test/r-g64-a30.test.mjs drives it with fake runs. Not evidence, not a gate, not run by npm test except its own tests.
//  1. Per entry: N >= 7 valid pairs. Pair i runs a25 then plain when i is even and plain then a25 when i is odd (ABBA
//     across repeats). Pair overhead = a25 median_ns / plain median_ns - 1. Entry overhead = median of the N pair
//     overheads; repeats are never pooled into one median_ns.
//  2. Entry PASS: median <= 0.100 exactly (no rounding: 10.04% fails) and fewer than ceil(N/2)+1 pairs above 10%. Entry FAIL otherwise. Each entry
//     reports its max and its count above 10%.
//  3. load1 is sampled before each pair; above the guard (4.0) the pair is void: it is logged, not run, and retried
//     after the back-off. At most 2N attempts (valid + void) per entry; if N valid pairs are not reached the entry is
//     INCONCLUSIVE, never PASS.
//  4. N, k, guard, back-off, bench sha and backstop sha are fixed before the run (pre-registration); the run takes
//     exactly N valid pairs per entry, never more.
export const A30 = Object.freeze({ N_MIN: 7, LIMIT: 0.10, GUARD_LOAD1: 4.0 });

export function pairOrder(i) {
  if (!Number.isInteger(i) || i < 0) throw new Error('pairOrder: i must be a non-negative integer');
  return i % 2 === 0 ? ['a25', 'plain'] : ['plain', 'a25'];
}
export function median(xs) {
  if (!xs.length) throw new Error('median of nothing');
  const v = [...xs].sort((a, b) => a - b);
  return (v[(v.length - 1) >> 1] + v[v.length >> 1]) / 2;
}
export const failCount = (N) => Math.ceil(N / 2) + 1;

// overheads: the N valid pair overheads (fractions). attempts: valid + void attempts made.
export function entryVerdict(overheads, { N, attempts }) {
  checkN(N);
  if (overheads.length > N) throw new Error(`entry has ${overheads.length} valid pairs, more than the pre-registered N=${N}`);
  if (overheads.length < N) return { verdict: 'INCONCLUSIVE', valid: overheads.length, attempts, median: null, max: overheads.length ? Math.max(...overheads) : null, above: overheads.filter((o) => o > A30.LIMIT).length };
  const med = median(overheads), above = overheads.filter((o) => o > A30.LIMIT).length;
  const pass = med <= A30.LIMIT && above < failCount(N);
  return { verdict: pass ? 'PASS' : 'FAIL', valid: N, attempts, median: med, max: Math.max(...overheads), above };
}

export function overallVerdict(entries) {
  if (!entries.length) return 'INCONCLUSIVE';
  if (entries.some((e) => e.verdict === 'FAIL')) return 'FAIL';
  if (entries.some((e) => e.verdict !== 'PASS')) return 'INCONCLUSIVE';
  return 'PASS';
}
function checkN(N) { if (!Number.isInteger(N) || N < A30.N_MIN) throw new Error(`A30 needs N >= ${A30.N_MIN} (got ${N})`); }

// Runs one entry. runChild(which, ctx) -> { median_ns, burned, ... }; sampleLoad() -> load1; sleep(ms) waits.
// Every attempt (void or valid) is returned in `pairs`, in order.
export async function runEntry({ key, N, guard = A30.GUARD_LOAD1, backoffMs, sampleLoad, runChild, sleep }) {
  checkN(N);
  if (guard !== A30.GUARD_LOAD1) throw new Error(`A30 guard is ${A30.GUARD_LOAD1} (got ${guard})`);
  const pairs = []; const overheads = []; let burned = null; let attempts = 0;
  while (overheads.length < N && attempts < 2 * N) {
    attempts++;
    const load1 = sampleLoad();
    if (!(load1 <= guard)) { pairs.push({ attempt: attempts, load1, void: true, reason: `load1 ${load1} > ${guard}` }); await sleep(backoffMs); continue; }
    const i = overheads.length; const order = pairOrder(i); const r = {};
    for (const which of order) { r[which] = await runChild(which, { key, burn: which === 'plain' ? burned : null }); if (which === 'a25') burned = r.a25.burned; }
    const overhead = r.a25.median_ns / r.plain.median_ns - 1;
    if (!Number.isFinite(overhead)) throw new Error(`${key}: pair ${i} overhead is not finite`);
    overheads.push(overhead);
    pairs.push({ attempt: attempts, load1, void: false, pair: i, order: order.join('>'), a25: r.a25, plain: r.plain, overhead });
  }
  return { key, pairs, ...entryVerdict(overheads, { N, attempts }) };
}

// The call shapes of verification/k-tests-v1.1.json, keyed and ordered exactly as r-g64-a25-stageA.mjs keys them
// (test/r-g64-a30.test.mjs checks the two agree on the real file).
export function shapeKey(k) {
  const p = k.parameters || {};
  return k.primitive === 'randomInt' ? `randomInt [${p.min},${p.max})` : k.primitive === 'shuffle' ? `shuffle n=${p.n ?? 52}`
    : k.primitive === 'sample' ? `sample n=${p.n} k=${p.k}` : `weightedPick ${Array.isArray(p.weights) ? `[${p.weights}]` : p.strip}`;
}
export function shapeKeys(tests) { const seen = []; for (const t of tests) { const k = shapeKey(t); if (!seen.includes(k)) seen.push(k); } return seen; }
