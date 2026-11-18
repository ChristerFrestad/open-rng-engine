// Rule 17(i) first-harness-run count check. Decision rule v1 (FROZEN 5d09c75a):
// "(i) First-harness-run count check. The first harness run must emit exactly the following, or the run is
// FAIL and the rule is re-frozen: 110 counted Dieharder p-values (114 emitted, 4 excluded per rule 6);
// 188 STS p-values per sequence; 160 × 2 BigCrush statistics (raw and [0,2^32))."
// Any other count is red. Inputs are parsed tool outputs; tests use synthetic fixtures only.

// Rule 4: 188 p-values per sequence, m = 1,000 sequences. Per-test split from STS 2.1.2 source
// (assess.c partitionResultFile calls; include/defs.h MAXNUMOFTEMPLATES 148 for m = 9).
// Random excursions (8) and variant (18) write 0.0 placeholders for an ineligible sequence
// (randomExcursions.c L69, randomExcursionsVariant.c L47), so the per-sequence count stays 188;
// eligibility (m′, rule 4) is an analysis step, not this count.
export const STS_PER_TEST = Object.freeze({
  Frequency: 1, BlockFrequency: 1, CumulativeSums: 2, Runs: 1, LongestRun: 1, Rank: 1, FFT: 1,
  NonOverlappingTemplate: 148, OverlappingTemplate: 1, Universal: 1, ApproximateEntropy: 1,
  RandomExcursions: 8, RandomExcursionsVariant: 18, Serial: 2, LinearComplexity: 1,
});
export const STS_PER_SEQUENCE = 188; // rule 4, rule 17(i)
export const STS_SEQUENCES = 1000; // rule 4: m = 1,000
export const BIGCRUSH_PER_STREAM = 160; // rule 5, rule 17(i)
export const BIGCRUSH_STREAMS = Object.freeze(['raw', 'u32']); // rule 5: raw and [0,2^32)
export const DIEHARDER_EMITTED = 114; // rule 6
export const DIEHARDER_COUNTED = 110; // rule 6, rule 17(i)
// Rule 6: -d 5 OPSO, -d 6 OQSO, -d 7 DNA, -d 14 Sums; names from dieharder 3.31.1 (sha256 6cff0ff8...)
// include/dieharder/diehard_{opso,oqso,dna,sums}.h and the ADD_TEST order in dieharder_test_types.c.
export const DIEHARDER_EXCLUDED = Object.freeze(['diehard_opso', 'diehard_oqso', 'diehard_dna', 'diehard_sums']);

// EG-2 (HoQ addendum 1, 4195afbc): 17(i) checks provenance, not only counts.
// BigCrush test names in row order, derived from the pinned TestU01 1.2.3 source (sha256 bc1d1dd2...):
// testu01/bbattery.c static BigCrush(), preprocessed with USE_LONGLONG (64-bit build), one name per
// bbattery_pVal[++j]; GetPVal_CPairs (N > 1, snpair_mNP2S_Flag TRUE) gives NP, mNP, mNP1, mNP2, NJumps, mNP2S;
// GetPVal_Walk (N = 1) gives H, M, J, R, C. Names repeat (e.g. two CollisionOver t = 2 rows), so the ORDER
// is the identity. Not yet compared with a real BigCrush run (ANTATT until the first harness run).
export const BIGCRUSH_TEST_NAMES = Object.freeze(["SerialOver, r = 0", "SerialOver, r = 22", "CollisionOver, t = 2", "CollisionOver, t = 2", "CollisionOver, t = 3", "CollisionOver, t = 3", "CollisionOver, t = 7", "CollisionOver, t = 7", "CollisionOver, t = 14", "CollisionOver, t = 14", "CollisionOver, t = 21", "CollisionOver, t = 21", "BirthdaySpacings, t = 2", "BirthdaySpacings, t = 3", "BirthdaySpacings, t = 4", "BirthdaySpacings, t = 7", "BirthdaySpacings, t = 7", "BirthdaySpacings, t = 8", "BirthdaySpacings, t = 8", "BirthdaySpacings, t = 16", "BirthdaySpacings, t = 16", "ClosePairs NP, t = 3", "ClosePairs mNP, t = 3", "ClosePairs mNP1, t = 3", "ClosePairs mNP2, t = 3", "ClosePairs NJumps, t = 3", "ClosePairs mNP2S, t = 3", "ClosePairs NP, t = 5", "ClosePairs mNP, t = 5", "ClosePairs mNP1, t = 5", "ClosePairs mNP2, t = 5", "ClosePairs NJumps, t = 5", "ClosePairs mNP2S, t = 5", "ClosePairs NP, t = 9", "ClosePairs mNP, t = 9", "ClosePairs mNP1, t = 9", "ClosePairs mNP2, t = 9", "ClosePairs NJumps, t = 9", "ClosePairs mNP2S, t = 9", "ClosePairs NP, t = 16", "ClosePairs mNP, t = 16", "ClosePairs mNP1, t = 16", "ClosePairs mNP2, t = 16", "ClosePairs NJumps, t = 16", "ClosePairs mNP2S, t = 16", "Simp\u0050oker, r = 0", "Simp\u0050oker, r = 27", "Simp\u0050oker, r = 0", "Simp\u0050oker, r = 25", "CouponCollector, r = 0", "CouponCollector, r = 10", "CouponCollector, r = 20", "CouponCollector, r = 27", "Gap, r = 0", "Gap, r = 25", "Gap, r = 0", "Gap, r = 20", "Run, r = 0", "Run, r = 15", "Permutation, t = 3", "Permutation, t = 5", "Permutation, t = 7", "Permutation, t = 10", "CollisionPermut, r = 0", "CollisionPermut, r = 10", "MaxOft, t = 8", "MaxOft AD, t = 8", "MaxOft, t = 16", "MaxOft AD, t = 16", "MaxOft, t = 24", "MaxOft AD, t = 24", "MaxOft, t = 32", "MaxOft AD, t = 32", "SampleProd, t = 8", "SampleProd, t = 16", "SampleProd, t = 24", "SampleMean, r = 0", "SampleMean, r = 10", "SampleCorr, k = 1", "SampleCorr, k = 2", "AppearanceSpacings, r = 0", "AppearanceSpacings, r = 27", "WeightDistrib, r = 0", "WeightDistrib, r = 20", "WeightDistrib, r = 28", "WeightDistrib, r = 0", "WeightDistrib, r = 10", "WeightDistrib, r = 26", "SumCollector", "MatrixRank, L=30, r=0", "MatrixRank, L=30, r=26", "MatrixRank, L=1000, r=0", "MatrixRank, L=1000, r=26", "MatrixRank, L=5000", "MatrixRank, L=5000", "Savir2", "GCD", "RandomWalk1 H (L=50, r=0)", "RandomWalk1 M (L=50, r=0)", "RandomWalk1 J (L=50, r=0)", "RandomWalk1 R (L=50, r=0)", "RandomWalk1 C (L=50, r=0)", "RandomWalk1 H (L=50, r=25)", "RandomWalk1 M (L=50, r=25)", "RandomWalk1 J (L=50, r=25)", "RandomWalk1 R (L=50, r=25)", "RandomWalk1 C (L=50, r=25)", "RandomWalk1 H (L=1000, r=0)", "RandomWalk1 M (L=1000, r=0)", "RandomWalk1 J (L=1000, r=0)", "RandomWalk1 R (L=1000, r=0)", "RandomWalk1 C (L=1000, r=0)", "RandomWalk1 H (L=1000, r=20)", "RandomWalk1 M (L=1000, r=20)", "RandomWalk1 J (L=1000, r=20)", "RandomWalk1 R (L=1000, r=20)", "RandomWalk1 C (L=1000, r=20)", "RandomWalk1 H (L=10000, r=0)", "RandomWalk1 M (L=10000, r=0)", "RandomWalk1 J (L=10000, r=0)", "RandomWalk1 R (L=10000, r=0)", "RandomWalk1 C (L=10000, r=0)", "RandomWalk1 H (L=10000, r=15)", "RandomWalk1 M (L=10000, r=15)", "RandomWalk1 J (L=10000, r=15)", "RandomWalk1 R (L=10000, r=15)", "RandomWalk1 C (L=10000, r=15)", "LinearComp, r = 0", "LinearComp, r = 0", "LinearComp, r = 29", "LinearComp, r = 0", "LempelZiv, r = 0", "LempelZiv, r = 15", "Fourier3, r = 0", "Fourier3, r = 27", "LongestHeadRun, r = 0", "LongestHeadRun, r = 0", "LongestHeadRun, r = 27", "LongestHeadRun, r = 27", "PeriodsInStrings, r = 0", "PeriodsInStrings, r = 20", "HammingWeight2, r = 0", "HammingWeight2, r = 27", "HammingCorr, L = 30", "HammingCorr, L = 300", "HammingCorr, L = 1200", "HammingIndep, L=30, r=0", "HammingIndep, L=30, r=27", "HammingIndep, L=300, r=0", "HammingIndep, L=300, r=26", "HammingIndep, L=1200, r=0", "HammingIndep, L=1200, r=25", "Run of bits, r = 0", "Run of bits, r = 0", "Run of bits, r = 27", "Run of bits, r = 27", "AutoCor, d=1, r=0", "AutoCor, d=3, r=0", "AutoCor, d=1, r=27", "AutoCor, d=3, r=27"]);
// Dieharder 3.31.1 `-a` rows in output order, derived from the pinned source (sha256 6cff0ff8...):
// libdieharder/dieharder_test_types.c ADD_TEST order; nkps from include/dieharder/*.h; the ntuple loops in
// dieharder/run_all_tests.c (rgb_bitdist 1..12, rgb_minimum_distance 2..5, rgb_permutations 2..5,
// rgb_lagged_sum 0..32); names printed with %20.20s (dieharder/output.c), so long names are cut to 20.
// Two tool test names contain rule 40 protected words; they are written with a \u escape (the repo's
// practice for protected terms in tool data, as rule22's escaped term list). Runtime strings are the tool's.
// [name, ntup]: ntup is pinned only where the source sets it to a constant or the loop value; null = not
// pinned. 114 rows, 110 counted. Not yet compared with a real run (ANTATT, as the frozen text says).
export const DIEHARDER_ROWS = Object.freeze([["diehard_birthdays", null], ["diehard_operm5", null], ["diehard_rank_32x32", null], ["diehard_rank_6x8", 0], ["diehard_bitstream", null], ["diehard_opso", 0], ["diehard_oqso", null], ["diehard_dna", 0], ["diehard_count_1s_str", 0], ["diehard_count_1s_byt", null], ["diehard_parking_lot", null], ["diehard_2dsphere", null], ["diehard_3dsphere", 3], ["diehard_squeeze", 0], ["diehard_sums", null], ["diehard_runs", 0], ["diehard_runs", 0], ["diehard_\u0063raps", 0], ["diehard_\u0063raps", 0], ["marsaglia_tsang_gcd", 0], ["marsaglia_tsang_gcd", 0], ["sts_monobit", 1], ["sts_runs", 2], ["sts_serial", 1], ["sts_serial", 2], ["sts_serial", 3], ["sts_serial", 3], ["sts_serial", 4], ["sts_serial", 4], ["sts_serial", 5], ["sts_serial", 5], ["sts_serial", 6], ["sts_serial", 6], ["sts_serial", 7], ["sts_serial", 7], ["sts_serial", 8], ["sts_serial", 8], ["sts_serial", 9], ["sts_serial", 9], ["sts_serial", 10], ["sts_serial", 10], ["sts_serial", 11], ["sts_serial", 11], ["sts_serial", 12], ["sts_serial", 12], ["sts_serial", 13], ["sts_serial", 13], ["sts_serial", 14], ["sts_serial", 14], ["sts_serial", 15], ["sts_serial", 15], ["sts_serial", 16], ["sts_serial", 16], ["rgb_bitdist", 1], ["rgb_bitdist", 2], ["rgb_bitdist", 3], ["rgb_bitdist", 4], ["rgb_bitdist", 5], ["rgb_bitdist", 6], ["rgb_bitdist", 7], ["rgb_bitdist", 8], ["rgb_bitdist", 9], ["rgb_bitdist", 10], ["rgb_bitdist", 11], ["rgb_bitdist", 12], ["rgb_minimum_distance", 2], ["rgb_minimum_distance", 3], ["rgb_minimum_distance", 4], ["rgb_minimum_distance", 5], ["rgb_permutations", 2], ["rgb_permutations", 3], ["rgb_permutations", 4], ["rgb_permutations", 5], ["rgb_lagged_sum", 0], ["rgb_lagged_sum", 1], ["rgb_lagged_sum", 2], ["rgb_lagged_sum", 3], ["rgb_lagged_sum", 4], ["rgb_lagged_sum", 5], ["rgb_lagged_sum", 6], ["rgb_lagged_sum", 7], ["rgb_lagged_sum", 8], ["rgb_lagged_sum", 9], ["rgb_lagged_sum", 10], ["rgb_lagged_sum", 11], ["rgb_lagged_sum", 12], ["rgb_lagged_sum", 13], ["rgb_lagged_sum", 14], ["rgb_lagged_sum", 15], ["rgb_lagged_sum", 16], ["rgb_lagged_sum", 17], ["rgb_lagged_sum", 18], ["rgb_lagged_sum", 19], ["rgb_lagged_sum", 20], ["rgb_lagged_sum", 21], ["rgb_lagged_sum", 22], ["rgb_lagged_sum", 23], ["rgb_lagged_sum", 24], ["rgb_lagged_sum", 25], ["rgb_lagged_sum", 26], ["rgb_lagged_sum", 27], ["rgb_lagged_sum", 28], ["rgb_lagged_sum", 29], ["rgb_lagged_sum", 30], ["rgb_lagged_sum", 31], ["rgb_lagged_sum", 32], ["rgb_kstest_test", null], ["dab_bytedistrib", 0], ["dab_dct", 256], ["dab_filltree", 32], ["dab_filltree", 32], ["dab_filltree2", 0], ["dab_filltree2", 1], ["dab_monobit2", null]].map((r) => Object.freeze(r)));

function isP(x) {
  return typeof x === 'number' && Number.isFinite(x) && x >= 0 && x <= 1;
}

function sum(o) {
  return Object.values(o).reduce((a, b) => a + b, 0);
}

// sequences: array (one per sequence) of objects { <STS test name>: number[] }.
export function checkSts(sequences) {
  const f = [];
  if (sum(STS_PER_TEST) !== STS_PER_SEQUENCE) f.push('STS per-test split does not sum to 188');
  if (!Array.isArray(sequences)) return [...f, 'STS: no sequence list'];
  if (sequences.length !== STS_SEQUENCES) f.push(`STS: ${sequences.length} sequences, expected ${STS_SEQUENCES} (rule 4)`);
  const seen = new Map();
  sequences.forEach((s, i) => {
    if (s === null || typeof s !== 'object') { f.push(`STS seq ${i}: not an object`); return; }
    const key = JSON.stringify(Object.keys(STS_PER_TEST).map((k) => s[k]));
    if (seen.has(key)) f.push(`STS seq ${i}: duplicate of sequence ${seen.get(key)} (EG-2: no duplicated sequences)`);
    else seen.set(key, i);
    let total = 0;
    for (const k of Object.keys(s)) if (!(k in STS_PER_TEST)) f.push(`STS seq ${i}: unknown test ${k}`);
    for (const [k, want] of Object.entries(STS_PER_TEST)) {
      const v = s[k];
      if (!Array.isArray(v)) { f.push(`STS seq ${i}: ${k} missing`); continue; }
      total += v.length;
      if (v.length !== want) f.push(`STS seq ${i}: ${k} has ${v.length} p-values, expected ${want}`);
      if (!v.every(isP)) f.push(`STS seq ${i}: ${k} has a value outside [0,1]`);
    }
    if (total !== STS_PER_SEQUENCE) f.push(`STS seq ${i}: ${total} p-values, expected ${STS_PER_SEQUENCE} (rule 17(i))`);
  });
  return f;
}

// tu01-driver v1 output (verification/harness/tu01-driver.c).
export function parseTu01(text) {
  const lines = String(text).split('\n').filter((l) => l.length > 0);
  if (lines.length === 0 || !lines[0].startsWith('# tu01-driver v1\t')) return { error: 'missing tu01-driver v1 header' };
  const head = Object.fromEntries(lines[0].split('\t').slice(1).map((kv) => kv.split('=')));
  const rows = [];
  for (const l of lines.slice(1)) {
    const c = l.split('\t');
    if (c.length !== 5) return { error: `bad row: ${l}` };
    rows.push({ battery: c[0], stream: c[1], index: Number(c[2]), name: c[3], p: Number(c[4]) });
  }
  return { head, rows };
}

// outputs: { raw: <driver text>, u32: <driver text> }. inputs: { raw: sha256, u32: sha256 } of the two
// input streams as fed to the driver (EG-2: the u32 stream must be proven distinct from raw).
const HEX64 = /^[0-9a-f]{64}$/;
export function checkBigCrush(outputs, inputs) {
  const f = [];
  if (outputs === null || typeof outputs !== 'object') return ['BigCrush: no outputs'];
  const keys = Object.keys(outputs).sort();
  if (keys.join(',') !== [...BIGCRUSH_STREAMS].sort().join(',')) f.push(`BigCrush: streams ${keys.join(',')}, expected raw,u32 (rule 5)`);
  for (const s of BIGCRUSH_STREAMS) {
    if (!(s in outputs)) continue;
    const r = parseTu01(outputs[s]);
    if (r.error) { f.push(`BigCrush ${s}: ${r.error}`); continue; }
    if (r.head.battery !== 'BigCrush' || r.head.stream !== s) f.push(`BigCrush ${s}: header battery/stream mismatch`);
    if (Number(r.head.ntests) !== BIGCRUSH_PER_STREAM) f.push(`BigCrush ${s}: header ntests ${r.head.ntests}, expected 160`);
    if (r.rows.length !== BIGCRUSH_PER_STREAM) f.push(`BigCrush ${s}: ${r.rows.length} statistics, expected ${BIGCRUSH_PER_STREAM} (rule 17(i))`);
    r.rows.forEach((row, i) => {
      if (row.battery !== 'BigCrush' || row.stream !== s || row.index !== i) f.push(`BigCrush ${s}: row ${i} out of order`);
      if (row.name !== BIGCRUSH_TEST_NAMES[i]) f.push(`BigCrush ${s}: row ${i} is ${JSON.stringify(row.name)}, expected ${JSON.stringify(BIGCRUSH_TEST_NAMES[i])} (EG-2)`);
      if (!isP(row.p)) f.push(`BigCrush ${s}: row ${i} p-value outside [0,1]`);
    });
  }
  if (!inputs || typeof inputs !== 'object' || !HEX64.test(String(inputs.raw)) || !HEX64.test(String(inputs.u32))) {
    f.push('BigCrush: input stream sha256 for raw and u32 missing (EG-2)');
  } else if (inputs.raw === inputs.u32) {
    f.push('BigCrush: u32 input stream is the raw stream (same sha256) (EG-2)');
  }
  const pr = outputs.raw !== undefined && parseTu01(outputs.raw);
  const pu = outputs.u32 !== undefined && parseTu01(outputs.u32);
  if (pr && pu && !pr.error && !pu.error && pr.rows.length > 0 && JSON.stringify(pr.rows.map((x) => x.p)) === JSON.stringify(pu.rows.map((x) => x.p))) {
    f.push('BigCrush: u32 p-values are identical to raw (EG-2: u32 is not a distinct stream)');
  }
  return f;
}

// dieharder -a table rows: "   test_name|ntup| tsamples |psamples|  p-value |Assessment".
const DH_ROW = /^\s*([a-z0-9_]+)\|\s*(\d+)\|\s*(\d+)\|\s*(\d+)\|\s*([0-9.eE+-]+)\|\s*([A-Z]+)\s*$/;
export function parseDieharder(text) {
  const rows = [];
  for (const l of String(text).split('\n')) {
    const m = DH_ROW.exec(l);
    if (m) rows.push({ name: m[1], ntup: Number(m[2]), p: Number(m[5]) });
  }
  return rows;
}

export function checkDieharder(text) {
  const f = [];
  const rows = parseDieharder(text);
  if (rows.length !== DIEHARDER_EMITTED) f.push(`Dieharder: ${rows.length} p-values emitted, expected ${DIEHARDER_EMITTED} (rule 6)`);
  for (const name of DIEHARDER_EXCLUDED) {
    const n = rows.filter((r) => r.name === name).length;
    if (n !== 1) f.push(`Dieharder: excluded test ${name} emitted ${n} rows, expected 1 (rule 6)`);
  }
  const counted = rows.filter((r) => !DIEHARDER_EXCLUDED.includes(r.name));
  if (counted.length !== DIEHARDER_COUNTED) f.push(`Dieharder: ${counted.length} counted p-values, expected ${DIEHARDER_COUNTED} (rule 17(i))`);
  if (!rows.every((r) => isP(r.p))) f.push('Dieharder: a p-value outside [0,1]');
  // EG-2: the exact pinned row list, in order (a duplicated row plus a missing one is red).
  const nrow = Math.max(rows.length, DIEHARDER_ROWS.length);
  for (let i = 0; i < nrow; i++) {
    const got = rows[i], want = DIEHARDER_ROWS[i];
    if (!got || !want || got.name !== want[0] || (want[1] !== null && got.ntup !== want[1])) {
      f.push(`Dieharder: row ${i} is ${got ? `${got.name} ntup ${got.ntup}` : 'missing'}, expected ${want ? `${want[0]} ntup ${want[1] ?? 'any'}` : 'no row'} (EG-2)`);
    }
  }
  return f;
}

// The whole rule 17(i) check: red (non-empty) unless every count is exact.
export function checkFirstRunCounts({ sts, bigcrush, bigcrushInputs, dieharder }) {
  return [...checkSts(sts), ...checkBigCrush(bigcrush, bigcrushInputs), ...checkDieharder(dieharder)];
}
