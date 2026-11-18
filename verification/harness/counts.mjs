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
  sequences.forEach((s, i) => {
    if (s === null || typeof s !== 'object') { f.push(`STS seq ${i}: not an object`); return; }
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

// outputs: { raw: <driver text>, u32: <driver text> }.
export function checkBigCrush(outputs) {
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
      if (!isP(row.p)) f.push(`BigCrush ${s}: row ${i} p-value outside [0,1]`);
    });
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
  return f;
}

// The whole rule 17(i) check: red (non-empty) unless every count is exact.
export function checkFirstRunCounts({ sts, bigcrush, dieharder }) {
  return [...checkSts(sts), ...checkBigCrush(bigcrush), ...checkDieharder(dieharder)];
}
