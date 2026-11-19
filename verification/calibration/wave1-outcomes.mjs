#!/usr/bin/env node
// H2 (CTO 04:37): outcomes consumed per replication for every wave-1 calibration entry, written into
// verification/calibration/wave1-results.json. Unit = one outcome as counted in HoQ's verified consumption
// column (hoq-ph1-coverage-c9d7c93-dbd4e00.md (e): M x b x u randomInt outcomes for duplicates, e.g.
// [0,2) 12208 x 4096 x 20 = 1,000,079,360). Duplicates and adjacency consume a fixed count (asserted equal
// to the measured minimum); coupon consumption is random, so it comes from a recount run of the same
// replications whose p-value digest must equal the original's bit for bit.
// Usage: node verification/calibration/wave1-outcomes.mjs --recount-dir D
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ENTRIES, mCal, N_CAL } from './wave1-entries.mjs';

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const dir = arg('--recount-dir', '/workspace/rng-backup/calibration-recount');
const file = fileURLToPath(new URL('./wave1-results.json', import.meta.url));
const doc = JSON.parse(readFileSync(file, 'utf8'));
const fail = (m) => { console.error(`wave1-outcomes: ${m}`); process.exit(1); };
doc.results = doc.results.map((row, i) => {
  const e = ENTRIES[i];
  if (e.id !== row.id) fail(`row ${i} is ${row.id}, expected ${e.id}`);
  const M = mCal(e); if (M !== row.M_cal) fail(`${e.id}: M_cal ${row.M_cal} != ${M}`);
  let o;
  if (e.kind === 'coupon') {
    const rc = JSON.parse(readFileSync(join(dir, `entry-${String(i).padStart(2, '0')}.json`), 'utf8')).row;
    if (rc.pvalue_sha256 !== row.pvalue_sha256 || rc.minOutcomes !== row.minOutcomes) fail(`${e.id}: recount differs from the original run`);
    o = { unit: e.r === 'lehmer' ? 'one forward Fisher-Yates first-card draw below(52) per coupon draw' : `one randomInt(${e.r}) outcome per coupon draw`,
      rule: 'random: sum over M_cal observations of the draws to collect all d coupons (>= M_cal x d)',
      lower_bound: M * e.d, min: rc.minOutcomes, max: rc.outcomes_max, mean: rc.outcomes_total / row.reps, per_rep_sha256: rc.outcomes_sha256, recount_pvalue_sha256_equal: true };
  } else if (e.kind === 'dup') {
    const n = M * e.b * e.u;
    if (row.minOutcomes !== n) fail(`${e.id}: measured ${row.minOutcomes} != M x b x u ${n}`);
    o = { unit: e.r === 'lehmer' ? 'one 52-card shuffle per urn' : `one randomInt(${e.r}) outcome; u = ${e.u} per urn`,
      rule: `fixed: M_cal x b x u = ${M} x ${e.b} x ${e.u}`, exact: n, urns: M * e.b };
  } else {
    if (row.minOutcomes !== M) fail(`${e.id}: measured ${row.minOutcomes} != M ${M}`);
    o = { unit: 'one 52-card shuffle (51 below() draws)', rule: `fixed: M_cal = ${M} shuffles`, exact: M };
  }
  o.meets_n_1e6 = (o.exact ?? o.min) >= N_CAL;
  return { ...row, outcomes_per_rep: o };
});
doc.outcomes_note = 'Per-replication outcomes (CTO 04:37 check): unit as in HoQ (e) consumption (M x b x u). No entry is below 10^6, so none was re-run and none is superseded. Rows were produced by wave1-calibrate.mjs at H1 5995a877 (sha256 in harness_sha256); the H2 runner change (error-listener removal, outcome fields) does not change any computed value, which the coupon recount confirms (equal p-value digests).';
writeFileSync(file, JSON.stringify(doc, null, 1) + '\n');
const short = doc.results.filter((r) => !r.outcomes_per_rep.meets_n_1e6);
console.log(`wave1-outcomes: ${doc.results.length} rows annotated; below 10^6: ${short.length}`);
if (short.length) process.exit(2);
