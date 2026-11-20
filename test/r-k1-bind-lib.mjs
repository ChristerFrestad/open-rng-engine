// Shared by test/r-k1-bind.test.mjs, test/g69-evidence-identity.test.mjs and test/r-k1-bind-entry9.test.mjs.
// R-K1-BIND (HoQ ruling; A9 "n"): every change to the wave-1 statistic module needs a statistic-equivalence
// test. The J3 calibration is recomputed with the CURRENT module by a deterministic re-run of the first 50 reps
// of ALL 26 entries from the committed IVs (stream = entry index + 1, rep, M_cal); every per-rep p must be
// bit-identical to the committed J3 p-values. If it fails, J3 is re-run under the R-CAL-FAIL record rules.
// d4021fb7 (the J3 statistic sha256) stays the provenance digest (test/labkit-calibration.test.mjs).
// G-69 GM-3/GM-5 (HoQ A9; report G-68): the evidence path (wave1-evidence statisticFromRecords) equals THE
// module fed the same real public-call outcome records (randomInt values; one fully drawn 52-card permutation,
// 51 forward Fisher-Yates draws, per shuffle) for ALL 26 entries.
// Entry 9 (randomInt/coupon-collector/min-0-max-4294967297) has its own file because its exact law takes about
// 3 minutes of BigInt work; BIND_GROUPS (below) pins that all 26 entries are bound.
import assert from 'node:assert/strict';
import { setPriority, getPriority } from 'node:os';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as S from '../verification/statistic/wave1-statistic.mjs';
import * as Src from '../verification/calibration/wave1-source.mjs';
import * as Ev from '../verification/harness/wave1-evidence.mjs';
import { RefStream } from '../verification/labkit/aes-ctr-ref.mjs';

// These files are minutes of pure CPU (about 15 CPU-min over five files). node --test runs files in parallel, so
// at normal priority they starve tests with wall-clock budgets (K3g gate: the rule27 M-167 self-test spawn hit
// its 60 s timeout). They lower their own scheduling priority (nice 10; lowering needs no privilege) so timed
// tests get the CPU first; the results are deterministic and do not depend on scheduling.
export const NICE = 10;
try { if (getPriority(0) < NICE) setPriority(0, NICE); } catch { /* not supported: run at normal priority */ }

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
export const J3 = JSON.parse(readFileSync(join(ROOT, 'verification/calibration/wave1-results-j.json'), 'utf8'));
export const REPS = 50;
export const SLOW = [9];
export const FAST = Src.ENTRIES.map((_, i) => i).filter((i) => !SLOW.includes(i));
export const ENTRIES = Src.ENTRIES;
// J3 re-run split over files so node --test runs them in parallel (wall ~5 min instead of ~15 min); the
// coverage test in test/r-k1-bind.test.mjs pins that the groups are disjoint and cover all 26 entries.
export const BIND_GROUPS = Object.freeze({
  'r-k1-bind.test.mjs': [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11],
  'r-k1-bind-dup.test.mjs': [12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23],
  'r-k1-bind-adj.test.mjs': [24, 25],
  'r-k1-bind-entry9.test.mjs': [9],
});

export function bindEntry(i, lumpedIn) {
  const e = Src.ENTRIES[i]; const row = J3.results[i];
  assert.equal(row.id, e.id); assert.equal(row.stream, i + 1); assert.ok(row.pvalues.length >= REPS);
  const M = Src.mCal(e); assert.equal(M, row.M_cal, 'M_cal');
  const lumped = lumpedIn ?? S.lumpExact(S.lawExact(e), M); assert.equal(lumped.cells.length, row.cells, 'cells');
  for (let rep = 0; rep < REPS; rep++) {
    const p = Src.replicate(e, rep, M, lumped).p;
    assert.ok(Object.is(p, row.pvalues[rep]), `${e.id} rep ${rep}: ${p} != J3 ${row.pvalues[rep]}`);
  }
}

export function identityEntry(i) {
  const e = Src.ENTRIES[i]; const M = e.kind === 'adj' ? 300 : 40;
  const lumped = S.lumpExact(S.lawExact(e), M);
  const src = Src.refSource(e, new RefStream(e.stream, 4242)); const rec = [];
  const tap = () => { let v = src(); if (typeof v === 'object') v = Array.from({ length: 52 }, (_, j) => v.card(j)); rec.push(v); return v; };
  const { h, outcomes } = S.histogram(e, M, tap, lumped.map.length);
  const direct = S.pearson(h, lumped, M);
  const ID = Array.from({ length: 52 }, (_, j) => j);
  if (Array.isArray(rec[0])) for (const p of rec) assert.deepEqual([...p].sort((a, b) => a - b), ID, e.id);
  const ev = Ev.statisticFromRecords(e, rec, M);
  assert.equal(ev.id, e.id); assert.equal(ev.statistic, S.STATISTIC_ID);
  assert.ok(Object.is(ev.x2, direct.x2), `${e.id} x2 ${ev.x2} != ${direct.x2}`); assert.ok(Object.is(ev.p, direct.p), `${e.id} p`);
  assert.equal(ev.outcomes, outcomes, e.id); assert.equal(ev.unread, 0, e.id);
  rec.push(rec[0]); assert.equal(Ev.statisticFromRecords(e, rec, M).unread, 1, e.id); rec.pop(); rec.pop();
  assert.throws(() => Ev.statisticFromRecords(e, rec, M), /records exhausted/, e.id);
}
