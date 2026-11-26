// R-G64 item 3: RC decision with the R118-2 stream-collapsed flag count (A23, CPO-accepted A23.1), pooled
// over run 1 and the pre-registered run 2 (R118-1/-3), and the gating M-R118-2b checks: a single-stream defect
// that flags >= 6 entries on one stream must still end in FAIL through the rule-9 re-run (variant i), and a
// re-run that omits a flagged entry makes the decision refuse (variant ii).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import * as D from '../verification/harness/rc-decision.mjs';
import * as P from '../verification/harness/run-plan.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const K = P.loadKTests(ROOT);
const BIG = K.filter((k) => /^shuffle\/positional\//.test(k.id) && k.parameters.n >= 104).map((k) => k.id);
const plan1 = P.buildPlan({ runId: '1', prefix: 'S', N: 1, kTests: K, M: Object.fromEntries(K.map((k) => [k.id, BIG.includes(k.id) ? 1e8 : 1e9])) });
const plan2 = P.buildPlan({ runId: '2', prefix: 'T', N: 1, kTests: K, M: Object.fromEntries(BIG.map((id) => [id, 1e9])) });
// p-values: a clean run at 0.5 everywhere unless overridden by entry id
const testsOf = (plan, ps = {}) => plan.streams.flatMap((s) => s.entries.map((e) => ({ run: plan.run_id, entry: e.id, stream: `${plan.run_id}/${s.id}`, M: e.M, p: ps[e.id] ?? 0.5 })));
const both = (ps1 = {}, ps2 = {}) => [...testsOf(plan1, ps1), ...testsOf(plan2, ps2)];
const BAD = 1e-6; // flagged (< 0.01/157), not in the failure band
// the shared stream with the most entries (22 on one stream): the single-stream defect of M-R118-2b
const wide = plan1.streams.reduce((a, s) => (s.entries.length > a.entries.length ? s : a));
const defect = Object.fromEntries(wide.entries.map((e) => [e.id, BAD]));
const rerunsOf = (flagged, p, { stream = (e) => `R/${e.entry}`, M = (e) => e.M } = {}) => flagged.map((e) => ({ of_run: e.run, entry: e.entry, stream: stream(e), M: M(e), p: typeof p === 'function' ? p(e) : p }));

test('counting rule constants: K_count 161, threshold 0.01/157, 28 independent streams over both runs', () => {
  assert.equal(D.K_COUNT, 161); assert.equal(D.THRESHOLD, 0.01 / 157); assert.equal(D.HARD_FLAGS, 6);
  assert.equal(D.COUNTING_RULE.K_count, 161); assert.equal(D.COUNTING_RULE.threshold, 0.01 / 157);
  assert.equal(plan1.streams.length + plan2.streams.length, 28);
  assert.equal(both().length, 161);
  assert.ok(wide.entries.length >= 6);
});

test('clean: 0 flags over both runs', () => {
  const r = D.decide({ tests: both(), expectK: 161 });
  assert.equal(r.verdict, 'CLEAN'); assert.equal(r.flags_per_entry, 0); assert.equal(r.flags_collapsed, 0);
});

test('threshold is 0.01/157, not 0.01/161', () => {
  const p = (0.01 / 157 + 0.01 / 161) / 2;
  const r = D.decide({ tests: both({ [K[0].id]: p }), expectK: 161 });
  assert.equal(r.verdict, 'SUSPECT'); assert.equal(r.flags_per_entry, 1);
});

test('M-R118-2b (i): a single-stream defect flagging >= 6 entries collapses to 1, is SUSPECT, and still FAILs when it persists in the fresh re-run', () => {
  const first = D.decide({ tests: both(defect), expectK: 161 });
  assert.equal(first.verdict, 'SUSPECT');
  assert.equal(first.flags_per_entry, wide.entries.length); assert.equal(first.flags_collapsed, 1);
  assert.deepEqual(first.rerun_required.map((x) => x.entry), wide.entries.map((e) => e.id));
  // report shows flags per entry and per stream (D22-2)
  const ps = first.per_stream.find((s) => s.stream === `1/${wide.id}`);
  assert.equal(ps.flags, wide.entries.length); assert.deepEqual(ps.entries, wide.entries.map((e) => e.id));
  assert.equal(first.per_stream.filter((s) => s.flags > 0).length, 1);
  const r = D.decide({ tests: both(defect), reruns: rerunsOf(first.flagged, BAD, { stream: () => 'R1/S99' }), expectK: 161 });
  assert.equal(r.verdict, 'FAIL'); assert.equal(r.why.length, wide.entries.length);
  assert.ok(r.reruns.every((x) => x.flagged_again));
  // the defect persisting in even one re-run entry is FAIL
  const one = D.decide({ tests: both(defect), reruns: rerunsOf(first.flagged, (e) => (e.entry === wide.entries[3].id ? BAD : 0.4)), expectK: 161 });
  assert.equal(one.verdict, 'FAIL'); assert.match(one.why.join(), new RegExp(wide.entries[3].id.replace(/[/]/g, '\\/')));
});

test('M-R118-2b: the same defect gone in the re-run is PASS-WITH-NOTE, with both results logged', () => {
  const first = D.decide({ tests: both(defect), expectK: 161 });
  const r = D.decide({ tests: both(defect), reruns: rerunsOf(first.flagged, 0.3), expectK: 161 });
  assert.equal(r.verdict, 'PASS-WITH-NOTE');
  assert.equal(r.reruns.length, wide.entries.length);
  assert.ok(r.reruns.every((x) => x.p === BAD && x.rerun_p === 0.3 && !x.flagged_again));
});

test('M-R118-2b (ii): a re-run that omits any flagged entry is refused', () => {
  const first = D.decide({ tests: both(defect), expectK: 161 });
  for (const skip of [0, first.flagged.length - 1]) {
    const rr = rerunsOf(first.flagged, BAD).filter((_, i) => i !== skip);
    assert.throws(() => D.decide({ tests: both(defect), reruns: rr, expectK: 161 }), /has no re-run/);
  }
  assert.throws(() => D.decide({ tests: both(defect), reruns: [], expectK: 161 }), /has no re-run/);
});

test('rule 9 re-run discipline: fresh stream, same M, exactly once, no other re-runs', () => {
  const tests = both({ [K[0].id]: BAD });
  const f = D.decide({ tests, expectK: 161 }).flagged;
  assert.throws(() => D.decide({ tests, reruns: rerunsOf(f, 0.5, { stream: (e) => e.stream }), expectK: 161 }), /reuses stream/);
  assert.throws(() => D.decide({ tests, reruns: rerunsOf(f, 0.5, { M: (e) => e.M / 10 }), expectK: 161 }), /same sample size/);
  assert.throws(() => D.decide({ tests, reruns: [...rerunsOf(f, 0.5), ...rerunsOf(f, 0.5)], expectK: 161 }), /more than once/);
  assert.throws(() => D.decide({ tests, reruns: [...rerunsOf(f, 0.5), { of_run: '1', entry: K[1].id, stream: 'R/x', M: 1e9, p: 0.5 }], expectK: 161 }), /unflagged/);
});

test('>= 6 flagged streams is hard FAIL with no re-run; 5 is SUSPECT; flags pool over both runs', () => {
  const ent = (s) => s.entries[0].id;
  const five = Object.fromEntries(plan1.streams.slice(0, 5).map((s) => [ent(s), BAD]));
  assert.equal(D.decide({ tests: both(five), expectK: 161 }).verdict, 'SUSPECT');
  const six = Object.fromEntries(plan1.streams.slice(0, 6).map((s) => [ent(s), BAD]));
  const r = D.decide({ tests: both(six), expectK: 161 });
  assert.equal(r.verdict, 'FAIL'); assert.equal(r.flags_collapsed, 6); assert.equal(r.rerun_required, undefined);
  // 3 run-1 streams + 3 run-2 streams: one pooled decision (R118-3)
  const p1 = Object.fromEntries(plan1.streams.slice(0, 3).map((s) => [ent(s), BAD]));
  const p2 = Object.fromEntries(plan2.streams.slice(0, 3).map((s) => [ent(s), BAD]));
  const pooled = D.decide({ tests: both(p1, p2), expectK: 161 });
  assert.equal(pooled.verdict, 'FAIL'); assert.equal(pooled.flags_collapsed, 6);
  // the run-1 10^8 entries stay in the family (no best-of): a run-1 flag on n-104 is counted even if run 2 is clean
  const b = D.decide({ tests: both({ [BIG[0]]: BAD }), expectK: 161 });
  assert.equal(b.verdict, 'SUSPECT'); assert.deepEqual(b.flagged.map((e) => [e.run, e.entry]), [['1', BIG[0]]]);
});

test('failure band p < 1e-10 is hard FAIL; missing evidence is FAIL; duplicates and bad p refused', () => {
  assert.equal(D.decide({ tests: both({ [K[5].id]: 1e-11 }), expectK: 161 }).verdict, 'FAIL');
  const r = D.decide({ tests: both().slice(1), expectK: 161 });
  assert.equal(r.verdict, 'FAIL'); assert.match(r.why[0], /missing evidence/);
  const t = both(); t[1] = { ...t[0] };
  assert.throws(() => D.decide({ tests: t, expectK: 161 }), /appears twice/);
  const u = both(); u[2] = { ...u[2], p: NaN };
  assert.throws(() => D.decide({ tests: u, expectK: 161 }), /no p-value/);
});

test('only launcher-counted streams are evidence', () => {
  const fake = plan2.streams.map((s) => ({ stream: s.id, counted: true, digest: 'x'.repeat(64), statistics: Object.fromEntries(s.entries.map((e) => [e.id, { p: 0.5 }])) }));
  assert.throws(() => D.testsFromRun(plan2, fake), /not counted by the launcher/);
  assert.throws(() => D.rerunTestsFromRun('1', plan2, fake), /not counted by the launcher/);
});
