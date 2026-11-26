// RC decision over mapped-output tests (frozen decision rule v1, rules 8-9) with HoQ addendum 1 A23:
// R118-1: K_count 161 (157 in run 1 + 4 in run 2), threshold stays 0.01/157; R118-2 (CPO-accepted, A23.1):
// for the >= 6-flags hard-FAIL count, all flags from entries on one shared stream count as one; R118-3: one
// decision pools the flags of both runs. Every flagged entry is still reported and re-run exactly once on a
// fresh stream with the same M; the same statistic flagged again is FAIL (M-R118-2b). Pure apart from the
// launcher's counting registry: only streams the launcher counted are evidence.
import { streamCounted } from './stream-launcher.mjs';

export const DECISION_ID = 'open-rng-engine/rc-decision/v1';
export const K_FROZEN = 157;
export const K_COUNT = 161;
export const THRESHOLD = 0.01 / K_FROZEN;
export const HARD_P = 1e-10;
export const HARD_FLAGS = 6;
export const COUNTING_RULE = Object.freeze({
  id: 'R118-2/stream-collapsed/v1',
  text: 'for the >= 6-flags hard-FAIL count, all flags from K entries that share one stream count as one flag; every flagged entry is reported and re-run under rule 9',
  K_count: K_COUNT, threshold: THRESHOLD, hard_p: HARD_P, hard_flags: HARD_FLAGS,
});

const isP = (p) => typeof p === 'number' && p >= 0 && p <= 1;

// tests: [{ run, entry, stream, M, p }], one per (run, entry). Returns the flags per entry and per stream.
export function tally(tests) {
  const seen = new Set();
  const entries = [], streams = new Map();
  for (const t of tests) {
    const key = `${t.run}\0${t.entry}`;
    if (seen.has(key)) throw new Error(`decision: ${t.entry} appears twice in run ${t.run}`);
    seen.add(key);
    if (!isP(t.p)) throw new Error(`decision: ${t.entry} (run ${t.run}) has no p-value`);
    const flag = t.p < THRESHOLD, hard = t.p < HARD_P;
    entries.push({ run: t.run, entry: t.entry, stream: t.stream, M: t.M, p: t.p, flag, hard });
    const sk = `${t.run}\0${t.stream}`;
    if (!streams.has(sk)) streams.set(sk, { run: t.run, stream: t.stream, flags: 0, entries: [] });
    if (flag) { const s = streams.get(sk); s.flags += 1; s.entries.push(t.entry); }
  }
  const flagged = entries.filter((e) => e.flag);
  const flaggedStreams = [...streams.values()].filter((s) => s.flags > 0);
  return { entries, streams: [...streams.values()], flagged, flags_per_entry: flagged.length, flags_collapsed: flaggedStreams.length, hard: entries.filter((e) => e.hard) };
}

// The decision itself. tests: the pooled tests of every run in the decision; reruns: the rule-9 re-run tests
// (null until they exist). expectK: how many (run, entry) tests this decision covers (161 for both runs).
export function decide({ tests, reruns = null, expectK }) {
  if (!Number.isSafeInteger(expectK) || expectK < 1) throw new Error('decision: expectK required');
  if (tests.length !== expectK) return { verdict: 'FAIL', why: [`missing evidence: ${tests.length} of ${expectK} tests (rule 14)`] };
  const t = tally(tests);
  const report = { decision: DECISION_ID, counting_rule: COUNTING_RULE.id, K: expectK, threshold: THRESHOLD, flags_per_entry: t.flags_per_entry, flags_collapsed: t.flags_collapsed, flagged: t.flagged, per_stream: t.streams.map((s) => ({ run: s.run, stream: s.stream, flags: s.flags, entries: s.entries })) };
  if (t.hard.length) return { ...report, verdict: 'FAIL', why: t.hard.map((e) => `${e.entry} (run ${e.run}): p ${e.p} < ${HARD_P} (failure band)`) };
  if (t.flags_collapsed >= HARD_FLAGS) return { ...report, verdict: 'FAIL', why: [`${t.flags_collapsed} flagged streams >= ${HARD_FLAGS} (rule 9, R118-2 count)`] };
  if (t.flags_per_entry === 0) return { ...report, verdict: 'CLEAN', why: [] };
  if (reruns === null) return { ...report, verdict: 'SUSPECT', why: ['rule-9 re-run of every flagged entry required'], rerun_required: t.flagged.map((e) => ({ run: e.run, entry: e.entry, M: e.M })) };
  // Rule 9: each flagged test re-run exactly once, fresh stream, same sample size; no other re-runs.
  const firstStreams = new Set(t.streams.map((s) => s.stream));
  const byEntry = new Map();
  for (const r of reruns) {
    const k = `${r.of_run}\0${r.entry}`;
    if (byEntry.has(k)) throw new Error(`decision refused: ${r.entry} (run ${r.of_run}) re-run more than once`);
    byEntry.set(k, r);
  }
  for (const e of t.flagged) {
    const r = byEntry.get(`${e.run}\0${e.entry}`);
    if (!r) throw new Error(`decision refused: flagged ${e.entry} (run ${e.run}) has no re-run (rule 9; M-R118-2b)`);
    if (r.M !== e.M) throw new Error(`decision refused: re-run of ${e.entry} at M ${r.M}, flagged run had ${e.M} (rule 9: same sample size)`);
    if (firstStreams.has(r.stream)) throw new Error(`decision refused: re-run of ${e.entry} reuses stream ${r.stream} (fresh stream required)`);
    if (!isP(r.p)) throw new Error(`decision refused: re-run of ${e.entry} has no p-value`);
  }
  for (const k of byEntry.keys()) if (!t.flagged.some((e) => `${e.run}\0${e.entry}` === k)) throw new Error(`decision refused: re-run of an unflagged test ${k.replace('\0', ' ')} (rule 9: no other re-runs)`);
  const again = t.flagged.filter((e) => byEntry.get(`${e.run}\0${e.entry}`).p < THRESHOLD);
  const rerunReport = t.flagged.map((e) => { const r = byEntry.get(`${e.run}\0${e.entry}`); return { run: e.run, entry: e.entry, p: e.p, rerun_stream: r.stream, rerun_p: r.p, flagged_again: r.p < THRESHOLD }; });
  if (again.length) return { ...report, reruns: rerunReport, verdict: 'FAIL', why: again.map((e) => `${e.entry} (run ${e.run}) flagged again in its re-run (rule 9)`) };
  return { ...report, reruns: rerunReport, verdict: 'PASS-WITH-NOTE', why: t.flagged.map((e) => `${e.entry} (run ${e.run}) flagged once, re-run clean`) };
}

// Tests from launcher results: only counted streams are evidence; the entry's stream and M come from the plan.
export function testsFromRun(plan, results) {
  const out = [];
  for (const r of results) {
    if (!streamCounted(r)) throw new Error(`decision refused: stream ${r && r.stream} is not counted by the launcher`);
    const s = plan.streams.find((x) => x.id === r.stream);
    if (!s) throw new Error(`decision refused: stream ${r.stream} is not in plan ${plan.run_id}`);
    for (const e of s.entries) {
      const st = r.statistics && r.statistics[e.id];
      if (!st) throw new Error(`decision refused: ${e.id} has no statistic in ${r.stream}`);
      out.push({ run: plan.run_id, entry: e.id, stream: `${plan.run_id}/${s.id}`, M: e.M, p: st.p });
    }
  }
  return out;
}

// Rule-9 re-run tests from a re-run plan's launcher results; ofRun names the run whose flags they re-run.
export function rerunTestsFromRun(ofRun, plan, results) {
  return testsFromRun(plan, results).map((t) => ({ ...t, of_run: ofRun }));
}
