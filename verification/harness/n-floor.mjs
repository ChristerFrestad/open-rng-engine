// M-153 harness floor. Decision rule v1 (FROZEN 5d09c75a), rule 8: "≥ 10^9 outcomes per usage per RC.
// One outcome = the result of one public call: one full permutation for shuffle, one complete sample set
// for sample, one value for randomInt and weightedPick (R107 B-3; P L742)." Rule 15: M-153
// (verification/m153-harness-mutant.md, sha256 0b017faa...): "B1–B3 refuse n < 10^9, and B4–B12 refuse
// counting draws, reads, tries, digits, bytes or window values instead of public calls."
// A plan only describes the planned n and its unit. Nothing here draws or collects data.

export const N_MIN = 1000000000; // rule 8: 10^9

// Unit vocabulary. Accepted: a public-call outcome, or (for the tuple/window tests of the K list whose
// n_unit says n counts tuples) one tuple of consecutive public calls (M-153 G8). Every other unit is refused.
export const UNIT_PUBLIC_CALL = 'public-call';
export const UNIT_PUBLIC_CALL_TUPLE = 'public-call-tuple';
export const COUNTER_PER_PUBLIC_CALL = 'per-public-call-return';

export function expectedUnit(kTest) {
  return /tuple/.test(String(kTest.n_unit)) ? UNIT_PUBLIC_CALL_TUPLE : UNIT_PUBLIC_CALL;
}

// plan: { id, n, unit, counter }. kTests: the tests array of verification/k-tests-v1.1.json.
// Returns { ok: boolean, reason: string }.
export function checkPlan(plan, kTests) {
  if (plan === null || typeof plan !== 'object') return { ok: false, reason: 'plan is not an object' };
  const k = kTests.find((t) => t.id === plan.id);
  if (!k) return { ok: false, reason: `unknown mapped-test id ${String(plan.id)}` };
  const n = plan.n;
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < N_MIN) {
    return { ok: false, reason: 'n < 10^9 public-call outcomes (rule 8; M-153 B1-B3)' };
  }
  if (plan.unit !== expectedUnit(k)) {
    return { ok: false, reason: `n is not a public-call count: unit ${String(plan.unit)} (rule 8; M-153 B4-B12)` };
  }
  if (plan.counter !== COUNTER_PER_PUBLIC_CALL) {
    return { ok: false, reason: `n is not a public-call count: counter ${String(plan.counter)} (rule 8; M-153 B5)` };
  }
  return { ok: true, reason: 'ok' };
}

// The harness refuses the whole run if any plan is refused, if a K-list id has no plan, or if a plan repeats.
export function checkRunPlans(plans, kTests) {
  const findings = [];
  const seen = new Set();
  for (const p of plans) {
    const r = checkPlan(p, kTests);
    if (!r.ok) findings.push(`${String(p && p.id)}: ${r.reason}`);
    if (p && seen.has(p.id)) findings.push(`${p.id}: duplicate plan`);
    if (p) seen.add(p.id);
  }
  for (const t of kTests) if (!seen.has(t.id)) findings.push(`${t.id}: no plan`);
  return findings;
}
