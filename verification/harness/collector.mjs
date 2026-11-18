// EG-1 (HoQ 4c7adda0/f575fe1f report gap H-1; addendum 1 4195afbc): M-153 B4–B12 enforced on what the
// collector actually counts, not on the declared unit label. Decision rule v1 (FROZEN 5d09c75a) rule 8:
// "One outcome = the result of one public call: one full permutation for shuffle, one complete sample set
// for sample, one value for randomInt and weightedPick (R107 B-3; P L742)."
//
// Design. The harness wraps the public call in a WITNESS before the collector sees it; the collector never
// sees the witness count. A collection result is accepted only if
//   collector n === number of records === witness returns / w   (w = 1, or the tuple/window width),
// and every record has the shape of ONE public-call outcome of the K entry's primitive. Inner draws, tries,
// bytes, Lehmer digits and window values are logged separately (diagnostics) and never feed n.
// Nothing here draws entropy; the self-check uses synthetic primitives (collectorSelfCheck in check.mjs).
import { N_MIN } from './n-floor.mjs';

// Tuple/window width from the K entry (M-153 G8, B12): 'window' if present, else 2 for tuple tests.
export function windowWidth(kTest) {
  if (!/tuple/.test(String(kTest.n_unit))) return 1;
  const w = kTest.parameters && kTest.parameters.window;
  return Number.isSafeInteger(w) && w >= 2 ? w : 2;
}

// The witness counts returns of the public call. It is created by the harness, not by the collector.
export function witness(call) {
  const box = { returns: 0 };
  const wrapped = (...a) => { const v = call(...a); box.returns += 1; return v; };
  return { call: wrapped, count: () => box.returns };
}

// The collector: one record per public-call return (or per w consecutive returns for a tuple test).
// source: the instrumented entropy/draw source's live counters { draws, tries, bytes, digits } (the byte
// log of M-153 G2). They are copied into diag at the end and NEVER feed n.
export function collect(kTest, call, n, source = { draws: 0, tries: 0, bytes: 0, digits: 0 }) {
  const w = windowWidth(kTest);
  const records = [];
  let count = 0;
  for (let i = 0; i < n; i++) {
    if (w === 1) {
      const v = call();
      records.push(v);
      count += 1;
    } else {
      const t = [];
      for (let j = 0; j < w; j++) t.push(call());
      records.push(t);
      count += 1;
    }
  }
  return { id: kTest.id, n: count, records, diag: { ...source } };
}

function isInt(v) { return (typeof v === 'number' && Number.isSafeInteger(v)) || typeof v === 'bigint'; }

// One public-call outcome of the primitive, per K entry parameters.
export function outcomeShapeError(kTest, v) {
  const p = kTest.parameters || {};
  switch (kTest.primitive) {
    case 'randomInt': {
      if (!isInt(v)) return 'randomInt outcome is not one integer';
      const min = BigInt(p.min ?? 0), max = BigInt(p.max ?? 0), x = BigInt(v);
      return x >= min && x < max ? null : 'randomInt outcome outside [min, max)';
    }
    case 'weightedPick': {
      const len = p.length ?? (Array.isArray(p.weights) ? p.weights.length : undefined);
      if (!(typeof v === 'number' && Number.isSafeInteger(v))) return 'weightedPick outcome is not one index';
      return len === undefined || (v >= 0 && v < len) ? null : 'weightedPick outcome outside the strip';
    }
    case 'shuffle': {
      const n = p.n ?? 52;
      if (!Array.isArray(v) || v.length !== n) return `shuffle outcome is not one permutation of ${n}`;
      const s = new Set(v);
      return s.size === n && v.every((x) => Number.isSafeInteger(x) && x >= 0 && x < n) ? null : 'shuffle outcome is not a permutation';
    }
    case 'sample': {
      const { n, k } = p;
      if (!Array.isArray(v) || v.length !== k) return `sample outcome is not one complete ${k}-set`;
      return new Set(v).size === k && v.every((x) => Number.isSafeInteger(x) && x >= 0 && x < n) ? null : 'sample outcome is not a k-set of distinct indices';
    }
    default:
      return `unknown primitive ${String(kTest.primitive)}`;
  }
}

// Acceptance of a collection result against the witness. opts.floor: false only in the self-check.
export function checkCollected(result, kTest, witnessReturns, { floor = true } = {}) {
  const f = [];
  if (!result || typeof result !== 'object' || !Array.isArray(result.records)) return ['collector result has no records'];
  const w = windowWidth(kTest);
  const n = result.n;
  if (!Number.isSafeInteger(n)) f.push('collector n is not an integer');
  if (n !== result.records.length) f.push(`collector n ${n} != ${result.records.length} records (M-153 B4-B12: n is not a public-call count)`);
  if (!Number.isSafeInteger(witnessReturns) || witnessReturns !== n * w) f.push(`collector n ${n} × ${w} != ${witnessReturns} public-call returns seen by the witness (M-153 B4-B12)`);
  if (floor && !(n >= N_MIN)) f.push('n < 10^9 public-call outcomes (rule 8; M-153 B1-B3)');
  let bad = 0;
  for (const r of result.records) {
    const parts = w === 1 ? [r] : (Array.isArray(r) && r.length === w ? r : null);
    if (!parts) { bad++; continue; }
    if (parts.some((v) => outcomeShapeError(kTest, v) !== null)) bad++;
  }
  if (bad) f.push(`${bad} record(s) are not ${w === 1 ? 'one public-call outcome' : `${w} public-call outcomes`} (M-153 B4-B12)`);
  return f;
}
