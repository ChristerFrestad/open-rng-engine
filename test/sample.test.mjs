// sample(n, k) unit tests: KATs over an injected fill (internal sampleWithFill only), the
// sample(n, n) = reverse(shuffle([0..n))) identity on the same fill calls, exhaustive ordered
// k-subset counts with rejections counted, bounds, and adapter failures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as core from '../src/index.ts';
import { sample, RngRangeError, RngHealthError, RngEntropyError } from '../src/index.ts';
import { sampleWithFill, shuffleWithFill, SHUFFLE_MAX_LENGTH, WIDTH_SMALL, TRY_LIMIT } from '../src/mapping/index.ts';

function tapeFill(values) {
  let i = 0;
  const fill = (target) => {
    const v = values[i];
    i += 1;
    if (v === undefined) throw new Error(`tape exhausted at ${i - 1}`);
    target.fill(0);
    target[target.length - 1] = v;
    return target;
  };
  fill.calls = () => i;
  return fill;
}

// Deterministic full-width words (LCG), recorded so two runs see the same calls.
function recordedFill(seed) {
  let x = seed >>> 0;
  const log = [];
  const fill = (target) => {
    for (let b = 0; b < target.length; b++) {
      x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
      target[b] = x >>> 24;
    }
    log.push(Uint8Array.from(target));
    return target;
  };
  fill.log = log;
  return fill;
}
function replayFill(log) {
  let i = 0;
  const fill = (target) => {
    const w = log[i];
    i += 1;
    if (w === undefined || w.length !== target.length) throw new Error('replay mismatch');
    target.set(w);
    return target;
  };
  fill.calls = () => i;
  return fill;
}

test('KAT: n = 5, k = 3, top-down draw order, one rejected word', () => {
  // i = 4: span 5, m = 3, c = 6 rejected, c = 1 -> swap 4,1: [0,4,2,3,1], emit 1
  // i = 3: span 4, m = 2, c = 0 -> swap 3,0: [3,4,2,0,1], emit 0
  // i = 2: span 3, m = 2, c = 2 -> swap 2,2, emit 2
  const fill = tapeFill([6, 1, 0, 2]);
  assert.deepEqual(sampleWithFill(5, 3, fill), [1, 0, 2]);
  assert.equal(fill.calls(), 4);
});

test('KAT: sample(52, 5) on all-zero words reads moved positions', () => {
  // j = 0 each step: emit a[0] then a[0] takes the old a[i].
  const fill = tapeFill([0, 0, 0, 0, 0]);
  assert.deepEqual(sampleWithFill(52, 5, fill), [0, 51, 50, 49, 48]);
  assert.equal(fill.calls(), 5);
});

test('sample(n, n) = reverse(shuffle([0..n))) with identical fill calls (PLAN MAJOR-1)', () => {
  for (const [n, seed] of [[2, 1], [3, 2], [7, 3], [52, 4], [1000, 5]]) {
    const rec = recordedFill(seed);
    const s = sampleWithFill(n, n, rec);
    const rep = replayFill(rec.log);
    const sh = shuffleWithFill(Array.from({ length: n }, (_, i) => i), rep);
    assert.deepEqual(s, [...sh].reverse(), `n=${n}`);
    assert.equal(rep.calls(), rec.log.length, `n=${n} same number of fill calls`);
  }
});

test('prefix property: sample(n, k) is the first k entries of sample(n, n) on the same calls', () => {
  const n = 52;
  const rec = recordedFill(9);
  const full = sampleWithFill(n, n, rec);
  for (const k of [0, 1, 5, 9, 51, 52]) {
    const rep = replayFill(rec.log);
    assert.deepEqual(sampleWithFill(n, k, rep), full.slice(0, k), `k=${k}`);
  }
});

// Exhaustive driver: low-byte values 0..7 per word (each m-bit pattern for m <= 3 appears
// 8 / 2^m times). A completed tape with r rejected words has length min(k, n-1) + r (the
// size-1 step reads 0 bytes), so bounding the length enumerates every path with r <= maxRejects.
const DRIVER_VALUES = 8;
function enumerate(n, k, maxRejects) {
  const buckets = new Map();
  const draws = Math.min(k, n - 1);
  const maxLen = draws + maxRejects;
  const walk = (tape) => {
    let pos = 0;
    let out;
    try {
      out = sampleWithFill(n, k, (t) => {
        if (pos >= tape.length) throw new Error('tape exhausted');
        t.fill(0);
        t[t.length - 1] = tape[pos];
        pos += 1;
        return t;
      });
    } catch (e) {
      if (!(e instanceof RngEntropyError)) throw e;
      if (tape.length < maxLen) for (let v = 0; v < DRIVER_VALUES; v++) walk([...tape, v]);
      return;
    }
    assert.equal(pos, tape.length, 'every word consumed');
    const key = `${tape.length - draws}|${out.join(',')}`;
    buckets.set(key, (buckets.get(key) ?? 0) + 1);
  };
  walk([]);
  return buckets;
}

function orderedSubsets(n, k) {
  if (k === 0) return [[]];
  const out = [];
  for (const p of orderedSubsets(n, k - 1)) {
    for (let v = 0; v < n; v++) if (!p.includes(v)) out.push([...p, v]);
  }
  return out;
}

for (const [n, k] of [[4, 0], [4, 1], [4, 2], [4, 3], [4, 4], [5, 2]]) {
  test(`exhaustive: n = ${n}, k = ${k}, every ordered k-subset equally often per reject count`, () => {
    const maxRejects = 2;
    const buckets = enumerate(n, k, maxRejects);
    const subsets = orderedSubsets(n, k).map((p) => p.join(','));
    let expected = 1;
    for (let t = 0; t < k; t++) expected *= n - t;
    assert.equal(subsets.length, expected);
    const draws = Math.min(k, n - 1);
    for (let r = 0; r <= maxRejects; r++) {
      const counts = subsets.map((p) => buckets.get(`${r}|${p}`) ?? 0);
      if (draws === 0) {
        // k = 0: one empty result, no draws, no rejects possible.
        assert.deepEqual(counts, r === 0 ? [1] : [0]);
        continue;
      }
      // r = 0 always has paths; r > 0 has none only when no span in the walk can reject (all powers of 2).
      if (r === 0 || !(n === 4 && k === 1)) assert.ok(counts[0] > 0, `r=${r} has paths`);
      for (const c of counts) assert.equal(c, counts[0], `n=${n} k=${k} r=${r} counts ${counts}`);
    }
    for (const key of buckets.keys()) assert.ok(subsets.includes(key.split('|')[1]), key);
  });
}

test('edges: k = 0, n = 0, n = 1 read 0 bytes; each call returns a new array', () => {
  const fill = tapeFill([]);
  assert.deepEqual(sampleWithFill(0, 0, fill), []);
  assert.deepEqual(sampleWithFill(9, 0, fill), []);
  assert.deepEqual(sampleWithFill(1, 1, fill), [0]);
  assert.deepEqual(sampleWithFill(1, 0, fill), []);
  assert.equal(fill.calls(), 0);
  const a = sample(0, 0);
  const b = sample(0, 0);
  assert.deepEqual(a, []);
  assert.notEqual(a, b);
  assert.deepEqual(sample(1, 1), [0]);
});

test('k = n = 2 reads exactly one word (the size-1 last step reads 0 bytes)', () => {
  const fill = tapeFill([1]);
  assert.deepEqual(sampleWithFill(2, 2, fill), [1, 0]);
  assert.equal(fill.calls(), 1);
});

test('bad arguments throw RngRangeError and read 0 bytes', () => {
  const fill = tapeFill([]);
  const bad = [
    [-1, 0], [3, -1], [3, 4], [0, 1], [2.5, 1], [3, 1.5], [NaN, 0], [3, NaN], [Infinity, 1],
    ['3', 1], [3, '1'], [3n, 1], [3, 1n], [null, 0], [undefined, 0], [3, undefined], [[3], 1], [true, 1],
    [SHUFFLE_MAX_LENGTH + 1, 0], [2 ** 53, 1], [Number.MAX_SAFE_INTEGER + 1, 0],
  ];
  for (const [n, k] of bad) {
    assert.throws(() => sampleWithFill(n, k, fill), (e) => e instanceof RngRangeError && e.code === 'RANGE_INVALID', `${String(n)} ${String(k)}`);
    assert.throws(() => sample(n, k), (e) => e instanceof RngRangeError && e.code === 'RANGE_INVALID', `${String(n)} ${String(k)}`);
  }
  assert.equal(fill.calls(), 0);
});

test('largest n: sample(2^32-1, 3) uses O(k) memory and returns distinct in-range indices', () => {
  assert.equal(SHUFFLE_MAX_LENGTH, 2 ** 32 - 1);
  const out = sample(SHUFFLE_MAX_LENGTH, 3);
  assert.equal(out.length, 3);
  assert.equal(new Set(out).size, 3);
  for (const v of out) assert.ok(Number.isSafeInteger(v) && v >= 0 && v < SHUFFLE_MAX_LENGTH, String(v));
  // A 7-byte width is never needed: every span is <= 2^32.
  const widths = [];
  sampleWithFill(SHUFFLE_MAX_LENGTH, 2, (t) => { widths.push(t.length); t.fill(0); return t; });
  assert.deepEqual(widths, [WIDTH_SMALL, WIDTH_SMALL]);
});

test('short and throwing adapters are ENTROPY_UNAVAILABLE; endless rejects are RNG_REJECTION_EXHAUSTED', () => {
  const short = (t) => t.subarray(0, 1);
  assert.throws(() => sampleWithFill(5, 2, short), (e) => e instanceof RngEntropyError && e.code === 'ENTROPY_UNAVAILABLE');
  const boom = () => { throw new Error('no source'); };
  assert.throws(() => sampleWithFill(5, 2, boom), (e) => e instanceof RngEntropyError && e.code === 'ENTROPY_UNAVAILABLE');
  const notBytes = () => [0, 0, 0, 0];
  assert.throws(() => sampleWithFill(5, 2, notBytes), (e) => e instanceof RngEntropyError);
  // n = 3 first draw is span 3; word 3 always rejects.
  const reject = tapeFill(Array.from({ length: TRY_LIMIT }, () => 3));
  assert.throws(() => sampleWithFill(3, 1, reject), (e) => e instanceof RngHealthError && e.code === 'RNG_REJECTION_EXHAUSTED');
  assert.equal(reject.calls(), TRY_LIMIT);
});

test('public surface: sample exported, no fill-injectable or raw-bytes export', () => {
  assert.equal(typeof core.sample, 'function');
  assert.equal(core.sample.length, 2);
  for (const name of ['sampleWithFill', 'shuffleWithFill', 'integerWithFill', 'fillBuffer', 'randomFillSync', 'randomBytes']) {
    assert.equal(name in core, false, name);
  }
});

test('public sample over the platform source returns distinct in-range indices', () => {
  for (let r = 0; r < 10; r++) {
    const out = sample(52, 9);
    assert.equal(out.length, 9);
    assert.equal(new Set(out).size, 9);
    for (const v of out) assert.ok(Number.isInteger(v) && v >= 0 && v < 52);
  }
  const all = sample(52, 52);
  assert.deepEqual([...all].sort((a, b) => a - b), Array.from({ length: 52 }, (_, i) => i));
});
