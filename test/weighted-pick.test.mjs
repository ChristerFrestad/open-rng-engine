// weightedPick(weights) unit tests: KATs over an injected fill (internal weightedPickWithFill only),
// exhaustive per-word counts with rejections counted, 7-byte reads above 2^32 (T = 2^48+1, 2^53-1),
// bounds and refusals with 0 bytes read, single-nonzero zero-byte path, and the public surface.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as core from '../src/index.ts';
import { weightedPick, RngRangeError, RngHealthError, RngEntropyError } from '../src/index.ts';
import { weightedPickWithFill, WEIGHT_TOTAL_MAX, WIDTH_SMALL, WIDTH_LARGE, TRY_LIMIT, bitLength } from '../src/mapping/index.ts';

// Each tape entry is one whole word value (big-endian into the target, safe integer).
function wordFill(values) {
  let i = 0;
  const widths = [];
  const fill = (target) => {
    const v = values[i];
    i += 1;
    if (v === undefined) throw new Error(`tape exhausted at ${i - 1}`);
    widths.push(target.length);
    let rest = v;
    for (let b = target.length - 1; b >= 0; b--) {
      target[b] = rest % 256;
      rest = Math.floor(rest / 256);
    }
    return target;
  };
  fill.calls = () => i;
  fill.widths = widths;
  return fill;
}

function noBytes() {
  const fill = () => { throw new Error('fill must not be called'); };
  return fill;
}

function prefixPick(weights, c) {
  let acc = 0;
  for (let i = 0; i < weights.length; i++) {
    acc += weights[i];
    if (c < acc) return i;
  }
  throw new Error('c out of range');
}

test('KAT: [1, 2, 3], T = 6, m = 3, one rejected word then c = 2', () => {
  // running sums before each index: 0, 1, 3. c = 7 rejected (>= 6); c = 2 -> largest i with before <= 2 is 1.
  const fill = wordFill([7, 2]);
  assert.equal(weightedPickWithFill([1, 2, 3], fill), 1);
  assert.equal(fill.calls(), 2);
  assert.deepEqual(fill.widths, [WIDTH_SMALL, WIDTH_SMALL]);
});

test('KAT: boundaries of each running sum on [1, 2, 3]', () => {
  const expect = [0, 1, 1, 2, 2, 2];
  for (let c = 0; c < 6; c++) {
    assert.equal(weightedPickWithFill([1, 2, 3], wordFill([c])), expect[c], `c=${c}`);
  }
});

test('KAT: zero weights are skipped at every boundary of [0, 5, 0, 2]', () => {
  const expect = [1, 1, 1, 1, 1, 3, 3];
  for (let c = 0; c < 7; c++) {
    assert.equal(weightedPickWithFill([0, 5, 0, 2], wordFill([c])), expect[c], `c=${c}`);
  }
  // trailing and leading zeros
  assert.equal(weightedPickWithFill([0, 0, 1, 1, 0], wordFill([0])), 2);
  assert.equal(weightedPickWithFill([0, 0, 1, 1, 0], wordFill([1])), 3);
});

test('exhaustive: each index picked exactly weight times per accepted word, for 0..2 rejected words', () => {
  const vectors = [[1, 2, 3], [0, 5, 0, 2], [3, 0, 1, 4, 0, 0, 2, 5, 1, 0], [1, 1], [2, 0, 0, 0, 1], [4, 4, 4, 4]];
  for (const w of vectors) {
    const T = w.reduce((a, b) => a + b, 0);
    const m = bitLength(T - 1);
    const rejected = [];
    for (let c = T; c < 2 ** m; c++) rejected.push(c);
    for (let r = 0; r <= 2; r++) {
      const prefixes = r === 0 ? [[]] : r === 1 ? rejected.map((a) => [a]) : rejected.flatMap((a) => rejected.map((b) => [a, b]));
      const counts = new Array(w.length).fill(0);
      for (const pre of prefixes) {
        for (let c = 0; c < T; c++) {
          const fill = wordFill([...pre, c]);
          const got = weightedPickWithFill(w, fill);
          assert.equal(fill.calls(), r + 1, `w=${w} r=${r} c=${c} calls`);
          assert.equal(got, prefixPick(w, c), `w=${w} r=${r} c=${c}`);
          counts[got] += 1;
        }
      }
      assert.deepEqual(counts, w.map((x) => x * prefixes.length), `w=${w} r=${r} counts`);
    }
  }
});

test('T = 2^48 + 1 reads 7-byte words (above the integer() span cap)', () => {
  const w = [2 ** 48, 1];
  const f1 = wordFill([2 ** 48]);
  assert.equal(weightedPickWithFill(w, f1), 1);
  assert.deepEqual(f1.widths, [WIDTH_LARGE]);
  assert.equal(weightedPickWithFill(w, wordFill([2 ** 48 - 1])), 0);
  // bitlen(2^48) = 49: 2^49 - 1 is rejected, the next word is used
  const f2 = wordFill([2 ** 49 - 1, 0]);
  assert.equal(weightedPickWithFill(w, f2), 0);
  assert.equal(f2.calls(), 2);
  // bits above the low 49 are ignored
  assert.equal(weightedPickWithFill(w, wordFill([2 ** 55 + 2 ** 48])), 1);
});

test('T = 2^53 - 1 is accepted, reads 7-byte words, rejects c = 2^53 - 1', () => {
  const w = [2 ** 52, 2 ** 52 - 1];
  assert.equal(w[0] + w[1], WEIGHT_TOTAL_MAX);
  const f = wordFill([2 ** 53 - 1, 2 ** 52]);
  assert.equal(weightedPickWithFill(w, f), 1);
  assert.equal(f.calls(), 2);
  assert.deepEqual(f.widths, [WIDTH_LARGE, WIDTH_LARGE]);
  assert.equal(weightedPickWithFill(w, wordFill([2 ** 52 - 1])), 0);
  assert.equal(weightedPickWithFill(w, wordFill([2 ** 53 - 2])), 1);
});

test('read width: T = 2^32 uses 4-byte words, T = 2^32 + 1 uses 7-byte words', () => {
  const a = wordFill([2 ** 32 - 1]);
  assert.equal(weightedPickWithFill([2 ** 31, 2 ** 31], a), 1);
  assert.deepEqual(a.widths, [WIDTH_SMALL]);
  const b = wordFill([2 ** 32]);
  assert.equal(weightedPickWithFill([2 ** 32, 1], b), 1);
  assert.deepEqual(b.widths, [WIDTH_LARGE]);
});

test('a single nonzero weight reads 0 bytes (R-42)', () => {
  assert.equal(weightedPickWithFill([7], noBytes()), 0);
  assert.equal(weightedPickWithFill([1], noBytes()), 0);
  assert.equal(weightedPickWithFill([0, 5, 0], noBytes()), 1);
  assert.equal(weightedPickWithFill([0, 0, 0, 9], noBytes()), 3);
  assert.equal(weightedPickWithFill([WEIGHT_TOTAL_MAX, 0], noBytes()), 0);
});

test('refusals are RngRangeError with 0 bytes read', () => {
  const sparse = [1, 2];
  sparse.length = 3; // hole at index 2
  const holeFirst = [];
  holeFirst[1] = 4;
  const bad = [
    undefined, null, 5, '1,2', { length: 2, 0: 1, 1: 1 }, new Uint8Array([1, 2]),
    [], [0], [0, 0, 0],
    [1, Number.NaN], [1, Number.POSITIVE_INFINITY], [1, -1], [1, -0.5], [1, 1.5], [0.5, 0.5],
    [1, '2'], [1, 2n], [1, null], [1, undefined], [1, true], sparse, holeFirst,
    [WEIGHT_TOTAL_MAX, 1], [2 ** 52, 2 ** 52], [2 ** 53, 1], [WEIGHT_TOTAL_MAX + 2],
    [2 ** 52, 2 ** 52, -(2 ** 52)],
  ];
  for (const w of bad) {
    assert.throws(() => weightedPickWithFill(w, noBytes()), (e) => e instanceof RngRangeError && e.code === 'RANGE_INVALID', String(w));
    assert.throws(() => weightedPick(w), RngRangeError, String(w));
  }
});

test('an empty array is refused by the length bound, before any weight check', () => {
  assert.throws(() => weightedPickWithFill([], noBytes()), /weights length must be an integer in 1\.\.2\^32-1/);
  assert.throws(() => weightedPickWithFill([0, 0], noBytes()), /at least one weight must be nonzero/);
});

test('the total cap is checked while summing (incremental, before any later weight)', () => {
  // Overflows at index 1; index 2 is a non-integer that would otherwise be reported.
  assert.throws(() => weightedPickWithFill([WEIGHT_TOTAL_MAX, 1, 0.5], noBytes()), /total must be at most 2\^53-1/);
  // the total exactly at the cap is fine
  assert.equal(weightedPickWithFill([WEIGHT_TOTAL_MAX - 1, 1], wordFill([WEIGHT_TOTAL_MAX - 1])), 1);
});

test('the input array is not modified and an array whose length changes while copying is refused', () => {
  const w = [3, 0, 2];
  weightedPickWithFill(w, wordFill([4]));
  assert.deepEqual(w, [3, 0, 2]);
  const shifting = new Proxy([1, 1], {
    get(t, k, r) {
      if (k === 'length') {
        t.reads = (t.reads ?? 0) + 1;
        return t.reads === 1 ? 2 : 3;
      }
      return Reflect.get(t, k, r);
    },
  });
  assert.throws(() => weightedPickWithFill(shifting, noBytes()), /length changed while copying/);
});

test('HoQ A16: typed arrays are refused, and the caller\'s own slice is never called', () => {
  for (const t of [new Uint32Array([1, 2]), new Float64Array([1, 2]), new Uint16Array([3])]) {
    assert.throws(() => weightedPickWithFill(t, noBytes()), /weights must be an array/);
  }
  const own = [1, 2, 3];
  own.slice = () => {
    throw new Error('own slice called');
  };
  // T = 6, x = 5 -> index 2, read through Array.prototype.slice
  assert.equal(weightedPickWithFill(own, wordFill([5])), 2);
  const lying = [0, 0, 1, 1];
  lying.slice = () => [5, 0, 0, 0];
  // the real copy is [0, 0, 1, 1]: two nonzero, T = 2, x = 1 -> index 3 (never 0)
  assert.equal(weightedPickWithFill(lying, wordFill([1])), 3);
});

test('adapter failures: short buffer and throwing fill are RngEntropyError; 128 rejects is RngHealthError', () => {
  assert.throws(() => weightedPickWithFill([1, 1], () => new Uint8Array(1)), RngEntropyError);
  assert.throws(() => weightedPickWithFill([1, 1], () => { throw new Error('x'); }), RngEntropyError);
  assert.throws(() => weightedPickWithFill([1, 1], () => [0, 0, 0, 0]), RngEntropyError);
  // T = 3, m = 2: word 3 is always rejected
  const f = wordFill(new Array(TRY_LIMIT).fill(3));
  assert.throws(() => weightedPickWithFill([1, 2], f), RngHealthError);
  assert.equal(f.calls(), TRY_LIMIT);
  const g = wordFill([...new Array(TRY_LIMIT - 1).fill(3), 2]);
  assert.equal(weightedPickWithFill([1, 2], g), 1);
});

test('public surface: weightedPick is exported from the core entry, the fill variant is not', () => {
  assert.equal(typeof core.weightedPick, 'function');
  assert.equal('weightedPickWithFill' in core, false);
  assert.equal('drawBelowWithFill' in core, false);
  for (let i = 0; i < 200; i++) {
    const v = weightedPick([0, 3, 0, 1]);
    assert.ok(v === 1 || v === 3, `got ${v}`);
  }
  assert.equal(weightedPick([0, 0, 5]), 2);
});
