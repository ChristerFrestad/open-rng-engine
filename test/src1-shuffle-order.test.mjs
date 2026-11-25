// SRC-1 (CTO E7): pins the production shuffle draw order (src/mapping/index.ts shuffleWithFill) and
// states how it relates to the calibration harness (verification/calibration/wave1-source.mjs
// lazyShuffle). Production runs top-down: for i = n-1 down to 1, j = integer(0, i + 1), so the index
// spans are n, n-1, ..., 2 (51 draws for n = 52, never a below(1)). The harness runs forward and lazily:
// card g fixes position g with j = g + below(52 - g), so a full read has the same span sequence
// 52, 51, ..., 2 but fixes positions in the opposite direction.
//
// Order the evidence reductions must use: the production order, i.e. the array returned by shuffle()
// read as is (top-down, 51 index draws per 52-card shuffle whatever the reduction reads). The harness
// order is NOT word-for-word the same: on the same draw script the permutations differ. They agree only
// through the mirror pinned below (production = reverse of the harness permutation with every card v
// replaced by 51 - v, on reflected draws x_t = (51 - t) - c_t), which preserves the law of every wave-1
// reduction but not per-stream bit identity or the harness word counts. Neither src nor the harness
// is changed here; any change to either needs a CTO ruling.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shuffleWithFill, sampleWithFill, WIDTH_SMALL } from '../src/mapping/index.ts';
import { lazyShuffle } from '../verification/calibration/wave1-source.mjs';

function word(c) {
  const w = new Uint8Array(WIDTH_SMALL);
  w[WIDTH_SMALL - 1] = c;
  return w;
}

function tapeFill(values) {
  let i = 0;
  const fill = (target) => {
    const v = values[i];
    i += 1;
    if (v === undefined) throw new Error(`tape exhausted at ${i - 1}`);
    assert.equal(target.length, WIDTH_SMALL);
    target.set(word(v));
    return target;
  };
  fill.calls = () => i;
  return fill;
}

const isPow2 = (s) => (s & (s - 1)) === 0;
const topDownSpans = (n) => Array.from({ length: Math.max(n - 1, 0) }, (_, t) => n - t);
const iota = (n) => Array.from({ length: n }, (_, i) => i);

// For each expected span S: if S is not a power of two, first offer S (must be rejected, so the real
// span is <= S), then S - 1 (must be accepted, so the real span is >= S). If S = 2^m, offer 2^m - 1,
// which a larger span would reject (its width needs one more bit). Any other span or draw count breaks
// the call count or exhausts the tape.
function spanProbeTape(spans) {
  const tape = [];
  for (const s of spans) {
    if (!isPow2(s)) tape.push(s);
    tape.push(s - 1);
  }
  return tape;
}

// Reference top-down Fisher-Yates on accepted draws c (c_t < n - t).
function refTopDown(n, c) {
  const a = iota(n);
  for (let i = n - 1, t = 0; i >= 1; i--, t++) {
    const j = c[t];
    const x = a[i]; a[i] = a[j]; a[j] = x;
  }
  return a;
}

for (const n of [0, 1, 2, 3, 5, 52]) {
  test(`SRC-1: production shuffle of n = ${n} draws spans ${n <= 1 ? 'none' : `${n} down to 2`}, top-down`, () => {
    const spans = topDownSpans(n);
    assert.equal(spans.length, Math.max(n - 1, 0));
    if (n === 52) {
      assert.equal(spans.length, 51);
      assert.equal(spans[0], 52);
      assert.equal(spans[50], 2);
    }
    assert.ok(!spans.includes(1), 'no below(1) draw');
    const tape = spanProbeTape(spans);
    const fill = tapeFill(tape);
    const out = shuffleWithFill(iota(n), fill);
    assert.equal(fill.calls(), tape.length, 'exactly the probed draws, nothing more');
    assert.deepEqual(out, refTopDown(n, spans.map((s) => s - 1)));
  });
}

test('SRC-1: production order on a fixed byte script (n = 52) is pinned', () => {
  const c = topDownSpans(52).map((s, t) => (7 * t + 3) % s);
  const fill = tapeFill(c);
  const out = shuffleWithFill(iota(52), fill);
  assert.equal(fill.calls(), 51);
  assert.deepEqual(out, [0, 30, 5, 18, 2, 1, 12, 8, 9, 11, 32, 14, 13, 37, 48, 21, 20, 28, 6, 42, 50, 41,
    22, 29, 36, 33, 46, 51, 19, 35, 26, 43, 4, 27, 49, 40, 34, 25, 16, 44, 39, 47, 23, 15, 7, 45, 38, 31,
    24, 17, 10, 3]);
  assert.deepEqual(out, refTopDown(52, c));
  // sample(52, k) is the first k steps of the same loop, emitted top-down (reverse of shuffle).
  const s = sampleWithFill(52, 10, tapeFill(c));
  assert.deepEqual(s, out.slice().reverse().slice(0, 10));
});

function harness(xs) {
  const below = [];
  let q = 0;
  const s = { below(r) { below.push(r); const x = xs[q]; q += 1; if (x === undefined) throw new Error('script exhausted'); assert.ok(x < r); return x; } };
  return { lazy: lazyShuffle(s), below };
}

test('SRC-1: the harness runs forward and lazily over the same span sequence 52..2', () => {
  const zeros = new Array(51).fill(0);
  const h1 = harness(zeros);
  h1.lazy.card(0);
  assert.deepEqual(h1.below, [52], 'reading card 0 costs one draw in the harness');
  const h = harness(zeros);
  const all = iota(52).map((i) => h.lazy.card(i));
  assert.deepEqual(h.below, topDownSpans(52), 'full read: spans 52, 51, ..., 2, no below(1)');
  assert.deepEqual(all, iota(52));
});

test('SRC-1: harness and production differ on the same draws and agree only through the pinned mirror', () => {
  const c = topDownSpans(52).map((s, t) => (7 * t + 3) % s);
  const prod = shuffleWithFill(iota(52), tapeFill(c));
  const same = harness(c);
  const hSame = iota(52).map((i) => same.lazy.card(i));
  assert.deepEqual(hSame, [3, 11, 19, 27, 35, 43, 51, 14, 23, 32, 41, 50, 2, 29, 39, 49, 8, 34, 45, 16, 4,
    47, 13, 42, 0, 10, 22, 44, 20, 6, 18, 25, 7, 9, 31, 30, 26, 24, 17, 12, 21, 28, 15, 1, 36, 48, 40, 33,
    37, 5, 38, 46]);
  assert.notDeepEqual(hSame, prod, 'not word-for-word interchangeable');
  const xs = c.map((ct, t) => (51 - t) - ct);
  const m = harness(xs);
  const hMirror = iota(52).map((i) => m.lazy.card(i));
  assert.deepEqual(hMirror.map((v) => 51 - v).reverse(), prod);
  assert.deepEqual(sampleWithFill(52, 10, tapeFill(c)), hMirror.slice(0, 10).map((v) => 51 - v));
});
