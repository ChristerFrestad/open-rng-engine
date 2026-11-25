// SRC-1 (CTO E7, ruled 2026-11-25 06:00 CET): pins the production shuffle draw order
// (src/mapping/index.ts shuffleWithFill) and states how it relates to the calibration harness
// (verification/calibration/wave1-source.mjs lazyShuffle). Production runs top-down: for i = n-1 down to
// 1, j = integer(0, i + 1), so the index spans are n, n-1, ..., 2 (51 draws for n = 52, never a
// below(1)). The harness runs forward and lazily: card g fixes position g with j = g + below(52 - g), so a
// full read has the same span sequence 52, 51, ..., 2 but fixes positions in the opposite direction.
//
// Order the evidence reductions must use (CTO ruling): the production order, i.e. the array shuffle()
// returns, read as is, with 51 index draws per 52-card shuffle whatever the reduction reads. Harness
// numbers are equal in distribution only, never equal stream for stream: on the same draw script the
// permutations differ, and they agree only through the pinned mirror (production = reverse of the
// harness permutation with every card v replaced by n - 1 - v, on reflected draws x_t = (n - 1 - t) - c_t).
// The exhaustive tests below (every draw tuple for n = 2..7, 5040 tuples at n = 7) check that the full
// permutation multisets and the reduction laws (card 0, Lehmer digits, adjacency mod/div labels) are
// exactly equal.
//
// HoQ condition: this equality in law holds only under H0 (uniform index draws). Under a defective
// generator the mirror moves the bias (the non-uniform tape test below gives different permutation laws
// for the two orders), so harness power and MDD figures for specific alternatives do not carry over to
// the production order unless they are re-derived or re-run there. Neither src nor the harness is
// changed here; any change to either needs a CTO ruling.
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
// The pinned mirror: production permutation = mirror(harness permutation on reflected draws).
const mirror = (perm) => perm.map((v) => perm.length - 1 - v).reverse();
const reflect = (c, n) => c.map((ct, t) => (n - 1 - t) - ct);

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
  const xs = reflect(c, 52);
  const m = harness(xs);
  const hMirror = iota(52).map((i) => m.lazy.card(i));
  assert.deepEqual(mirror(hMirror), prod);
  assert.deepEqual(sampleWithFill(52, 10, tapeFill(c)), mirror(hMirror).reverse().slice(0, 10));
  // The small-n forward model used below is the harness loop with 52 replaced by n: anchor it here.
  assert.deepEqual(forward(52, xs), hMirror);
  assert.deepEqual(forward(52, c), hSame);
});

// lazyShuffle's loop with 52 replaced by n (anchored to lazyShuffle at n = 52 above), read in full.
function forward(n, xs) {
  const a = iota(n);
  for (let g = 0; g < n - 1; g++) {
    const x = xs[g];
    assert.ok(x >= 0 && x < n - g);
    const j = g + x;
    const t = a[g]; a[g] = a[j]; a[j] = t;
  }
  return a;
}

// Every accepted index-draw tuple for n: c_t in [0, n - 1 - t], t = 0..n-2 (n! tuples).
function allDrawTuples(n) {
  let out = [[]];
  for (let t = 0; t < n - 1; t++) {
    const next = [];
    for (const pre of out) for (let v = 0; v < n - t; v++) next.push([...pre, v]);
    out = next;
  }
  return out;
}

function allPerms(n) {
  if (n === 0) return [[]];
  const out = [];
  for (const p of allPerms(n - 1)) for (let k = 0; k <= p.length; k++) out.push([...p.slice(0, k), n - 1, ...p.slice(k)]);
  return out;
}

const lehmer = (p) => p.slice(0, -1).map((v, i) => p.slice(i + 1).filter((w) => w < v).length);
const adjX = (p, lab) => p.slice(1).reduce((x, v, i) => x + (lab(v) === lab(p[i]) ? 1 : 0), 0);
const LABELS = { mod2: (v) => v % 2, div2: (v) => Math.floor(v / 2) };

// Exact law of each small-n wave-1 reduction analogue over a list of permutations, as sorted count maps.
function laws(perms) {
  const tally = (f) => {
    const m = new Map();
    for (const p of perms) { const k = JSON.stringify(f(p)); m.set(k, (m.get(k) ?? 0) + 1); }
    return [...m.entries()].sort();
  };
  const out = { perm: tally((p) => p), card0: tally((p) => p[0]), lehmer: tally(lehmer) };
  for (let i = 0; i < (perms[0]?.length ?? 0) - 1; i++) out[`lehmer${i}`] = tally((p) => lehmer(p)[i]);
  for (const [name, lab] of Object.entries(LABELS)) out[`adj-${name}`] = tally((p) => adjX(p, lab));
  return out;
}

const fact = (n) => (n <= 1 ? 1 : n * fact(n - 1));

// Production order and harness order (forward, raw and mirrored) on every draw tuple of n.
function orders(n) {
  const tuples = allDrawTuples(n);
  const prod = tuples.map((c) => {
    const fill = tapeFill(c);
    const out = shuffleWithFill(iota(n), fill);
    assert.equal(fill.calls(), Math.max(n - 1, 0));
    return out;
  });
  return { tuples, prod, harnessSame: tuples.map((c) => forward(n, c)), harnessMirrored: tuples.map((c) => mirror(forward(n, reflect(c, n)))) };
}

for (const n of [2, 3, 4, 5, 6, 7]) {
  test(`SRC-1: exhaustive n = ${n} (${fact(n)} draw tuples): equal permutation multisets and reduction laws under H0`, () => {
    const { tuples, prod, harnessSame, harnessMirrored } = orders(n);
    assert.equal(tuples.length, fact(n));
    // The reflection c -> x is a bijection of the draw-tuple set onto itself.
    const key = (a) => a.join(',');
    const tupleSet = new Set(tuples.map(key));
    const reflected = new Set(tuples.map((c) => key(reflect(c, n))));
    assert.equal(tupleSet.size, tuples.length);
    assert.equal(reflected.size, tuples.length);
    for (const k of reflected) assert.ok(tupleSet.has(k));
    // Per tuple: production equals the mirrored harness, and (n >= 3) is not the raw harness on the same draws.
    for (let k = 0; k < tuples.length; k++) assert.deepEqual(prod[k], harnessMirrored[k], `tuple ${key(tuples[k])}`);
    if (n >= 3) assert.ok(prod.some((p, k) => key(p) !== key(harnessSame[k])), 'never equal stream for stream');

    // Exact uniform law from an independent enumeration of all permutations.
    const reference = laws(allPerms(n));
    assert.equal(reference.perm.length, fact(n));
    for (const [, count] of reference.perm) assert.equal(count, 1);
    for (const [, count] of reference.card0) assert.equal(count, fact(n - 1));
    for (const [, count] of reference.lehmer) assert.equal(count, 1);
    const lp = laws(prod);
    const lh = laws(harnessSame);
    const lm = laws(harnessMirrored);
    assert.deepEqual(lp.perm, lh.perm, 'full permutation multiset: production = harness');
    assert.deepEqual(lp, reference, 'production law is the exact uniform law');
    assert.deepEqual(lh, reference, 'harness law is the exact uniform law');
    assert.deepEqual(lm, reference, 'mirrored harness law is the exact uniform law');
    assert.deepEqual(lp, lh, 'equal in distribution: permutation, card 0, Lehmer digits, adjacency mod/div labels');
  });
}

// Exact weighted law of the permutation (and card 0) when draw value 0 has weight 3 and every other value
// weight 1: a below() biased to 0. Weights are integers, so the comparison is exact.
function biasedLaws(tuples, perms) {
  const w = (c) => c.reduce((acc, v) => acc * (v === 0 ? 3 : 1), 1);
  const tally = (f) => {
    const m = new Map();
    perms.forEach((p, k) => { const kk = JSON.stringify(f(p)); m.set(kk, (m.get(kk) ?? 0) + w(tuples[k])); });
    return [...m.entries()].sort();
  };
  return { perm: tally((p) => p), card0: tally((p) => p[0]) };
}

for (const n of [4, 5]) {
  test(`SRC-1: under a non-uniform tape (below() biased to 0, n = ${n}) the two orders give different laws`, () => {
    const { tuples, prod, harnessSame } = orders(n);
    const bp = biasedLaws(tuples, prod);
    const bh = biasedLaws(tuples, harnessSame);
    const uniform = (law) => new Set(law.map(([, c]) => c)).size === 1;
    assert.ok(!uniform(bp.perm) && !uniform(bh.perm), 'the tape is visibly non-uniform in both orders');
    assert.notDeepEqual(bp.perm, bh.perm, 'the check tells the two orders apart off H0');
    assert.notDeepEqual(bp.card0, bh.card0, 'the mirror moves the bias: card 0 laws differ off H0');
  });
}
