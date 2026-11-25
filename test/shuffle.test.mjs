// shuffle unit tests: KAT over an injected fill (internal shuffleWithFill only), exhaustive
// permutation counts for n = 3 and n = 4 with rejections counted, edges and adapter failures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as core from '../src/index.ts';
import { shuffle, RngRangeError, RngHealthError, RngEntropyError } from '../src/index.ts';
import { shuffleWithFill, SHUFFLE_MAX_LENGTH, WIDTH_SMALL, TRY_LIMIT } from '../src/mapping/index.ts';

// One 4-byte word whose low bits hold c (c < 256 here).
function word(c) {
  const w = new Uint8Array(WIDTH_SMALL);
  w[WIDTH_SMALL - 1] = c;
  return w;
}

function tapeFill(values) {
  let i = 0;
  const widths = [];
  const fill = (target) => {
    const v = values[i];
    i += 1;
    widths.push(target.length);
    if (v === undefined) throw new Error(`tape exhausted at ${i - 1}`);
    target.set(word(v));
    return target;
  };
  fill.calls = () => i;
  fill.widths = widths;
  return fill;
}

test('KAT: n = 4, top-down draw order, one rejected word', () => {
  // i = 3: span 4, m = 2, c = 1 -> swap 3,1: a d c b
  // i = 2: span 3, m = 2, c = 3 rejected, then c = 0 -> swap 2,0: c d a b
  // i = 1: span 2, m = 1, c = 1 -> swap 1,1: c d a b
  const fill = tapeFill([1, 3, 0, 1]);
  assert.deepEqual(shuffleWithFill(['a', 'b', 'c', 'd'], fill), ['c', 'd', 'a', 'b']);
  assert.equal(fill.calls(), 4);
  assert.deepEqual(fill.widths, [4, 4, 4, 4]);
});

test('KAT: n = 5, all-zero words', () => {
  // j = 0 every step: i=4 swap 4,0; i=3 swap 3,0; i=2 swap 2,0; i=1 swap 1,0.
  const fill = tapeFill([0, 0, 0, 0]);
  assert.deepEqual(shuffleWithFill([0, 1, 2, 3, 4], fill), [1, 2, 3, 4, 0]);
  assert.equal(fill.calls(), 4);
});

// Exhaustive driver: low-byte values 0..7 per word (each m-bit pattern for m <= 3 appears
// 8 / 2^m times). Every tape with at most maxRejects rejected words is enumerated; paths are
// bucketed by (number of rejected words, permutation). Rejections are i.i.d. per draw, so for
// every reject count each permutation must have the same number of tapes.
const DRIVER_VALUES = 8;
function enumerate(n, maxRejects) {
  const buckets = new Map();
  const base = Array.from({ length: n }, (_, i) => i);
  // A completed tape with k rejected words has length (n - 1) + k, so bounding the tape length
  // at (n - 1) + maxRejects enumerates every path with k <= maxRejects exactly once.
  const maxLen = (n - 1) + maxRejects;
  const walk = (tape) => {
    let pos = 0;
    let out;
    try {
      out = shuffleWithFill(base, (t) => {
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
    const rejects = tape.length - (n - 1);
    const key = `${rejects}|${out.join(',')}`;
    buckets.set(key, (buckets.get(key) ?? 0) + 1);
  };
  walk([]);
  return buckets;
}

function permutations(n) {
  if (n === 0) return [[]];
  const out = [];
  for (const p of permutations(n - 1)) {
    for (let i = 0; i <= p.length; i++) out.push([...p.slice(0, i), n - 1, ...p.slice(i)]);
  }
  return out;
}

for (const n of [3, 4]) {
  test(`exhaustive: n = ${n}, every permutation equally often per reject count`, () => {
    const maxRejects = 2;
    const buckets = enumerate(n, maxRejects);
    const perms = permutations(n).map((p) => p.join(','));
    assert.equal(perms.length, n === 3 ? 6 : 24);
    for (let k = 0; k <= maxRejects; k++) {
      const counts = perms.map((p) => buckets.get(`${k}|${p}`) ?? 0);
      assert.ok(counts[0] > 0, `k=${k} has paths`);
      for (const c of counts) assert.equal(c, counts[0], `n=${n} k=${k} counts ${counts}`);
    }
    // No outcome outside the n! permutations.
    for (const key of buckets.keys()) assert.ok(perms.includes(key.split('|')[1]), key);
  });
}

test('edges: empty and length 1 read 0 bytes and return new arrays', () => {
  const fill = tapeFill([]);
  const empty = [];
  const e = shuffleWithFill(empty, fill);
  assert.deepEqual(e, []);
  assert.notEqual(e, empty);
  const one = ['x'];
  const o = shuffleWithFill(one, fill);
  assert.deepEqual(o, ['x']);
  assert.notEqual(o, one);
  assert.equal(fill.calls(), 0);
  assert.deepEqual(shuffle([]), []);
  assert.deepEqual(shuffle([7]), [7]);
});

test('input is not mutated, including frozen input and on adapter failure', () => {
  const input = Object.freeze([1, 2, 3, 4, 5, 6]);
  const out = shuffle(input);
  assert.deepEqual(input, [1, 2, 3, 4, 5, 6]);
  assert.deepEqual([...out].sort((a, b) => a - b), [1, 2, 3, 4, 5, 6]);
  const live = [1, 2, 3, 4];
  assert.throws(() => shuffleWithFill(live, tapeFill([0])), (e) => e instanceof RngEntropyError);
  assert.deepEqual(live, [1, 2, 3, 4]);
});

test('non-array input throws RngRangeError and reads 0 bytes', () => {
  const fill = tapeFill([]);
  const bad = [null, undefined, 'abc', 3, {}, { length: 2, 0: 'a', 1: 'b' }, new Uint8Array(3), new Set([1, 2]), 1n, true];
  for (const v of bad) {
    assert.throws(() => shuffleWithFill(v, fill), (e) => e instanceof RngRangeError && e.code === 'RANGE_INVALID', String(v));
    assert.throws(() => shuffle(v), (e) => e instanceof RngRangeError && e.code === 'RANGE_INVALID', String(v));
  }
  assert.equal(fill.calls(), 0);
});

test('length above 2^32-1 throws RngRangeError and reads 0 bytes', () => {
  assert.equal(SHUFFLE_MAX_LENGTH, 2 ** 32 - 1);
  const fill = tapeFill([]);
  for (const len of [2 ** 32, 2 ** 53, -1, 1.5, NaN]) {
    const fake = new Proxy([], { get: (t, k) => (k === 'length' ? len : Reflect.get(t, k)) });
    assert.throws(() => shuffleWithFill(fake, fill), (e) => e instanceof RngRangeError, String(len));
  }
  assert.equal(fill.calls(), 0);
});

test('length that changes between the check and the copy throws RngRangeError, 0 bytes', () => {
  const fill = tapeFill([]);
  let reads = 0;
  const shifty = new Proxy([1, 2, 3], {
    get: (t, k) => {
      if (k === 'length') { reads += 1; return reads === 1 ? 3 : 2; }
      return Reflect.get(t, k);
    },
  });
  assert.throws(() => shuffleWithFill(shifty, fill), (e) => e instanceof RngRangeError && e.code === 'RANGE_INVALID');
  assert.equal(fill.calls(), 0);
});

test('short and throwing adapters are ENTROPY_UNAVAILABLE; endless rejects are RNG_REJECTION_EXHAUSTED', () => {
  const short = (t) => t.subarray(0, 1);
  assert.throws(() => shuffleWithFill([1, 2, 3], short), (e) => e instanceof RngEntropyError && e.code === 'ENTROPY_UNAVAILABLE');
  const boom = () => { throw new Error('no source'); };
  assert.throws(() => shuffleWithFill([1, 2, 3], boom), (e) => e instanceof RngEntropyError && e.code === 'ENTROPY_UNAVAILABLE');
  const notBytes = () => 'xxxx';
  assert.throws(() => shuffleWithFill([1, 2], notBytes), (e) => e instanceof RngEntropyError);
  // n = 3 first draw is span 3; word 3 always rejects.
  const reject = tapeFill(Array.from({ length: TRY_LIMIT }, () => 3));
  assert.throws(() => shuffleWithFill([1, 2, 3], reject), (e) => e instanceof RngHealthError && e.code === 'RNG_REJECTION_EXHAUSTED');
  assert.equal(reject.calls(), TRY_LIMIT);
});

test('public surface: shuffle exported, no fill-injectable or raw-bytes export', () => {
  assert.equal(typeof core.shuffle, 'function');
  assert.equal(core.shuffle.length, 1);
  for (const name of ['shuffleWithFill', 'integerWithFill', 'fillBuffer', 'randomFillSync', 'randomBytes']) {
    assert.equal(name in core, false, name);
  }
});

test('public shuffle over the platform source returns a permutation', () => {
  const src = Array.from({ length: 52 }, (_, i) => i);
  for (let r = 0; r < 10; r++) {
    const out = shuffle(src);
    assert.equal(out.length, 52);
    assert.deepEqual([...out].sort((a, b) => a - b), src);
  }
});

test('sparse input (HoQ A14 NIT, documented): a moved hole becomes explicit undefined, index 0 may stay a hole', async () => {
  const { shuffleWithFill: sw } = await import('../src/mapping/index.ts');
  const tape = (vals) => { let i = 0; return (t) => { t.fill(0); t[t.length - 1] = vals[i++]; return t; }; };
  // j = i on every step: no element moves, but each splice re-writes index i
  const kept = sw([, 2, , 4, 5], tape([4, 3, 2, 1]));
  assert.equal(kept.length, 5);
  assert.equal(0 in kept, false);
  assert.equal(2 in kept, true);
  assert.equal(kept[2], undefined);
  // j = 0 on every step: index 0 is swapped, so every slot is an own element
  const moved = sw([1, , 3, , 5], tape([0, 0, 0, 0]));
  assert.deepEqual([0, 1, 2, 3, 4].map((i) => i in moved), [true, true, true, true, true]);
  assert.equal(moved.filter((x) => x === undefined).length, 2);
});
