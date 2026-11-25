// HoQ A14 (b), PLAN R-23 / QR-08: the shared draw routine (integer, shuffle, sample, weightedPick) zeroes its target buffer, and the buffer the fill
// returned when that is a different Uint8Array, on every path: return, reject-and-retry, and throw.
// Spy fills keep every buffer they saw and the tests check each one is all zero afterwards.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RngEntropyError, RngHealthError } from '../src/index.ts';
import { integerWithFill, shuffleWithFill, sampleWithFill, weightedPickWithFill, TRY_LIMIT } from '../src/mapping/index.ts';

const allZero = (b) => b.every((x) => x === 0);

// Writes 0xff in every byte, then the low byte = v, so stale bytes would be visible.
function spyFill(values, { separate = false, shortBy = 0 } = {}) {
  const seen = [];
  let i = 0;
  const fill = (target) => {
    const v = values[i];
    i += 1;
    if (v === undefined) throw new Error('tape exhausted');
    const out = separate ? new Uint8Array(target.length - shortBy) : target;
    out.fill(0xff);
    out[out.length - 1] = v;
    seen.push(target);
    if (out !== target) seen.push(out);
    return out;
  };
  fill.seen = seen;
  return fill;
}

test('return path: target zeroed after the value is read', () => {
  const f = spyFill([5]);
  // span 6 (m = 3): low byte 5 with 0xff above -> low 3 bits of 5 = 5 < 6
  assert.equal(integerWithFill(0, 6, f), 5);
  assert.equal(f.seen.length, 1);
  assert.ok(f.seen.every(allZero));
});

test('return path with a separate returned buffer: both zeroed', () => {
  const f = spyFill([2], { separate: true });
  assert.equal(integerWithFill(10, 16, f), 12);
  assert.equal(f.seen.length, 2);
  assert.notEqual(f.seen[0], f.seen[1]);
  assert.ok(f.seen.every(allZero));
});

test('reject path: every rejected and the accepted buffer zeroed (4- and 7-byte widths)', () => {
  const f = spyFill([7, 6, 1]);
  assert.equal(integerWithFill(0, 6, f), 1);
  assert.equal(f.seen.length, 3);
  assert.ok(f.seen.every(allZero));
  const g = spyFill([3], { separate: true });
  assert.equal(integerWithFill(0, 2 ** 48, g), 2 ** 48 - 256 + 3);
  assert.equal(g.seen[0].length, 7);
  assert.ok(g.seen.every(allZero));
});

test('throw paths: adapter throw, short buffer, non-buffer, 128 rejects', () => {
  const targets = [];
  assert.throws(() => integerWithFill(0, 6, (t) => { t.fill(0xff); targets.push(t); throw new Error('x'); }), RngEntropyError);
  const short = spyFill([1], { separate: true, shortBy: 1 });
  assert.throws(() => integerWithFill(0, 6, short), RngEntropyError);
  assert.equal(short.seen.length, 2);
  assert.throws(() => integerWithFill(0, 6, (t) => { t.fill(0xff); targets.push(t); return [1, 2, 3, 4]; }), RngEntropyError);
  const rej = spyFill(new Array(TRY_LIMIT).fill(7));
  assert.throws(() => integerWithFill(0, 6, rej), RngHealthError);
  assert.equal(rej.seen.length, TRY_LIMIT);
  assert.equal(targets.length, 2);
  assert.ok([...targets, ...short.seen, ...rej.seen].every(allZero));
});

test('shuffle and sample buffers are zeroed too (they draw through integerWithFill)', () => {
  const f = spyFill([3, 2, 1, 0], { separate: true });
  shuffleWithFill(['a', 'b', 'c', 'd', 'e'], f);
  const g = spyFill([0, 0, 0]);
  sampleWithFill(52, 3, g);
  assert.ok([...f.seen, ...g.seen].every(allZero));
});

test('weightedPick buffers are zeroed on return, reject, 7-byte and throw paths', () => {
  // T = 6, 4-byte read, m = 3: x = 5, running sums [0, 1, 3] -> index 2
  const a = spyFill([5], { separate: true });
  assert.equal(weightedPickWithFill([1, 2, 3], a), 2);
  assert.equal(a.seen.length, 2);
  // T = 5: 7 and 6 rejected, then x = 1 -> index 1
  const b = spyFill([7, 6, 1]);
  assert.equal(weightedPickWithFill([1, 2, 2], b), 1);
  assert.equal(b.seen.length, 3);
  // T = 2^49 > 2^32: 7-byte read, x = 2^49 - 256 + 3 >= 2^48 -> index 1
  const c = spyFill([3]);
  assert.equal(weightedPickWithFill([2 ** 48, 2 ** 48], c), 1);
  assert.equal(c.seen[0].length, 7);
  // 128 rejects -> RngHealthError
  const d = spyFill(new Array(TRY_LIMIT).fill(7));
  assert.throws(() => weightedPickWithFill([1, 2, 2], d), RngHealthError);
  assert.equal(d.seen.length, TRY_LIMIT);
  assert.ok([...a.seen, ...b.seen, ...c.seen, ...d.seen].every(allZero));
});
