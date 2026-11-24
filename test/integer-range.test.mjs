// Integer-range unit tests: validation, edges, KATs, and exhaustive rejection check.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { integer, RngRangeError, RngHealthError, RngEntropyError } from '../src/index.ts';
import {
  integerWithFill,
  bitLength,
  readWidth,
  lowBits,
  MAX_SPAN,
  WIDTH_SMALL_MAX,
  WIDTH_SMALL,
  WIDTH_LARGE,
  TRY_LIMIT,
} from '../src/mapping/index.ts';

const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const MIN_SAFE = Number.MIN_SAFE_INTEGER;

function packLowBits(width, m, value) {
  const buf = new Uint8Array(width);
  let v = value;
  const fullBytes = Math.floor(m / 8);
  const rem = m - fullBytes * 8;
  for (let i = 0; i < fullBytes; i++) {
    buf[width - 1 - i] = v % 256;
    v = Math.floor(v / 256);
  }
  if (rem > 0) {
    buf[width - fullBytes - 1] = v % (2 ** rem);
  }
  return buf;
}

function packWithHighBits(width, m, low, highExtra) {
  const buf = packLowBits(width, m, low);
  // Add a marker in a byte above the m-bit field (if any unused bits exist).
  if (m < width * 8) {
    buf[0] = (buf[0] + highExtra) % 256;
    if (m > (width - 1) * 8) {
      // top byte also holds rem low bits; restore them after adding high
      const rem = m - (width - 1) * 8;
      const lowMask = (2 ** rem) - 1;
      const originalLow = packLowBits(width, m, low)[0] & lowMask;
      buf[0] = (buf[0] & ~lowMask) | originalLow;
    }
  }
  return buf;
}

function tapeFill(chunks) {
  let i = 0;
  const fill = (target) => {
    const next = chunks[i];
    i += 1;
    if (next === undefined || next.length !== target.length) {
      throw new Error(`tape exhausted or width mismatch at ${i - 1}`);
    }
    target.set(next);
    return target;
  };
  fill.calls = () => i;
  return fill;
}

test('size-1 range returns min and reads 0 bytes', () => {
  const fill = tapeFill([]);
  assert.equal(integerWithFill(7, 8, fill), 7);
  assert.equal(integerWithFill(-4, -3, fill), -4);
  assert.equal(integerWithFill(0, 1, fill), 0);
  assert.equal(integerWithFill(MAX_SAFE - 1, MAX_SAFE, fill), MAX_SAFE - 1);
  assert.equal(fill.calls(), 0);
  assert.equal(integer(19, 20), 19);
});

test('validation: non-integers, unsafe ints, inverted and empty spans, 0 bytes', () => {
  const fill = tapeFill([new Uint8Array(4)]);
  const bad = [
    [1.5, 3],
    [0, 2.2],
    ['0', 2],
    [0, '2'],
    [true, 2],
    [0, false],
    [null, 2],
    [undefined, 2],
    [0n, 2],
    [NaN, 2],
    [Infinity, 2],
    [-Infinity, 2],
    [0, NaN],
    [MAX_SAFE + 1, MAX_SAFE + 2],
    [2, 2],
    [5, 1],
    [0, 0],
    [MIN_SAFE, MAX_SAFE],
    [0, MAX_SPAN + 1],
    [0, MAX_SPAN + 2],
    [-1, MAX_SPAN],
    [1, 1 + MAX_SPAN + 1],
  ];
  for (const [min, max] of bad) {
    assert.throws(() => integerWithFill(min, max, fill), (e) => e instanceof RngRangeError && e.code === 'RANGE_INVALID', `${min} ${max}`);
  }
  assert.equal(fill.calls(), 0);
  assert.throws(() => integer(0, 0), (e) => e instanceof RngRangeError && e.code === 'RANGE_INVALID');
});

test('span edges: r = 2, r = 2^32, r = 2^32+1, r = 2^48 accepted', () => {
  const r2 = tapeFill([packLowBits(WIDTH_SMALL, 1, 1)]);
  assert.equal(integerWithFill(10, 12, r2), 11);
  assert.equal(r2.calls(), 1);

  const at32 = tapeFill([packLowBits(WIDTH_SMALL, 32, 1)]);
  assert.equal(readWidth(WIDTH_SMALL_MAX), WIDTH_SMALL);
  assert.equal(integerWithFill(0, WIDTH_SMALL_MAX, at32), 1);
  assert.equal(at32.calls(), 1);

  const above32 = tapeFill([packLowBits(WIDTH_LARGE, 33, 0)]);
  assert.equal(readWidth(WIDTH_SMALL_MAX + 1), WIDTH_LARGE);
  assert.equal(integerWithFill(0, WIDTH_SMALL_MAX + 1, above32), 0);
  assert.equal(above32.calls(), 1);

  const at48 = tapeFill([packLowBits(WIDTH_LARGE, 48, 123)]);
  assert.equal(readWidth(MAX_SPAN), WIDTH_LARGE);
  assert.equal(integerWithFill(0, MAX_SPAN, at48), 123);
  assert.equal(at48.calls(), 1);

  const over48 = tapeFill([new Uint8Array(WIDTH_LARGE)]);
  assert.throws(() => integerWithFill(0, MAX_SPAN + 1, over48), (e) => e instanceof RngRangeError);
  assert.equal(over48.calls(), 0);
});

test('KATs: fixed bytes produce fixed outputs, including a rejected word', () => {
  // r = 6, m = 3, w = 4. First word low bits = 7 (reject), second = 2 (accept) -> min+2.
  const kat1 = tapeFill([packLowBits(4, 3, 7), packLowBits(4, 3, 2)]);
  assert.equal(integerWithFill(10, 16, kat1), 12);
  assert.equal(kat1.calls(), 2);

  // Same r, a single accepted word with unused high bits set.
  const high = packWithHighBits(4, 3, 5, 0xaa);
  const kat2 = tapeFill([high]);
  assert.equal(lowBits(high, 3), 5);
  assert.equal(integerWithFill(10, 16, kat2), 15);
  assert.equal(kat2.calls(), 1);

  // Negative min, r = 37 (wheel-sized), m = 6, w = 4, c = 36.
  const kat3 = tapeFill([packLowBits(4, 6, 36)]);
  assert.equal(integerWithFill(-10, 27, kat3), 26);
  assert.equal(kat3.calls(), 1);

  // 7-byte width: r = 2^32+3, m = 33, c = 2, unused high bits set.
  const span = WIDTH_SMALL_MAX + 3;
  const m = bitLength(span - 1);
  assert.equal(m, 33);
  const word = packWithHighBits(7, 33, 2, 0x5a);
  const kat4 = tapeFill([word]);
  assert.equal(integerWithFill(100, 100 + span, kat4), 102);
  assert.equal(kat4.calls(), 1);
});

test('KAT: word c == r is rejected (boundary), next word accepted (HoQ A13 NIT)', () => {
  // r = 6, m = 3, w = 4: c = 6 equals r and is rejected; c = 5 = r - 1 is accepted.
  const eq6 = tapeFill([packLowBits(4, 3, 6), packLowBits(4, 3, 5)]);
  assert.equal(integerWithFill(10, 16, eq6), 15);
  assert.equal(eq6.calls(), 2);
  // r = 37, m = 6: c = 37 rejected, then c = 0 -> min.
  const eq37 = tapeFill([packLowBits(4, 6, 37), packLowBits(4, 6, 0)]);
  assert.equal(integerWithFill(-10, 27, eq37), -10);
  assert.equal(eq37.calls(), 2);
  // 7-byte width: r = 2^32+3, m = 33, c = r rejected, then c = r - 1 accepted.
  const span = WIDTH_SMALL_MAX + 3;
  const eqWide = tapeFill([packLowBits(7, 33, span), packLowBits(7, 33, span - 1)]);
  assert.equal(integerWithFill(0, span, eqWide), span - 1);
  assert.equal(eqWide.calls(), 2);
});

test('exhaustive rejection check: every r in 2..256, every m-bit word', () => {
  for (let r = 2; r <= 256; r++) {
    const m = bitLength(r - 1);
    const w = readWidth(r);
    const space = 2 ** m;
    const accepted = [];
    for (let c = 0; c < space; c++) {
      // Unused high bits must not change the drawn value (mask, not whole-word compare).
      const first = packWithHighBits(w, m, c, 0xc3);
      if (c < r) {
        const fill = tapeFill([first]);
        const out = integerWithFill(1000, 1000 + r, fill);
        assert.equal(out, 1000 + c, `r=${r} c=${c}`);
        assert.equal(fill.calls(), 1);
        accepted.push(c);
      } else {
        const fill = tapeFill([first, packLowBits(w, m, 0)]);
        const out = integerWithFill(1000, 1000 + r, fill);
        assert.equal(out, 1000, `r=${r} reject c=${c}`);
        assert.equal(fill.calls(), 2);
      }
    }
    assert.equal(accepted.length, r, `r=${r} accepted count`);
    assert.deepEqual(accepted, Array.from({ length: r }, (_, i) => i));
    // A word c >= r is not reduced by remainder (the rejected form).
    if (space > r) {
      const fill = tapeFill([packLowBits(w, m, r), packLowBits(w, m, 1)]);
      assert.equal(integerWithFill(0, r, fill), 1);
      assert.equal(fill.calls(), 2);
    }
  }
});

test('128 consecutive rejects throws RngHealthError; 127 rejects then accept succeeds', () => {
  const r = 3;
  const m = 2;
  const w = 4;
  const reject = packLowBits(w, m, 3);
  const accept = packLowBits(w, m, 1);
  const allReject = tapeFill(Array.from({ length: TRY_LIMIT }, () => reject));
  assert.throws(() => integerWithFill(0, 3, allReject), (e) => e instanceof RngHealthError && e.code === 'RNG_REJECTION_EXHAUSTED');
  assert.equal(allReject.calls(), TRY_LIMIT);

  const almost = Array.from({ length: TRY_LIMIT - 1 }, () => reject);
  almost.push(accept);
  const fill = tapeFill(almost);
  assert.equal(integerWithFill(0, 3, fill), 1);
  assert.equal(fill.calls(), TRY_LIMIT);
});

test('adapter failure is ENTROPY_UNAVAILABLE; short return is too', () => {
  const boom = () => { throw new Error('no source'); };
  assert.throws(() => integerWithFill(0, 4, boom), (e) => e instanceof RngEntropyError && e.code === 'ENTROPY_UNAVAILABLE');
  const short = (target) => target.subarray(0, 1);
  assert.throws(() => integerWithFill(0, 4, short), (e) => e instanceof RngEntropyError && e.code === 'ENTROPY_UNAVAILABLE');
});

test('public integer() draws a value in range over the platform source', () => {
  for (let i = 0; i < 20; i++) {
    const v = integer(-3, 5);
    assert.ok(Number.isSafeInteger(v) && v >= -3 && v < 5, String(v));
  }
  const wide = integer(0, WIDTH_SMALL_MAX + 2);
  assert.ok(wide >= 0 && wide < WIDTH_SMALL_MAX + 2);
});
