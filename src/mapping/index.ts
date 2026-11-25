// Integer-range mapping: half-open [min, maxExclusive). PLAN R-42, R-50, R-72, QR-03.
// A.5.1 simple discard: m = bitlen(r-1), accept c < r, else retry. No BigInt.

import { RngEntropyError, RngHealthError, RngRangeError } from '../errors.ts';

export const MAX_SPAN = 2 ** 48;
export const WIDTH_SMALL_MAX = 2 ** 32;
export const WIDTH_SMALL = 4;
export const WIDTH_LARGE = 7;
export const TRY_LIMIT = 128;

export type FillBuffer = (target: Uint8Array) => Uint8Array;

export type IncomingBound = number | string | boolean | null | undefined | object | bigint;

function isSafeInt(v: IncomingBound): boolean {
  return typeof v === 'number' && Number.isSafeInteger(v);
}

function rangeInvalid(detail: string): never {
  throw new RngRangeError(detail);
}

/** Bit length of a positive integer; n is a safe integer >= 1. */
export function bitLength(n: number): number {
  let bits = 0;
  let v = n;
  while (v > 0) {
    v = Math.floor(v / 2);
    bits += 1;
  }
  return bits;
}

export function readWidth(span: number): number {
  return span <= WIDTH_SMALL_MAX ? WIDTH_SMALL : WIDTH_LARGE;
}

/** Low m bits of a big-endian w-byte word, using Number only (m <= 53). */
export function lowBits(buf: Uint8Array, m: number): number {
  if (m <= 0) return 0;
  const fullBytes = Math.floor(m / 8);
  const rem = m - fullBytes * 8;
  let c = 0;
  if (rem > 0) {
    const idx = buf.length - fullBytes - 1;
    const b = buf[idx];
    if (b === undefined) throw new RngEntropyError('short read');
    const mask = (2 ** rem) - 1;
    c = b - (Math.floor(b / (mask + 1)) * (mask + 1));
  }
  const start = buf.length - fullBytes;
  for (let i = start; i < buf.length; i++) {
    const b = buf[i];
    if (b === undefined) throw new RngEntropyError('short read');
    c = c * 256 + b;
  }
  return c;
}

function takeFilled(target: Uint8Array, out: Uint8Array): Uint8Array {
  if (out instanceof Uint8Array && out.length === target.length) return out;
  throw new RngEntropyError('adapter returned a short buffer');
}

/**
 * Draw an integer in [min, maxExclusive) from a fill callback.
 * Draws through drawBelowWithFill, which zeroes every drawn byte (R-23 / QR-08).
 * Not part of the public "." surface; tests inject a fill here.
 */
export function integerWithFill(min: IncomingBound, maxExclusive: IncomingBound, fill: FillBuffer): number {
  if (!isSafeInt(min) || !isSafeInt(maxExclusive) || typeof min !== 'number' || typeof maxExclusive !== 'number') {
    rangeInvalid('min and maxExclusive must be safe integers');
  }
  if (min >= maxExclusive) {
    rangeInvalid('min must be less than maxExclusive');
  }
  const span = maxExclusive - min;
  if (!Number.isSafeInteger(span) || min + span !== maxExclusive || span < 1 || span > MAX_SPAN) {
    rangeInvalid('span must be an exact integer in 1..2^48');
  }
  return min + drawBelowWithFill(span, fill);
}

/**
 * The shared A.5.1 routine (PLAN QR-05, PRQ-04): x in [0, span) for a safe
 * integer span in 1..2^53-1, already checked by the caller. span 1 reads 0
 * bytes (R-42). One 4-byte read per try when span <= 2^32, else 7 bytes;
 * low bitlen(span-1) bits, accept c < span, else retry; 128 tries.
 * Every try zeroes its target buffer, and the buffer the fill returned when it
 * is a different Uint8Array, in finally before the call returns, retries or
 * throws (PLAN R-23 / QR-08; HoQ A14 (b)), so integer, shuffle, sample and
 * weightedPick are all covered.
 * Module-private: integerWithFill keeps its public 2^48 span cap in front.
 */
function drawBelowWithFill(span: number, fill: FillBuffer): number {
  if (span === 1) return 0;

  const width = readWidth(span);
  const m = bitLength(span - 1);
  for (let t = 0; t < TRY_LIMIT; t++) {
    const target = new Uint8Array(width);
    let returned: Uint8Array | undefined;
    try {
      let filled: Uint8Array;
      try {
        const raw = fill(target);
        if (raw instanceof Uint8Array) returned = raw;
        filled = takeFilled(target, raw);
      } catch (e) {
        if (e instanceof RngRangeError || e instanceof RngHealthError || e instanceof RngEntropyError) throw e;
        throw new RngEntropyError('adapter failed');
      }
      const c = lowBits(filled, m);
      if (c < span) return c;
    } finally {
      // PLAN R-23 / QR-08: no drawn byte outlives the call, on return, reject or throw.
      target.fill(0);
      if (returned !== undefined && returned !== target) returned.fill(0);
    }
  }
  throw new RngHealthError('128 consecutive rejects');
}

/** PLAN R-72: shuffle length bound 0..2^32-1; longer is RANGE_INVALID with 0 bytes read. */
export const SHUFFLE_MAX_LENGTH = 2 ** 32 - 1;

/**
 * Fisher-Yates (Durstenfeld) over a copy, loop pinned top-down (PLAN R-42):
 * for i = n-1 down to 1, j = integerWithFill(0, i + 1, fill). Each index draw
 * takes its own fresh fill call(s) through the same rejection path as
 * integer(); no modulo. n <= 1 reads 0 bytes. The input is never written.
 * Not part of the public "." surface; tests inject a fill here.
 */
export function shuffleWithFill<T>(items: readonly T[], fill: FillBuffer): T[] {
  if (!Array.isArray(items)) {
    rangeInvalid('items must be an array');
  }
  const n: number = items.length;
  if (!Number.isSafeInteger(n) || n < 0 || n > SHUFFLE_MAX_LENGTH) {
    rangeInvalid('items length must be an integer in 0..2^32-1');
  }
  const out: T[] = items.slice();
  if (out.length !== n) {
    rangeInvalid('items length changed while copying');
  }
  for (let i = n - 1; i >= 1; i--) {
    const j = integerWithFill(0, i + 1, fill);
    const atI = out.splice(i, 1, ...out.slice(j, j + 1));
    out.splice(j, 1, ...atI);
  }
  return out;
}

/**
 * PLAN ADR-08 sample(n, k): k distinct indices of [0..n) in draw order, defined
 * as the first k steps of the pinned Fisher-Yates loop over [0..n) (R-42):
 * for i = n-1 down to n-k, j = integerWithFill(0, i + 1, fill), swap a[i] and
 * a[j], emit a[i]. So sample(n, n) is reverse(shuffle([0..n))) on the same
 * fill calls. Only moved positions are held (at most k entries, O(k) memory); no byte buffer is
 * introduced here. Bounds 0 <= k <= n <= 2^32-1 (R-72), else RANGE_INVALID
 * with 0 bytes read. Not part of the public "." surface; tests inject a fill.
 */
export function sampleWithFill(n: IncomingBound, k: IncomingBound, fill: FillBuffer): number[] {
  if (!isSafeInt(n) || !isSafeInt(k) || typeof n !== 'number' || typeof k !== 'number') {
    rangeInvalid('n and k must be safe integers');
  }
  if (n < 0 || n > SHUFFLE_MAX_LENGTH) {
    rangeInvalid('n must be an integer in 0..2^32-1');
  }
  if (k < 0 || k > n) {
    rangeInvalid('k must be an integer in 0..n');
  }
  const moved = new Map<number, number>();
  const out: number[] = [];
  for (let t = 0; t < k; t++) {
    const i = n - 1 - t;
    const j = integerWithFill(0, i + 1, fill);
    const atJ = moved.get(j) ?? j;
    const atI = moved.get(i) ?? i;
    moved.set(j, atI);
    out.push(atJ);
  }
  return out;
}

/** PLAN R-72: weightedPick weight total bound, 1 <= T <= 2^53-1. */
export const WEIGHT_TOTAL_MAX = Number.MAX_SAFE_INTEGER;

/** weightedPick binary-search step cap (HoQ A16): ceil(log2(2^32-1)) = 32 steps suffice; 33 allowed. Internal guard, unreachable in correct code; reports as RngHealthError RNG_REJECTION_EXHAUSTED. */
const SEARCH_ITER_MAX = 33;

/**
 * PLAN §3.3 weightedPick(weights) (R-72, QR-05, PRQ-04): one draw x over
 * [0, T) by the shared A.5.1 routine (7-byte reads when T > 2^32, so T may
 * exceed the integer() span cap 2^48), then a binary search over the integer
 * running sums for the largest index whose sum of earlier weights is <= x.
 * A zero weight is never picked. Weights are non-negative safe integers,
 * length 1..2^32-1, at least one nonzero, T <= 2^53-1 checked while summing;
 * a hole in a sparse array reads as undefined and is refused. Typed arrays
 * (Uint32Array and the like) are not arrays and are refused; pass Array.from(t).
 * Any violation is RANGE_INVALID with 0 bytes read. A single nonzero weight
 * reads 0 bytes (R-42). Memory is O(n): one copy of the weights and one array
 * of running sums. The search is capped at SEARCH_ITER_MAX steps (enough for
 * n <= 2^32-1). The cap is an internal non-convergence guard that correct code
 * cannot reach; past it the call throws RngHealthError under the existing code
 * RNG_REJECTION_EXHAUSTED (no new code, PLAN §3.3 taxonomy unchanged), so a
 * broken search fails instead of hanging. No floats, no modulo. Not part of the public "." surface;
 * tests inject a fill.
 */
export function weightedPickWithFill(weights: readonly number[], fill: FillBuffer): number {
  if (!Array.isArray(weights)) {
    rangeInvalid('weights must be an array');
  }
  const n: number = weights.length;
  if (!Number.isSafeInteger(n) || n < 1 || n > SHUFFLE_MAX_LENGTH) {
    rangeInvalid('weights length must be an integer in 1..2^32-1');
  }
  // HoQ A16: never call the caller's own slice.
  const copy: readonly number[] = Array.prototype.slice.call(weights);
  if (copy.length !== n) {
    rangeInvalid('weights length changed while copying');
  }
  const before: number[] = [];
  let total = 0;
  let nonzero = 0;
  let lastNonzero = 0;
  for (const w of copy) {
    if (!isSafeInt(w) || w < 0) {
      rangeInvalid('every weight must be a non-negative safe integer');
    }
    if (w > WEIGHT_TOTAL_MAX - total) {
      rangeInvalid('weight total must be at most 2^53-1');
    }
    if (w > 0) {
      nonzero += 1;
      lastNonzero = before.length;
    }
    before.push(total);
    total += w;
  }
  if (nonzero === 0) {
    rangeInvalid('at least one weight must be nonzero');
  }
  if (nonzero === 1) return lastNonzero;

  const x = drawBelowWithFill(total, fill);
  let lo = 0;
  let hi = n - 1;
  let steps = 0;
  while (lo < hi) {
    steps += 1;
    if (steps > SEARCH_ITER_MAX) throw new RngHealthError('weightedPick search did not converge');
    const mid = hi - ((hi - lo) >>> 1);
    const sumBefore = before[mid];
    if (sumBefore === undefined) throw new RngRangeError('running sum missing');
    if (sumBefore <= x) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  return lo;
}
