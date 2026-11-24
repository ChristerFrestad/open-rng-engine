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
 * Every try zeroes its target buffer, and the buffer the fill returned when it
 * is a different Uint8Array, before the call returns, retries or throws
 * (PLAN R-23 / QR-08; HoQ A14 (b)).
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
  if (span === 1) return min;

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
      if (c < span) return min + c;
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
