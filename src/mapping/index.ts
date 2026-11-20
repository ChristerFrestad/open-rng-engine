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
    let filled: Uint8Array;
    try {
      filled = takeFilled(target, fill(target));
    } catch (e) {
      if (e instanceof RngRangeError || e instanceof RngHealthError || e instanceof RngEntropyError) throw e;
      throw new RngEntropyError('adapter failed');
    }
    const c = lowBits(filled, m);
    if (c < span) return min + c;
  }
  throw new RngHealthError('128 consecutive rejects');
}
