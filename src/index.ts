// Core "." entry: outcome-producing slices (integer range, shuffle, sample).
import { fillBuffer } from './entropy/index.ts';
import { integerWithFill, sampleWithFill, shuffleWithFill } from './mapping/index.ts';

export { RngEntropyError, RngHealthError, RngRangeError } from './errors.ts';

export function integer(min: number, maxExclusive: number): number {
  return integerWithFill(min, maxExclusive, fillBuffer);
}

/**
 * Returns a new array holding the items in a random order (Fisher-Yates,
 * every swap index drawn like integer()). The input array is not modified.
 * Throws RngRangeError for a non-array or a length above 2^32-1.
 * A hole in a sparse input reads as undefined: an element moved by a swap comes
 * out as an explicit undefined, and the element left at index 0 can stay a hole
 * when no swap moved it.
 */
export function shuffle<T>(items: readonly T[]): T[] {
  return shuffleWithFill(items, fillBuffer);
}

/**
 * Returns k distinct indices of [0, n) in draw order: the first k steps of
 * the same Fisher-Yates loop as shuffle(), every index drawn like integer().
 * sample(n, n) equals the reverse of shuffle([0..n)) on the same draws.
 * Throws RngRangeError unless n and k are integers with 0 <= k <= n <= 2^32-1.
 * Memory grows with k, not n: the result holds k numbers and up to k moved
 * positions are kept while drawing, so a large k (up to 2^32-1) needs memory
 * for that many entries.
 */
export function sample(n: number, k: number): number[] {
  return sampleWithFill(n, k, fillBuffer);
}
