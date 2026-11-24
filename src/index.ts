// Core "." entry: outcome-producing slices (integer range, shuffle).
import { fillBuffer } from './entropy/index.ts';
import { integerWithFill, shuffleWithFill } from './mapping/index.ts';

export { RngEntropyError, RngHealthError, RngRangeError } from './errors.ts';

export function integer(min: number, maxExclusive: number): number {
  return integerWithFill(min, maxExclusive, fillBuffer);
}

/**
 * Returns a new array holding the items in a random order (Fisher-Yates,
 * every swap index drawn like integer()). The input array is not modified.
 * Throws RngRangeError for a non-array or a length above 2^32-1.
 */
export function shuffle<T>(items: readonly T[]): T[] {
  return shuffleWithFill(items, fillBuffer);
}
