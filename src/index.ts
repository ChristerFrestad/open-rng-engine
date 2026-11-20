// Core "." entry: first outcome-producing slice (integer range).
import { fillBuffer } from './entropy/index.ts';
import { integerWithFill } from './mapping/index.ts';

export { RngEntropyError, RngHealthError, RngRangeError } from './errors.ts';

export function integer(min: number, maxExclusive: number): number {
  return integerWithFill(min, maxExclusive, fillBuffer);
}
