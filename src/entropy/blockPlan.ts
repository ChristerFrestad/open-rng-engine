// R-56 pinned `blockPlan(n)` (PLAN L164; cto-g1-spec.md §5.1). Pure, SHARED, no imports, no state.
// MAX_DATA = 65,520 (= 65,536 - 16). While remaining > 0: data = min(remaining, MAX_DATA); fetch data + 16
// (the last 16 bytes are the fingerprint: never returned, logged or reused). Each width is in 17..65,536.
// Σ widths = n + 16·⌈n / 65520⌉ (checked against PLAN L164 before coding; see SEAT-LOG C-11 entry).
// n ≥ 1 (PLAN L605): n = 0, non-integers and unsafe integers are RANGE_INVALID (no plan, no evidence).

export const MAX_DATA = 65520;
export const FINGERPRINT_BYTES = 16;
export const MAX_WIDTH = MAX_DATA + FINGERPRINT_BYTES; // 65,536

export function isValidBlockPlanN(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 1;
}

function assertN(n: unknown): asserts n is number {
  if (!isValidBlockPlanN(n)) throw new RangeError('RANGE_INVALID: blockPlan(n) requires a safe integer n >= 1');
}

/** Number of blocks, ⌈n / 65520⌉, without materialising the plan. */
export function blockCount(n: number): number {
  assertN(n);
  return Math.ceil(n / MAX_DATA);
}

/** Width of block i (0-based), without materialising the plan. */
export function blockWidthAt(n: number, i: number): number {
  const count = blockCount(n);
  if (!Number.isSafeInteger(i) || i < 0 || i >= count) throw new RangeError('RANGE_INVALID: block index out of range');
  const data = i < count - 1 ? MAX_DATA : n - MAX_DATA * (count - 1);
  return data + FINGERPRINT_BYTES;
}

/** Σ blockPlan(n) = n + 16·⌈n / 65520⌉. */
export function blockPlanTotal(n: number): number {
  return n + FINGERPRINT_BYTES * blockCount(n);
}

/** The ordered list of fetch widths, by the literal R-56 loop. */
export function blockPlan(n: number): number[] {
  assertN(n);
  const widths: number[] = [];
  let remaining = n;
  while (remaining > 0) {
    const data = Math.min(remaining, MAX_DATA);
    widths.push(data + FINGERPRINT_BYTES);
    remaining -= data;
  }
  return widths;
}
