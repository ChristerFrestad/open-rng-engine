// Typed reason codes for the core API (PLAN §3.3 taxonomy).

export class RngRangeError extends Error {
  readonly code: 'RANGE_INVALID';
  constructor(detail: string) {
    super(`RANGE_INVALID: ${detail}`);
    this.name = 'RngRangeError';
    this.code = 'RANGE_INVALID';
  }
}

export class RngHealthError extends Error {
  readonly code: 'RNG_REJECTION_EXHAUSTED';
  constructor(detail: string) {
    super(`RNG_REJECTION_EXHAUSTED: ${detail}`);
    this.name = 'RngHealthError';
    this.code = 'RNG_REJECTION_EXHAUSTED';
  }
}

export class RngEntropyError extends Error {
  readonly code: 'ENTROPY_UNAVAILABLE';
  constructor(detail: string) {
    super(`ENTROPY_UNAVAILABLE: ${detail}`);
    this.name = 'RngEntropyError';
    this.code = 'ENTROPY_UNAVAILABLE';
  }
}
