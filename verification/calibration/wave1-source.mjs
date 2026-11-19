// Stream injection for the A6 calibration (CTO batch J, G-56): the labkit reference stream turned into
// public-call outcomes, fed to THE wave-1 statistic (../statistic/wave1-statistic.mjs). Nothing here
// computes a statistic. randomInt outcome = min + below(r); shuffle outcome = a forward Fisher-Yates
// permutation whose cards are drawn lazily as the statistic reads them ([CS-1]: a prefix read is
// distributionally the prefix of a full shuffle).
import * as S from '../statistic/wave1-statistic.mjs';
import { RefStream } from '../labkit/aes-ctr-ref.mjs';

export const STATISTIC = S;
export const ENTRIES = S.ENTRIES.map((e, i) => Object.freeze({ ...e, stream: i + 1 }));

export function lazyShuffle(s) {
  const a = new Uint8Array(52); for (let i = 0; i < 52; i++) a[i] = i;
  let g = 0;
  return { card(i) { while (g <= i && g < 51) { const j = g + s.below(52 - g); const t = a[g]; a[g] = a[j]; a[j] = t; g += 1; } return a[i]; } };
}
export function refSource(e, s) {
  if (e.kind === 'adj' || e.r === 'lehmer') return () => lazyShuffle(s);
  return () => e.min + s.below(e.r);
}

// M_cal (A6, R-A6n): >= 10^6 public-call outcomes per replication and >= 200 observations (adjacency:
// 10^6 shuffles), doubled until the exactly lumped table has >= 10 cells.
export const N_CAL = 1e6, M_CAL_FLOOR = 200, MIN_CELLS = 10;
export function mCal(e) {
  const per = e.kind === 'coupon' ? e.d : e.kind === 'dup' ? e.b * e.u : 1;
  let M = Math.max(Math.ceil(N_CAL / per), e.kind === 'adj' ? 0 : M_CAL_FLOOR);
  while (S.lumpExact(S.lawExact(e), M).cells.length < MIN_CELLS) M *= 2;
  return M;
}
export const urnsPerRep = (e, M) => (e.kind === 'dup' ? M * e.b : null);

// One replication: reference stream (stream, rep) -> M observations -> Pearson p.
export function replicate(e, rep, M, lumped) {
  const s = new RefStream(e.stream, rep);
  const { h, outcomes } = S.histogram(e, M, refSource(e, s), lumped.map.length);
  const { x2, p } = S.pearson(h, lumped, M);
  return { x2, p, outcomes, words: s.words };
}
