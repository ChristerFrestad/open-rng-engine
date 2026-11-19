// Evidence-path entry to THE wave-1 statistic (CTO batch J, G-56; closes Quant OPEN-f1 by identity): the
// counted wave-1 EBC tests are computed by verification/statistic/wave1-statistic.mjs, the same module (the
// same function objects) the A6 calibration runs through verification/calibration/wave1-source.mjs. Here the
// outcomes are the collector's records (one public-call outcome each, EG-1), and a result must carry the
// backstop's grant stamp (G-54). Nothing here draws entropy.
import * as S from '../statistic/wave1-statistic.mjs';
import { grantStampError } from './collector.mjs';

export const STATISTIC = S;

// Pure: M observations of entry e read from records, through the statistic module.
export function statisticFromRecords(e, records, M) {
  let i = 0;
  const next = () => { if (i >= records.length) throw new Error(`${e.id}: records exhausted after ${i} outcomes`); return records[i++]; };
  const lumped = S.lumpExact(S.lawExact(e), M);
  const { h, outcomes } = S.histogram(e, M, next, lumped.map.length);
  return { id: e.id, ...S.pearson(h, lumped, M), outcomes, unread: records.length - i, statistic: S.STATISTIC_ID };
}

// Counted: the collection result must be stamped inside an open evidence grant.
export function evidenceStatistic(entryId, result, M) {
  const e = S.ENTRIES.find((x) => x.id === entryId);
  if (!e) throw new Error(`unknown wave-1 entry ${entryId}`);
  const g = grantStampError(result);
  if (g) throw new Error(`wave-1 statistic refused: ${g}`);
  return statisticFromRecords(e, result.records, M);
}
