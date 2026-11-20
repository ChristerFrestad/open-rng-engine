// Evidence-path entry to THE wave-1 statistic (CTO batch J, G-56; closes Quant OPEN-f1 by identity): the
// counted wave-1 EBC tests are computed by verification/statistic/wave1-statistic.mjs, the same module (the
// same function objects) the A6 calibration runs through verification/calibration/wave1-source.mjs. Here the
// outcomes are the collector's records (one public-call outcome each, EG-1), and a counted result must be one
// the evidence launcher counted (G-64, HoQ A11): a stamp or marker the guarded process can set for itself, or a
// complete forged marker in a plain process, is no proof. Nothing here draws entropy.
import * as S from '../statistic/wave1-statistic.mjs';
import { launcherCounted } from './evidence-launcher.mjs';

export const STATISTIC = S;

// Pure: M observations of entry e read from records, through the statistic module.
export function statisticFromRecords(e, records, M) {
  let i = 0;
  const next = () => { if (i >= records.length) throw new Error(`${e.id}: records exhausted after ${i} outcomes`); return records[i++]; };
  const lumped = S.lumpExact(S.lawExact(e), M);
  const { h, outcomes } = S.histogram(e, M, next, lumped.map.length);
  return { id: e.id, ...S.pearson(h, lumped, M), outcomes, unread: records.length - i, statistic: S.STATISTIC_ID };
}

// Counted: the result must be one evidence-launcher runCounted counted (parent-held, digest re-checked).
export function evidenceStatistic(entryId, result, M) {
  const e = S.ENTRIES.find((x) => x.id === entryId);
  if (!e) throw new Error(`unknown wave-1 entry ${entryId}`);
  if (!launcherCounted(result)) throw new Error('wave-1 statistic refused: result not counted by the evidence launcher (G-64)');
  if (result.id !== entryId) throw new Error(`wave-1 statistic refused: counted result is for ${result.id}, not ${entryId} (G-64)`);
  return statisticFromRecords(e, result.records, M);
}
