// PH1: verification build only; never reachable from production (rule 24).
export { checkRandomBytesReplay, validateReadsOutputSchema } from './replayRandomBytes.ts';
export type { ReplayCode, ReplayResult } from './replayRandomBytes.ts';
