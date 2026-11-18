// Evidence-run entry point guard. Decision rule v1 (FROZEN 5d09c75a) rule 18 and the rule 8 / 15 / 17
// preconditions: no counted evidence run starts unless the harness is READY. The PH0 gate (check:ph0)
// reports readiness but does not fail on it; this guard is what blocks a run.
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dfReadiness } from './df-table.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

export function harnessReadiness(root = ROOT) {
  const kTests = JSON.parse(readFileSync(join(root, 'verification/k-tests-v1.1.json'), 'utf8')).tests;
  const df = dfReadiness(kTests);
  return { ready: df.ready, df };
}

// Every evidence-run start must call this first. It throws while anything is open.
export function assertEvidenceRunReady(root = ROOT) {
  const r = harnessReadiness(root);
  if (!r.ready) {
    throw new Error(`harness NOT-READY: rule 8 df open for ${r.df.open.length} of ${r.df.dfNull} df-null entries (${r.df.open.slice(0, 3).join(', ')}${r.df.open.length > 3 ? ', ...' : ''})`);
  }
  return r;
}
