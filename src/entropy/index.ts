// PH1 skeleton: module boundary (PLAN r4.9 §3.1 `entropy/`). The exact named
// import below is the L596 pair (randomFillSync, entropy/), so a live
// package.json `exports` map (rule 22) can exist without firing rule 27
// no-fewer as a missing-pair hit. The typings ignore is because this repo
// pins typescript 5.9.3 only (no @types/node); a typings package would be a
// new devDependency (B8 / L825(7) G4 PASS is PENDING).
// int-v8 r8 (CTO): the import is never re-exported; this module exports exactly
// {fillBuffer} (test/entropy-exports.test.mjs 'r8 ENTROPY-EXPORTS', mutant M86).
// @ts-expect-error node:crypto typings are not in the pinned devDependencies.
import { randomFillSync } from 'node:crypto';

export function fillBuffer(target: Uint8Array): Uint8Array {
  randomFillSync(target);
  return target;
}
