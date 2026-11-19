// G-64 (HoQ A9): static ban on defining the backstop marker outside the backstop.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { markerBanFindings } from '../tools/ci/marker-ban.mjs';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
test('G-64: no file outside the backstop (and test/) defines the backstop marker', () => {
  assert.deepEqual(markerBanFindings(ROOT), []);
});
test('G-64: a planted forger (HoQ probe A2 shape) is found in verification/ and tools/', () => {
  const d = mkdtempSync(join(tmpdir(), 'g64-ban-'));
  try {
    for (const sub of ['verification', 'tools']) mkdirSync(join(d, sub), { recursive: true });
    const forger = "const M = Symbol.for('open-rng-engine/entropy-backstop/v1');\nObject.defineProperty(globalThis, M, { value: Object.freeze({ evidence: {} }), writable: false, configurable: false });\n";
    writeFileSync(join(d, 'verification/zz-forge.mjs'), forger);
    writeFileSync(join(d, 'tools/zz-forge2.mjs'), "globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')] = {};\n");
    writeFileSync(join(d, 'verification/ok.mjs'), "const M = Symbol.for('open-rng-engine/entropy-backstop/v1'); export const read = () => globalThis[M];\n");
    const f = markerBanFindings(d);
    assert.equal(f.length, 2, f.join('; ')); assert.ok(f.some((x) => x.startsWith('verification/zz-forge.mjs'))); assert.ok(f.some((x) => x.startsWith('tools/zz-forge2.mjs')));
  } finally { rmSync(d, { recursive: true, force: true }); }
});
