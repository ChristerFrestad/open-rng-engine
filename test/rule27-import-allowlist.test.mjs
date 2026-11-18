// CI rule 27 (quality.md v5.5.7 L596; QR-25 L228; PLAN R-44 L152): real import-allowlist check, escaped scratch fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { scanTree, scanFile, writeFixture, BAD, selfTest } from '../tools/ci/import-allowlist.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const EXPECT = {
  'namespace-import': 'namespace-import', 'default-import': 'default-import', 'require-crypto': 'require-crypto',
  'dynamic-import': 'dynamic-import', 'process-binding': 'process-binding', 'process-getBuiltinModule': 'process-binding',
  'globalThis-crypto': 'globalThis-crypto', 'globalThis-computed': 'globalThis-computed', 'bare-global-crypto': 'bare-global-crypto',
  'global-crypto': 'global-self', 'self-crypto': 'global-self', 'node-module': 'node-module', 'createRequire': 'createRequire',
  'setFips': 'fips', 'fips-member': 'fips', 'extra-pair': 'extra-pair', 'createHash-outside-evidence': 'extra-pair',
  'audited-import': 'audited-import', 'defineProperty-globalThis': 'defineProperty-globalThis',
};

test('rule 27: the compliant fixture (exact pair set, audited -> evidence) is green', () => {
  const d = mkdtempSync(join(tmpdir(), 'r27-')); try { writeFixture(d); assert.deepEqual(scanTree(d).hits, []); } finally { rmSync(d, { recursive: true, force: true }); }
});

for (const [name, src] of Object.entries(BAD)) {
  test(`rule 27 known-bad fixture is red for its own reason: ${name}`, () => {
    const d = mkdtempSync(join(tmpdir(), 'r27-'));
    try {
      const file = name === 'audited-import' ? 'src/audited/bad.ts' : name === 'createHash-outside-evidence' ? 'src/entropy/bad.ts' : 'src/mapping/bad.ts';
      writeFixture(d, { [file]: src });
      const hits = scanTree(d).hits;
      assert.ok(hits.some((h) => h.startsWith(file) && h.includes(`rule27-${EXPECT[name]} `)), hits.join('\n'));
    } finally { rmSync(d, { recursive: true, force: true }); }
  });
}

test('rule 27: a missing pair is red (no fewer)', () => {
  const d = mkdtempSync(join(tmpdir(), 'r27-'));
  try { writeFixture(d, { 'src/identity/a.ts': 'export const g = 1;\n' }); assert.deepEqual(scanTree(d).hits, ['src/identity/:0: rule27-missing-pair (getFips, identity/) required by L596 is absent']); }
  finally { rmSync(d, { recursive: true, force: true }); }
});

test('rule 27: comments and string contents are not code', () => {
  const src = "// import * as c from 'node:crypto'; crypto.fips\n/* global.crypto self createRequire */\nexport const s = 'crypto global self fips setFips import(x)';\n";
  assert.deepEqual(scanFile('src/mapping/x.ts', src).hits, []);
});

test('rule 27: --self-test passes', () => { assert.deepEqual(selfTest(), []); });

test('rule 27 on this repo: only the three missing (symbol, directory) pairs, no banned form (not yet in check:ph0)', () => {
  const r = spawnSync(process.execPath, [join(ROOT, 'tools/ci/import-allowlist.mjs'), ROOT], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.deepEqual(r.stdout.trim().split('\n').slice(0, -1), [
    'src/entropy/:0: rule27-missing-pair (randomFillSync, entropy/) required by L596 is absent',
    'src/evidence/:0: rule27-missing-pair (createHash, evidence/) required by L596 is absent',
    'src/identity/:0: rule27-missing-pair (getFips, identity/) required by L596 is absent']);
});
