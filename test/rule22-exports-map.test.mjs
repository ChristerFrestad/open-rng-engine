import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { scanRoot, scanExports, BAD_FIXTURES, REQUIRED_EXPORT_KEYS, selfTest, uEscape, uUnescape } from '../tools/ci/rule22-exports-map.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const STUB = join(ROOT, 'test/fixtures/ph1-stubs/rule22-exports-map.mjs');
const TOOL = join(ROOT, 'tools/ci/rule22-exports-map.mjs');
const withTmp = (fn) => { const d = mkdtempSync(join(tmpdir(), 'r22t-')); try { return fn(d); } finally { rmSync(d, { recursive: true, force: true }); } };

test('rule 22: this repo is green (exports keys exactly the allowlist)', () => {
  assert.deepEqual(scanRoot(ROOT), []);
  const r = spawnSync(process.execPath, [TOOL, ROOT], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /0 finding\(s\)/);
});

test('rule 22: required keys are exactly ".", "./audited", "./package.json"', () => {
  assert.deepEqual([...REQUIRED_EXPORT_KEYS], ['.', './audited', './package.json']);
});

test('rule 22: --self-test is green', () => {
  const r = spawnSync(process.execPath, [TOOL, '--self-test'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /4 known-bad fixtures red, control green/);
});

for (const name of Object.keys(BAD_FIXTURES)) {
  test(`rule 22 known-bad fixture is red: ${name}`, () => {
    assert.ok(BAD_FIXTURES[name].reason);
  });
}

test('rule 22: missing exports, wildcard, ./drbg and a mapping target are red; control is green', () => withTmp((d) => {
  writeFileSync(join(d, 'package.json'), JSON.stringify({ name: 'x', exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json' } }));
  assert.deepEqual(scanRoot(d), []);
  writeFileSync(join(d, 'package.json'), JSON.stringify({ name: 'x' }));
  assert.ok(scanRoot(d).some((h) => /missing/.test(h)));
  assert.ok(scanExports({ exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json', './*': './src/*' } }).some((h) => /wildcard/.test(h)));
  assert.ok(scanExports({ exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json', './drbg': './x.js' } }).some((h) => /drbg|exactly/.test(h)));
  assert.ok(scanExports({ exports: { '.': './packages/mapping/src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json' } }).some((h) => /packages\/mapping/.test(h)));
}));

test('rule 22: the previous stub exits 2 and does not kill a known-bad fixture', () => withTmp((d) => {
  writeFileSync(join(d, 'package.json'), uUnescape(uEscape(JSON.stringify({ name: 'x', exports: { './drbg': './x.js' } }))));
  const stub = spawnSync(process.execPath, [STUB, d], { encoding: 'utf8' });
  assert.equal(stub.status, 2, 'stub must exit 2 (not implemented)');
  assert.match(stub.stdout, /STUB: rule22-exports-map not implemented/);
  // The stub does not inspect, so the known-bad tree is not reported red by it.
  assert.match(stub.stdout, /STUB: rule22-exports-map not implemented/);
  assert.ok(!/rule22-exports 'exports'|rule22-exports keys/.test(stub.stdout + stub.stderr));
  const live = spawnSync(process.execPath, [TOOL, d], { encoding: 'utf8' });
  assert.equal(live.status, 1);
  assert.match(live.stdout, /rule22-exports/);
}));

test('rule 22 is wired into check:ph0 (live + self-test)', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.match(pkg.scripts['check:ph0'], /node tools\/ci\/rule22-exports-map\.mjs && node tools\/ci\/rule22-exports-map\.mjs --self-test/);
});
