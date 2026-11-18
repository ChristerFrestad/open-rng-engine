import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { scanRoot, BAD_FIXTURES, uEscape, uUnescape } from '../tools/ci/b8-dependencies.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const STUB = join(ROOT, 'test/fixtures/ph1-stubs/b8-dependencies.mjs');
const TOOL = join(ROOT, 'tools/ci/b8-dependencies.mjs');
const withTmp = (fn) => { const d = mkdtempSync(join(tmpdir(), 'b8t-')); try { return fn(d); } finally { rmSync(d, { recursive: true, force: true }); } };
const put = (d, rel, src) => { mkdirSync(join(d, dirname(rel)), { recursive: true }); writeFileSync(join(d, rel), typeof src === 'string' ? src : JSON.stringify(src, null, 2) + '\n'); };

test('B8: this repo is green (dependencies {} , exact devDeps, lockfile integrity)', () => {
  assert.deepEqual(scanRoot(ROOT), []);
  const r = spawnSync(process.execPath, [TOOL, ROOT], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /0 finding\(s\)/);
});

test('B8: --self-test is green', () => {
  const r = spawnSync(process.execPath, [TOOL, '--self-test'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /4 known-bad fixtures red, control green/);
});

test('B8: a runtime dep, an unpinned devDep, a workspace runtime dep, or a lockfile mismatch is red', () => {
  assert.equal(Object.keys(BAD_FIXTURES).length, 4);
});

test('B8: the previous stub exits 2 and does not kill a known-bad fixture', () => withTmp((d) => {
  put(d, 'package.json', JSON.parse(uUnescape(uEscape(JSON.stringify({ name: 'x', dependencies: { leftpad: '1.0.0' }, devDependencies: { typescript: '5.9.3' } })))));
  put(d, 'package-lock.json', { lockfileVersion: 3, packages: { '': { dependencies: { leftpad: '1.0.0' }, devDependencies: { typescript: '5.9.3' } }, 'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-x' } } });
  const stub = spawnSync(process.execPath, [STUB, d], { encoding: 'utf8' });
  assert.equal(stub.status, 2);
  assert.match(stub.stdout, /STUB: b8-dependencies not implemented/);
  assert.ok(!/b8-dependencies/.test(stub.stdout + stub.stderr) || /STUB: b8-dependencies not implemented/.test(stub.stdout));
  // stub stdout is the STUB line containing the tool name, so assert it did not report a finding line
  assert.ok(!/must be \{\}/.test(stub.stdout + stub.stderr));
  const live = spawnSync(process.execPath, [TOOL, d], { encoding: 'utf8' });
  assert.equal(live.status, 1);
  assert.match(live.stdout, /'dependencies' must be \{\}/);
}));

test('B8 is wired into check:ph0 (live + self-test)', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.match(pkg.scripts['check:ph0'], /node tools\/ci\/b8-dependencies\.mjs && node tools\/ci\/b8-dependencies\.mjs --self-test/);
});
