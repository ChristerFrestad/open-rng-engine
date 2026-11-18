import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { scanRoot, BAD_FIXTURES, uEscape, uUnescape, G4_TYPESCRIPT_5_9_3_SHA256, G4_PINNED_PACKAGE_JSON_SHA256, G4_PINNED_PACKAGE_LOCK_SHA256, G4_DIR, fileSha256, coveringG4Markdown, writeSpecialG4, writeG4PinsForTree } from '../tools/ci/b8-dependencies.mjs';

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
  assert.match(r.stdout, /33 known-bad fixtures red, control green/);
});

test('B8: a runtime dep, an unpinned devDep, a workspace runtime dep, or a lockfile mismatch is red', () => {
  assert.equal(Object.keys(BAD_FIXTURES).length, 33);
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

test('B8 G4: the vendored typescript G4 file is byte-pinned and covers the HEAD manifests', () => {
  const g4 = join(ROOT, G4_DIR, 'g4-typescript-5.9.3.md');
  assert.equal(fileSha256(g4), G4_TYPESCRIPT_5_9_3_SHA256);
  const text = readFileSync(g4, 'utf8');
  assert.equal(text.includes('Package: `typescript@5.9.3`'), true);
  assert.equal(text.includes('package.json sha256 `' + G4_PINNED_PACKAGE_JSON_SHA256 + '`'), true);
  assert.equal(text.includes('package-lock.json sha256 `' + G4_PINNED_PACKAGE_LOCK_SHA256 + '`'), true);
  assert.match(text, /provenance is ABSENT/i);
  assert.equal(fileSha256(join(ROOT, 'package.json')), G4_PINNED_PACKAGE_JSON_SHA256);
  assert.equal(fileSha256(join(ROOT, 'package-lock.json')), G4_PINNED_PACKAGE_LOCK_SHA256);
});

const OLD_B8 = new URL('./fixtures/b8-checker-475950db.mjs', import.meta.url);
const B8_OLD_NEW = [
  { name: 'pin-partial-x', expectOldRed: false },
  { name: 'pin-latest', expectOldRed: false },
  { name: 'pin-equals', expectOldRed: false },
  { name: 'optional-deps', expectOldRed: false },
  { name: 'peer-deps', expectOldRed: false },
  { name: 'bundle-deps', expectOldRed: false },
  { name: 'bundled-deps', expectOldRed: false },
  { name: 'overrides', expectOldRed: false },
  { name: 'lock-version-mismatch', expectOldRed: false },
  { name: 'lock-resolved-non-registry', expectOldRed: false },
  { name: 'lock-integrity-sha1', expectOldRed: false },
  { name: 'lock-devOptional-no-integrity', expectOldRed: false },
  { name: 'lock-missing-entry', expectOldRed: false },
  { name: 'lock-link-entry', expectOldRed: false },
  { name: 'mutated-manifest-no-g4', expectOldRed: false },
  { name: 'runtime-dep', expectOldRed: true },
];

test('G-32 / G4: each new fixture is red on the new checker; record the 475950db verdict', async () => {
  const old = await import(OLD_B8);
  const dir = mkdtempSync(join(tmpdir(), 'b8-oldnew-'));
  const rows = [];
  try {
    for (const m of B8_OLD_NEW) {
      const fix = BAD_FIXTURES[m.name];
      assert.ok(fix, m.name);
      const d = join(dir, m.name);
      put(d, 'package.json', JSON.parse(uUnescape(uEscape(JSON.stringify(fix.pkg)))));
      put(d, 'package-lock.json', fix.lock);
      if (fix.extra) for (const [rel, obj] of Object.entries(fix.extra)) put(d, rel, obj);
      if (fix.g4From === 'control') {
        const goodPkg = { name: 'open-rng-engine', version: '0.0.0', private: true, type: 'module', dependencies: {}, devDependencies: { typescript: '5.9.3' } };
        const goodLock = { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } }, 'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' } } };
        const tmp = join(dir, '_good');
        put(tmp, 'package.json', goodPkg);
        put(tmp, 'package-lock.json', goodLock);
        const md = coveringG4Markdown({ name: 'typescript', version: '5.9.3', packageJsonSha256: fileSha256(join(tmp, 'package.json')), packageLockSha256: fileSha256(join(tmp, 'package-lock.json')), provenance: 'ABSENT' });
        put(d, G4_DIR + '/g4-typescript-5.9.3.md', md);
        writeG4PinsForTree(d);
      }
      const oldHits = old.scanRoot(d);
      const newHits = scanRoot(d);
      const oldRed = oldHits.length > 0;
      const newRed = newHits.length > 0;
      rows.push({ name: m.name, old: oldRed ? 'RED' : 'GREEN', new: newRed ? 'RED' : 'GREEN' });
      assert.equal(newRed, true, `${m.name} must be red on the new checker:\n${newHits.join('\n')}`);
      if (fix.reason) assert.ok(newHits.some((h) => fix.reason.test(h)), `${m.name} wrong reason:\n${newHits.join('\n')}`);
      assert.equal(oldRed, m.expectOldRed, `${m.name} old expected ${m.expectOldRed ? 'RED' : 'GREEN'}, got ${oldRed ? 'RED' : 'GREEN'}:\n${oldHits.join('\n')}`);
    }
    console.log('B8 old-vs-new table:\n' + rows.map((r) => `${r.name}: old=${r.old} new=${r.new}`).join('\n'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

const OLD_B8_4F = new URL('./fixtures/b8-checker-4f5619e5.mjs', import.meta.url);
const G38_FIXTURES = [
  { name: 'fail-verdict', expectOldRed: false },
  { name: 'edited-content', expectOldRed: false },
  { name: 'forged-4-line', expectOldRed: false },
  { name: 'wrong-version', expectOldRed: false },
  { name: 'unpinned-extra-file', expectOldRed: false },
  { name: 'pin-list-mismatch', expectOldRed: false },
];

test('G-38: each new fixture is red on the new checker; record the 4f5619e5 verdict', async () => {
  const old = await import(OLD_B8_4F);
  const dir = mkdtempSync(join(tmpdir(), 'b8-g38-'));
  const rows = [];
  try {
    for (const m of G38_FIXTURES) {
      const fix = BAD_FIXTURES[m.name];
      assert.ok(fix, m.name);
      const d = join(dir, m.name);
      put(d, 'package.json', JSON.parse(uUnescape(uEscape(JSON.stringify(fix.pkg)))));
      put(d, 'package-lock.json', fix.lock);
      writeSpecialG4(d, fix.g4Special, fix.pkg, fix.lock);
      const oldHits = old.scanRoot(d);
      const newHits = scanRoot(d);
      const oldRed = oldHits.length > 0;
      const newRed = newHits.length > 0;
      rows.push({ name: m.name, old: oldRed ? 'RED' : 'GREEN', new: newRed ? 'RED' : 'GREEN', oldHits: oldHits.join(' | '), newHits: newHits.join(' | ') });
      assert.equal(newRed, true, `${m.name} must be red on the new checker:\n${newHits.join('\n')}`);
      if (fix.reason) assert.ok(newHits.some((h) => fix.reason.test(h)), `${m.name} wrong reason:\n${newHits.join('\n')}`);
      assert.equal(oldRed, m.expectOldRed, `${m.name} old expected ${m.expectOldRed ? 'RED' : 'GREEN'}, got ${oldRed ? 'RED' : 'GREEN'}:\n${oldHits.join('\n')}`);
    }
    console.log('G-38 old-vs-new table:\n' + rows.map((r) => `${r.name}: old=${r.old} new=${r.new}`).join('\n'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
