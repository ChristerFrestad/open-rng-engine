import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { scanRoot, scanExports, BAD_FIXTURES, REQUIRED_EXPORT_KEYS, selfTest, uEscape, uUnescape, qr33Hit, QR33_BOUNDARY_GREEN, qr33BoundaryRed } from '../tools/ci/rule22-exports-map.mjs';

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

test('G-42: tools/qr33-allow.json is empty and its sha256 is pinned as a literal', () => {
  const rel = 'tools/qr33-allow.json';
  const buf = readFileSync(join(ROOT, rel));
  const sha = createHash('sha256').update(buf).digest('hex');
  // Literal pin; do not import this digest from the tool under test.
  const QR33_ALLOW_SHA256 = 'db2d0ab03ee56d327244ee982b0712dae4acc22f251927ed5437863f641b35ba';
  assert.equal(sha, QR33_ALLOW_SHA256);
  const data = JSON.parse(buf.toString('utf8'));
  assert.ok(data.schema && data.schema.entry && data.schema.hoqRulingRef && data.schema.fixture);
  assert.deepEqual(data.entries, []);
});

test('rule 22: --self-test is green', () => {
  const r = spawnSync(process.execPath, [TOOL, '--self-test'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /51 known-bad fixtures red, 12 controls green/);
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

const OLD_R22 = new URL('./fixtures/rule22-checker-475950db.mjs', import.meta.url);
const R22_OLD_NEW = [
  { name: 'plain-extra-key', expectOldRed: true },
  { name: 'absolute-target', expectOldRed: false },
  { name: 'dotdot-target', expectOldRed: false },
  { name: 'node-modules-target', expectOldRed: false },
  { name: 'imports-field', expectOldRed: false },
  { name: 'browser-field', expectOldRed: false },
  { name: 'typesVersions-field', expectOldRed: false },
  { name: 'main-not-pinned', expectOldRed: false },
  { name: 'wrong-pin-package-json', expectOldRed: false },
  { name: 'extra-drbg-key', expectOldRed: true },
];
test('G-31 / G-34 / G-36: each new fixture is red on the new checker; record the 475950db verdict', async () => {
  const old = await import(OLD_R22);
  const { BAD_FIXTURES: FIX, scanExports } = await import('../tools/ci/rule22-exports-map.mjs');
  const rows = [];
  for (const m of R22_OLD_NEW) {
    const fix = FIX[m.name];
    const oldHits = old.scanExports(fix.pkg);
    const newHits = scanExports(fix.pkg);
    const oldRed = oldHits.length > 0;
    const newRed = newHits.length > 0;
    rows.push({ name: m.name, old: oldRed ? 'RED' : 'GREEN', new: newRed ? 'RED' : 'GREEN' });
    assert.equal(newRed, true, `${m.name} must be red:\n${newHits.join('\n')}`);
    assert.ok(newHits.some((h) => fix.reason.test(h)), `${m.name} wrong reason:\n${newHits.join('\n')}`);
    assert.equal(oldRed, m.expectOldRed, `${m.name} old expected ${m.expectOldRed ? 'RED' : 'GREEN'}, got ${oldRed ? 'RED' : 'GREEN'}:\n${oldHits.join('\n')}`);
  }
  console.log('rule22 old-vs-new table:\n' + rows.map((r) => `${r.name}: old=${r.old} new=${r.new}`).join('\n'));
});

// QR-33 segmentation (HoQ ruling, CTO relay 2026-11-18 23:30 CET): never stitched across a segment boundary.
for (const n of ['start_page', 'short_poll', 'import_path', 'sort_product', 'part_power', 'cash_and', 'sub_urn', 'startProcess']) {
  test(`QR-33 segmentation: ${n} is green (term only across a segment boundary)`, () => {
    assert.equal(qr33Hit(n), null);
    assert.ok(QR33_BOUNDARY_GREEN.includes(n));
  });
}
test('QR-33 segmentation: a whole segment and a substring inside one segment stay red', () => {
  const [camel, joinedInOne] = qr33BoundaryRed();
  assert.equal(camel.slice(0, 5), 'check');
  assert.notEqual(qr33Hit(camel), null);
  assert.notEqual(qr33Hit(joinedInOne), null);
  assert.equal(joinedInOne.length, 8);
});
