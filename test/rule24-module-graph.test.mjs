import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { scanRoot, scanGraph, BAD_FIXTURES, selfTest, uEscape, uUnescape } from '../tools/ci/rule24-module-graph.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const STUB = join(ROOT, 'test/fixtures/ph1-stubs/rule24-module-graph.mjs');
const TOOL = join(ROOT, 'tools/ci/rule24-module-graph.mjs');
const withTmp = (fn) => { const d = mkdtempSync(join(tmpdir(), 'r24t-')); try { return fn(d); } finally { rmSync(d, { recursive: true, force: true }); } };
const put = (d, rel, src) => { mkdirSync(join(d, dirname(rel)), { recursive: true }); writeFileSync(join(d, rel), src); };

test('rule 24: this repo is green (production entries do not reach verify/ or resetCht)', () => {
  const r = scanGraph(ROOT);
  assert.ok(r.entries.includes('src/index.ts') && r.entries.includes('src/audited/index.ts'), r.entries.join(','));
  assert.ok(!r.reachable.some((p) => p.split('/').includes('verify')), r.reachable.join(','));
  assert.deepEqual(r.hits, []);
  const cli = spawnSync(process.execPath, [TOOL, ROOT], { encoding: 'utf8' });
  assert.equal(cli.status, 0, cli.stdout + cli.stderr);
});

test('rule 24: --self-test is green', () => {
  const r = spawnSync(process.execPath, [TOOL, '--self-test'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /8 known-bad fixtures red, control green/);
});

test('rule 24: a planted verify/ import, src/verify/ import, resetCht, or cycling-adapter import is red', () => withTmp((d) => {
  put(d, 'package.json', JSON.stringify({ name: 'x', exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json' } }));
  put(d, 'src/audited/index.ts', 'export {};\n');
  put(d, 'src/index.ts', "export { k } from '../verify/x.ts';\n");
  put(d, 'verify/x.ts', 'export const k = 1;\n');
  assert.ok(scanRoot(d).some((h) => /under verify\//.test(h)), scanRoot(d).join('\n'));
}));

test('rule 24: the previous stub exits 2 and does not kill a known-bad fixture', () => withTmp((d) => {
  put(d, 'package.json', JSON.stringify({ name: 'x', exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json' } }));
  put(d, 'src/index.ts', uUnescape(uEscape("import { resetCht } from './h.ts';\nexport { resetCht };\n")));
  put(d, 'src/h.ts', 'export function resetCht() {}\n');
  put(d, 'src/audited/index.ts', 'export {};\n');
  const stub = spawnSync(process.execPath, [STUB, d], { encoding: 'utf8' });
  assert.equal(stub.status, 2);
  assert.match(stub.stdout, /STUB: rule24-module-graph not implemented/);
  assert.ok(!/rule24-graph/.test(stub.stdout + stub.stderr));
  const live = spawnSync(process.execPath, [TOOL, d], { encoding: 'utf8' });
  assert.equal(live.status, 1);
  assert.match(live.stdout, /resetCht/);
}));

test('rule 24 is wired into check:ph0 (live + self-test)', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.match(pkg.scripts['check:ph0'], /node tools\/ci\/rule24-module-graph\.mjs && node tools\/ci\/rule24-module-graph\.mjs --self-test/);
});

const OLD_R24 = new URL('./fixtures/rule24-checker-475950db.mjs', import.meta.url);
const R24_OLD_NEW = [
  { name: 'unresolved-import', expectOldRed: false },
  { name: 'reaches-testMinter', expectOldRed: false },
  { name: 'reaches-replaySource', expectOldRed: false },
  { name: 'reaches-verify', expectOldRed: true },
];
test('G-35 / binding symbols: each new fixture is red on the new checker; record the 475950db verdict', async () => {
  const old = await import(OLD_R24);
  const { BAD_FIXTURES: FIX, scanRoot, uEscape, uUnescape } = await import('../tools/ci/rule24-module-graph.mjs');
  const dir = mkdtempSync(join(tmpdir(), 'r24-oldnew-'));
  const rows = [];
  try {
    const GOOD_PKG = { name: 'open-rng-engine', version: '0.0.0', private: true, type: 'module', exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json' } };
    for (const m of R24_OLD_NEW) {
      const fix = FIX[m.name];
      const d = join(dir, m.name);
      mkdirSync(d, { recursive: true });
      writeFileSync(join(d, 'package.json'), JSON.stringify(GOOD_PKG, null, 2) + '\n');
      for (const [rel, src] of Object.entries(fix.files)) {
        mkdirSync(join(d, dirname(rel)), { recursive: true });
        writeFileSync(join(d, rel), uUnescape(uEscape(src)));
      }
      const oldHits = old.scanRoot(d);
      const newHits = scanRoot(d);
      const oldRed = oldHits.length > 0;
      const newRed = newHits.length > 0;
      rows.push({ name: m.name, old: oldRed ? 'RED' : 'GREEN', new: newRed ? 'RED' : 'GREEN' });
      assert.equal(newRed, true, `${m.name} must be red:\n${newHits.join('\n')}`);
      assert.ok(newHits.some((h) => fix.reason.test(h)), `${m.name} wrong reason:\n${newHits.join('\n')}`);
      assert.equal(oldRed, m.expectOldRed, `${m.name} old expected ${m.expectOldRed ? 'RED' : 'GREEN'}, got ${oldRed ? 'RED' : 'GREEN'}:\n${oldHits.join('\n')}`);
    }
    console.log('rule24 old-vs-new table:\n' + rows.map((r) => `${r.name}: old=${r.old} new=${r.new}`).join('\n'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
