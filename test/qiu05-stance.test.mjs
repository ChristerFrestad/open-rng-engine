// QIU-05 market-stance pin (DECISIONS P2 as amended 2026-11-19): only the current sentence passes. node --test, zero deps.
// Terms are \u-escaped so this file itself stays clean under the QIU-05 scan.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync, execFileSync } from 'node:child_process';

const ROOT = new URL('..', import.meta.url).pathname;
const NEW = 'This project is not intended for, aimed at, or marketed to any market where the integrator lacks a licence.';
const OLD = 'This project is not intended for, aimed at, or marketed to \u004eorway, or any market where the integrator lacks a licence.';

test('ALLOWED.sentence is exactly the amended P2 sentence', () => {
  const src = readFileSync(join(ROOT, 'tools/qiu05-check.mjs'), 'utf8');
  const m = src.match(/sentence: '([^']*)'/);
  assert.ok(m); assert.equal(m[1], NEW);
});
test('the README on this tree carries the amended sentence', () => assert.ok(readFileSync(join(ROOT, 'README.md'), 'utf8').includes(NEW)));

test('QIU-05 in a scratch clone: new sentence green; old sentence and missing sentence red', () => {
  const dir = mkdtempSync(join(tmpdir(), 'qiu05-stance-'));
  try {
    const r = join(dir, 'r');
    execFileSync('git', ['clone', '-q', '--no-hardlinks', ROOT, r]);
    const run = () => spawnSync(process.execPath, ['tools/qiu05-check.mjs'], { cwd: r, encoding: 'utf8' });
    const readme = readFileSync(join(r, 'README.md'), 'utf8');
    assert.ok(readme.includes(NEW));
    const ok = run(); assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    writeFileSync(join(r, 'README.md'), readme.split(NEW).join(OLD));
    const old = run(); assert.equal(old.status, 1); assert.match(old.stdout, /F1-tie/); assert.match(old.stdout, /present in README: false/);
    writeFileSync(join(r, 'README.md'), readme.split(NEW).join(''));
    const miss = run(); assert.equal(miss.status, 1); assert.match(miss.stdout, /present in README: false/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
  assert.equal(existsSync(dir), false);
});
