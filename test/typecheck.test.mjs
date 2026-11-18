// Strict tsc gate (CPO-R103 item 1): pinned devDependency, lockfile integrity, dependencies {}, tsc --noEmit clean,
// strict flags really active, node_modules never scanned. node --test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync, execFileSync } from 'node:child_process';
import { lintTree } from '../tools/claims-lint.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const TSC = join(ROOT, 'node_modules/typescript/bin/tsc');
const TS_INTEGRITY = 'sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdiaUpFT4bXlb1RHhLpp8wtm6M5TgSw==';
const dir = mkdtempSync(join(tmpdir(), 'typecheck-test-'));
test.after(() => { rmSync(dir, { recursive: true, force: true }); assert.equal(existsSync(dir), false); });

test('package.json: dependencies {} and devDependencies exactly typescript 5.9.3 (exact pin)', () => {
  const p = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.deepEqual(p.dependencies, {});
  assert.deepEqual(p.devDependencies, { typescript: '5.9.3' });
  assert.match(p.scripts['check:ph0'], /^npm run -s typecheck && /);
});
test('package-lock.json: only typescript, from the public registry, with the pinned integrity', () => {
  const l = JSON.parse(readFileSync(join(ROOT, 'package-lock.json'), 'utf8'));
  assert.deepEqual(Object.keys(l.packages), ['', 'node_modules/typescript']);
  assert.equal(l.packages[''].dependencies, undefined);
  const t = l.packages['node_modules/typescript'];
  assert.equal(t.version, '5.9.3'); assert.equal(t.dev, true);
  assert.equal(t.resolved, 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz');
  assert.equal(t.integrity, TS_INTEGRITY);
});
test('tsc --noEmit with the strict tsconfig exits 0', () => {
  const r = spawnSync(process.execPath, [TSC, '--noEmit', '-p', join(ROOT, 'tsconfig.json')], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});
test('strict flags are active: a scratch noUncheckedIndexedAccess / implicit-any error fails tsc', () => {
  const cfg = JSON.parse(execFileSync(process.execPath, [TSC, '--showConfig', '-p', join(ROOT, 'tsconfig.json')], { encoding: 'utf8' })).compilerOptions;
  for (const k of ['strict', 'noUncheckedIndexedAccess', 'exactOptionalPropertyTypes', 'noPropertyAccessFromIndexSignature']) assert.equal(cfg[k], true, k);
  const f = join(dir, 'bad.ts');
  writeFileSync(f, 'export function f(x) { const a: number[] = []; const b: number = a[0]; return b + x; }\n');
  const r = spawnSync(process.execPath, [TSC, '--noEmit', '--strict', '--noUncheckedIndexedAccess', f], { encoding: 'utf8' });
  assert.notEqual(r.status, 0); assert.match(r.stdout, /TS7006/); assert.match(r.stdout, /TS2322/);
});
test('node_modules is gitignored and never scanned as a claims surface, package.json or shipped source', () => {
  assert.match(readFileSync(join(ROOT, '.gitignore'), 'utf8'), /^node_modules\/$/m);
  assert.equal(spawnSync('git', ['check-ignore', '-q', 'node_modules/typescript/package.json'], { cwd: ROOT }).status, 0);
  assert.equal(execFileSync('git', ['ls-files', 'node_modules'], { cwd: ROOT, encoding: 'utf8' }), '');
  const plant = 'This library is \u0063ertified.';
  const files = new Map([...['README.md', 'package.json', 'LICENSE', 'REMOTE-PENDING.md', 'npm-reserved/README.md', '.gitattributes'].map((p) => [p, readFileSync(join(ROOT, p))]),
    ['node_modules/x/README.md', Buffer.from(plant)], ['node_modules/x/package.json', Buffer.from(JSON.stringify({ description: plant }))],
    ['node_modules/x/index.d.ts', Buffer.from(`/** ${plant} */`)], ['packages/a/node_modules/y/package.json', Buffer.from(JSON.stringify({ description: plant }))]]);
  const hits = lintTree(files).hits;
  // CPO-R104 G-10: a tracked node_modules/ path is itself red; its content is never linted as a surface or shipped source.
  assert.equal(hits.length, 4, hits.join('\n'));
  assert.ok(hits.every((h) => h.includes('G10-node-modules')), hits.join('\n'));
});
test('G-10: check:ph0 fails on a tracked node_modules/ path (scratch clone)', () => {
  const c = join(dir, 'clone');
  execFileSync('git', ['clone', '-q', '--no-hardlinks', ROOT, c]);
  for (const p of execFileSync('git', ['ls-files', '-z'], { cwd: ROOT }).toString().split('\0').filter(Boolean)) if (existsSync(join(ROOT, p))) writeFileSync(join(c, p), readFileSync(join(ROOT, p)));
  execFileSync('git', ['add', '-A'], { cwd: c });
  const lint = () => spawnSync(process.execPath, [join(c, 'tools/claims-lint.mjs')], { cwd: c, encoding: 'utf8' });
  assert.equal(lint().status, 0, lint().stdout);
  execFileSync('mkdir', ['-p', join(c, 'node_modules/x')]); writeFileSync(join(c, 'node_modules/x/index.js'), 'module.exports = 1;\n');
  execFileSync('git', ['add', '-f', 'node_modules/x/index.js'], { cwd: c });
  const r = lint(); assert.equal(r.status, 1); assert.match(r.stdout, /node_modules\/x\/index\.js:0: G10-node-modules/);
  assert.match(JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).scripts['check:ph0'], /node tools\/claims-lint\.mjs &&/);
});
