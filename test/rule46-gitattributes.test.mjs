// CI rule 46 (LICENSE exact-sha integrity; CPO-R101 LF-7) and the LF-only .gitattributes (CPO-R100 F-15). node --test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';
import { rule46 } from '../tools/ci/rule46-license-integrity.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const CLI = join(ROOT, 'tools/ci/rule46-license-integrity.mjs');
const dir = mkdtempSync(join(tmpdir(), 'rule46-test-'));
test.after(() => { rmSync(dir, { recursive: true, force: true }); assert.equal(existsSync(dir), false); });
const LIC = readFileSync(join(ROOT, 'LICENSE'));

test('rule 46: the tracked LICENSE matches the pinned sha', () => {
  assert.equal(rule46(LIC).ok, true);
  assert.equal(spawnSync(process.execPath, [CLI]).status, 0);
});
test('rule 46: one changed byte, an appended line, CRLF line endings or a missing file fail', () => {
  for (const b of [Buffer.from(LIC.toString().replace('Apache', 'apache')), Buffer.concat([LIC, Buffer.from('\n')]), Buffer.from(LIC.toString().replace(/\n/g, '\r\n')), null])
    assert.equal(rule46(b).ok, false);
});
test('rule 46 CLI: an altered scratch copy exits 1; an exact scratch copy exits 0', () => {
  const f = join(dir, 'LICENSE');
  writeFileSync(f, `${LIC}x`);
  const r = spawnSync(process.execPath, [CLI, '--file', f], { encoding: 'utf8' });
  assert.equal(r.status, 1, r.stdout); assert.match(r.stdout, /FAIL/);
  writeFileSync(f, LIC);
  assert.equal(spawnSync(process.execPath, [CLI, '--file', f]).status, 0);
  assert.equal(spawnSync(process.execPath, [CLI, '--file', join(dir, 'missing')]).status, 1);
});
test('F-15: .gitattributes forces LF for all text', () => {
  assert.equal(readFileSync(join(ROOT, '.gitattributes'), 'utf8'), '* text=auto eol=lf\n');
  const out = execFileSync('git', ['check-attr', 'text', 'eol', '--', 'README.md', 'tools/claims-lint.mjs', 'LICENSE'], { cwd: ROOT, encoding: 'utf8' });
  assert.match(out, /README\.md: eol: lf/); assert.match(out, /LICENSE: eol: lf/);
});
test('F-15: no tracked file has CR line endings in the index or the worktree', () => {
  const rows = execFileSync('git', ['ls-files', '--eol'], { cwd: ROOT, encoding: 'utf8' }).trim().split('\n');
  const bad = rows.filter((r) => /\b[iw]\/(crlf|mixed)\b/.test(r));
  assert.deepEqual(bad, []);
});
