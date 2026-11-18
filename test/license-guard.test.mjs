// LICENSE exact-path + sha256 guard (tools/license-guard.mjs) and its use in the QIU-05 check. node --test, zero deps.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, writeFileSync, cpSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync, execFileSync } from 'node:child_process';
import { licenseGuard, LICENSE_SHA256 } from '../tools/license-guard.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const LIC = readFileSync(join(ROOT, 'LICENSE'));

test('unmodified LICENSE at the exact path is exempt', () => {
  const g = licenseGuard('LICENSE', LIC);
  assert.equal(g.exempt, true); assert.equal(g.red, false); assert.equal(g.sha256, LICENSE_SHA256);
});
for (const [name, buf] of [['one byte appended', Buffer.concat([LIC, Buffer.from('x')])], ['one byte changed', Buffer.from(LIC.toString().replace('Apache', 'Apachf'))], ['truncated', LIC.subarray(0, 100)], ['empty', Buffer.alloc(0)]]) {
  test(`altered LICENSE (${name}) is red, never exempt`, () => { const g = licenseGuard('LICENSE', buf); assert.equal(g.exempt, false); assert.equal(g.red, true); });
}
test('missing LICENSE is red', () => assert.equal(licenseGuard('LICENSE', null).red, true));
for (const p of ['LICENSE.txt', 'license', './LICENSE', 'docs/LICENSE', 'LICENSE ']) {
  test(`same bytes at another path (${JSON.stringify(p)}) are not exempt`, () => assert.equal(licenseGuard(p, LIC).exempt, false));
}
test('QIU-05 end to end in a scratch clone: altered LICENSE turns the check red; pristine stays green', () => {
  const dir = mkdtempSync(join(tmpdir(), 'license-guard-'));
  try {
    execFileSync('git', ['clone', '-q', '--no-hardlinks', ROOT, join(dir, 'r')]);
    const r = join(dir, 'r');
    for (const f of ['tools/qiu05-check.mjs', 'tools/license-guard.mjs']) cpSync(join(ROOT, f), join(r, f));
    const ok = spawnSync(process.execPath, ['tools/qiu05-check.mjs'], { cwd: r, encoding: 'utf8' });
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    writeFileSync(join(r, 'LICENSE'), Buffer.concat([LIC, Buffer.from('\nextra\n')]));
    const bad = spawnSync(process.execPath, ['tools/qiu05-check.mjs'], { cwd: r, encoding: 'utf8' });
    assert.equal(bad.status, 1); assert.match(bad.stdout, /LICENSE altered/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
  assert.equal(existsSync(dir), false);
});
