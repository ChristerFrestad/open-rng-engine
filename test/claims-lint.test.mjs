// C-10 (CPO-R97) near-miss tests for tools/claims-lint.mjs. node --test, zero dependencies.
// Every case text comes from \u-escaped source in tools/claims-lint.mjs, is written to a scratch dir,
// linted from disk, and the scratch dir is removed afterwards (same discipline as the known-bad fixture).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';
import { ALLOW, RULES, lintText, nearMissCases, verifyAllowPins, KNOWN_BAD_README } from '../tools/claims-lint.mjs';

const LINT = new URL('../tools/claims-lint.mjs', import.meta.url).pathname;
const dir = mkdtempSync(join(tmpdir(), 'claims-lint-test-'));
test.after(() => { rmSync(dir, { recursive: true, force: true }); assert.equal(existsSync(dir), false); });

const lintScratch = (name, text) => {
  const f = join(dir, `${name.replace(/[^A-Za-z0-9]+/g, '_').slice(0, 80)}.md`);
  writeFileSync(f, text);
  return lintText(name, readFileSync(f, 'utf8'));
};

test('allow-list sha256 pins match the CPO-R97 pins', () => {
  assert.deepEqual(verifyAllowPins(), []);
  assert.equal(ALLOW.length, 6);
});

test('a changed allow-list string fails its pin', () => {
  const saved = ALLOW[1][1];
  try { ALLOW[1][1] = saved + ' '; assert.deepEqual(verifyAllowPins(), ['S-P1-short']); }
  finally { ALLOW[1][1] = saved; }
  assert.deepEqual(verifyAllowPins(), []);
});

test('align and FIPS rules are present and not exemptable by design', () => {
  const ids = RULES.map(([id]) => id);
  for (const id of ['R16-align', 'R16-fips', 'C10-drbg-reserved']) assert.ok(ids.includes(id), id);
});

for (const [i, t] of nearMissCases().entries()) {
  test(`near-miss ${String(i).padStart(3, '0')} ${t.id} -> ${t.expect}`, () => {
    const hits = lintScratch(`case-${i}-${t.id}`, t.text);
    if (t.expect === 'clean') assert.equal(hits.length, 0, hits.join('\n'));
    else assert.ok(hits.length > 0, `expected a hit for: ${t.id}`);
  });
}

test('known-bad fixture stays red via --expect-red on a scratch file', () => {
  const f = join(dir, 'README.known-bad.md');
  writeFileSync(f, KNOWN_BAD_README);
  const r = spawnSync(process.execPath, [LINT, '--expect-red', f], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

test('--self-test exits 0 (known-bad red + all near-miss cases pass)', () => {
  const out = execFileSync(process.execPath, [LINT, '--self-test'], { encoding: 'utf8' });
  assert.match(out, /near-miss (\d+)\/\1 PASS; scratch removed: true/);
});

test('repo scope lints clean', () => {
  const r = spawnSync(process.execPath, [LINT], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});
