// CI rule 27 (quality.md v5.5.7 L596; QR-25 L228; PLAN R-44 L152): real import-allowlist check, escaped scratch fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { scanTree, scanFile, writeFixture, BAD, BAD_PATH, GUARD_OK, selfTest, entropyTriggers, READ_NAME_ALLOW } from '../tools/ci/import-allowlist.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const EXPECT = {
  'namespace-import': 'namespace-import', 'default-import': 'default-import', 'require-crypto': 'require-crypto',
  'dynamic-import': 'dynamic-import', 'process-binding': 'process-binding', 'process-getBuiltinModule': 'process-binding',
  'globalThis-crypto': 'globalThis-crypto', 'globalThis-computed': 'globalThis-computed', 'bare-global-crypto': 'bare-global-crypto',
  'global-crypto': 'global-self', 'self-crypto': 'global-self', 'node-module': 'node-module', 'createRequire': 'createRequire',
  'setFips': 'fips', 'fips-member': 'fips', 'extra-pair': 'extra-pair', 'createHash-outside-evidence': 'extra-pair',
  'audited-import': 'audited-import', 'defineProperty-globalThis': 'defineProperty-globalThis',
  'capability-crypto': 'extra-pair', 'mapping-namespace': 'namespace-import', 'verify-drbg': 'verify-drbg-binding',
  'verify-drbg-relative': 'verify-drbg-binding', 'verify-binding-wrong-path': 'verify-drbg-binding', 'entropy-alias': 'crypto-alias', 'entropy-other-path': 'randomFillSync-other-path', 'randomFillSync-outside-entropy': 'randomFillSync-outside-entropy',
};
const withTmp = (fn) => { const d = mkdtempSync(join(tmpdir(), 'r27-')); try { return fn(d); } finally { rmSync(d, { recursive: true, force: true }); } };
const put = (d, p, s) => { mkdirSync(join(d, p, '..'), { recursive: true }); writeFileSync(join(d, p), s); };

test('rule 27: the compliant fixture (exact pair set, audited -> evidence) is green', () => {
  const d = mkdtempSync(join(tmpdir(), 'r27-')); try { writeFixture(d); assert.deepEqual(scanTree(d).hits, []); } finally { rmSync(d, { recursive: true, force: true }); }
});

for (const [name, src] of Object.entries(BAD)) {
  test(`rule 27 known-bad fixture is red for its own reason: ${name}`, () => {
    const d = mkdtempSync(join(tmpdir(), 'r27-'));
    try {
      const file = BAD_PATH[name] ?? 'src/mapping/bad.ts';
      writeFixture(d, { [file]: src });
      const hits = scanTree(d).hits;
      assert.ok(hits.some((h) => h.startsWith(file) && h.includes(`rule27-${EXPECT[name]} `)), hits.join('\n'));
    } finally { rmSync(d, { recursive: true, force: true }); }
  });
}

test('rule 27: a missing pair is red (no fewer)', () => {
  const d = mkdtempSync(join(tmpdir(), 'r27-'));
  try { writeFixture(d, { 'src/identity/a.ts': 'export const g = 1;\n' }); assert.deepEqual(scanTree(d).hits, ['src/identity/:0: rule27-missing-pair (getFips, identity/) required by L596 is absent']); }
  finally { rmSync(d, { recursive: true, force: true }); }
});

test('rule 27: comments and string contents are not code', () => {
  const src = "// import * as c from 'node:crypto'; crypto.fips\n/* global.crypto self createRequire */\nexport const s = 'crypto global self fips setFips import(x)';\n";
  assert.deepEqual(scanFile('src/mapping/x.ts', src).hits, []);
});

test('rule 27: --self-test passes', () => { assert.deepEqual(selfTest(), []); });

test('Q1 no-fewer: a missing pair whose directory does not exist is report-only, red under --phase-exit', () => withTmp((d) => {
  writeFixture(d); rmSync(join(d, 'src/identity'), { recursive: true });
  const r = scanTree(d); assert.deepEqual(r.hits, []); assert.equal(r.reports.length, 1); assert.match(r.reports[0], /getFips, identity\/\).*report-only/);
  assert.deepEqual(scanTree(d, { phaseExit: true }).hits, ['src/identity/:0: rule27-missing-pair (getFips, identity/) required by L596 is absent']);
}));
test('Q1 no-fewer: an existing directory without its pair blocks', () => withTmp((d) => {
  writeFixture(d, { 'src/evidence/a.ts': 'export const h = 1;\n' });
  assert.deepEqual(scanTree(d).hits, ['src/evidence/:0: rule27-missing-pair (createHash, evidence/) required by L596 is absent']);
}));
test('Q1 no-more blocks even when no required directory exists', () => withTmp((d) => {
  put(d, 'src/mapping/x.ts', "import { randomBytes } from 'node:crypto';\n");
  const r = scanTree(d); assert.equal(r.hits.length, 1); assert.match(r.hits[0], /rule27-extra-pair \(randomBytes, mapping\/\)/); assert.equal(r.reports.length, 3);
}));
test('Q3: coreGuard.ts exact-path defineProperty form is green; wrong forms are red', () => withTmp((d) => {
  writeFixture(d, { 'packages/capability/src/coreGuard.ts': GUARD_OK }); assert.deepEqual(scanTree(d).hits, []);
  for (const bad of [GUARD_OK.replace("'__oreCoreGuard', {", 'KEY, {'), GUARD_OK.replace("throw new Error('GUARD_PRESENT')", 'return'),
    GUARD_OK.replace('writable: false', 'writable: true'), GUARD_OK + "Object.defineProperty(globalThis, 'b', { value: 1, writable: false, configurable: false, enumerable: false });\n",
    GUARD_OK + 'const s = Symbol.for(KEY);\n']) {
    writeFixture(d, { 'packages/capability/src/coreGuard.ts': bad });
    assert.ok(scanTree(d).hits.some((h) => h.includes('rule27-defineProperty-globalThis')), bad);
  }
  rmSync(join(d, 'packages/capability/src/coreGuard.ts')); put(d, 'packages/capability/src/other.ts', GUARD_OK);
  assert.ok(scanTree(d).hits.some((h) => h.startsWith('packages/capability/src/other.ts') && h.includes('outside packages/capability/src/coreGuard.ts')));
}));
test('Q3: only verify/src/testingBinding.ts (PLAN L535) may bind packages/drbg; the scan reaches verify/ and packages/mapping', () => withTmp((d) => {
  writeFixture(d, { 'verify/src/testingBinding.ts': "import { d } from '@open-rng-engine/drbg';\nexport const b = d;\n" });
  assert.deepEqual(scanTree(d).hits, []);
  put(d, 'verify/src/other.ts', "import { d } from '@open-rng-engine/drbg';\n");
  put(d, 'packages/mapping/src/m.ts', "import { createHash } from 'node:crypto';\n");
  const h = scanTree(d).hits;
  assert.ok(h.some((x) => x.startsWith('verify/src/other.ts:1: rule27-verify-drbg-binding')), h.join('\n'));
  assert.ok(h.some((x) => x.startsWith('packages/mapping/src/m.ts:1: rule27-extra-pair')), h.join('\n'));
}));
test('Q2 all-import ban: no false red on current legit code (every scanned file, pair findings aside)', () => {
  const r = scanTree(ROOT);
  assert.deepEqual(r.hits.filter((h) => !h.includes('rule27-missing-pair')), []);
  assert.ok(existsSync(join(ROOT, 'src/verify/replayRandomBytes.ts')) && existsSync(join(ROOT, 'packages/capability/src/index.ts')) && existsSync(join(ROOT, 'packages/mapping/src/index.ts')));
});
const run = (args) => spawnSync(process.execPath, [join(ROOT, 'tools/ci/import-allowlist.mjs'), ROOT, ...args], { encoding: 'utf8' });
test('rule 27 on this repo: 0 findings, exit 0 (check:ph0 green); evidence/ and identity/ placeholders removed', () => {
  const r = run([]); assert.equal(r.status, 0, r.stdout); assert.match(r.stdout, /0 finding\(s\)/);
  assert.match(r.stdout, /\(randomFillSync, entropy\/\).*report-only: src\/entropy\/ has no entropy read path/);
  assert.ok(!existsSync(join(ROOT, 'src/evidence')) && !existsSync(join(ROOT, 'src/identity')));
  assert.match(JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).scripts['check:ph0'], /node tools\/ci\/import-allowlist\.mjs && node tools\/ci\/import-allowlist\.mjs --self-test/);
});
test('(c) --phase-exit on the current tree is red for exactly the three missing pairs', () => {
  const r = run(['--phase-exit']); assert.equal(r.status, 1);
  const lines = r.stdout.trim().split('\n').slice(0, -1);
  assert.deepEqual(lines.map((l) => l.split(' required')[0]), ['src/entropy/:0: rule27-missing-pair (randomFillSync, entropy/)',
    'src/evidence/:0: rule27-missing-pair (createHash, evidence/)', 'src/identity/:0: rule27-missing-pair (getFips, identity/)']);
  assert.match(lines[0], /PH1-M1 trigger: \(iii\) --phase-exit/);
});
test('trigger (ii) does not fire on the current tree (no package main/module/exports, core entries export nothing)', () => {
  assert.deepEqual(entropyTriggers(ROOT), []);
});
test('(d) control: blockPlan.ts alone in src/entropy/ is green (report-only)', () => withTmp((d) => {
  put(d, 'src/entropy/blockPlan.ts', readFileSync(join(ROOT, 'src/entropy/blockPlan.ts'), 'utf8'));
  const r = scanTree(d); assert.deepEqual(r.hits, []); assert.deepEqual(entropyTriggers(d), []);
  assert.ok(r.reports.some((x) => /entropy.*report-only/.test(x)));
}));
for (const [name, src] of [['export function readBytes', 'export function readBytes(n: number) { return n; }\n'],
  ['export const drawEntropy', 'export const drawEntropy = (n: number) => n;\n'], ['aliased export', 'const f = 1;\nexport { f as fillBuffer };\n'],
  ['export *', "export * from './blockPlan.ts';\n"], ['export default', 'export default function (n: number) { return n; }\n'],
  ['buffer fill call', 'const b = new Uint8Array(4);\nb.fill(0);\nexport const k = b;\n'], ['non-numeric BYTES const', 'export const SEED_BYTES = make();\n'],
  ['getRandomValues call', 'export const g = (b: Uint8Array) => getRandomValues(b);\n']]) {
  test(`(b) entropy/ read API without randomFillSync is red under trigger (i): ${name}`, () => withTmp((d) => {
    put(d, 'src/entropy/blockPlan.ts', readFileSync(join(ROOT, 'src/entropy/blockPlan.ts'), 'utf8')); put(d, 'src/entropy/r.ts', src);
    const h = scanTree(d).hits; assert.equal(h.length >= 1, true);
    assert.ok(h.some((x) => /rule27-missing-pair \(randomFillSync, entropy\/\).*PH1-M1 trigger: \(i\)/.test(x)), h.join('\n'));
  }));
}
for (const [name, files, code] of [
  ['alias', { 'src/entropy/r.ts': "import { randomFillSync as rf } from 'node:crypto';\nexport const x = rf;\n" }, 'crypto-alias'],
  ['other path (re-export via mapping)', { 'src/mapping/x.ts': "export { randomFillSync } from 'node:crypto';\n", 'src/entropy/r.ts': "import { randomFillSync } from '../mapping/x.ts';\n" }, 'randomFillSync-other-path'],
  ['bare crypto specifier', { 'src/entropy/r.ts': "import { randomFillSync } from 'crypto';\n" }, 'bare-crypto-specifier'],
  ['namespace', { 'src/entropy/r.ts': "import * as c from 'node:crypto';\nc.randomFillSync(b);\n" }, 'namespace-import']]) {
  test(`(a) entropy/ randomFillSync not as the exact named import stays red: ${name}`, () => withTmp((d) => {
    for (const [p, s2] of Object.entries(files)) put(d, p, s2);
    const h = scanTree(d).hits; assert.ok(h.some((x) => x.includes(`rule27-${code} `)), h.join('\n'));
  }));
}
test('(a) control: the exact named import in entropy/ is green and satisfies no-fewer', () => withTmp((d) => {
  put(d, 'src/entropy/r.ts', "import { randomFillSync } from 'node:crypto';\nexport const x = randomFillSync;\n");
  assert.deepEqual(scanTree(d).hits, []);
}));
test('randomFillSync anywhere outside src/entropy/ is red', () => withTmp((d) => {
  put(d, 'packages/capability/src/c.ts', 'export const r = randomFillSync;\n');
  assert.ok(scanTree(d).hits.some((x) => x.includes('rule27-randomFillSync-outside-entropy')));
}));
for (const [name, files] of [['package exports', { 'package.json': '{"name":"x","exports":{".":"./dist/index.js"}}' }],
  ['entry re-exports randomInt', { 'src/index.ts': "export { randomInt } from './mapping/m.ts';\n", 'src/mapping/m.ts': 'export function randomInt() { return 1; }\n' }],
  ['entry reaches createRng transitively', { 'src/index.ts': "export * from './a/x.ts';\n", 'src/a/x.ts': "export { createRng } from '../b/y.ts';\n", 'src/b/y.ts': 'export const createRng = () => 1;\n' }]]) {
  test(`trigger (ii) fires and blocks entropy no-fewer: ${name}`, () => withTmp((d) => {
    put(d, 'src/entropy/blockPlan.ts', readFileSync(join(ROOT, 'src/entropy/blockPlan.ts'), 'utf8'));
    for (const [p, s2] of Object.entries(files)) put(d, p, s2);
    assert.ok(scanTree(d).hits.some((x) => /entropy\/\).*PH1-M1 trigger: .*\(ii\)/.test(x)), JSON.stringify(scanTree(d)));
  }));
}

// HoQ tighten ruling: trigger (i) carve-out is the exact-name allow-list { FINGERPRINT_BYTES } = `export const ... = 16;`.
const BP = () => readFileSync(join(ROOT, 'src/entropy/blockPlan.ts'), 'utf8');
const trig = (d) => scanTree(d).hits.some((x) => /rule27-missing-pair \(randomFillSync, entropy\/\).*PH1-M1 trigger: \(i\)/.test(x));
test('(e) export const SEED_BYTES = 32 is red (no UPPER_CASE numeric carve-out any more)', () => withTmp((d) => {
  put(d, 'src/entropy/blockPlan.ts', BP()); put(d, 'src/entropy/s.ts', 'export const SEED_BYTES = 32;\n'); assert.ok(trig(d));
}));
for (const v of ['15', '0x10', '1_6', '16n', "'16'", '16.0', '16 + 0', 'SIXTEEN', '(16)', '16, X_BYTES = 1']) {
  test(`(f) FINGERPRINT_BYTES = ${v} is red`, () => withTmp((d) => {
    put(d, 'src/entropy/blockPlan.ts', BP().replace('export const FINGERPRINT_BYTES = 16;', `const SIXTEEN = 16;\nexport const FINGERPRINT_BYTES = ${v};`)); assert.ok(trig(d));
  }));
}
test('(f) FINGERPRINT_BYTES with a type annotation or via a re-export is red', () => withTmp((d) => {
  put(d, 'src/entropy/blockPlan.ts', BP().replace('export const FINGERPRINT_BYTES = 16;', 'export const FINGERPRINT_BYTES: number = 16;')); assert.ok(trig(d));
  put(d, 'src/entropy/blockPlan.ts', BP().replace('export const FINGERPRINT_BYTES = 16;', 'const FINGERPRINT_BYTES = 16;\nexport { FINGERPRINT_BYTES };')); assert.ok(trig(d));
}));
for (const kw of ['let', 'var']) {
  test(`(g) export ${kw} FINGERPRINT_BYTES = 16 is red`, () => withTmp((d) => {
    put(d, 'src/entropy/blockPlan.ts', BP().replace('export const FINGERPRINT_BYTES = 16;', `export ${kw} FINGERPRINT_BYTES = 16;`)); assert.ok(trig(d));
  }));
}
test('control: blockPlan.ts unchanged stays green; allow-list holds exactly FINGERPRINT_BYTES', () => withTmp((d) => {
  put(d, 'src/entropy/blockPlan.ts', BP()); assert.deepEqual(scanTree(d).hits, []); assert.deepEqual(entropyTriggers(d), []);
  assert.deepEqual(Object.entries(READ_NAME_ALLOW), [['FINGERPRINT_BYTES', '16']]);
}));
