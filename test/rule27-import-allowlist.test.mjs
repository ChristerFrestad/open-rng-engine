// CI rule 27 (quality.md v5.5.7 L596; QR-25 L228; PLAN R-44 L152): real import-allowlist check, escaped scratch fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { scanTree, scanFile, writeFixture, BAD, BAD_PATH, BAD_EXTRA, GUARD_OK, selfTest, strip, entropyTriggers, READ_NAME_ALLOW, BAD_REASON, SELF_TEST_EXTRA_CASES, GLOBALTHIS_MEMBERS_ALLOWED, PROCESS_MEMBERS_ALLOWED, COMPUTED_LITERAL_KEYS_ALLOWED, REFLECTIVE_BASES } from '../tools/ci/import-allowlist.mjs';

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
      writeFixture(d, { [file]: src, ...(BAD_EXTRA[name] ?? {}) });
      const hits = scanTree(d).hits;
      if (BAD_REASON[name]) assert.ok(hits.some((h) => BAD_REASON[name].test(h)), hits.join('\n'));
      else assert.ok(hits.some((h) => h.startsWith(file) && h.includes(`rule27-${EXPECT[name]} `)), hits.join('\n'));
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

test('HoQ: --self-test carries 137 known-bad fixtures (allow-list, G-12/13/15/16, G-17..G-25, G-26/G-27, M-158..161) plus 4 extra cases', () => {
  assert.equal(Object.keys(BAD).length, 137);
  for (const n of ['gt-self-crypto', 'gt-window-crypto', 'gt-globalThis-crypto', 'gt-Function', 'gt-eval', 'gt-Reflect-get', 'gt-process-getBuiltinModule', 'gt-process-binding', 'process-alias', 'process-destructure', 'process-linkedBinding', 'process-dlopen', 'process-mainModule', 'process-plain-member', 'module-require', 'mainModule-require', 'require-alias', 'require-destructure', 'require-member-call', 'window-alias', 'constructor-call', 'guard-forms-non-guard-path', 'unicode-ident-globalThis', 'unicode-key-constructor', 'import-node-vm-default', 'import-node-vm-named', 'import-node-inspector', 'import-node-worker_threads', 'import-node-child_process', 'dynamic-import-node-vm', 'export-from-node-vm', 'require-node-vm', 'import-bare-fs', 'constructor-element', 'reflect-construct', 'object-getPrototypeOf', 'reflect-getPrototypeOf', 'proto-member', 'm158-concat-reflect-constructor', 'm158-template-key', 'm158-concat-crypto', 'extensionless-relative', 'parse-error', 'import-type-non-relative', 'm161-literal-typed-var', 'm161-string-typed', 'm161-concatenation-defineProperty', 'm161-fromCharCode-__proto__', 'm161-array-join-getPrototypeOf']) assert.ok(BAD_REASON[n] instanceof RegExp && typeof BAD[n] === 'string', n);
  assert.deepEqual(SELF_TEST_EXTRA_CASES, ['allowlist-control', 'guard-control', 'MX-12 p8-package key plant', 'MX-12 clean control']);
  for (const n of ['allowlist-FINGERPRINT_BYTES-multi', 'globalThis-destructure', 'globalThis-alias', 'globalThis-Reflect-get', 'globalThis-getOwnPropertyDescriptor', 'Function-return-this', 'require-node-module', 'require-module', 'fips-identifier', 'fips-computed']) assert.ok(BAD_REASON[n] instanceof RegExp && typeof BAD[n] === 'string', n);
  const five = { 'allowlist-SEED_BYTES': 'export const SEED_BYTES = 32;\n', 'allowlist-FINGERPRINT_BYTES-15': 'export const FINGERPRINT_BYTES = 15;\n',
    'allowlist-FINGERPRINT_BYTES-string': "export const FINGERPRINT_BYTES = '16';\n", 'allowlist-FINGERPRINT_BYTES-let': 'export let FINGERPRINT_BYTES = 16;\n',
    'allowlist-FINGERPRINT_BYTES-reexport': 'const FINGERPRINT_BYTES = 16;\nexport { FINGERPRINT_BYTES };\n' };
  for (const [n, src] of Object.entries(five)) { assert.equal(BAD[n], src, n); assert.equal(BAD_PATH[n], 'src/entropy/a.ts'); assert.ok(BAD_REASON[n] instanceof RegExp, n); }
  const r = spawnSync(process.execPath, [join(ROOT, 'tools/ci/import-allowlist.mjs'), '--self-test'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout); assert.match(r.stdout, /137 known-bad fixtures red, good fixture green, 4 extra cases ok/);
});

// G-12 (HoQ 2de685b2): fail-closed reach to the global object.
for (const [name, src, code] of [['window alias', 'const w = window;\nw.crypto;\n', 'global-self'], ['new Function', "new Function('return this')();\n", 'function-eval'],
  ['eval', "eval('this');\n", 'function-eval'], ['constructor call', "(() => 1).constructor('return this')();\n", 'function-eval'],
  ['globalThis as call argument', 'f(globalThis);\n', 'globalThis-alias'], ['self alias', 'const s2 = self;\n', 'global-self'],
  ['hasOwn(globalThis) outside the guard', "Object.hasOwn(globalThis, 'k');\n", 'globalThis-alias']]) {
  test(`G-12: ${name} is red`, () => assert.ok(scanFile('src/mapping/x.ts', src).hits.some((h) => h.includes(`rule27-${code} `)), name));
}
test('G-17: globalThis.<member> outside the (empty) allow-list is red; the coreGuard.ts exact-path forms stay green', () => {
  assert.deepEqual(GLOBALTHIS_MEMBERS_ALLOWED, []); assert.deepEqual(PROCESS_MEMBERS_ALLOWED, []);
  assert.ok(scanFile('src/mapping/x.ts', 'export const t = globalThis.queueMicrotask;\n').hits.some((h) => h.includes('rule27-globalThis-member ')));
  assert.deepEqual(scanFile('packages/capability/src/coreGuard.ts', GUARD_OK).hits, []);
});

test('G-17/G-18 allow-lists equal what real core source uses: no globalThis/process/module/require token in any scanned file', () => {
  const r = scanTree(ROOT); assert.deepEqual(r.hits, []);
  const roots = ['src', 'packages/capability/src', 'packages/mapping'];
  const files = execFileSync('git', ['ls-files', ...roots], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter((f) => /\.(ts|mts|cts|js|mjs|cjs)$/.test(f));
  assert.ok(files.length >= 10);
  for (const f of files) { const code = strip(readFileSync(join(ROOT, f), 'utf8'))[1]; assert.doesNotMatch(code, /\b(globalThis|process|require)\b/, f); }
});

test('G-25: M-152c fixture is hasOwn(globalThis, k) at a non-guard path, not the exact guard forms', () => {
  assert.equal(BAD['guard-forms-non-guard-path'], "Object.hasOwn(globalThis, 'k');\n");
  assert.equal(BAD_PATH['guard-forms-non-guard-path'], 'packages/capability/src/other.ts');
  assert.match(String(BAD_REASON['guard-forms-non-guard-path']), /globalThis-alias/);
  assert.ok(!BAD['guard-forms-non-guard-path'].includes('defineProperty'));
});

test('G-23: unicode escapes in comments or non-key strings are not red; identifiers and string-literal keys are', () => {
  assert.deepEqual(scanFile('src/mapping/x.ts', "const s = 'glob\\u0061lThis'; // glob\\u0061lThis\n").hits, []);
  assert.ok(scanFile('src/mapping/x.ts', 'glob\\u0061lThis.crypto;\n').hits.some((h) => h.includes('rule27-unicode-escape ')));
  assert.ok(scanFile('src/mapping/x.ts', "x['\\u0063onstructor'];\n").hits.some((h) => h.includes('rule27-unicode-escape ')));
});

test('G-21/22: constructor member access, Reflect.construct, getPrototypeOf and __proto__ are red', () => {
  for (const [src, code] of [["x['constructor'];\n", 'constructor-reach'], ['Reflect.construct(X, []);\n', 'reflect-construct'],
    ['Object.getPrototypeOf(x);\n', 'getPrototypeOf'], ['Reflect.getPrototypeOf(x);\n', 'getPrototypeOf'],
    ['x.__proto__;\n', 'proto-member'], ['const { constructor: c } = x;\n', 'constructor-reach']]) {
    assert.ok(scanFile('src/mapping/x.ts', src).hits.some((h) => h.includes(`rule27-${code} `)), src);
  }
});

// HoQ 06cb884b mutants: each is red on the new checker. Run the same source against the OLD
// regex checker at 06cb884b (file-identical at 43671116) and record whether it survived there.
const OLD_RULE27_SHA = '06cb884b43222793cb271647bc182347bbe8fe1c';
const MUTANTS = [
  { id: 'M-155', name: 'unicode-ident-globalThis', expectOldRed: false },
  { id: 'M-155', name: 'unicode-key-constructor', expectOldRed: false },
  { id: 'M-156', name: 'import-node-vm-default', expectOldRed: true, oldWhy: 'default-import' },
  { id: 'M-156', name: 'import-node-vm-named', expectOldRed: false },
  { id: 'M-156', name: 'import-node-inspector', expectOldRed: false },
  { id: 'M-156', name: 'import-node-worker_threads', expectOldRed: false },
  { id: 'M-156', name: 'import-node-child_process', expectOldRed: false },
  { id: 'M-156', name: 'dynamic-import-node-vm', expectOldRed: true, oldWhy: 'dynamic-import' },
  { id: 'M-156', name: 'export-from-node-vm', expectOldRed: false },
  { id: 'M-156', name: 'require-node-vm', expectOldRed: false },
  { id: 'M-156', name: 'import-bare-fs', expectOldRed: false },
  { id: 'M-157', name: 'constructor-element', expectOldRed: false },
  { id: 'M-157', name: 'reflect-construct', expectOldRed: false },
  { id: 'M-157', name: 'object-getPrototypeOf', expectOldRed: false },
  { id: 'M-157', name: 'reflect-getPrototypeOf', expectOldRed: false },
  { id: 'M-157', name: 'proto-member', expectOldRed: false },
];
test('HoQ 06cb884b mutants: new checker kills each; old-checker verdict recorded', async () => {
  const { pathToFileURL } = await import('node:url');
  const dir = mkdtempSync(join(tmpdir(), 'r27-old-'));
  try {
    const old = await import(new URL('./fixtures/rule27-old-checker.mjs', import.meta.url));
    const rows = [];
    for (const m of MUTANTS) {
      const file = BAD_PATH[m.name] ?? 'src/mapping/bad.ts';
      const d = join(dir, m.name); writeFixture(d, { [file]: BAD[m.name], ...(BAD_EXTRA[m.name] ?? {}) });
      const oldHits = old.scanTree(d).hits;
      const newHits = scanTree(d).hits;
      const oldRed = oldHits.length > 0;
      const newRed = newHits.length > 0;
      rows.push({ id: m.id, name: m.name, old: oldRed ? 'RED' : 'GREEN', new: newRed ? 'RED' : 'GREEN', oldHits: oldHits.join(' | '), newHits: newHits.join(' | ') });
      assert.equal(newRed, true, `${m.id} ${m.name} must be red on the new checker:\n${newHits.join('\n')}`);
      if (BAD_REASON[m.name]) assert.ok(newHits.some((h) => BAD_REASON[m.name].test(h)), `${m.id} ${m.name} wrong new reason:\n${newHits.join('\n')}`);
      assert.equal(oldRed, m.expectOldRed, `${m.id} ${m.name} old-checker expected ${m.expectOldRed ? 'RED' : 'GREEN'} (survives-old proof), got ${oldRed ? 'RED' : 'GREEN'}:\n${oldHits.join('\n')}`);
    }
    const meaningful = rows.filter((r) => r.old === 'GREEN');
    assert.ok(meaningful.length >= 12, `need surviving-old mutants as proof; got ${JSON.stringify(rows, null, 2)}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('NIT: object-literal keys such as { binding: 1 } are green', () => {
  assert.deepEqual(scanFile('src/mapping/x.ts', 'const o = { binding: 1 };\n').hits, []);
});

test('G-26: source-literal and number-typed keys are green; non-literal and string-typed keys are red', () => {
  assert.equal(scanFile('src/mapping/x.ts', "const o: Record<string, unknown> = {};\no['kind'];\n").hits.filter((h) => /computed-access/.test(h)).length, 0);
  assert.equal(scanFile('src/mapping/x.ts', 'const i: number = 0;\nconst a: string[] = [];\na[i];\n').hits.filter((h) => /computed-access/.test(h)).length, 0);
  assert.ok(scanFile('src/mapping/x.ts', "const s: string = 'x';\no[s];\n").hits.some((h) => /computed-access/.test(h)));
  assert.ok(scanFile('src/mapping/x.ts', "const k = 'foo' as const;\no[k];\n").hits.some((h) => /computed-access/.test(h)));
});

test('G-26: production computed-literal allow-list is empty; test injection greens only listed literals', () => {
  assert.deepEqual([...COMPUTED_LITERAL_KEYS_ALLOWED], []);
  const src = "const k = 'm161-ok' as const;\no[k];\n";
  withTmp((d) => {
    writeFixture(d, { 'src/mapping/x.ts': src });
    assert.ok(scanTree(d).hits.some((h) => /computed-access/.test(h)));
    assert.equal(scanTree(d, { computedLiteralAllow: ['m161-ok'] }).hits.filter((h) => /computed-access/.test(h)).length, 0);
  });
});

test('G-27: relative specifier must have an explicit allowed extension and resolve to a parsed file', () => {
  withTmp((d) => {
    writeFixture(d, { 'src/health/a.ts': "// @ts-ignore\nimport { k } from './ev';\n", 'src/health/ev': 'export const k = 1;\n' });
    const hits = scanTree(d).hits;
    assert.ok(hits.some((h) => /rule27-relative-specifier /.test(h)), hits.join('\n'));
  });
});

test('M-160: a parse error is red; treating parse errors as green is killed', () => {
  const hits = scanFile('src/mapping/bad.ts', 'const x: = ;\n').hits;
  assert.ok(hits.some((h) => /rule27-parse /.test(h)), hits.join('\n'));
});

test('NIT: import type is red unless the specifier is a relative core path', () => {
  assert.ok(scanFile('src/mapping/x.ts', "import type { X } from 'fs';\n").hits.some((h) => /specifier-not-allowed/.test(h)));
  assert.equal(scanFile('src/health/a.ts', "import type { k } from './cht.ts';\n").hits.filter((h) => /specifier-not-allowed|relative-specifier/.test(h)).length, 0);
});

const PREV_RULE27_SHA = '41d5ca7a55d97b0ee3e5a3b1a54eb50e50618e0c';
const NEW_MUTANTS = [
  { id: 'M-158', name: 'm158-concat-reflect-constructor' },
  { id: 'M-158', name: 'm158-reflect-get-constructor-literal' },
  { id: 'M-158', name: 'm158-template-key' },
  { id: 'M-158', name: 'm158-concat-crypto' },
  { id: 'M-159', name: 'extensionless-relative' },
  { id: 'M-160', name: 'parse-error' },
  { id: 'M-161', name: 'm161-literal-typed-var' },
  { id: 'M-161', name: 'm161-string-typed' },
  { id: 'M-161', name: 'm161-concatenation-Reflect' },
  { id: 'M-161', name: 'm161-concatenation-getOwnPropertyDescriptor' },
  { id: 'M-161', name: 'm161-concatenation-defineProperty' },
  { id: 'M-161', name: 'm161-concatenation-getPrototypeOf' },
  { id: 'M-161', name: 'm161-concatenation-constructor' },
  { id: 'M-161', name: 'm161-concatenation-__proto__' },
  { id: 'M-161', name: 'm161-template-sub-Reflect' },
  { id: 'M-161', name: 'm161-variable-defineProperty' },
  { id: 'M-161', name: 'm161-function-return-constructor' },
  { id: 'M-161', name: 'm161-fromCharCode-__proto__' },
  { id: 'M-161', name: 'm161-atob-getOwnPropertyDescriptor' },
  { id: 'M-161', name: 'm161-buffer-toString-defineProperty' },
  { id: 'M-161', name: 'm161-array-join-getPrototypeOf' },
];

test('HoQ 41d5ca7a mutants: new checker kills each; mid-checker (41d5ca7a) verdict recorded', async () => {
  const mid = await import(new URL('./fixtures/rule27-checker-41d5ca7a.mjs', import.meta.url));
  const old06 = await import(new URL('./fixtures/rule27-old-checker.mjs', import.meta.url));
  const dir = mkdtempSync(join(tmpdir(), 'r27-mid-'));
  const rows = [];
  try {
    for (const m of NEW_MUTANTS) {
      assert.ok(BAD[m.name], `missing BAD fixture ${m.name}`);
      const file = BAD_PATH[m.name] ?? 'src/mapping/bad.ts';
      const d = join(dir, m.name); writeFixture(d, { [file]: BAD[m.name], ...(BAD_EXTRA[m.name] ?? {}) });
      const newHits = scanTree(d).hits;
      const midHits = mid.scanTree(d).hits;
      const oldHits = old06.scanTree(d).hits;
      const row = { id: m.id, name: m.name, mid41: midHits.length ? 'RED' : 'GREEN', old06: oldHits.length ? 'RED' : 'GREEN', neu: newHits.length ? 'RED' : 'GREEN' };
      rows.push({ ...row, newHits: newHits.join(' | '), midHits: midHits.join(' | ') });
      assert.equal(row.neu, 'RED', `${m.id} ${m.name} must be red on the new checker:\n${newHits.join('\n')}`);
      if (BAD_REASON[m.name]) assert.ok(newHits.some((h) => BAD_REASON[m.name].test(h)), `${m.id} ${m.name} wrong reason:\n${newHits.join('\n')}`);
    }
    // Record the table on stdout for the commit report (assert at least the parse-error mid verdict is a boolean we observed).
    console.log('RULE27_MID_VERDICTS', JSON.stringify(rows.map((r) => ({ id: r.id, name: r.name, mid41: r.mid41, old06: r.old06, new: r.neu })), null, 2));
    assert.ok(rows.every((r) => r.neu === 'RED'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('M-162 package.json test script installs the entropy backstop via --import', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.match(pkg.scripts.test, /--import\s+\.\/tools\/ci\/entropy-backstop\.mjs/);
});
