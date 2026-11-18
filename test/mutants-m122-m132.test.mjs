// quality v5.5.6 (5b6d1d0c) M-122 and M-126..M-132 kill tests (CPO-R103 item 2). node --test, zero dependencies.
// Plants are \u-escaped and materialised only in memory or in scratch dirs that are removed afterwards.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync, symlinkSync, unlinkSync, copyFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';
import { ALLOW, lintTree, lintFile, selfExempt, loadAllowlist, loadTerms, loadLabNames, loadAuthorities, nonCanonicalPath,
  ALLOWLIST_PATH, TERMS_PATH, LAB_NAMES_PATH, AUTHORITY_PATH, P8_README_PATH } from '../tools/claims-lint.mjs';
import { scanTree, LIST_PATH, CONFIG_PATH, FIXTURE_PATH } from '../tools/ci/rule40-protected-names.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const dir = mkdtempSync(join(tmpdir(), 'm122-m132-'));
test.after(() => { rmSync(dir, { recursive: true, force: true }); assert.equal(existsSync(dir), false); });
const read = (p) => readFileSync(join(ROOT, p));
const tracked = () => new Map(execFileSync('git', ['ls-files', '-z'], { cwd: ROOT }).toString().split('\0').filter(Boolean)
  .filter((p) => existsSync(join(ROOT, p))).map((p) => [p, read(p)]));
const withFiles = (o) => { const m = tracked(); for (const [k, v] of Object.entries(o)) m.set(k, Buffer.isBuffer(v) ? v : Buffer.from(v)); return m; };
const g = (id) => ALLOW.find(([x]) => x === id)[1];
const PLANT = '\u0076alidated by an independent lab';
const red = (hits, prefix) => hits.some((h) => h.startsWith(prefix));

// ---------- M-122: exact-path exemptions vs path variants, symlinks, traversal, known-bad at the exempt path ----------
const VARIANTS = (p) => [`./${p}`, `${p}/`, p.toUpperCase(), p.replace('tools/', 'tools/../tools/'), p.replace('tools/', 'tools//'), p.replace('tools/', 'tools/./'), `/${p}`, `docs/${p.split('/').pop()}`, `${p}.bak`, `tools/x/${p.split('/').pop()}`];
for (const [p, load] of [[ALLOWLIST_PATH, loadAllowlist], [TERMS_PATH, loadTerms], [LAB_NAMES_PATH, loadLabNames], [AUTHORITY_PATH, loadAuthorities]]) {
  test(`M-122: ${p}: every path variant fails to load and is never self-exempt; exact path + sha is`, () => {
    const b = read(p);
    assert.equal(selfExempt(p, b), true);
    for (const v of VARIANTS(p)) { assert.ok(load(b, v).errors.length > 0, v); assert.equal(selfExempt(v, b), false, v); }
  });
  test(`M-122: ${p}: sha mismatch (one byte, a known-bad string appended) fails closed and is not self-exempt`, () => {
    const b = read(p);
    for (const alt of [Buffer.concat([b, Buffer.from(' ')]), Buffer.concat([b, Buffer.from(`\n${PLANT}\n`)])]) {
      assert.ok(load(alt).errors.length > 0); assert.equal(selfExempt(p, alt), false);
    }
  });
}
test('M-122: the known-bad string is red wherever it is placed (exempt path with altered bytes, variants, surfaces)', () => {
  const kb = Buffer.concat([read(ALLOWLIST_PATH), Buffer.from(`\n${PLANT}\n`)]);
  for (const p of [ALLOWLIST_PATH, ...VARIANTS(ALLOWLIST_PATH)]) assert.ok(lintFile(p, kb).length > 0, p);
  for (const p of ['README.md', 'docs/a.md', 'NOTICE']) assert.ok(red(lintTree(withFiles({ [p]: `${PLANT}\n` })).hits, `${p}:`), p);
});
test('M-122: non-canonical scanned paths are red in the tree scan', () => {
  for (const p of ['./README.md', 'docs/../README.md', 'docs//a.md', 'docs/./a.md', '/etc/x', 'docs/a.md/', 'docs\\a.md']) {
    assert.equal(nonCanonicalPath(p), true, p);
    assert.ok(lintTree(withFiles({ [p]: '# ok\n' })).hits.some((h) => h.includes('M122-path')), p);
  }
  for (const p of ['README.md', 'docs/a.md', 'tools/claims-allowlist.json']) assert.equal(nonCanonicalPath(p), false, p);
});
test('M-122: rule40 list exemption does not follow path variants (list text is scanned there)', () => {
  const base = tracked();
  const list = base.get(LIST_PATH);
  for (const v of VARIANTS(LIST_PATH)) {
    const m = new Map(base); m.set(v, list);
    const r = scanTree(m);
    assert.ok(r.hits.length > 0 || r.configErrors.length > 0, v);
  }
});
test('M-122: symlinks in a scratch clone: at an exempt path, pointing at a config, or escaping the repo, all red (claims lint + rule40)', () => {
  const c = join(dir, 'clone');
  execFileSync('git', ['clone', '-q', '--no-hardlinks', ROOT, c]);
  // working tree as committed in HEAD; overlay current tracked bytes so the scratch clone matches this tree
  for (const [p, b] of tracked()) { mkdirSync(join(c, p, '..'), { recursive: true }); writeFileSync(join(c, p), b); }
  execFileSync('git', ['add', '-A'], { cwd: c });
  const lint = () => spawnSync(process.execPath, [join(c, 'tools/claims-lint.mjs')], { cwd: c, encoding: 'utf8' });
  const r40 = () => spawnSync(process.execPath, [join(c, 'tools/ci/rule40-protected-names.mjs')], { cwd: c, encoding: 'utf8' });
  { const r0 = lint(); assert.equal(r0.status, 0, r0.stdout + r0.stderr); }
  // (a) exempt config replaced by a symlink to an identical copy elsewhere
  copyFileSync(join(c, ALLOWLIST_PATH), join(c, 'copy.json')); unlinkSync(join(c, ALLOWLIST_PATH)); symlinkSync('../copy.json', join(c, ALLOWLIST_PATH));
  execFileSync('git', ['add', '-A'], { cwd: c });
  let r = lint(); assert.notEqual(r.status, 0); assert.match(r.stdout, /M122-symlink/);
  execFileSync('git', ['checkout', '-q', 'HEAD', '--', '.'], { cwd: c }); execFileSync('git', ['rm', '-q', '--cached', 'copy.json'], { cwd: c }); unlinkSync(join(c, 'copy.json'));
  for (const [p, b] of tracked()) writeFileSync(join(c, p), b);
  // (b) a docs/ symlink to the config, and (c) one escaping the repo
  symlinkSync('../tools/claims-allowlist.json', join(c, 'docs-allow.json'));
  mkdirSync(join(c, 'docs'), { recursive: true }); symlinkSync('../../../../etc/hostname', join(c, 'docs/escape.md'));
  execFileSync('git', ['add', '-A'], { cwd: c });
  r = lint(); assert.notEqual(r.status, 0); assert.match(r.stdout, /docs-allow\.json:0: M122-symlink/); assert.match(r.stdout, /docs\/escape\.md:0: M122-symlink/);
  // (d) rule40: the list path as a symlink is a config error (index blob is the link text, not the approved list)
  unlinkSync(join(c, 'docs-allow.json')); unlinkSync(join(c, 'docs/escape.md'));
  copyFileSync(join(c, LIST_PATH), join(c, 'list-copy.txt')); unlinkSync(join(c, LIST_PATH)); symlinkSync('../list-copy.txt', join(c, LIST_PATH));
  execFileSync('git', ['add', '-A'], { cwd: c });
  r = r40(); assert.notEqual(r.status, 0, r.stdout);
  // (e) LICENSE as a symlink to an identical copy: claims lint red (symlink + guard sees link text in the index-based rule46)
  execFileSync('git', ['checkout', '-q', 'HEAD', '--', '.'], { cwd: c });
  for (const [p, b] of tracked()) writeFileSync(join(c, p), b); // checkout restored HEAD bytes; re-overlay this tree's tools
  copyFileSync(join(c, 'LICENSE'), join(c, 'lic-copy')); unlinkSync(join(c, 'LICENSE')); symlinkSync('lic-copy', join(c, 'LICENSE'));
  execFileSync('git', ['add', '-A'], { cwd: c });
  assert.match(lint().stdout, /LICENSE:0: M122-symlink/);
  assert.notEqual(spawnSync(process.execPath, [join(c, 'tools/ci/rule46-license-integrity.mjs')], { cwd: c }).status, 0);
});

// ---------- M-126: surface coverage ----------
test('M-126: the plant is red on every claims surface', () => {
  const pkg = JSON.parse(read('package.json'));
  const rp = read('REMOTE-PENDING.md').toString();
  const cases = {
    'README.md': `${read('README.md')}\n${PLANT}\n`, [P8_README_PATH]: `${read(P8_README_PATH)}\n${PLANT}\n`, 'docs/guide.md': `${PLANT}\n`,
    'docs/examples/wheel-37/a.ts': `// ${g('S-R39')}\n// ${PLANT}\nexport {};\n`, 'ARCHITECTURE.md': `${PLANT}\n`, 'SECURITY.md': `${read('SECURITY.md')}\n${PLANT}\n`,
    NOTICE: `${read('NOTICE')}\n${PLANT}\n`, 'CHANGELOG.md': `## 0.0.1\n- ${PLANT}\n`, 'CONTRIBUTING.md': `${PLANT}\n`, 'release-notes/v0.0.1.md': `${PLANT}\n`,
    'packages/drbg/package.json': JSON.stringify({ ...JSON.parse(read('packages/drbg/package.json')), description: PLANT }),
  };
  for (const [p, t] of Object.entries(cases)) assert.ok(red(lintTree(withFiles({ [p]: t })).hits, `${p}`), p);
  for (const [k, v] of [['description', PLANT], ['keywords', [...pkg.keywords, PLANT]], ['homepage', PLANT], ['author', PLANT], ['author', { name: PLANT }]])
    assert.ok(red(lintTree(withFiles({ 'package.json': JSON.stringify({ ...pkg, [k]: v }) })).hits, 'package.json#'), k);
  assert.ok(red(lintTree(withFiles({ 'REMOTE-PENDING.md': rp.replace(/^description: .*$/m, `description: ${PLANT}`) })).hits, 'REMOTE-PENDING.md#repo-description'));
  assert.ok(red(lintTree(withFiles({ 'REMOTE-PENDING.md': rp.replace(/^topics: (.*)$/m, `topics: $1, ${PLANT}`) })).hits, 'REMOTE-PENDING.md#repo-topics'));
});
test('M-126 controls: src/ comment and test/ title are green for the claims lint (src/ string: see F-21 note)', () => {
  assert.deepEqual(lintTree(withFiles({ 'src/rng.ts': `// ${PLANT}\nexport const a = 1;\n` })).hits, []);
  assert.deepEqual(lintTree(withFiles({ 'test/rng.test.mjs': `test('${PLANT}', () => {});\n` })).hits, []);
  // F-21 (CPO-R101) + accepted stricter choice (a) (CPO-R103): a string literal in shipped source IS linted, so this v5.5.6 control is red by ruling.
  assert.ok(lintTree(withFiles({ 'src/rng.ts': `export const a = '${PLANT}';\n` })).hits.length > 0);
});

// ---------- M-127: term-list governance ----------
test('M-127: terms list changes fail closed (sha, fourth entry, case, trailing space, regex/prefix form, non-exact path)', () => {
  const j = JSON.parse(read(TERMS_PATH));
  const mk = (f) => { const c = structuredClone(j); f(c); return Buffer.from(`${JSON.stringify(c, null, 2)}\n`); };
  for (const b of [mk((c) => c.validatAllowedPhrases.push('\u0076alidated input')), mk((c) => { c.validatAllowedPhrases[0] = 'Schema-\u0076alidated'; }),
    mk((c) => { c.validatAllowedPhrases[1] += ' '; }), mk((c) => { c.validatAllowedPhrases[2] = 'schema \u0076alidat.*'; }), mk((c) => { c.validatAllowedPhrases[2] = 'schema'; }),
    Buffer.concat([read(TERMS_PATH), Buffer.from(' ')])]) assert.ok(loadTerms(b).errors.length > 0);
  assert.ok(loadTerms(read(TERMS_PATH), 'docs/claims-terms.json').errors.length > 0);
  assert.deepEqual(loadTerms(read(TERMS_PATH)).errors, []);
});

// ---------- M-128: single-field P1 surfaces ----------
const SP1 = () => g('S-P1');
const P1_PLANTS = () => [`${SP1()} Fast and zero-dependency.`, `Fast. ${SP1()}`, `${SP1()} `, SP1().slice(0, -1), g('S-P1-short'), '', SP1().replace('TypeScript', 'Typescript'), SP1().replace("licensee's", 'licensee\u2019s')];
test('M-128: package.json description: exact S-P1 green, every plant red', () => {
  const pkg = JSON.parse(read('package.json'));
  assert.deepEqual(lintTree(withFiles({ 'package.json': JSON.stringify({ ...pkg, description: SP1() }, null, 2) })).hits, []);
  for (const d of P1_PLANTS()) assert.ok(lintTree(withFiles({ 'package.json': JSON.stringify({ ...pkg, description: d }, null, 2) })).hits.some((h) => h.includes('package.json description:0: O67')), JSON.stringify(d));
});
test('M-128: repo description: exact S-P1 green, every plant red; descriptive topics are a control', () => {
  const rp = read('REMOTE-PENDING.md').toString();
  for (const d of P1_PLANTS()) {
    const hits = lintTree(withFiles({ 'REMOTE-PENDING.md': rp.replace(/^description: .*$/m, `description: ${d}`) })).hits;
    assert.ok(hits.some((h) => h.startsWith('repo description (REMOTE-PENDING scope block):0: O67') || h.startsWith('REMOTE-PENDING.md#scope:0')), JSON.stringify(d));
  }
  assert.deepEqual(lintTree(withFiles({ 'REMOTE-PENDING.md': rp.replace(/^topics: (.*)$/m, 'topics: $1, fast, zero-dependency') })).hits, []);
});

// ---------- M-129: published P8 artefacts (scratch copies; the live fetch is recorded in the CTO report) ----------
test('M-129: --surface p8 / p8-package on scratch copies of a published reserved README and package.json', () => {
  const LINT = join(ROOT, 'tools/claims-lint.mjs');
  const run = (kind, text) => { const f = join(dir, `p8-${kind}-${Math.random().toString(16).slice(2)}`); writeFileSync(f, text); return spawnSync(process.execPath, [LINT, '--surface', kind, f], { encoding: 'utf8' }).status; };
  assert.equal(run('p8', '# open-rng-engine\n\nThis package name is reserved.\n'), 1);
  assert.equal(run('p8', `# x\n\n${SP1().replace("system ", "system\n")}\n`), 1);
  assert.equal(run('p8', `# x\n\n${SP1().replace('TypeScript', 'Typescript')}\n`), 1);
  assert.equal(run('p8', `# x\n\n${SP1()}\n`), 0);
  assert.equal(run('p8-package', JSON.stringify({ name: 'open-rng-engine', description: 'Name reserved. Pre-alpha.' })), 1);
  assert.equal(run('p8-package', JSON.stringify({ name: 'open-rng-engine', description: SP1(), keywords: [PLANT] })), 1);
  assert.equal(run('p8-package', JSON.stringify({ name: 'open-rng-engine', description: SP1() })), 0);
});

// ---------- M-130: line endings ----------
test('M-130: .gitattributes missing or without an LF rule is red; CRLF on a claims surface is red', () => {
  const m = tracked(); m.delete('.gitattributes');
  assert.ok(lintTree(m).hits.some((h) => h.includes('M130-eol: missing')));
  for (const t of ['* text=auto\n', '*.md text\n', '# * text=auto eol=lf\n', '* text=auto eol=crlf\n'])
    assert.ok(lintTree(withFiles({ '.gitattributes': t })).hits.some((h) => h.includes('M130-eol')), t);
  for (const t of ['* text=auto eol=lf\n', '* text eol=lf\n']) assert.deepEqual(lintTree(withFiles({ '.gitattributes': t })).hits, [], t);
  assert.ok(lintTree(withFiles({ 'README.md': read('README.md').toString().replace(/\n/g, '\r\n') })).hits.some((h) => h.includes('M130-crlf')));
  assert.ok(lintTree(withFiles({ 'docs/a.md': `- ${g('S-P1-short')}\r\n` })).hits.length > 0);
});
test('M-130 / CI 8: no test file is skipped, todo, or .only (a skipped test is a FAIL)', () => {
  const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', 'test/*.test.mjs'], { cwd: ROOT, encoding: 'utf8' }).trim().split('\n');
  assert.ok(files.length >= 8);
  const bad = new RegExp(['test\\.(skip|todo|only)\\(', '\\{\\s*(skip|todo|only)\\s*:', 'describe\\.(skip|only)\\(', '\\bt\\.skip\\('].join('|'));
  for (const f of files) assert.doesNotMatch(readFileSync(join(ROOT, f), 'utf8').replace(/const bad = new RegExp\([^\n]*\n/, ''), bad, f);
});

// ---------- M-131: CA-1 statement tied to its tests ----------
test('M-131: PH0-DOD carries the CA-1 statement (does NOT scan LICENSE) and names tests that exist and are not skipped', () => {
  const dod = read('PH0-DOD.md').toString();
  assert.match(dod, /CA-1 statement[^\n]*the claims lint does \*\*NOT\*\* scan `LICENSE`/);
  assert.match(dod, /cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30/);
  const cl = read('test/claims-lint.test.mjs').toString();
  for (const name of [...dod.matchAll(/"(CA-1:[^"]+)"/g)].map((x) => x[1])) assert.ok(cl.includes(`test('${name}'`), name);
  assert.ok(existsSync(join(ROOT, 'tools/ci/rule46-license-integrity.mjs')) && existsSync(join(ROOT, 'test/rule46-gitattributes.test.mjs')));
});

// ---------- M-132: X-13 (rule 40) and S-R39 not narrowed by the claims scope ----------
test('M-132: a protected name in src/ (comment, identifier, string), a test/ title, CHANGELOG, a non-root package.json name and a .d.ts is red for rule 40', () => {
  const N = '\u0072\u006f\u0075\u006c\u0065\u0074\u0074\u0065';
  const plants = {
    'src/a.ts': `// ${N} wheel\nexport const x = 1;\n`, 'src/b.ts': `export const ${N}Wheel = 1;\n`, 'src/c.ts': `export const s = '${N}';\n`,
    'test/a.test.mjs': `test('${N} works', () => {});\n`, 'CHANGELOG.md': `- add ${N}\n`, 'packages/x/package.json': JSON.stringify({ name: `@open-rng-engine/${N}` }),
    'types/index.d.ts': `export declare const ${N}: 1;\n`,
  };
  for (const [p, t] of Object.entries(plants)) {
    const m = tracked(); m.set(p, Buffer.from(t));
    const r = scanTree(m);
    assert.ok(r.hits.some((h) => JSON.stringify(h).includes(p)), `${p}: ${JSON.stringify(r.hits).slice(0, 200)}`);
  }
});
test('M-132: an example file under docs/examples/ without the S-R39 header is red (CI 36)', () => {
  assert.ok(lintTree(withFiles({ 'docs/examples/wheel-37/a.ts': 'export const a = 1;\n' })).hits.some((h) => h.includes('CI36-r39-header')));
});
