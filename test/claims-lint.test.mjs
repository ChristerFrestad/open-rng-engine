// Claims-lint tests (C-10 / CPO-R97..R102; quality v5.5.6). node --test, zero dependencies.
// Every case text comes from \u-escaped source, is written to a scratch dir, linted from disk, and the scratch dir is
// removed afterwards. Tree-level tests build an in-memory copy of the tracked tree and change one file at a time.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  ALLOW, RULES, CONFIG_ERRORS, lintText, lintFile, lintTree, lintCode, nearMissCases, KNOWN_BAD_README, loadAllowlist, loadTerms,
  loadLabNames, loadAuthorities, selfExempt, knownBadAllowlistConfig, knownBadTermsConfig, jsonStrings, isClaimsSurface,
  ALLOWLIST_PATH, TERMS_PATH, LAB_NAMES_PATH, AUTHORITY_PATH, LAB_NAMES, AUTHORITIES, LAB_NAMES_COUNT, AUTHORITY_COUNT, P8_README_PATH,
} from '../tools/claims-lint.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const LINT = join(ROOT, 'tools/claims-lint.mjs');
const dir = mkdtempSync(join(tmpdir(), 'claims-lint-test-'));
test.after(() => { rmSync(dir, { recursive: true, force: true }); assert.equal(existsSync(dir), false); });

const lintScratch = (name, text) => {
  const f = join(dir, `${name.replace(/[^A-Za-z0-9]+/g, '_').slice(0, 80)}.md`);
  writeFileSync(f, text);
  return lintText(name, readFileSync(f, 'utf8'));
};
const tracked = () => new Map(execFileSync('git', ['ls-files', '-z'], { cwd: ROOT }).toString().split('\0').filter(Boolean)
  .filter((p) => existsSync(join(ROOT, p))).map((p) => [p, readFileSync(join(ROOT, p))]));
const withFile = (p, text) => { const m = tracked(); m.set(p, Buffer.from(text)); return m; };
const read = (p) => readFileSync(join(ROOT, p));
const g = (id) => ALLOW.find(([x]) => x === id)[1];
const PLANT = 'This library is \u0063ertified.';
const VPLANT = 'a \u0076alidated module';

// ---------- configs (LF-2, F-16, F-24, LF-10) ----------
test('configs load clean; exactly six CPO-pinned allowlist strings', () => {
  assert.deepEqual(CONFIG_ERRORS, []);
  assert.equal(ALLOW.length, 6);
  assert.deepEqual(ALLOW.map(([id]) => id), ['S-P1', 'S-P1-short', 'S-R39', 'S-FIPS-1.0', 'S-FIPS-1.0-typographic', 'S-PACK']);
});
test('LF-2: allowlist config changed by one byte fails closed', () => {
  const b = read(ALLOWLIST_PATH);
  const alt = Buffer.from(b.toString().replace('Not certified', 'Not  certified'));
  assert.ok(loadAllowlist(alt).errors.length > 0);
  assert.ok(loadAllowlist(Buffer.concat([b, Buffer.from(' ')])).errors.length > 0);
});
test('LF-2: allowlist config at any other path is not honoured and not self-exempt', () => {
  const b = read(ALLOWLIST_PATH);
  for (const p of ['./tools/claims-allowlist.json', 'tools/claims-allowlist.json.bak', 'Tools/claims-allowlist.json', 'docs/claims-allowlist.json', 'tools/x/claims-allowlist.json']) {
    assert.ok(loadAllowlist(b, p).errors.length > 0, p);
    assert.equal(selfExempt(p, b), false, p);
    assert.ok(lintFile(p, b).length > 0, p); // its literal strings are linted as content
  }
  assert.equal(selfExempt(ALLOWLIST_PATH, b), true);
  assert.deepEqual(lintFile(ALLOWLIST_PATH, b), []);
});
test('LF-2: known-bad allowlist config (extra unreviewed string) fails closed and lints red at the exact path', () => {
  const kb = knownBadAllowlistConfig(read(ALLOWLIST_PATH));
  const f = join(dir, 'allow.kb.json'); writeFileSync(f, kb);
  assert.ok(loadAllowlist(readFileSync(f)).errors.length > 0);
  assert.equal(selfExempt(ALLOWLIST_PATH, readFileSync(f)), false);
  assert.ok(lintFile(ALLOWLIST_PATH, readFileSync(f)).length > 0);
});
test('F-16: terms config is closed (exact three phrases, sha pin); a widened phrase set fails', () => {
  const b = read(TERMS_PATH);
  assert.deepEqual(loadTerms(b).errors, []);
  assert.ok(loadTerms(knownBadTermsConfig(b)).errors.length > 0);
  assert.ok(loadTerms(b, 'tools/claims-terms.json.bak').errors.length > 0);
});
for (const [name, path, load, count, list] of [['F-24 lab-name list', LAB_NAMES_PATH, loadLabNames, LAB_NAMES_COUNT, LAB_NAMES], ['LF-10 authority list', AUTHORITY_PATH, loadAuthorities, AUTHORITY_COUNT, AUTHORITIES]]) {
  test(`${name}: pinned path + sha + count; every entry has a source line`, () => {
    const b = read(path);
    assert.deepEqual(load(b).errors, []);
    assert.equal(list.length, count);
    for (const l of b.toString().split('\n').filter((x) => x && !x.startsWith('#'))) assert.match(l, /^[^|]+\|[^|]+:\d+$/);
  });
  test(`${name}: an added entry, a malformed line, a duplicate or another path fails closed`, () => {
    const b = read(path).toString();
    assert.ok(load(Buffer.from(`${b}Example Lab|PLAN.md:1\n`)).errors.length > 0);
    assert.ok(load(Buffer.from(`${b}no source here\n`)).errors.length > 0);
    assert.ok(load(Buffer.from(b.replace(/\n([^#\n][^\n]*)\n/, '\n$1\n$1\n'))).errors.length > 0);
    assert.ok(load(Buffer.from(b), `${path}.bak`).errors.length > 0);
  });
}
test('F-24 / F-26: required lab entries are present; SIQ is a lab (CPO-R102)', () => {
  for (const n of ['GLI', 'Gaming Laboratories International', 'BMM', 'BMM Testlabs', 'eCOGRA', 'Trisigma', 'NMi', 'Quinel', 'iTech Labs', 'Gaming Associates',
    'SIQ', 'RiskCherry', 'Global Lab Ltd', 'Nick Farley & Associates', 'Eclipse', 'ITL', 'ITL-21', 'itechlabs', 'NMi Metrology & Gaming', 'BMM Spain', 'BMM Australia', 'GA Europe', 'Quinel Ltd'])
    assert.ok(LAB_NAMES.includes(n), n);
  assert.equal(AUTHORITIES.includes('SIQ'), false);
});
test('LF-10: required authority entries are present', () => {
  for (const n of ['NIST', 'UKGC', 'MGA', 'RTS', 'lab', 'labs', 'AGCO', 'NJ DGE', 'IAGR', 'ISO/IEC', 'Lottstift', 'Spelinspektionen', 'KSA']) assert.ok(AUTHORITIES.includes(n), n);
});
test('rule ids: align, FIPS, drbg-reserved, validat, crypto-module and CMVP are present', () => {
  const ids = RULES.map(([id]) => id);
  for (const id of ['R16-align', 'R16-fips', 'C10-drbg-reserved', 'C10-validat', 'C10-crypto-module', 'C10-cmvp']) assert.ok(ids.includes(id), id);
});

// ---------- line-level cases (M-89..M-99, M-111..M-114, M-119, M-120, LF-8, F-23, F-24, LF-10, F-27) ----------
for (const [i, t] of nearMissCases().entries()) {
  test(`near-miss ${String(i).padStart(3, '0')} ${t.id} -> ${t.expect}`, () => {
    const hits = lintScratch(`case-${i}-${t.id}`, t.text);
    if (t.expect === 'clean') assert.equal(hits.length, 0, hits.join('\n'));
    else assert.ok(hits.length > 0, `expected a hit for: ${t.id}`);
  });
}

// ---------- LICENSE (CPO-R100 CA-1, G-PH0 exit condition) ----------
test('CA-1: unmodified LICENSE at the exact path is not scanned', () => {
  const { hits, report } = lintTree(tracked());
  assert.equal(hits.filter((h) => h.startsWith('LICENSE')).length, 0);
  assert.equal(report.license, 'LICENSE unmodified (exact path + sha)');
});
test('CA-1: changed LICENSE bytes are red and the changed text is linted as content', () => {
  const lic = read('LICENSE').toString();
  const { hits } = lintTree(withFile('LICENSE', `${lic}\n${PLANT}\n`));
  assert.ok(hits.some((h) => h.includes('LF3-license-altered')), hits.join('\n'));
  assert.ok(hits.some((h) => /^LICENSE:\d+: R16-certif/.test(h)), hits.join('\n'));
  const one = lintTree(withFile('LICENSE', lic.replace('Apache', 'Apach3'))).hits;
  assert.ok(one.some((h) => h.includes('LF3-license-altered')));
});
test('CA-1: a missing LICENSE is red; a LICENSE-like sibling is linted, never exempt', () => {
  const m = tracked(); m.delete('LICENSE');
  assert.ok(lintTree(m).hits.some((h) => h.includes('LF3-license-altered')));
  const s = lintTree(withFile('LICENSE.txt', `${read('LICENSE')}\n${PLANT}\n`)).hits;
  assert.ok(s.some((h) => h.startsWith('LICENSE.txt:')), s.join('\n'));
});

// ---------- S-P1 presence (O-67, F-17; M-115, M-116) ----------
const readme = () => read('README.md').toString();
test('O-67: repo README, package.json description and repo description carry S-P1 (tree clean)', () => {
  const { hits, report } = lintTree(tracked());
  assert.deepEqual(hits, []);
  for (const r of report.p1) assert.ok(r.ok === true, `${r.surface}: ${r.detail}`);
});
test('M-115: S-P1 split over two lines in the README lead is red', () => {
  const s = g('S-P1');
  const split = readme().replace(s, s.replace("licensee's system ", "licensee's system\n"));
  assert.ok(lintTree(withFile('README.md', split)).hits.some((h) => h.includes('O67-p1-presence')));
});
test('O-67: S-P1 only after the first ## heading is red; removed is red', () => {
  const s = g('S-P1');
  const moved = `${readme().replace(`${s}\n\n`, '')}\n## Later\n\n${s}\n`;
  assert.ok(lintTree(withFile('README.md', moved)).hits.some((h) => h.includes('O67-p1-presence')));
  assert.ok(lintTree(withFile('README.md', readme().replace(`${s}\n\n`, ''))).hits.some((h) => h.includes('O67-p1-presence')));
});
test('M-116: package.json description must equal S-P1 exactly (prefix, suffix, whitespace all red)', () => {
  const pkg = JSON.parse(read('package.json'));
  for (const d of [`${g('S-P1')} Pre-alpha.`, `Pre-alpha. ${g('S-P1')}`, `${g('S-P1')} `, g('S-P1').replace('. ', '.  ')]) {
    const hits = lintTree(withFile('package.json', JSON.stringify({ ...pkg, description: d }, null, 2))).hits;
    assert.ok(hits.some((h) => h.includes('package.json description:0: O67-p1-presence')), d);
  }
});
test('F-17: repo description in the REMOTE-PENDING scope block must equal S-P1 exactly', () => {
  const rp = read('REMOTE-PENDING.md').toString();
  const hits = lintTree(withFile('REMOTE-PENDING.md', rp.replace(`description: ${g('S-P1')}`, `description: ${g('S-P1')} Pre-alpha.`))).hits;
  assert.ok(hits.some((h) => h.includes('repo description (REMOTE-PENDING scope block):0: O67-p1-presence')), hits.join('\n'));
});
test('F-22: the local P8 reserved npm README is tracked and carries S-P1; without it the tree is red', () => {
  const m = tracked();
  assert.ok(m.has(P8_README_PATH));
  const p8 = m.get(P8_README_PATH).toString();
  const hits = lintTree(withFile(P8_README_PATH, p8.replace(`${g('S-P1')}\n`, ''))).hits;
  assert.ok(hits.some((h) => h.includes('O67-p1-presence')), hits.join('\n'));
});
test('F-22 / F-25: --surface lints an external artefact (scratch) read-only', () => {
  const f = join(dir, 'published-readme.md');
  writeFileSync(f, '# open-rng-engine\n\nThis package name is reserved. There is no code yet.\n');
  let r = spawnSync(process.execPath, [LINT, '--surface', 'p8', f], { encoding: 'utf8' });
  assert.equal(r.status, 1); assert.match(r.stdout, /O67-p1-presence/);
  writeFileSync(f, `# x\n\n${g('S-P1')}\n`);
  assert.equal(spawnSync(process.execPath, [LINT, '--surface', 'p8', f]).status, 0);
  writeFileSync(f, `${g('S-P1')}\n`);
  assert.equal(spawnSync(process.execPath, [LINT, '--surface', 'repo-description', f]).status, 0);
  writeFileSync(f, 'General-purpose Node.js library. Pre-alpha.\n');
  r = spawnSync(process.execPath, [LINT, '--surface', 'repo-description', f], { encoding: 'utf8' });
  assert.equal(r.status, 1); assert.match(r.stdout, /does not equal S-P1 exactly/);
});

// ---------- S-R39 header (O-70, LF-4; M-93, M-118) ----------
const R39 = () => `// ${g('S-R39')}`;
test('LF-4: S-R39 on line 1 (or after a shebang/comment, within 5 lines) is green', () => {
  assert.deepEqual(lintTree(withFile('docs/examples/a.mjs', `${R39()}\nconsole.log(1);\n`)).hits, []);
  assert.deepEqual(lintTree(withFile('docs/examples/a.mjs', `#!/usr/bin/env node\n// example\n\n${R39()}\nconsole.log(1);\n`)).hits, []);
});
test('M-93: S-R39 after line 5 is red', () => {
  const hits = lintTree(withFile('docs/examples/a.mjs', `// a\n// b\n// c\n// d\n// e\n${R39()}\n`)).hits;
  assert.ok(hits.some((h) => h.includes('CI36-r39-header')), hits.join('\n'));
});
test('M-118: a code token before the S-R39 header is red even within lines 1-5', () => {
  const hits = lintTree(withFile('docs/examples/a.mjs', `import x from 'y';\n${R39()}\n`)).hits;
  assert.ok(hits.some((h) => h.includes('code token before')), hits.join('\n'));
});
test('O-70: an examples file without the header, or with a wrapped/split header, is red', () => {
  for (const t of ['console.log(1);\n', `// ${g('S-R39').replace(', not for', ',\n// not for')}\n`, `  ${g('S-R39')}\n`])
    assert.ok(lintTree(withFile('docs/examples/b.ts', t)).hits.some((h) => h.includes('CI36-r39-header')), t);
});

// ---------- surfaces (F-16, LF-5, LF-6 / F-28, F-21) ----------
test('LF-5: CHANGELOG, CONTRIBUTING and release notes are claims surfaces at any depth', () => {
  for (const p of ['CHANGELOG.md', 'CONTRIBUTING.md', 'RELEASE-NOTES.md', 'release-notes/v0.1.0.md', 'docs/CHANGELOG.md', 'packages/drbg/CHANGELOG.md', 'CHANGES.md', '.github/release.yml', 'CONTRIBUTING', 'releases/1.0.0.md']) {
    assert.ok(isClaimsSurface(p), p);
    assert.ok(lintTree(withFile(p, `${PLANT}\n`)).hits.some((h) => h.startsWith(`${p}:`)), p);
  }
});
test('F-16: src/ and test/ prose files are out of claims scope (other rules still apply)', () => {
  for (const p of ['src/NOTES.md', 'test/fixtures/README.md', 'tools/notes.txt']) assert.deepEqual(lintTree(withFile(p, `${PLANT}\n`)).hits, [], p);
});
test('LF-6 / F-28: every string VALUE of every package.json at any path is in scope, at any depth', () => {
  for (const p of ['package.json', 'packages/drbg/package.json', 'test/fixtures/deep/x/package.json', 'docs/examples/package.json']) {
    const base = tracked().has(p) ? JSON.parse(read(p)) : { name: 'x' };
    for (const [w, extra] of [['top-level field', { homepage: PLANT }], ['nested object', { publishConfig: { tag: PLANT } }], ['array', { files: ['a', VPLANT] }],
      ['deep', { a: { b: [{ c: { d: 'NIST-\u0063ertified' } }] } }], ['author', { author: 'GLI \u0061ligned' }]]) {
      const hits = lintTree(withFile(p, JSON.stringify({ ...base, ...extra }, null, 2))).hits;
      assert.ok(hits.some((h) => h.startsWith(`${p}#/`)), `${p} ${w}: ${hits.join('; ')}`);
    }
  }
});
test('D-1 (CPO-R104, supersedes F-28): package.json KEYS at every depth are in claims scope', () => {
  const pkg = JSON.parse(read('package.json'));
  for (const kb of [{ ...pkg, scripts: { ...pkg.scripts, ['\u0063ertified-check']: 'node -v' } }, { ...pkg, exports: { ['./\u0076alidated']: './x.js' } },
    { ...pkg, a: { b: [{ ['GLI-\u0061ligned']: 1 }] } }, { ...pkg, ['\u0046IPS']: true }]) {
    const hits = lintTree(withFile('package.json', JSON.stringify(kb, null, 2))).hits;
    assert.ok(hits.some((h) => /^package\.json#\/.*\(key\):/.test(h)), JSON.stringify(Object.keys(kb)));
  }
  assert.deepEqual(lintTree(withFile('package.json', JSON.stringify({ ...pkg, scripts: { ...pkg.scripts, 'lint:docs': 'node -v' } }, null, 2))).hits, []);
});
const PHR = 'schema \u0076alidation';
test('D-2 (CPO-R104): list entries match by prefix, case-insensitive; left boundary only (no preceding letter/digit)', () => {
  for (const v of ['BMMTestlabs', 'GLI19', 'ITL21', 'gli_11', 'iTech_Labs', 'UKGCs', 'eCOGRAs', 'NISTIR', 'Trisigma-NL', '_GLI', 'bmm-testlabs']) {
    assert.ok(lintText('docs/a.md', `${PHR} as ${v} does it`).length > 0, v);
  }
  for (const v of ['xGLI', 'aBMM', '9NIST']) assert.deepEqual(lintText('docs/a.md', `${PHR} as ${v} does it`), [], v);
});
test('D-2 / D-3: the generic words lab and labs stay whole-word', () => {
  for (const v of ['lab', 'labs', 'Lab', 'LABS']) assert.ok(lintText('docs/a.md', `${PHR} in the ${v}`).length > 0, v);
  for (const v of ['labelled', 'collab', 'labsheet']) assert.deepEqual(lintText('docs/a.md', `${PHR} ${v}`), [], v);
});
test('G-4 (CPO-R104): certif, complian and align match without a left boundary', () => {
  for (const w of ['un\u0063ertified', 'non\u0063ompliant', 'mis\u0061ligned', 're\u0063ertification', 'x_\u0061lign', 'pre\u0061ligned']) assert.ok(lintText('docs/a.md', `It is ${w}.`).length > 0, w);
});
test('G-6 (CPO-R104): the comparative rule anchors on lab, labs and every list entry (prefix)', () => {
  for (const t of ['exceeds UKGCs rules', 'beyond BMMTestlabs requirements', 'goes above ISO norms', 'surpasses Lottstift', 'meets the lab bar', 'Kahnawake Gaming Commission rules we exceed',
    'beyond what AGCO asks', 'above GLI19 thresholds', 'labs we surpass']) {
    assert.ok(lintText('docs/a.md', t).some((h) => h.includes('R16-comparative')), t);
  }
  for (const t of ['above the threshold', 'beyond the end of the buffer', 'meets the deadline']) assert.deepEqual(lintText('docs/a.md', t), [], t);
});
test('F-21: adopter-visible error and reason strings in shipped source are linted (escapes decoded)', () => {
  for (const src of [`throw new Error('${VPLANT}');`, 'export const reason = "\\u0063ertified by GLI";', 'return { ok: false, detail: `not ${x} \\u0063ryptographic module` };',
    "throw new RangeError('RNG \\u0061ligned');", 'const m = "FIPS mode";']) {
    for (const p of ['src/x.ts', 'packages/drbg/src/y.ts']) assert.ok(lintTree(withFile(p, `${src}\n`)).hits.some((h) => h.startsWith(`${p}:`)), `${p}: ${src}`);
  }
});
test('F-21: JSDoc in shipped source is linted; plain // comments are not adopter-visible strings', () => {
  assert.ok(lintTree(withFile('src/x.ts', `/**\n * Returns a ${VPLANT} handle.\n */\nexport const a = 1;\n`)).hits.some((h) => h.includes('jsdoc')));
  assert.deepEqual(lintTree(withFile('src/x.ts', 'export const a = 1; // not a claim: \\u0063ertif is spelled here as an escape\n')).hits, []);
  assert.deepEqual(lintTree(withFile('src/x.ts', "const re = /'\\u0063/g; const s = 'ok';\n")).hits, []);
});
test('F-21: shipped .d.ts (incl. JSDoc) is linted; test/ code is out', () => {
  assert.ok(lintTree(withFile('types/index.d.ts', `/** ${PLANT} */\nexport declare const a: 1;\n`)).hits.some((h) => h.startsWith('types/index.d.ts:')));
  assert.ok(lintTree(withFile('src/index.d.ts', `export declare const a: '${VPLANT}';\n`)).hits.length > 0);
  assert.deepEqual(lintTree(withFile('test/x.test.mjs', `throw new Error('${VPLANT}');\n`)).hits, []);
});
test('F-21: built output is linted when present; with no build the half is reported PENDING', () => {
  assert.match(lintTree(tracked()).report.builtOutput, /^PENDING/);
  const built = new Map([['dist/index.js', Buffer.from(`throw new Error("${VPLANT}");\n`)], ['dist/index.d.ts', Buffer.from(`/** ${PLANT} */\n`)]]);
  const hits = lintTree(tracked(), built).hits;
  assert.ok(hits.some((h) => h.startsWith('dist/index.js:')) && hits.some((h) => h.startsWith('dist/index.d.ts:')), hits.join('\n'));
  assert.deepEqual(lintTree(tracked(), new Map([['dist/index.js', Buffer.from('throw new Error("RANGE_INVALID: n must be >= 1");\n')]])).hits, []);
});
test('F-21: lintCode on a fixture file materialised in scratch', () => {
  const f = join(dir, 'fixture.ts');
  writeFileSync(f, "export function f(n: number) {\n  if (n < 1) throw new RangeError(`n=${n}: not a \\u0063ryptographic\\u00a0module`);\n}\n");
  assert.ok(lintCode('src/fixture.ts', readFileSync(f, 'utf8')).length > 0);
});

// ---------- CLI ----------
test('known-bad fixture stays red via --expect-red on a scratch file', () => {
  const f = join(dir, 'README.known-bad.md');
  writeFileSync(f, KNOWN_BAD_README);
  const r = spawnSync(process.execPath, [LINT, '--expect-red', f], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});
test('--self-test exits 0 (known-bad fixtures red + all near-miss cases pass)', () => {
  const out = execFileSync(process.execPath, [LINT, '--self-test'], { encoding: 'utf8' });
  assert.match(out, /near-miss (\d+)\/\1 PASS; scratch removed: true/);
});
test('repo scope lints clean', () => {
  const r = spawnSync(process.execPath, [LINT], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});
