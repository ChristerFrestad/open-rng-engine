// Rule 40 / quality CI 31 product scanner tests (R-79, R-81, quality v5.5.2 §7.5, C-9 dadae96e). node --test, zero deps.
// All banned-name strings are \u-escaped below; plants are materialised only in in-memory or scratch trees.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  parseList, scanTree, scanText, compileEntry, normScan, validateConfig, decodeFixture, fixtureSelfTest, genericFixtureTree,
  LIST_PATH, FIXTURE_PATH, CONFIG_PATH, EXEMPT_PATHS,
} from '../tools/ci/rule40-protected-names.mjs';
import { createHash } from 'node:crypto';

const ROOT = new URL('..', import.meta.url).pathname;
const LIST = readFileSync(join(ROOT, LIST_PATH));
const FIX = readFileSync(join(ROOT, FIXTURE_PATH));
const CFG = readFileSync(join(ROOT, CONFIG_PATH));
const sha = (b) => createHash('sha256').update(b).digest('hex');
const good = parseList(LIST);
const entries = good.meta.entries;
const hitsOf = (text, path = 'notes.txt') => scanText(path, text, entries);
// Minimal valid tree: the three config files + one clean file.
const tree = (extra = {}, over = {}) => {
  const m = new Map([[LIST_PATH, LIST], [FIXTURE_PATH, FIX], [CONFIG_PATH, CFG], ['README.md', Buffer.from('# open-rng-engine\n')]]);
  for (const [k, v] of Object.entries(over)) m.set(k, Buffer.isBuffer(v) ? v : Buffer.from(v));
  for (const [k, v] of Object.entries(extra)) m.set(k, Buffer.isBuffer(v) ? v : Buffer.from(v));
  return m;
};
const red = (r) => r.configErrors.length > 0 || r.hits.length > 0;
// Config bytes keep reference texts \u-escaped (as the real config must).
const escAll = (t) => [...t].map((ch) => (/[A-Za-z]/.test(ch) ? `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}` : ch)).join('');
const cfgWith = (mut) => {
  const c = JSON.parse(CFG.toString()); mut(c);
  let out = JSON.stringify(c, null, 2) + '\n';
  for (const r of Array.isArray(c.references) ? c.references : []) if (r && typeof r.text === 'string') out = out.split(JSON.stringify(r.text)).join(`"${escAll(r.text)}"`);
  return Buffer.from(out);
};
const listWith = (s) => Buffer.from(LIST.toString() + s);
const listLines = LIST.toString();

const POSITIVE = [
  '\u0072\u006f\u0075\u006c\u0065\u0074\u0074\u0065',
  '\u0048\u006f\u006c\u0064\u2019\u0065\u006d',
  '\u0048\u004f\u004c\u0044\u0045\u004d',
  '\uff32\uff2f\uff35\uff2c\uff25\uff34\uff34\uff25',
  '\u0068\u006f\u006c\u0064\u0045\u006d',
  '\u0073\u006c\u006f\u0074 \u006d\u0061\u0063\u0068\u0069\u006e\u0065',
  '\u0073\u006c\u006f\u0074.\u0072\u0065\u0065\u006c\u0073@1',
  '\u0053\u0075\u0070\u0065\u0072 \u0048\u006f\u006c\u0064\'\u0065\u006d',
  '\u0042\u006c\u0061\u0063\u006b\u004a\u0061\u0063\u006b',
  '\u0068\u006f\u006c\u0064_\u0065\u006d',
  '\u0050\u0075\u006e\u0074\u006f \u0042\u0061\u006e\u0063\u006f',
  '\u0076\u0069\u0064\u0065\u006f \u0073\u006c\u006f\u0074\u0073',
  '\u006b\u0065\u006e\u006f-\u0064\u0072\u0061\u0077',
  '\u0053\u0075\u0070\u0065\u0072 \u0054\u0065\u0078\u0061\u0073 \u0048\u006f\u006c\u0064\'\u0065\u006d',
  '\u0053\u0074\u0072\u0061\u00df\u0065 \u0072\u006f\u0075\u006c\u0065\u0074\u0074\u0065'
];
const NEGATIVE = [
  '\u0053\u0074\u0061\u006e\u0064\u0061\u0072\u0064\u0073 \u0066\u006f\u0072 \u0049\u006e\u0074\u0065\u0072\u0061\u0063\u0074\u0069\u0076\u0065 \u0047\u0061\u006d\u0069\u006e\u0067 \u0053\u0079\u0073\u0074\u0065\u006d\u0073',
  '\u0047\u0061\u006d\u0069\u006e\u0067 \u0044\u0065\u0076\u0069\u0063\u0065\u0073 \u0069\u006e \u0043\u0061\u0073\u0069\u006e\u006f\u0073',
  '\u0052\u0065\u006d\u006f\u0074\u0065 \u0067\u0061\u006d\u0062\u006c\u0069\u006e\u0067 \u0061\u006e\u0064 \u0073\u006f\u0066\u0074\u0077\u0061\u0072\u0065 \u0074\u0065\u0063\u0068\u006e\u0069\u0063\u0061\u006c \u0073\u0074\u0061\u006e\u0064\u0061\u0072\u0064\u0073',
  '\u0063\u0061\u0072\u0064-\u0064\u0065\u0061\u006c-52',
  '\u0077\u0068\u0065\u0065\u006c-37',
  '\u0072\u0065\u0065\u006c-5\u00783',
  '\u006c\u0061\u0073\u0074-\u0072\u0065\u0061\u0064 \u0073\u006c\u006f\u0074',
  '\u0066\u0069\u006e\u0067\u0065\u0072\u0070\u0072\u0069\u006e\u0074 \u0073\u006c\u006f\u0074',
  '\u0070\u0072\u0069\u0076\u0061\u0074\u0065-\u0073\u006c\u006f\u0074',
  '\u0072\u0061\u006e\u0064\u006f\u006d\u0049\u006e\u0074(0, 37)',
  '\u0073\u0068\u0075\u0066\u0066\u006c\u0065 \u0061 \u0064\u0065\u0063\u006b \u006f\u0066 \u0063\u0061\u0072\u0064\u0073',
  '\u0063\u0061\u0072\u0064',
  '\u0064\u0065\u0063\u006b',
  '\u0068\u0061\u006e\u0064',
  '\u0077\u0068\u0065\u0065\u006c',
  '\u0070\u006f\u0063\u006b\u0065\u0074',
  '\u0072\u0065\u0065\u006c',
  '\u0073\u0079\u006d\u0062\u006f\u006c',
  '\u0073\u0074\u0072\u0069\u0070',
  '\u0070\u0061\u0079\u0074\u0061\u0062\u006c\u0065',
  '\u0047\u0041\u004d\u0045_\u0045\u0052\u0052\u004f\u0052'
];
const PLANT = '\u0072\u006f\u0075\u006c\u0065\u0074\u0074\u0065';
const BARE = '\u0073\u006c\u006f\u0074';

// ---------- list, report, approval pin ----------
test('real list parses: version 1, 38 entries, sha 7f56688e, 0 errors', () => {
  assert.deepEqual(good.errors, []);
  assert.equal(good.meta.version, 1);
  assert.equal(entries.length, 38);
  assert.equal(good.meta.sha256, '7f56688ee17193182f47cc7e048b2bc2b25baa7f3c0a1ea678cfa5c77144277b');
});
test('real tree scan: report carries version, sha, count, approval pin; 0 config errors on config files', () => {
  const r = scanTree(tree());
  assert.deepEqual(r.configErrors, []); assert.deepEqual(r.hits, []);
  assert.equal(r.report.listVersion, 1); assert.equal(r.report.listEntries, 38);
  assert.equal(r.report.listSha256, r.report.approvedSha256);
  assert.match(r.report.cpoVerdict, /CPO-R96a/);
  assert.match(r.report.fixture, /9\/9/);
});

// ---------- parser: one unit test per C-9 §4 condition (+ errata) ----------
const row = (...f) => `${f.join('\t')}\n`;
const unit = [
  ['missing header', Buffer.from(row('PN-001', 'P1', 'phrase', 'zzz', 'X')), /header/],
  ['wrong header', Buffer.from(listLines.replace('protected-names/v1', 'protected-names/v2')), /header/],
  ['version 0', Buffer.from(listLines.replace('version: 1', 'version: 0')), /version/],
  ['version not int', Buffer.from(listLines.replace('version: 1', 'version: one')), /version/],
  ['field count', listWith(row('PN-099', 'P1', 'phrase', 'zzz', 'X', 'extra')), /field count/],
  ['unknown group', listWith(row('PN-099', 'P10', 'phrase', 'zzz', 'X')), /unknown group/],
  ['unknown kind', listWith(row('PN-099', 'P1', 'glob', 'zzz', 'X')), /unknown kind/],
  ['regex outside P7', listWith(row('PN-099', 'P8', 'regex', 'zz?', 'X')), /regex outside P7/],
  ['regex capturing group (E-5)', listWith(row('PN-099', 'P7', 'regex', 'zz(?:a|b)(c|d)', 'X')), /REGEX_CAPTURING_GROUP/],
  ['regex lookbehind (E-6)', listWith(row('PN-099', 'P7', 'regex', '(?<=a)zz', 'X')), /lookbehind/],
  ['regex negative lookbehind (E-6)', listWith(row('PN-099', 'P7', 'regex', '(?<!a)zz', 'X')), /lookbehind/],
  ['regex backreference', listWith(row('PN-099', 'P7', 'regex', '(?:a)\\1', 'X')), /backreference/],
  ['regex inline flags', listWith(row('PN-099', 'P7', 'regex', '(?i)zz', 'X')), /flags/],
  ['regex does not compile', listWith(row('PN-099', 'P7', 'regex', 'zz[', 'X')), /does not compile/],
  ['duplicate id', listWith(row('PN-001', 'P1', 'phrase', 'zzzunique', 'X')), /duplicate id/],
  ['duplicate normalised pattern', listWith(row('PN-099', 'P1', 'phrase', '\u0070\u006f\u006b\u0065\u0072', 'X')), /duplicate normalised/],
  ['empty field', listWith(row('PN-099', 'P1', 'phrase', '', 'X')), /empty field/],
  ['pattern not normalised', listWith(row('PN-099', 'P1', 'phrase', 'Zzz', 'X')), /not normalised/],
  ['phrase token rule', listWith(row('PN-099', 'P1', 'phrase', 'zz  zz', 'X')), /phrase tokens/],
  ['source with whitespace', listWith(row('PN-099', 'P1', 'phrase', 'zzz', 'a b')), /source tag/],
  ['product-only beyond the bare P7 entries', listWith(row('PN-099', 'P7', 'product-only', 'zzz', 'X')), /product-only/],
  ['product-only outside P7', listWith(row('PN-099', 'P8', 'product-only', BARE, 'X')), /product-only/],
  ['BOM', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), LIST]), /BOM/],
  ['CRLF', Buffer.from(listLines.replace(/\n/g, '\r\n')), /CR/],
  ['no final newline', Buffer.from(listLines.replace(/\n$/, '')), /final newline/],
  ['not UTF-8', Buffer.concat([LIST, Buffer.from([0xff, 0x0a])]), /not UTF-8/],
  ['not NFC', Buffer.from(listLines + '# cafe\u0301\n'), /NFC/],
  ['trailing whitespace', Buffer.from(listLines + '# x \n'), /trailing whitespace/],
  ['tab in comment', Buffer.from(listLines + '# a\tb\n'), /tab in a comment/],
  ['empty list', Buffer.from('format: open-rng-engine/protected-names/v1\nversion: 1\n\n# none\n'), /empty list/],
  ['generic-vocabulary guard: card (M-71 d)', listWith(row('PN-099', 'P8', 'phrase', 'card', 'X')), /generic-vocabulary guard/],
  ['generic-vocabulary guard: reel (M-71 d)', listWith(row('PN-099', 'P8', 'phrase', 'reel', 'X')), /generic-vocabulary guard/],
  ['TECHNICAL_TERM form', listWith(row('PN-099', 'P7', 'phrase', `fingerprint ${BARE}`, 'X')), /TECHNICAL_TERM/],
];
for (const [name, buf, re] of unit) {
  test(`parser: ${name} is a parse error`, () => {
    const { errors } = parseList(buf);
    assert.ok(errors.some((e) => re.test(e)), `${re} not in ${JSON.stringify(errors)}`);
  });
  test(`tree: ${name} in the list turns the scan red (config error)`, () => {
    const r = scanTree(tree({}, { [LIST_PATH]: buf }));
    assert.ok(r.configErrors.length > 0);
  });
}

// ---------- normalisation and controls (round-trip vs o55 156340f7 controls + CPO-R95) ----------
for (const p of POSITIVE) test(`positive control hits: ${JSON.stringify(p)}`, () => assert.ok(hitsOf(p).length > 0));
for (const n of NEGATIVE) test(`negative control clean: ${JSON.stringify(n)}`, () => assert.deepEqual(hitsOf(n), []));
test('normalisation: NFKC + camelCase split + casefold', () => {
  assert.equal(normScan('\uff32\uff2f'), 'ro');
  assert.equal(normScan('cardCount'), 'card count');
  assert.equal(normScan('\u0068\u006fld\u0045m'), '\u0068\u006fld \u0065m');
  assert.equal(normScan('HTMLParser'), 'html parser');
  assert.equal(normScan('STRASSE'), normScan('Stra\u00dfe'));
});
test('word boundary: no [a-z0-9] on either side', () => {
  assert.deepEqual(hitsOf(`x${PLANT}`), []);
  assert.deepEqual(hitsOf(`${PLANT}2`), []);
  assert.ok(hitsOf(`(${PLANT})`).length > 0);
});
test('regex entries compile to bounded, non-capturing JS regexes', () => {
  for (const e of entries.filter((x) => x.kind === 'regex')) { assert.ok(e.rx instanceof RegExp); assert.equal(/\((?!\?)/.test(e.rx.source.replace(/\\\(/g, '')), false); }
  assert.throws(() => compileEntry('regex', '(a)'), /REGEX_CAPTURING_GROUP/);
});

// ---------- product-only positions (E-3) ----------
const PRODUCT_POSITIONS = [
  ['package.json name', 'package.json', (t) => JSON.stringify({ name: `open-rng-${t}` })],
  ['package.json description', 'package.json', (t) => JSON.stringify({ name: 'x', description: `A ${t} library` })],
  ['package.json keywords', 'package.json', (t) => JSON.stringify({ name: 'x', keywords: [t] })],
  ['nested package.json keywords', 'packages/mapping/package.json', (t) => JSON.stringify({ name: 'x', keywords: [t] })],
  ['README heading', 'README.md', (t) => `# ${t[0].toUpperCase()}${t.slice(1)}`],
  ['doc heading', 'docs/guide.md', (t) => `## Using ${t}`],
];
for (const t of [BARE, `${BARE}s`]) {
  for (const [name, path, mk] of PRODUCT_POSITIONS) test(`product-only ${JSON.stringify(t)} red in ${name}`, () => assert.ok(scanText(path, mk(t), entries).length > 0));
  test(`product-only ${JSON.stringify(t)} red as example name`, () => assert.ok(scanTree(tree({ [`docs/examples/${t}/README.md`]: '# ex\n' })).hits.length > 0));
  test(`product-only ${JSON.stringify(t)} NOT flagged outside product positions`, () => {
    assert.deepEqual(scanText('src/x.ts', `// the ${t} holds 16 bytes`, entries), []);
    assert.deepEqual(scanText('README.md', `Body text: one ${t} per width.`, entries), []);
    assert.deepEqual(scanText('package.json', JSON.stringify({ name: 'x', scripts: { a: `echo ${t}` } }), entries), []);
  });
}
test('product-only has no implicit plural: only the two explicit entries exist', () => {
  assert.deepEqual(entries.filter((e) => e.kind === 'product-only').map((e) => e.pattern).sort(), [BARE, `${BARE}s`]);
});

// ---------- exact-path self-scan (R-81, quality §7.5) and M-71 (e) ----------
test('exempt paths are exactly the two pinned strings', () => assert.deepEqual([...EXEMPT_PATHS], [LIST_PATH, FIXTURE_PATH]));
for (const p of [`${LIST_PATH}.bak`, 'tools/other.txt', 'tools/protected-names.TXT', 'src/protected-names.txt', `./${LIST_PATH}`, 'tools//protected-names.txt']) {
  test(`M-71(e): list content at ${p} is red`, () => assert.ok(scanTree(tree({ [p]: LIST })).hits.length > 0));
}
test('M-71(e): fixture copied to a sibling path is red once decoded? (raw escaped copy is clean, decoded copy red)', () => {
  const dec = decodeFixture(FIX).cases.map((c) => c.text).join('\n');
  assert.ok(scanTree(tree({ 'tools/protected-names.known-bad.decoded.md': dec })).hits.length > 0);
});
test('M-71(e): broken parse of the list is red', () => assert.ok(scanTree(tree({}, { [LIST_PATH]: Buffer.from('garbage\n') })).configErrors.length > 0));
test('M-71(e): broken fixture is red', () => {
  for (const bad of ['not json', '{"format":"x","cases":[]}', JSON.stringify({ format: 'open-rng-engine/rule40-known-bad/v1', cases: [{ group: 'P1', path: 'a.md', text: 'harmless' }] })]) {
    assert.ok(scanTree(tree({}, { [FIXTURE_PATH]: bad })).configErrors.length > 0, bad);
  }
});
test('fixture stored unescaped is red', () => {
  const j = { format: 'open-rng-engine/rule40-known-bad/v1', cases: [{ group: 'P4', path: 'a.md', text: PLANT }] };
  assert.match(decodeFixture(Buffer.from(JSON.stringify(j))).error, /unescaped/);
});
test('fixture self-test: every P-group and both product-only entries hit; scratch removed', () => {
  const r = fixtureSelfTest(FIX, entries);
  assert.equal(r.ok, true, r.detail);
});
test('missing list / config / fixture is red', () => {
  for (const p of [LIST_PATH, CONFIG_PATH, FIXTURE_PATH]) { const t = tree(); t.delete(p); assert.ok(scanTree(t).configErrors.length > 0, p); }
});

// ---------- M-60 plants and M-71 (a) ----------
for (const [i, p] of POSITIVE.entries()) {
  test(`M-60 plant ${i} in docs/examples/wheel-37/README.md is red`, () => assert.ok(scanTree(tree({ 'docs/examples/wheel-37/README.md': `# wheel-37\n\n${p}\n` })).hits.length > 0));
}
test('M-60 plant in a test title is red', () => assert.ok(scanTree(tree({ 'test/a.test.mjs': `test('${PLANT} works', () => {});\n` })).hits.length > 0));
test('M-60 plant in package.json keywords is red', () => assert.ok(scanTree(tree({}, { 'package.json': JSON.stringify({ name: 'x', keywords: [PLANT] }) })).hits.length > 0));
test('M-60 plant in a path name is red', () => assert.ok(scanTree(tree({ [`src/${PLANT}.ts`]: 'export {};\n' })).hits.length > 0));
test('M-71(a): plant outside any references section is red', () => assert.ok(scanTree(tree({ 'docs/notes.md': `See ${PLANT}.\n` })).hits.length > 0));
test('RQ-FC-23: non-UTF-8 tracked file is red (binary allowlist empty)', () => assert.ok(scanTree(tree({ 'img.bin': Buffer.from([0xff, 0xfe, 0x00]) })).hits.some((h) => h.id === 'UNSCANNABLE')));
test('unparseable package.json is red (product positions unscannable)', () => assert.ok(scanTree(tree({ 'packages/x/package.json': '{ nope' })).hits.length > 0));

// ---------- approval pin (R-79; M-71 c) ----------
test('M-71(c): unreviewed list change (sha != CPO approval pin) is red', () => {
  const r = scanTree(tree({}, { [LIST_PATH]: listWith('# reviewed? no\n') }));
  assert.ok(r.configErrors.some((e) => /approval pin/.test(e)));
});
test('approval pin: version and count mismatches are red', () => {
  assert.ok(scanTree(tree({}, { [CONFIG_PATH]: cfgWith((c) => { c.approval.version = 2; }) })).configErrors.some((e) => /version/.test(e)));
  assert.ok(scanTree(tree({}, { [CONFIG_PATH]: cfgWith((c) => { c.approval.entries = 37; }) })).configErrors.some((e) => /entry count/.test(e)));
  assert.ok(scanTree(tree({}, { [CONFIG_PATH]: cfgWith((c) => { c.approval.cpoVerdict = ''; }) })).configErrors.length > 0);
});

// ---------- references allowlist (R-79) and M-61 ----------
const BEGIN = '## References';
const END = '<!-- references:end -->';
const refDoc = (cite) => `# Notes\n\n${BEGIN}\n\n${cite}\n${END}\n\nBody.\n`;
const CITE = `- Montreal ${'\u006b\u0065\u006e\u006f'} incident [source: RES-01]`;
const ref = (over = {}) => ({ path: 'RESEARCH-NOTES.md', line: 5, text: `Montreal ${'\u006b\u0065\u006e\u006f'}`, lineSha256: sha(Buffer.from(CITE)), sourceTag: '[source: RES-01]', approver: 'CPO', beginAnchor: BEGIN, endAnchor: END, ...over });
const withRef = (r, doc = refDoc(CITE)) => scanTree(tree({ 'RESEARCH-NOTES.md': doc }, { [CONFIG_PATH]: cfgWith((c) => { c.references = Array.isArray(r) ? r : [r]; }) }));
test('valid references-section citation with source tag and CPO approver is allowed', () => {
  const r = withRef(ref());
  assert.deepEqual(r.configErrors, []); assert.deepEqual(r.hits, []);
});
test('without the entry the same citation is red', () => assert.ok(scanTree(tree({ 'RESEARCH-NOTES.md': refDoc(CITE) })).hits.length > 0));
const m61 = [
  ['glob path', ref({ path: '*.md' })],
  ['directory prefix', ref({ path: 'docs/' })],
  ['stale line hash', ref({ lineSha256: '0'.repeat(64) })],
  ['citation outside anchors', ref({ line: 1 })],
  ['missing approver', ref({ approver: '' })],
  ['non-CPO approver', ref({ approver: 'CTO' })],
  ['source path exemption', ref({ path: 'src/index.ts' })],
  ['test path exemption', ref({ path: 'test/a.test.mjs' })],
  ['example path exemption', ref({ path: 'docs/examples/wheel-37/README.md' })],
  ['exempt list path', ref({ path: LIST_PATH })],
  ['extra key (further exemption)', { ...ref(), exempt: true }],
  ['untracked path (stale)', ref({ path: 'GONE.md' })],
];
for (const [name, r] of m61) test(`M-61: ${name} is red`, () => assert.ok(red(withRef(r))));
test('reference text stored unescaped in config is red', () => {
  const c = JSON.parse(CFG.toString()); c.references = [ref()];
  const r = scanTree(tree({ 'RESEARCH-NOTES.md': refDoc(CITE) }, { [CONFIG_PATH]: JSON.stringify(c) }));
  assert.ok(r.configErrors.some((e) => /unescaped/.test(e)) || r.hits.length > 0);
});
test('M-61: any further top-level exemption key in config is red', () => {
  assert.ok(scanTree(tree({}, { [CONFIG_PATH]: cfgWith((c) => { c.exemptPaths = ['docs/']; }) })).configErrors.length > 0);
});
test('M-71(b): references-section citation without a source tag is red', () => {
  const noTag = `- Montreal ${'\u006b\u0065\u006e\u006f'} incident`;
  assert.ok(red(withRef(ref({ lineSha256: sha(Buffer.from(noTag)) }), refDoc(noTag))));
  assert.ok(red(withRef(ref({ sourceTag: '' }))));
});
test('M-71(a): a second, uncited occurrence elsewhere in the same file stays red', () => {
  const doc = refDoc(CITE) + `Also ${'\u006b\u0065\u006e\u006f'} here.\n`;
  const r = withRef(ref(), doc);
  assert.ok(r.hits.length > 0);
});

// ---------- R-81 generic-vocabulary fixture (tracked) ----------
test('generic-vocabulary fixture: tracked files equal the generator and scan with 0 hits', () => {
  const gen = genericFixtureTree();
  for (const p of ['test/x13-fixtures/generic-vocabulary/README.md', 'test/x13-fixtures/generic-vocabulary/package.json']) {
    assert.equal(readFileSync(join(ROOT, p), 'utf8'), gen.get(p), p);
  }
  const r = scanTree(tree(Object.fromEntries(gen)));
  assert.deepEqual(r.hits, []); assert.deepEqual(r.configErrors, []);
});
test('M-71(d): adding card or reel to the list turns the generic fixture red', () => {
  for (const w of ['card', 'reel']) assert.ok(parseList(listWith(row('PN-099', 'P8', 'phrase', w, 'X'))).errors.some((e) => /generic-vocabulary/.test(e)), w);
});

// ---------- CLI ----------
test('CLI --self-test passes and the repo index scans clean', async () => {
  const { spawnSync } = await import('node:child_process');
  const s = join(ROOT, 'tools/ci/rule40-protected-names.mjs');
  const a = spawnSync(process.execPath, [s, '--self-test', '--worktree'], { encoding: 'utf8' });
  assert.equal(a.status, 0, a.stdout + a.stderr);
  const b = spawnSync(process.execPath, [s, '--worktree'], { encoding: 'utf8' });
  assert.equal(b.status, 0, b.stdout + b.stderr);
  assert.match(b.stdout, /list version 1 sha256 7f56688e\w+ entries 38/);
});
