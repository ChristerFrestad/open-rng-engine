#!/usr/bin/env node
// Shared claims lint (PLAN R-16 / B10 / QIU-07 / RQ-FC-13). Zero dependencies.
// Scope (R-16): README*, package.json description + keywords, docs/**, release notes,
// SECURITY.md, and the intended GitHub repo description/topics recorded in REMOTE-PENDING.md
// between the CLAIMS-LINT-SCOPE markers.
// Usage:  node tools/claims-lint.mjs                 -> lint the repo scope, exit 1 on any hit
//         node tools/claims-lint.mjs --expect-red F  -> lint file F only, exit 0 only if it has >= 1 hit
//         node tools/claims-lint.mjs --self-test     -> (1) materialise the known-bad README fixture in a scratch dir
//                                                       (from \u-escaped source, never a literal in the repo), expect red;
//                                                       (2) run the C-10 near-miss cases the same way, scratch removed after
// C-10 allow-list (CPO-R97, inputs/drafts/cpo-c10-c11-rulings.md sha256 bdde9834..., DECISIONS L75):
//   - exempt only the stems certif* and complian*, and only when the hit lies wholly inside one byte-exact,
//     case-sensitive occurrence of an allowlisted string that is the whole line apart from wrappers (see allowedSpans);
//   - align* is unconditional; there is no allowlisted sentence containing it;
//   - the FIPS exception set is empty in 1.0 (the allowed S-FIPS-1.0 sentence has no FIPS token): every FIPS token is a hit;
//   - the /drbg sentence reserved by PLAN L633 is not allowlisted in 1.0; its NIST SP 800-90A / CAVP claim tokens are hits;
//   - allowlist strings are \u-escaped like the banned patterns and pinned by sha256; a pin mismatch is a config error (exit 2),
//     so a list change without a CPO verdict cannot go green silently.
import { readFileSync, readdirSync, statSync, existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const ROOT = new URL('..', import.meta.url).pathname;
const ANCHOR = String.raw`(?:GLI-11|GLI|NIST|UKGC|RTS|MGA|lab)`;
const COMPAR = String.raw`(?:exceed\w*|above|beyond|surpass\w*|meets)`;
const NEAR = String.raw`(?:\W+\w+){0,4}\W+`; // within 5 words
export const RULES = [
  ['R16-certif', /\b\u0063ertif\w*/gi],
  ['R16-complian', /\b\u0063omplian\w*/gi],
  ['R16-align', /\b\u0061lign\w*/gi],
  ['R16-comparative', new RegExp(String.raw`\b${COMPAR}${NEAR}${ANCHOR}\b|\b${ANCHOR}${NEAR}${COMPAR}\b`, 'gi')],
  ['R16-nist-claim', /\bNIST[- ](?:\u0063ertified|\u0061pproved|\u0063ompliant)\b/gi],
  ['R16-approved', /\b\u0061pproved\b/gi],
  ['R16-gold-standard', /\b\u0067old\s+standard\b/gi],
  ['R16-fips', /\b\u0046IPS\b/gi],
  ['R16-badge', /!\[[^\]]*(?:GLI|NIST)[^\]]*\]\([^)]*\)|!\[[^\]]*\]\([^)]*(?:GLI|NIST)[^)]*\)|<img\b[^>]*(?:GLI|NIST)[^>]*>/gi],
  ['C10-drbg-reserved', /\bNIST\s+SP\s*800-90A\b|\b\u0043AVP\b/gi],
];
// Only these rule ids can be exempted by an allowlisted occurrence (CPO-R97: certif* and complian*).
// R16-align and R16-fips are never exempt.
const EXEMPTABLE = new Set(['R16-certif', 'R16-complian']);

// C-10 allow-list, byte-exact (CPO-R97). \u-escaped stems; sha256 pins are CPO's (rulings L118-L173).
export const ALLOW = [
  ['S-P1', 'Open-source TypeScript RNG and mapping library for Node.js, intended to be submitted as part of a licensee\'s system for independent lab evaluation. Not \u0063ertified. Not a validated module.',
    '7efa5b3e0197f88a2431c0b789e452be169fc0e2710915f387fb5c515d87bf37'],
  ['S-P1-short', 'Not \u0063ertified. Not a validated module.',
    '3df21d8f1e9af56b213950311b61830029c7e7c2cb80c34fc56d13606f4f2d92'],
  ['S-R39', 'non-normative, not \u0063ertified, not for real money',
    '21df984dabb4744ffbb8f45ff1c3b818f6b129a676e10d654c1a79fbc852c04a'],
  ['S-FIPS-1.0', 'Uses the host platform\'s CSPRNG (Node.js `crypto.randomFillSync` \u2192 OpenSSL). Not a validated module. The library performs no SP 800-90B entropy-source validation.',
    'c605f8209f4c87758e66b79bee4b4bfcbe77cfde7474da7301a44511a93cc3df'],
  ['S-FIPS-1.0-typographic', 'Uses the host platform\'s CSPRNG (Node.js `crypto.randomFillSync` \u2192 OpenSSL). **Not a validated module.** The library performs no SP 800-90B entropy-source validation.',
    '5791250b5981c58eec3df5664905d992124576f0ae208cb1b3b941ba5e0ed8b6'],
  ['S-PACK', 'The library is not \u0063ertified and cannot be.',
    'e9baf096f5c743271fb41c7fbe697beafc56e55d5f585ac7ea3fafc0d6e10552'],
];
export function verifyAllowPins() {
  const bad = ALLOW.filter(([, s, pin]) => createHash('sha256').update(s, 'utf8').digest('hex') !== pin).map(([id]) => id);
  return bad;
}

// Strict reading (C-10): an allowlisted string is honoured only when it is the whole line apart from
// comment / markdown wrapper tokens (quality L1121: the wrapper may vary). Before it: only wrapper tokens since
// the start of the line; after it: only wrapper tokens until the end of the line. Any other text on the line
// (e.g. "soon " before, " yet" after, a preceding sentence) means the occurrence is not honoured, so its stem is a hit.
const PREFIX_WRAP = /^(?:[\s>*_#|+\-"'`;]|\/\/|\/\*|<!--|\d+[.)])*$/;
const SUFFIX_WRAP = /^(?:[\s*_#|"'`;]|\*\/|-->)*$/;

function allowedSpans(line) {
  const spans = [];
  for (const [, s] of ALLOW) {
    let from = 0;
    for (;;) {
      const i = line.indexOf(s, from);
      if (i < 0) break;
      from = i + 1;
      const before = line.slice(0, i);
      const after = line.slice(i + s.length);
      const okBefore = PREFIX_WRAP.test(before);
      const okAfter = SUFFIX_WRAP.test(after);
      if (okBefore && okAfter) spans.push([i, i + s.length]);
    }
  }
  return spans;
}

export function lintText(name, text) {
  const hits = [];
  const lines = text.split('\n');
  lines.forEach((line, i) => {
    const spans = allowedSpans(line);
    for (const [id, re] of RULES) {
      re.lastIndex = 0;
      for (const m of line.matchAll(re)) {
        const a = m.index, b = m.index + m[0].length;
        if (EXEMPTABLE.has(id) && spans.some(([s, e]) => a >= s && b <= e)) continue;
        hits.push(`${name}:${i + 1}: ${id}: "${m[0]}"`);
      }
    }
  });
  return hits;
}

function walk(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

function scopeTexts() {
  const out = [];
  for (const n of readdirSync(ROOT)) {
    if (/^(README|RELEASE-NOTES|CHANGELOG|SECURITY)[^/]*\.md$/i.test(n)) out.push([n, readFileSync(join(ROOT, n), 'utf8')]);
  }
  for (const p of walk(join(ROOT, 'docs'))) out.push([relative(ROOT, p), readFileSync(p, 'utf8')]);
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  out.push(['package.json#description', String(pkg.description ?? '')]);
  out.push(['package.json#keywords', (pkg.keywords ?? []).join('\n')]);
  const rp = join(ROOT, 'REMOTE-PENDING.md');
  if (existsSync(rp)) {
    const m = readFileSync(rp, 'utf8').match(/<!-- CLAIMS-LINT-SCOPE:BEGIN -->([\s\S]*?)<!-- CLAIMS-LINT-SCOPE:END -->/);
    if (!m) { console.error('claims-lint: REMOTE-PENDING.md has no CLAIMS-LINT-SCOPE block'); process.exit(2); }
    out.push(['REMOTE-PENDING.md#repo-description-and-topics', m[1]]);
  }
  return out;
}

// Known-bad README fixture (QIU-07 / RQ-FC-13 / F-12): kept \u-escaped here and materialised only in scratch.
export const KNOWN_BAD_README = '# known-bad fixture\n\nThis library is \u0063\u0065\u0072\u0074\u0069\u0066\u0069\u0065\u0064.\n';

// C-10 near-miss cases (CPO-R97). Every case is built from the \u-escaped strings above or below and is
// materialised only in a scratch dir by --self-test / test/claims-lint.test.mjs. expect: 'clean' = 0 hits, 'red' = >= 1 hit.
const STEM = '\u0063ertif';
const swapAroundStem = (s) => s.replace(new RegExp(String.raw`(\w+) (${STEM}\w*)`), '$2 $1');
export function nearMissCases() {
  const c = [];
  const add = (id, text, expect) => c.push({ id, text, expect });
  for (const [id, s] of ALLOW) {
    add(`${id}: exact`, s, 'clean');
    add(`${id}: markdown quote wrapper`, `> ${s}`, 'clean');
    add(`${id}: bold wrapper`, `**${s}**`, 'clean');
    add(`${id}: list item`, `- ${s}`, 'clean');
    add(`${id}: whole-line upper case`, s.toUpperCase(), s.includes(STEM) ? 'red' : 'clean'); // no stem token -> nothing to flag
  }
  // Stem-bearing allowlisted strings: every near-miss must be red.
  for (const [id, s] of ALLOW.filter(([, t]) => t.includes(STEM))) {
    const k = s.indexOf(STEM);
    add(`${id}: one-char change in stem word`, s.replace(`${STEM}ied`, `${STEM}ies`), 'red');
    add(`${id}: one-char change in negation (o->0)`, s.slice(0, k - 3) + s.slice(k - 3, k).replace('o', '0') + s.slice(k), 'red');
    add(`${id}: first-char case flipped`, (s[0] === s[0].toUpperCase() ? s[0].toLowerCase() : s[0].toUpperCase()) + s.slice(1), 'red');
    add(`${id}: stem word capitalised`, s.replace(STEM, 'C' + STEM.slice(1)), 'red');
    if (s.endsWith('.')) add(`${id}: missing final period`, s.slice(0, -1), 'red');
    else add(`${id}: trailing period added`, `${s}.`, 'red');
    add(`${id}: comma removed / changed`, s.includes(',') ? s.replace(',', '') : s.replace('.', ','), 'red');
    add(`${id}: word swap around stem`, swapAroundStem(s), 'red');
    add(`${id}: extra word before stem`, s.slice(0, k) + 'yet ' + s.slice(k), 'red');
    add(`${id}: extra word after stem`, s.replace(new RegExp(`(${STEM}\\w*)`), '$1 yet'), 'red');
    add(`${id}: followed by 'yet' (no space-sentence)`, `${s} yet`, 'red');
    if (s.endsWith('.')) add(`${id}: 'yet' before final period`, `${s.slice(0, -1)} yet.`, 'red');
    add(`${id}: preceded by 'soon'`, `soon ${s}`, 'red');
    add(`${id}: preceded by 'Soon,'`, `Soon, ${s}`, 'red');
    add(`${id}: embedded mid-claim`, `It is ${s} until next year`, 'red');
    add(`${id}: exact plus later NIST claim on same line`, `${s} It is NIST-\u0063ertified.`, 'red');
    add(`${id}: preceded by another sentence on the same line`, `Pre-alpha. ${s}`, 'red');
    add(`${id}: followed by another sentence on the same line`, `${s} Pre-alpha.`, 'red');
    add(`${id}: exact plus later stem on next line`, `${s}\nThis library is \u0063ertified.`, 'red');
  }
  // S-R39 comment wrappers may vary (quality L1121).
  const r39 = ALLOW.find(([id]) => id === 'S-R39')[1];
  for (const [w, t] of [['//', `// ${r39}`], ['/* */', `/* ${r39} */`], ['#', `# ${r39}`], ['<!-- -->', `<!-- ${r39} -->`], [' * ', ` * ${r39}`]]) add(`S-R39: wrapper ${w}`, t, 'clean');
  add('S-R39: capitalised (Non-normative)', 'N' + r39.slice(1), 'red');
  add('S-R39: shorthand paraphrase', 'not \u0063ertified, not for real money', 'red');
  add('S-P1-short: E12 shorthand (lowercase, comma)', 'not \u0063ertified, not a validated module', 'red');
  add('paraphrase: never \u0063ertified', 'This library is never \u0063ertified.', 'red');
  add('paraphrase: \u0063ertifiable', 'This library is \u0063ertifiable.', 'red');
  add('paraphrase: \u0063ompliance', 'Designed for \u0063ompliance.', 'red');
  add('all allowlisted strings, one per line', ALLOW.map(([, s]) => s).join('\n'), 'clean');
  // FIPS: empty exception in 1.0.
  add('FIPS: bare token', '\u0046IPS', 'red');
  add('FIPS: lower case', 'see \u0066ips mode', 'red');
  add('FIPS: Node-docs citation (PLAN L625)', 'Node.js is not itself \u0046IPS validated', 'red');
  add('FIPS: negated 140-3', 'Not \u0046IPS 140-3 validated.', 'red');
  add('FIPS: after exact S-FIPS-1.0', `${ALLOW.find(([id]) => id === 'S-FIPS-1.0')[1]} No \u0046IPS mode.`, 'red');
  // align: unconditional.
  for (const w of ['\u0061lign', '\u0061ligned', '\u0061lignment', 'in \u0061lignment with GLI-19', 'the buffers \u0061lign perfectly', 'Not \u0061ligned with any standard.']) add(`align: ${w}`, w, 'red');
  // /drbg reserved sentence (PLAN L633): not allowlisted in 1.0.
  add('drbg reserved sentence (L633)', 'Implements HMAC_DRBG (SHA-256) as specified in NIST SP 800-90A Rev. 1, verified against NIST \u0043AVP known-answer test vectors. Not a validated module.', 'red');
  // C-14: the ARCHITECTURE.md disclaimer on the remote is not an allowlisted sentence.
  add('C-14: ARCHITECTURE.md disclaimer', '\u0043ertification applies to an operator\'s or supplier\'s complete system, never to this library.', 'red');
  // Known-bad shape stays red.
  add('known-bad fixture', KNOWN_BAD_README, 'red');
  return c;
}

export function runNearMiss() {
  const dir = mkdtempSync(join(tmpdir(), 'claims-lint-near-miss-'));
  const results = [];
  try {
    nearMissCases().forEach((t, i) => {
      const f = join(dir, `case-${String(i).padStart(3, '0')}.md`);
      writeFileSync(f, t.text);
      const hits = lintText(`scratch:case-${i}`, readFileSync(f, 'utf8'));
      const pass = t.expect === 'clean' ? hits.length === 0 : hits.length > 0;
      results.push({ ...t, hits, pass });
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return { results, scratchRemoved: !existsSync(dir) };
}

function main() {
  const badPins = verifyAllowPins();
  if (badPins.length) { console.error(`claims-lint: allow-list sha256 pin mismatch (needs a CPO verdict): ${badPins.join(', ')}`); process.exit(2); }
  const args = process.argv.slice(2);
  if (args[0] === '--self-test') {
    const dir = mkdtempSync(join(tmpdir(), 'claims-lint-fixture-'));
    const f = join(dir, 'README.md');
    writeFileSync(f, KNOWN_BAD_README);
    const hits = lintText('scratch:README.md', readFileSync(f, 'utf8'));
    rmSync(dir, { recursive: true, force: true });
    hits.forEach((h) => console.log(h));
    if (hits.length === 0) { console.error('claims-lint: known-bad fixture did NOT turn red (FAIL)'); process.exit(1); }
    console.log(`claims-lint: scratch known-bad fixture turned red with ${hits.length} hit(s) (expected, PASS); scratch removed`);
    const { results, scratchRemoved } = runNearMiss();
    const fails = results.filter((r) => !r.pass);
    fails.forEach((r) => console.error(`  FAIL ${r.id}: expected ${r.expect}, got ${r.hits.length} hit(s)`));
    console.log(`claims-lint: C-10 near-miss ${results.length - fails.length}/${results.length} PASS; scratch removed: ${scratchRemoved}`);
    process.exit(fails.length || !scratchRemoved ? 1 : 0);
  }
  if (args[0] === '--expect-red') {
    const f = args[1];
    const hits = lintText(f, readFileSync(f, 'utf8'));
    hits.forEach((h) => console.log(h));
    if (hits.length === 0) { console.error(`claims-lint: known-bad fixture ${f} did NOT turn red (FAIL)`); process.exit(1); }
    console.log(`claims-lint: known-bad fixture ${f} turned red with ${hits.length} hit(s) (expected, PASS)`);
    process.exit(0);
  }
  const texts = scopeTexts();
  const hits = texts.flatMap(([n, t]) => lintText(n, t));
  hits.forEach((h) => console.log(h));
  console.log(`claims-lint: ${texts.length} scope item(s), ${hits.length} hit(s)`);
  process.exit(hits.length ? 1 : 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
