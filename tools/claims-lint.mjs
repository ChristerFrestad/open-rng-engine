#!/usr/bin/env node
// Shared claims lint (PLAN R-16 / B10 / QIU-07 / RQ-FC-13; quality v5.5.4 CI 9, CI 36, CI 46). Zero dependencies.
// Scope (CPO-R100 F-16): claims surfaces ONLY: README*.md (any tracked, outside src/ and test/), docs/**, ARCHITECTURE*.md,
// SECURITY.md, NOTICE, release notes / CHANGELOG, package.json description + keywords, and the intended GitHub repo
// description/topics in REMOTE-PENDING.md between the CLAIMS-LINT-SCOPE markers. src/ and test/ are out of scope.
// LICENSE is NOT scanned (CPO-R97b (3), CPO-R99 LF-3, CPO-R100 CA-1): it is excluded by exact path 'LICENSE' plus
// sha256 cfc7749b…; if its bytes change the lint is red and the changed LICENSE is linted as content.
// Usage:  node tools/claims-lint.mjs                 -> lint the repo scope (exit 1 on any hit, 2 on a config error)
//         node tools/claims-lint.mjs --expect-red F  -> lint file F only, exit 0 only if it has >= 1 hit
//         node tools/claims-lint.mjs --self-test     -> known-bad fixtures + C-10 near-miss cases, materialised in scratch
// Matching (CPO-R97, R97b, R99, R100): a stem hit is exempt only on an allowlisted WHOLE line: after stripping comment or
// markdown wrappers the line is byte-exact one of the six configured strings; no trailing whitespace (space, tab, NBSP,
// CR); leading whitespace only as indentation before a wrapper marker. align*, FIPS, 800-90A, CAVP, CMVP and
// `cryptographic module` (hyphen/space/tab/line-break variants) are never exempt. validat* is exempt only on such a whole
// line or inside the closed sha-pinned phrase list in tools/claims-terms.json, and never on a line with a co-term.
// Allowlist config tools/claims-allowlist.json (LF-2): exact path + sha pin; each entry sha = the CPO pin; self-exempt
// only at that exact path with that exact sha. Any mismatch is a config error (exit 2), 0 lines exempted.
import { readFileSync, readdirSync, statSync, existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { licenseGuard, LICENSE_PATH } from './license-guard.mjs';

const ROOT = new URL('..', import.meta.url).pathname;
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
export const ALLOWLIST_PATH = 'tools/claims-allowlist.json';
export const ALLOWLIST_SHA256 = '3baac529361b534da38b8330631bbedf93335fca01d63ec6a3fcc5ad009a8e8b';
export const TERMS_PATH = 'tools/claims-terms.json';
export const TERMS_SHA256 = '3c5227c0a1e836e53c0cf5823d2f7d8181db986c0b98b9ef7f9c7e800ae030d4';
// CPO-R101 F-24: closed lab-name list v1, exact path + sha pin; additions need CPO review.
export const LAB_NAMES_PATH = 'tools/lab-names.txt';
export const LAB_NAMES_SHA256 = '1d9e087bdc3f3a945b52206fcdd999053742a5f548017704a123a83417f32dd4'; // CPO-R105: + BMMTestlabs (re-approval pending)
export const LAB_NAMES_COUNT = 46;
// CPO-R102 LF-10: closed authority co-term list v1 (regulators, standards bodies, lab/labs), exact path + sha pin.
export const AUTHORITY_PATH = 'tools/authority-terms.txt';
export const AUTHORITY_SHA256 = '43091c7aa6d1d76d6d955b6b9e4d191a0bfbbc5e497de77fbc169c07258540e1'; // CPO-R106: header-only reword of 5f4ff573 (non-# lines byte-identical)
export const AUTHORITY_COUNT = 36;
// CPO pins (rulings bdde9834 L118-L173; quality §8.19.2). Exactly these six ids; nothing else may be configured.
export const CPO_PINS = Object.freeze({
  'S-P1': '7efa5b3e0197f88a2431c0b789e452be169fc0e2710915f387fb5c515d87bf37',
  'S-P1-short': '3df21d8f1e9af56b213950311b61830029c7e7c2cb80c34fc56d13606f4f2d92',
  'S-R39': '21df984dabb4744ffbb8f45ff1c3b818f6b129a676e10d654c1a79fbc852c04a',
  'S-FIPS-1.0': 'c605f8209f4c87758e66b79bee4b4bfcbe77cfde7474da7301a44511a93cc3df',
  'S-FIPS-1.0-typographic': '5791250b5981c58eec3df5664905d992124576f0ae208cb1b3b941ba5e0ed8b6',
  'S-PACK': 'e9baf096f5c743271fb41c7fbe697beafc56e55d5f585ac7ea3fafc0d6e10552',
});
export const TERMS_PHRASES_EXPECTED = Object.freeze(['schema-validated', 'schema validator', 'schema validation']);

/** Load and verify the allowlist config bytes. Returns { allow: [[id, text, sha]], errors }. Fail closed. */
export function loadAllowlist(buf, path = ALLOWLIST_PATH) {
  const errors = [];
  if (path !== ALLOWLIST_PATH) errors.push(`allowlist: path ${JSON.stringify(path)} is not the exact config path`);
  if (!buf) return { allow: [], errors: [...errors, 'allowlist: config missing'] };
  const fsha = sha256(buf);
  if (fsha !== ALLOWLIST_SHA256) errors.push(`allowlist: config sha256 ${fsha} != pinned ${ALLOWLIST_SHA256} (needs a CPO verdict)`);
  let j;
  try { j = JSON.parse(buf.toString('utf8')); } catch { return { allow: [], errors: [...errors, 'allowlist: not JSON'] }; }
  const keysOk = (o, ks) => o && typeof o === 'object' && !Array.isArray(o) && Object.keys(o).length === ks.length && ks.every((k) => Object.prototype.hasOwnProperty.call(o, k));
  if (!keysOk(j, ['format', 'cpoVerdict', 'entries']) || j.format !== 'open-rng-engine/claims-allowlist/v1' || !Array.isArray(j.entries)) return { allow: [], errors: [...errors, 'allowlist: wrong shape'] };
  const ids = Object.keys(CPO_PINS);
  if (j.entries.length !== ids.length) errors.push(`allowlist: ${j.entries.length} entries, expected exactly ${ids.length}`);
  const seen = new Set();
  for (const e of j.entries) {
    if (!keysOk(e, ['id', 'sha256', 'text'])) { errors.push('allowlist: entry keys must be exactly id, sha256, text (no regex/prefix forms)'); continue; }
    if (!Object.prototype.hasOwnProperty.call(CPO_PINS, e.id)) { errors.push(`allowlist: unknown entry ${e.id}`); continue; }
    if (seen.has(e.id)) errors.push(`allowlist: duplicate entry ${e.id}`);
    seen.add(e.id);
    if (typeof e.text !== 'string' || sha256(Buffer.from(e.text, 'utf8')) !== CPO_PINS[e.id] || e.sha256 !== CPO_PINS[e.id]) errors.push(`allowlist: entry ${e.id} does not match its CPO sha256 pin`);
  }
  if (errors.length) return { allow: [], errors };
  return { allow: j.entries.map((e) => [e.id, e.text, e.sha256]), errors };
}

/** Load and verify the validat term config. Returns { phrases, coTerms, errors }. */
export function loadTerms(buf, path = TERMS_PATH) {
  const errors = [];
  if (path !== TERMS_PATH) errors.push('terms: not the exact config path');
  if (!buf) return { phrases: [], coTerms: [], errors: [...errors, 'terms: config missing'] };
  if (sha256(buf) !== TERMS_SHA256) errors.push(`terms: config sha256 ${sha256(buf)} != pinned ${TERMS_SHA256} (needs a CPO verdict)`);
  let j;
  try { j = JSON.parse(buf.toString('utf8')); } catch { return { phrases: [], coTerms: [], errors: [...errors, 'terms: not JSON'] }; }
  if (!j || j.format !== 'open-rng-engine/claims-terms/v1' || JSON.stringify(j.validatAllowedPhrases) !== JSON.stringify(TERMS_PHRASES_EXPECTED) || !Array.isArray(j.forbiddenCoTerms) || !j.forbiddenCoTerms.length) errors.push('terms: wrong shape or phrase set (closed: exactly the three CPO-R100 phrases)');
  if (errors.length) return { phrases: [], coTerms: [], errors };
  return { phrases: j.validatAllowedPhrases, coTerms: j.forbiddenCoTerms.map((p) => new RegExp(p, 'i')), errors };
}

/** Load and verify the lab-name list. Returns { names, errors }. Fail closed. */
export function loadLabNames(buf, path = LAB_NAMES_PATH) {
  return loadNameList(buf, path, { label: 'lab-names', path: LAB_NAMES_PATH, sha: LAB_NAMES_SHA256, count: LAB_NAMES_COUNT });
}
export function loadAuthorities(buf, path = AUTHORITY_PATH) {
  return loadNameList(buf, path, { label: 'authority-terms', path: AUTHORITY_PATH, sha: AUTHORITY_SHA256, count: AUTHORITY_COUNT });
}
function loadNameList(buf, path, pin) {
  const errors = [];
  const L = pin.label;
  if (path !== pin.path) errors.push(`${L}: not the exact list path`);
  if (!buf) return { names: [], errors: [...errors, `${L}: list missing`] };
  if (sha256(buf) !== pin.sha) errors.push(`${L}: sha256 ${sha256(buf)} != pinned ${pin.sha} (needs a CPO verdict)`);
  const names = [];
  for (const [i, l] of buf.toString('utf8').split('\n').entries()) {
    if (l === '' || l.startsWith('#')) continue;
    const m = /^([^|#]+)\|([^|]+:\d+)$/.exec(l);
    if (!m || m[1] !== m[1].trim()) { errors.push(`${L}: line ${i + 1} is not <name>|<source file:line>`); continue; }
    names.push(m[1]);
  }
  if (names.length !== pin.count) errors.push(`${L}: ${names.length} entries, expected ${pin.count}`);
  if (new Set(names.map((n) => n.toLowerCase())).size !== names.length) errors.push(`${L}: duplicate entry`);
  return errors.length ? { names: [], errors } : { names, errors };
}
// Unicode-aware separators: any whitespace (JS \s covers NBSP, U+2000-U+200A, U+202F, U+205F, U+3000, U+FEFF), soft hyphen,
// zero-width chars, and hyphen/dash variants (CPO-R100 F-19, CPO-R101 LF-8).
export const SEP_CLASS = String.raw`[\s\u00ad\u180e\u200b-\u200d\u2060\u2010-\u2015\u2212\-]`;
const escRe = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// CPO-R104 D-2: named entries match by PREFIX, case-insensitive: left boundary = no preceding letter or digit, NO right
// boundary (BMMTestlabs, GLI19, ITL21, gli_11, iTech_Labs, UKGCs are hits). The generic words lab/labs stay whole-word (D-3).
export const GENERIC_LAB_WORDS = new Set(['lab', 'labs']);
// CPO-R105 G-11: entries of <= 3 characters (trimmed) also need no following LETTER (GLI19, ITL21, gli_11 stay red; glitch,
// game, each, isObj are green). Entries of >= 4 characters stay bare-prefix (R104 D-2).
const entrySrc = (n) => {
  if (GENERIC_LAB_WORDS.has(n.toLowerCase())) return String.raw`(?<![A-Za-z0-9_])${escRe(n)}(?![A-Za-z0-9_])`;
  const body = String.raw`(?<![A-Za-z0-9])${n.trim().split(/\s+/).map(escRe).join(String.raw`\s+`)}`;
  return [...n.trim()].length <= 3 ? `${body}(?![A-Za-z])` : body;
};
export const labNameRe = (n) => new RegExp(entrySrc(n), 'i');

const readMaybe = (p) => { try { return readFileSync(p); } catch { return null; } };
const A = loadAllowlist(readMaybe(join(ROOT, ALLOWLIST_PATH)));
const T = loadTerms(readMaybe(join(ROOT, TERMS_PATH)));
const L = loadLabNames(readMaybe(join(ROOT, LAB_NAMES_PATH)));
const AU = loadAuthorities(readMaybe(join(ROOT, AUTHORITY_PATH)));
export const LAB_NAMES = L.names;
export const AUTHORITIES = AU.names;
export const CONFIG_ERRORS = [...A.errors, ...T.errors, ...L.errors, ...AU.errors];
export const ALLOW = A.allow;
const PHRASES = T.phrases;
const CO_TERMS = [...T.coTerms, ...L.names.map(labNameRe), ...AU.names.map(labNameRe)];

// CPO-R104 G-6: the comparative rule anchors on lab, labs and every lab-names and authority-terms entry (prefix match, D-2).
const ANCHOR = `(?:${[...new Set(['lab', 'labs', ...L.names, ...AU.names])].sort((a, b) => b.length - a.length).map(entrySrc).join('|')})`;
const COMPAR = String.raw`(?:exceed\w*|above|beyond|surpass\w*|meets)`;
const NEAR = String.raw`(?:\W+\w+){0,4}\W+`; // within 5 words
export const RULES = [
  // CPO-R104 G-4: no left boundary for certif, complian and align (they match like validat: uncertified, misaligned are hits).
  ['R16-certif', /[A-Za-z0-9_]*\u0063ertif\w*/gi],
  ['R16-complian', /[A-Za-z0-9_]*\u0063omplian\w*/gi],
  ['R16-align', /[A-Za-z0-9_]*\u0061lign\w*/gi],
  ['R16-comparative', new RegExp(String.raw`\b${COMPAR}${NEAR}${ANCHOR}|${ANCHOR}\w*${NEAR}${COMPAR}\b`, 'gi')],
  ['R16-nist-claim', /\bNIST[- ](?:\u0063ertified|\u0061pproved|\u0063ompliant)\b/gi],
  ['R16-approved', /\b\u0061pproved\b/gi],
  ['R16-gold-standard', /\b\u0067old\s+standard\b/gi],
  ['R16-fips', /\b\u0046IPS\b/gi],
  ['R16-badge', /!\[[^\]]*(?:GLI|NIST)[^\]]*\]\([^)]*\)|!\[[^\]]*\]\([^)]*(?:GLI|NIST)[^)]*\)|<img\b[^>]*(?:GLI|NIST)[^>]*>/gi],
  ['C10-drbg-reserved', /(?<![0-9])800-90A\b|\b\u0043AVP\b/gi], // CPO-R97b (2)
  ['C10-validat', /[A-Za-z0-9_]*\u0076alidat\w*/gi], // CPO-R99 O-68 (no leading boundary: un-/in-/_-prefixed forms are hits, quality M-124); term exceptions per CPO-R100 F-16
  ['C10-crypto-module', new RegExp(String.raw`\b\u0063ryptographic${SEP_CLASS}+modules?\b`, 'gi')], // CPO-R99 O-68; variants CPO-R100 F-19
  ['C10-cmvp', /\b\u0043MVP\b/gi], // CPO-R99 O-68
];
// Exempt only on an allowlisted whole line (LF-1: certif in S-P1, S-P1-short, S-R39, S-PACK; validat on the S-P1 /
// S-P1-short / S-FIPS-1.0 lines that contain it). Everything else is never exempt.
const EXEMPTABLE = new Set(['R16-certif', 'R16-complian', 'C10-validat']);

// Wrapper grammar (CPO-R97b (1); O-71; F-14 CONFIRMED). Prefix: zero or more wrapper markers, each optionally preceded by
// indentation; bare indentation is NOT a wrapper. Suffix: zero or more closing markers. Quotes, backticks, pipes and any
// other text are not wrappers. Trailing whitespace (incl. NBSP and CR) on the line means it is not allowlisted.
const PREFIX_WRAP = /^(?:[ \t]*(?:\/\/+|\/\*+|\*{1,2}|_{1,2}|#{1,6}|<!--|>|[-+]|\d+[.)])[ \t]*)*$/;
const SUFFIX_WRAP = /^(?:[ \t]*(?:\*\/|\*{1,2}|_{1,2}|-->))*$/;
const TRAILING_WS = /[ \t\u00a0\r]$/;

/** The allowlist id the whole line is, or null. */
export function allowlistedLine(line) {
  if (TRAILING_WS.test(line)) return null;
  for (const [id, s] of ALLOW) {
    const i = line.indexOf(s);
    if (i < 0) continue;
    if (line.indexOf(s, i + 1) >= 0) continue;
    const before = line.slice(0, i);
    const after = line.slice(i + s.length);
    if (PREFIX_WRAP.test(before) && SUFFIX_WRAP.test(after)) return id; // bare indentation fails PREFIX_WRAP
  }
  return null;
}

function validatPhraseOk(line, a, b) {
  for (const p of PHRASES) {
    let k = line.indexOf(p);
    while (k >= 0) {
      const end = k + p.length;
      // CPO-R101 F-23: strict boundaries; no letter, digit, hyphen or underscore on either side.
      const leftOk = k === 0 || !/[A-Za-z0-9_-]/.test(line[k - 1]);
      const rightOk = end === line.length || !/[A-Za-z0-9_-]/.test(line[end]);
      if (leftOk && rightOk && a >= k && b <= end) return !CO_TERMS.some((re) => re.test(line));
      k = line.indexOf(p, k + 1);
    }
  }
  return false;
}

const CROSS_A = new RegExp(String.raw`\b\u0063ryptographic${SEP_CLASS}*$`, 'i');
const CROSS_B = new RegExp(String.raw`^(?:${SEP_CLASS}|[>*#/|])*modules?\b`, 'i');
export function lintText(name, text) {
  if (CONFIG_ERRORS.length) return CONFIG_ERRORS.map((e) => `${name}:0: CONFIG: ${e}`);
  const hits = [];
  const lines = text.split('\n');
  lines.forEach((line, i) => {
    const allowed = allowlistedLine(line);
    for (const [id, re] of RULES) {
      re.lastIndex = 0;
      for (const m of line.matchAll(re)) {
        const a = m.index, b = m.index + m[0].length;
        if (allowed && EXEMPTABLE.has(id)) continue;
        if (id === 'C10-validat' && validatPhraseOk(line, a, b)) continue;
        hits.push(`${name}:${i + 1}: ${id}: "${m[0]}"`);
      }
    }
    // `cryptographic` at the end of one line and `module` at the start of the next (F-19).
    if (CROSS_A.test(line) && i + 1 < lines.length && CROSS_B.test(lines[i + 1])) hits.push(`${name}:${i + 1}: C10-crypto-module: "<line break>"`);
  });
  return hits;
}

// ---------- scope, exemptions, surfaces ----------
const isUnder = (p, d) => p.startsWith(d);
export function isClaimsSurface(path) {
  if (/(^|\/)node_modules\//.test(path)) return false; // installed devDependencies are never claims surfaces or shipped source
  if (isUnder(path, 'src/') || isUnder(path, 'test/') || isUnder(path, 'tests/')) return false;
  if (/(^|\/)README[^/]*\.md$/i.test(path)) return true;
  if (isUnder(path, 'docs/')) return true;
  if (/^(ARCHITECTURE|SECURITY)[^/]*\.md$/i.test(path)) return true;
  // CPO-R101 LF-5: CHANGELOG, CONTRIBUTING and release notes at any depth (any extension), plus release-notes dirs.
  if (/(^|\/)(CHANGELOG|CHANGES|HISTORY|CONTRIBUTING|RELEASE[-_ ]?NOTES|RELEASES)([-_.][^/]*)?$/i.test(path)) return true;
  if (/(^|\/)(release-notes|releases)\//i.test(path) || isUnder(path, '.github/release')) return true;
  if (path === 'NOTICE') return true;
  if (/^(LICEN[CS]E|COPYING)[^/]*$/i.test(path) && path !== LICENSE_PATH) return true; // licence-like siblings: never exempt
  return false;
}
// CPO-R101 LF-6: every package.json at any path (node_modules is never tracked/scanned).
const isPkg = (p) => /(^|\/)package\.json$/.test(p) && !/(^|\/)node_modules\//.test(p);
/** Every string value in a parsed JSON document, with a JSON-pointer-like path. */
/** Every object KEY at any depth, with its JSON-pointer-like path (CPO-R104 D-1: keys are in claims scope too). */
export function jsonKeys(v, at = '') {
  if (Array.isArray(v)) return v.flatMap((x, i) => jsonKeys(x, `${at}/${i}`));
  if (v && typeof v === 'object') return Object.entries(v).flatMap(([k, x]) => [[`${at}/${k}`, k], ...jsonKeys(x, `${at}/${k}`)]);
  return [];
}
export function jsonStrings(v, at = '') {
  if (typeof v === 'string') return [[at || '/', v]];
  if (Array.isArray(v)) return v.flatMap((x, i) => jsonStrings(x, `${at}/${i}`));
  if (v && typeof v === 'object') return Object.entries(v).flatMap(([k, x]) => jsonStrings(x, `${at}/${k}`));
  return [];
}
// CPO-R101 F-21: shipped source = src/** and packages/*/src/** (what the build ships); built output = dist/** and
// packages/*/dist/** (no build exists yet: the built-output half is reported PENDING until one does).
export const isShippedSource = (p) => /^(src|packages\/[^/]+\/src)\/.*\.(m?ts|m?js|cjs|cts)$/.test(p) && !/\.d\.[mc]?ts$/.test(p);
export const isBuiltOutput = (p) => /^(dist|packages\/[^/]+\/dist)\//.test(p);
export const isDts = (p) => /\.d\.[mc]?ts$/.test(p) && !/^(test|tests)\//.test(p) && !/(^|\/)node_modules\//.test(p);
/**
 * Minimal JS/TS lexer: returns every string literal (decoded, incl. template text) and every JSDoc block (/** ... *\/),
 * each with its 1-based start line. Regex literals are skipped. Used for F-21 (error/reason strings, JSDoc).
 */
export function extractCodeText(src) {
  const strings = [], jsdoc = [];
  let i = 0, line = 1, prev = '';
  const n = src.length;
  const decode = (raw) => { try { return JSON.parse(`"${raw.replace(/\\'/g, "'").replace(/\\`/g, '`').replace(/\\\$/g, '$').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\\(?!["\\/bfnrtu])/g, '')}"`); } catch { return raw; } };
  while (i < n) {
    const c = src[i];
    if (c === '\n') { line++; i++; continue; }
    if (/\s/.test(c)) { i++; continue; }
    if (c === '/' && src[i + 1] === '/') { while (i < n && src[i] !== '\n') i++; continue; }
    if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2); const stop = end < 0 ? n : end + 2;
      const body = src.slice(i, stop);
      if (src[i + 2] === '*' && src[i + 3] !== '/') jsdoc.push({ line, text: body });
      line += (body.match(/\n/g) || []).length; i = stop; continue;
    }
    if (c === '"' || c === "'") {
      const start = line; let j = i + 1, raw = '';
      while (j < n && src[j] !== c && src[j] !== '\n') { if (src[j] === '\\') { raw += src[j] + (src[j + 1] ?? ''); j += 2; } else raw += src[j++]; }
      strings.push({ line: start, value: decode(raw) }); i = j + 1; prev = 'x'; continue;
    }
    if (c === '`') {
      let j = i + 1, raw = '', start = line, depth = 0;
      while (j < n) {
        if (src[j] === '\\') { raw += src[j] + (src[j + 1] ?? ''); j += 2; continue; }
        if (src[j] === '`') break;
        if (src[j] === '$' && src[j + 1] === '{') { // skip the expression (nested braces/strings kept simple)
          strings.push({ line: start, value: decode(raw) }); raw = ''; depth = 1; j += 2;
          while (j < n && depth) { if (src[j] === '{') depth++; else if (src[j] === '}') depth--; else if (src[j] === '\n') line++; j++; }
          start = line; continue;
        }
        if (src[j] === '\n') line++;
        raw += src[j++];
      }
      strings.push({ line: start, value: decode(raw) }); i = j + 1; prev = 'x'; continue;
    }
    if (c === '/' && (prev === '' || /[(,=:[!&|?{};+\-*%<>~^]$/.test(prev) || /\b(return|typeof|case|throw|in|of|void|delete|new)$/.test(prev))) {
      let j = i + 1, cls = false;
      while (j < n && src[j] !== '\n') { if (src[j] === '\\') { j += 2; continue; } if (src[j] === '[') cls = true; else if (src[j] === ']') cls = false; else if (src[j] === '/' && !cls) break; j++; }
      i = j + 1; while (i < n && /[a-z]/i.test(src[i])) i++; prev = 'x'; continue;
    }
    if (/[A-Za-z0-9_$]/.test(c)) { let j = i; while (j < n && /[A-Za-z0-9_$]/.test(src[j])) j++; prev = src.slice(i, j); i = j; continue; }
    prev = c; i++;
  }
  return { strings, jsdoc };
}
/** Lint the adopter-visible text of one code file: every string literal (error/reason strings are a subset) and JSDoc. */
export function lintCode(path, text) {
  const { strings, jsdoc } = extractCodeText(text);
  const hits = [];
  for (const s of strings) hits.push(...lintText(path, s.value).map((h) => h.replace(`${path}:`, `${path}:${s.line}+string:`)));
  for (const d of jsdoc) hits.push(...lintText(path, d.text).map((h) => h.replace(/^([^:]+):(\d+):/, (_, a, b) => `${a}:${d.line + Number(b) - 1}:jsdoc:`)));
  return hits;
}
/** Config self-exemption (LF-2): exact path AND exact pinned sha. Anything else is linted as content. */
export function selfExempt(path, buf) {
  if (path === ALLOWLIST_PATH) return sha256(buf) === ALLOWLIST_SHA256;
  if (path === TERMS_PATH) return sha256(buf) === TERMS_SHA256;
  if (path === LAB_NAMES_PATH) return sha256(buf) === LAB_NAMES_SHA256;
  if (path === AUTHORITY_PATH) return sha256(buf) === AUTHORITY_SHA256;
  return false;
}
/** Lint one repo-relative file with the exemptions applied (used by --file and the LF-2 tests). */
export function lintFile(path, buf) {
  if (selfExempt(path, buf)) return [];
  return lintText(path, buf.toString('utf8'));
}
const SP1 = () => (ALLOW.find(([id]) => id === 'S-P1') ?? [])[1];
export const P8_README_PATH = 'npm-reserved/README.md';

/** O-67 / CPO-R100 F-17: S-P1 presence on the required surfaces. Returns [{surface, ok, detail}]. */
export function p1Presence(files) {
  const out = [];
  const s = SP1();
  const text = (p) => (files.has(p) ? files.get(p).toString('utf8') : null);
  const readme = text('README.md');
  if (readme === null) out.push({ surface: 'README.md', ok: false, detail: 'missing' });
  else {
    const lines = readme.split('\n');
    const end = lines.findIndex((l, i) => i > 0 && /^##\s/.test(l));
    const lead = end < 0 ? lines : lines.slice(0, end);
    const ok = lead.some((l) => allowlistedLine(l) === 'S-P1');
    out.push({ surface: 'README.md (lead, before the first ## heading)', ok, detail: ok ? 'single-line byte-exact S-P1' : 'no single-line byte-exact S-P1 in the lead' });
  }
  const p8 = text(P8_README_PATH);
  out.push({ surface: `P8 reserved npm README (${P8_README_PATH})`, ok: p8 === null ? null : p8.split('\n').some((l) => allowlistedLine(l) === 'S-P1'), detail: p8 === null ? 'not tracked in this repo (published artefact; checked read-only outside the lint)' : 'tracked copy checked' });
  const pkg = text('package.json');
  let desc = null;
  try { desc = pkg === null ? null : JSON.parse(pkg).description; } catch { desc = null; }
  out.push({ surface: 'package.json description', ok: desc === s, detail: desc === s ? 'equals S-P1' : 'does not equal S-P1 exactly' });
  const rp = text('REMOTE-PENDING.md');
  const blk = rp && rp.match(/<!-- CLAIMS-LINT-SCOPE:BEGIN -->\n([\s\S]*?)<!-- CLAIMS-LINT-SCOPE:END -->/);
  const dl = blk ? blk[1].split('\n').find((l) => l.startsWith('description: ')) : null;
  const rdesc = dl ? dl.slice('description: '.length) : null;
  out.push({ surface: 'repo description (REMOTE-PENDING scope block)', ok: rdesc === s, detail: rdesc === s ? 'equals S-P1' : 'does not equal S-P1 exactly' });
  return out;
}

/** O-70 + CPO-R100 LF-4: every docs/examples/ file has the whole-line S-R39 on lines 1-5, before any code token. */
const COMMENT_ONLY = /^\s*(?:$|#!|\/\/|\/\*|\*|#|<!--|-->)/;
export function r39Header(path, text) {
  const lines = text.split('\n');
  const k = lines.findIndex((l) => allowlistedLine(l) === 'S-R39');
  if (k < 0) return `${path}:0: CI36-r39-header: no whole-line S-R39 header`;
  if (k > 4) return `${path}:${k + 1}: CI36-r39-header: S-R39 header after line 5`;
  const code = lines.slice(0, k).findIndex((l) => !COMMENT_ONLY.test(l));
  if (code >= 0) return `${path}:${code + 1}: CI36-r39-header: code token before the S-R39 header`;
  return null;
}

/** Lint a whole tree. files: Map<repo-relative path, Buffer>. */
// M-122: exact-path exemptions and scanned paths must be canonical repo-relative paths; tracked symlinks are red
// (a symlink could point an exempt path at other bytes or escape the repo).
export const nonCanonicalPath = (p) => p === '' || p.startsWith('/') || p.startsWith('./') || p.endsWith('/') || p.includes('\\') || p.includes('//') || p.split('/').some((seg) => seg === '.' || seg === '..');
// M-130: .gitattributes must force LF for text files.
export const GITATTR_LF = /^\*\s+(?:text=auto\s+eol=lf|text\s+eol=lf|eol=lf|text=auto\s+eol=lf\s+.*)\s*$/m;
export function lintTree(files, built = new Map(), { symlinks = new Set() } = {}) {
  const hits = [];
  let codeFiles = 0, dtsFiles = 0;
  for (const p of files.keys()) if (nonCanonicalPath(p)) hits.push(`${p}:0: M122-path: non-canonical path (./, .., //, trailing slash or absolute)`);
  // CPO-R104 G-10: any tracked path under node_modules/ fails (check:ph0 runs this lint on the tracked tree).
  for (const p of files.keys()) if (/(^|\/)node_modules\//.test(p)) hits.push(`${p}:0: G10-node-modules: tracked path under node_modules/`);
  for (const p of symlinks) hits.push(`${p}:0: M122-symlink: tracked symlink (exempt paths and scanned files must be regular files)`);
  if (files.has('package.json')) {
    const ga = files.get('.gitattributes');
    if (!ga) hits.push('.gitattributes:0: M130-eol: missing (text must be forced to LF)');
    else if (!GITATTR_LF.test(ga.toString('utf8'))) hits.push('.gitattributes:0: M130-eol: no LF rule for text files (* text=auto eol=lf)');
  }
  if (CONFIG_ERRORS.length) return { hits: CONFIG_ERRORS.map((e) => `CONFIG: ${e}`), report: { config: 'ERROR' } };
  let scoped = 0;
  for (const [p, b] of files) {
    if (selfExempt(p, b)) continue;
    if (isClaimsSurface(p)) {
      scoped++;
      const t = b.toString('utf8');
      hits.push(...lintText(p, t));
      if (t.includes('\r')) hits.push(`${p}:0: M130-crlf: CR line ending on a claims surface`);
    }
    if (isPkg(p)) {
      let j;
      try { j = JSON.parse(b.toString('utf8')); } catch { hits.push(`${p}:0: CONFIG: package.json does not parse`); continue; }
      scoped++;
      for (const [at, v] of jsonStrings(j)) hits.push(...lintText(`${p}#${at}`, v)); // every string value (LF-6)
      for (const [at, k] of jsonKeys(j)) hits.push(...lintText(`${p}#${at}(key)`, k)); // every key, any depth (CPO-R104 D-1)
    }
    if (isUnder(p, 'docs/examples/')) { const h = r39Header(p, b.toString('utf8')); if (h) hits.push(h); }
    if (isDts(p)) { dtsFiles++; hits.push(...lintText(p, b.toString('utf8'))); } // shipped .d.ts incl. JSDoc (F-21)
    else if (isShippedSource(p)) { codeFiles++; hits.push(...lintCode(p, b.toString('utf8'))); } // error/reason strings + JSDoc (F-21)
  }
  for (const [p, b] of built) { // built output (F-21): .d.ts whole, .js string literals + JSDoc
    if (/\.d\.[mc]?ts$/.test(p)) hits.push(...lintText(p, b.toString('utf8')));
    else if (/\.[mc]?js$/.test(p)) hits.push(...lintCode(p, b.toString('utf8')));
  }
  const rp = files.get('REMOTE-PENDING.md');
  if (rp) {
    const m = rp.toString('utf8').match(/<!-- CLAIMS-LINT-SCOPE:BEGIN -->([\s\S]*?)<!-- CLAIMS-LINT-SCOPE:END -->/);
    if (!m) hits.push('REMOTE-PENDING.md:0: CONFIG: no CLAIMS-LINT-SCOPE block');
    else {
      // Field values are linted as values (like package.json): `description: <value>` / `topics: a, b, c`.
      scoped++;
      const fields = m[1].split('\n').filter((l) => l.trim() !== '');
      for (const l of fields) {
        const fm = /^(description|topics): (.*)$/.exec(l);
        if (!fm) { hits.push(`REMOTE-PENDING.md#scope:0: CONFIG: unexpected scope-block line ${JSON.stringify(l.slice(0, 40))}`); continue; }
        const vals = fm[1] === 'topics' ? fm[2].split(', ') : [fm[2]];
        hits.push(...lintText(`REMOTE-PENDING.md#repo-${fm[1]}`, vals.join('\n')));
      }
    }
  }
  // LICENSE: not scanned when unmodified (exact path + sha); red and linted as content when changed or missing.
  let lic = { detail: 'not in tree' };
  if (files.has(LICENSE_PATH) || files.has('package.json')) {
    lic = licenseGuard(LICENSE_PATH, files.get(LICENSE_PATH) ?? null);
    if (lic.red) { hits.push(`LICENSE:0: LF3-license-altered: ${lic.detail}`); if (files.has(LICENSE_PATH)) hits.push(...lintText(LICENSE_PATH, files.get(LICENSE_PATH).toString('utf8'))); }
  }
  const p1 = files.has('package.json') ? p1Presence(files) : [];
  for (const r of p1) if (r.ok === false) hits.push(`${r.surface}:0: O67-p1-presence: ${r.detail}`);
  return { hits, report: { scoped, codeFiles, dtsFiles, builtOutput: built.size ? `${built.size} built file(s) scanned` : 'PENDING (no build output: dist/ absent)', license: lic.detail, p1, allowlist: ALLOWLIST_SHA256.slice(0, 8), terms: TERMS_SHA256.slice(0, 8) } };
}

/** Built output on disk (untracked, gitignored dist/). Empty Map when no build exists. */
export function builtFiles(root) {
  const out = new Map();
  const walk = (rel) => {
    const abs = join(root, rel);
    if (!existsSync(abs)) return;
    for (const e of readdirSync(abs, { withFileTypes: true })) {
      const r = `${rel}/${e.name}`;
      if (e.isDirectory()) walk(r); else if (e.isFile()) out.set(r, readFileSync(join(root, r)));
    }
  };
  walk('dist');
  if (existsSync(join(root, 'packages'))) for (const d of readdirSync(join(root, 'packages'))) walk(`packages/${d}/dist`);
  return out;
}

/** Tracked symlinks (index mode 120000). */
export function trackedSymlinks(root) {
  const out = execFileSync('git', ['ls-files', '-s', '-z'], { cwd: root }).toString('utf8').split('\0').filter(Boolean);
  return new Set(out.filter((l) => l.startsWith('120000 ')).map((l) => l.split('\t')[1]));
}

function trackedFiles(root) {
  const out = execFileSync('git', ['ls-files', '--cached', '-z'], { cwd: root }).toString('utf8').split('\0').filter(Boolean);
  // existsSync/statSync follow links; a dangling or directory-target symlink is skipped here and reported by trackedSymlinks.
  return new Map(out.filter((p) => existsSync(join(root, p)) && statSync(join(root, p)).isFile()).map((p) => [p, readFileSync(join(root, p))]));
}

// ---------- known-bad fixtures (escaped; materialised only in scratch) ----------
export const KNOWN_BAD_README = '# known-bad fixture\n\nThis library is \u0063\u0065\u0072\u0074\u0069\u0066\u0069\u0065\u0064.\n';
/** Known-bad allowlist config: the real config plus a seventh, unreviewed string. Must fail closed and lint red. */
export function knownBadAllowlistConfig(realBuf) {
  const j = JSON.parse(realBuf.toString('utf8'));
  j.entries.push({ id: 'S-EXTRA', sha256: '0'.repeat(64), text: 'This library is \u0063\u0065\u0072\u0074\u0069\u0066\u0069\u0065\u0064.' });
  return Buffer.from(`${JSON.stringify(j, null, 2)}\n`);
}
/** Known-bad terms config: adds a phrase that would exempt module wording. */
export function knownBadTermsConfig(realBuf) {
  const j = JSON.parse(realBuf.toString('utf8'));
  j.validatAllowedPhrases.push('\u0076alidated module');
  return Buffer.from(`${JSON.stringify(j, null, 2)}\n`);
}
// C-10 near-miss cases (CPO-R97). Every case is built from the \u-escaped strings above or below and is
// materialised only in a scratch dir by --self-test / test/claims-lint.test.mjs. expect: 'clean' = 0 hits, 'red' = >= 1 hit.
const STEM = '\u0063ertif';
const VSTEM = '\u0076alidat';
const swapAroundStem = (s) => s.replace(new RegExp(String.raw`(\w+) (${STEM}\w*)`), '$2 $1');
export function nearMissCases() {
  const c = [];
  const add = (id, text, expect) => c.push({ id, text, expect });
  for (const [id, s] of ALLOW) {
    add(`${id}: exact`, s, 'clean');
    add(`${id}: markdown quote wrapper`, `> ${s}`, 'clean');
    add(`${id}: bold wrapper`, `**${s}**`, 'clean');
    add(`${id}: list item`, `- ${s}`, 'clean');
    add(`${id}: whole-line upper case`, s.toUpperCase(), 'red'); // every string carries certif or validat
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
  // CPO-R97b (1): strict whole-line reading. A stem-bearing allowlisted sentence wrapped across lines is a hit,
  // at every space. Single exception, by construction: S-P1 split exactly before its last two sentences leaves
  // line 2 == S-P1-short (itself allowlisted, whole line) and line 1 with no stem token, so there is nothing to flag.
  for (const [id, s] of ALLOW.filter(([, t]) => t.includes(STEM) || t.includes(VSTEM))) {
    const short = ALLOW.find(([i]) => i === 'S-P1-short')[1];
    for (let j = 0; j < s.length; j++) {
      if (s[j] !== ' ') continue;
      const wrapped = `${s.slice(0, j)}\n${s.slice(j + 1)}`;
      const benign = id === 'S-P1' && s.slice(j + 1) === short;
      add(`${id}: wrapped across lines at col ${j}${benign ? ' (line 2 is S-P1-short alone)' : ''}`, wrapped, benign ? 'clean' : 'red');
    }
  }
  const p1 = ALLOW.find(([i]) => i === 'S-P1')[1];
  add('S-P1: must sit on one line (markdown soft wrap mid-sentence)', p1.replace(' evaluation.', '\nevaluation.').replace('Not \u0063ertified.', 'Not\n\u0063ertified.'), 'red');
  add('S-P1: indented continuation line', p1.replace(' Not \u0063ertified.', '\n  Not \u0063ertified.').replace(' Not a validated', ' Not a\n  validated'), 'red');
  // CPO-R97b (2): S-FIPS-1.0 cites SP 800-90B and stays green; 800-90A and CAVP are hits.
  for (const id of ['S-FIPS-1.0', 'S-FIPS-1.0-typographic']) {
    const f = ALLOW.find(([i]) => i === id)[1];
    add(`${id}: SP 800-90B citation stays green`, f, 'clean');
    add(`${id}: 800-90B -> 800-90A is a hit`, f.replace('800-90B', '800-90A'), 'red');
    add(`${id}: 800-90B -> NIST SP 800-90A is a hit`, f.replace('SP 800-90B', 'NIST SP 800-90A'), 'red');
    add(`${id}: plus CAVP claim is a hit`, `${f} Tested with \u0043AVP vectors.`, 'red');
  }
  add('800-90A: bare', 'Implements SP800-90A.', 'red');
  add('800-90A: lower case', 'see sp 800-90a', 'red');
  add('CAVP: bare', '\u0043AVP', 'red');
  add('800-90B sentence fragment alone: validat outside an allowlisted line (O-68)', 'The library performs no SP 800-90B entropy-source \u0076alidation.', 'red');
  add('800-90B citation with no stem stays green', 'The library performs no SP 800-90B entropy-source checks.', 'clean');
  // ===== quality v5.5.3 §8.19.4 / v5.5.4 §8.20.2 mutant plants (lint scope). Ids in the case names. =====
  const g = (i) => ALLOW.find(([x]) => x === i)[1];
  const P1 = g('S-P1'), SH = g('S-P1-short'), R39 = g('S-R39'), FI = g('S-FIPS-1.0'), FT = g('S-FIPS-1.0-typographic'), PK = g('S-PACK');
  const C = '\u0063ertified', Cc = '\u0043ertified', V = '\u0076alidated', VAL = '\u0076alidat';
  // M-89: S-P1-short / tail near-misses (standalone and inside S-P1)
  const m89 = [
    `Not ${C.slice(0, 6)}ed. Not a ${V} module.`, `Not ${C}d. Not a ${V} module.`, `Not ${C}. Not a ${VAL}d module.`,
    `not ${C}. Not a ${V} module.`, `Not ${Cc}. Not a ${V} module.`, SH.toUpperCase(),
    SH.replace('. ', '.  '), SH.replace('. ', '.\t'), SH.replace('. ', '.\u00a0'), SH.replace('. ', '.\n'),
    `Not ${C}, not a ${V} module.`, `Not ${C}; Not a ${V} module.`, `Not ${C}! Not a ${V} module.`, SH.slice(0, -1),
    `Not ${C}.`, `Not ${C}. Not a ${VAL}ed`, `Not yet ${C}. Not a ${V} module.`, `Not ${C}. Not a fully ${V} module.`,
    `**Not ${C}.** Not a ${V} module.`, `Our status: ${SH} See docs.`, `"${SH}"`, `Soon: ${SH}`,
  ];
  m89.forEach((t, i) => add(`M-89 plant ${i}`, t, 'red'));
  for (const s of [P1.replace(SH, '') + m89[0], P1.replace(SH, '') + m89[3]]) add('M-89 plant inside S-P1', s, 'red');
  [P1, SH, `**${P1}**`, `- ${SH}`, `**${SH}**`].forEach((t, i) => add(`M-89 control ${i}`, t, 'clean'));
  // M-90: S-P1 head near-misses on one line (red on the lint)
  [P1.replace('TypeScript', 'Typescript'), P1.replace('Open-source', 'open-source'), P1.replace('Open-source', 'Open source'),
    P1.replace("licensee's", 'licensee\u2019s'), P1.replace('Node.js', 'Node.JS'), P1.replace(' lab ', ' labs '), P1.replace('independent ', ''),
    P1.replace('library', 'small library')].forEach((t, i) => add(`M-90 one-line plant ${i}`, t, 'red'));
  // M-91: matcher errors (prefix/fragment, case-insensitive, normalised whitespace, joined lines, shorthand alias)
  [`Not ${C}.`, SH.toUpperCase(), SH.replace('. ', '.\u00a0'), P1.replace("licensee's ", "licensee's\n"), `not ${C}, not a ${V} module`].forEach((t, i) => add(`M-91 plant ${i}`, t, 'red'));
  add('M-91 control: standalone S-P1-short', SH, 'clean');
  // M-92: S-R39 near-misses + controls
  ['N' + R39.slice(1), R39.replace('non-normative', 'non normative'), R39.replace(/, /g, '; '), R39.replace('real money', 'real-money'),
    R39.replace('real money', 'real\u00a0money'), R39.replace('real money', 'real  money'), R39.replace(', not for real money', ''),
    `// ${R39.replace(', not for', ',\n// not for')}`, `// ${R39}.`, `// "${R39}"`, `// ${R39} games`, `// ${R39}. Do not ship.`,
    `// ${R39} `, `// ${R39}\t`, `// ${R39}\r`].forEach((t, i) => add(`M-92 plant ${i}`, t, 'red'));
  [`// ${R39}`, `# ${R39}`, `/* ${R39} */`, ` * ${R39}`, `<!-- ${R39} -->`].forEach((t, i) => add(`M-92 control ${i}`, t, 'clean'));
  // M-94: S-PACK near-misses + controls
  [PK.replace('cannot', 'can not'), 't' + PK.slice(1), PK.replace('The library', 'This library'), `The library is not ${C}.`,
    PK.replace('not ', 'not yet '), PK.replace('be.', `be ${C}.`), `**The library is not ${C}** and cannot be.`,
    `\u0043ertification applies to an operator's or supplier's complete system, never to this library.`,
    `${PK} Evidence is the adopter's job.`].forEach((t, i) => add(`M-94 plant ${i}`, t, 'red'));
  [PK, `**${PK}**`].forEach((t, i) => add(`M-94 control ${i}`, t, 'clean'));
  // M-95: FIPS tokens + controls
  [FI.replace('Not a validated', 'Not a \u0046IPS validated'), FI.replace('OpenSSL)', 'OpenSSL \u0046IPS)'), `${FI} No \u0046IPS mode.`,
    '\u0066ips', '\u0046ips', '\u0046IPS-140-3', '\u0046IPS 140-2', 'Node.js is not itself \u0046IPS validated'].forEach((t, i) => add(`M-95 plant ${i}`, t, 'red'));
  [FI, FT].forEach((t, i) => add(`M-95 control ${i}`, t, 'clean'));
  // M-96 (a) /drbg wording; (b) stem-free FIPS-topic wording, now killed by O-68
  ['Implements HMAC_DRBG (SHA-256) as specified in NIST SP 800-90A Rev. 1, verified against NIST \u0043AVP known-answer test vectors. Not a validated module.',
    'Uses NIST SP 800-90A.', 'Tested against \u0043AVP vectors.'].forEach((t, i) => add(`M-96a plant ${i}`, t, 'red'));
  [FI.replace('OpenSSL)', 'OpenSSL]'), FI.replace('800-90B', '800-90b'), FI.replace('\u2192', '->'), `Not a ${V} \u0063ryptographic module.`,
    `uses a ${V} OpenSSL provider`, '\u0043MVP'].forEach((t, i) => add(`M-96b plant ${i}`, t, 'red'));
  // M-97: align unconditional
  ['\u0061ligned', '\u0061lignment', '\u0041lign', '\u0041LIGNED', '\u0061ligns', 'byte-\u0061ligned', 'in \u0061lignment with GLI-19',
    'the buffers \u0061lign perfectly', 'we \u0061lign the output to word boundaries for speed and nothing else here at all',
    `${P1} \u0041ligned with GLI-19.`, `Not ${C}. Not an \u0061ligned module.`].forEach((t, i) => add(`M-97 plant ${i}`, t, 'red'));
  // M-98: allowlist used as a blanket (same-line plants)
  [`soon ${P1}`, `${P1} It is NIST-${C}.`, `// ${R39} ${Cc} by an independent lab.`, `${PK} GLI-${C}.`, `${P1} Beyond lab requirements.`,
    `${FI} \u0046IPS`, `![GLI](x.png) ${P1}`].forEach((t, i) => add(`M-98 plant ${i}`, t, 'red'));
  // M-111: validat* (O-68) + controls (the four allowlisted lines that contain validat)
  [V, '\u0056alidated', '\u0056ALIDATED', '\u0076alidation', '\u0076alidates', '\u0076alidator', '\u0076alidating', `${SH} Soon ${V}.`,
    FI.replace('OpenSSL)', 'OpenSSL]'), FI.replace('800-90B', '800-90b'), FI.replace('\u2192', '->'), `uses a ${V} OpenSSL provider`].forEach((t, i) => add(`M-111 plant ${i}`, t, 'red'));
  [P1, SH, FI, FT].forEach((t, i) => add(`M-111 control ${i}`, t, 'clean'));
  // CPO-R100 F-16: closed term list; never with a co-term
  ['The context is schema-\u0076alidated before hashing.', 'The schema \u0076alidator rejects unknown keys.', 'See schema \u0076alidation errors.'].forEach((t, i) => add(`F-16 term control ${i}`, t, 'clean'));
  ['The schema \u0076alidator is a \u0063ryptographic component.', 'Schema \u0076alidation of the module.', 'schema \u0076alidation (\u0046IPS)', 'schema-\u0076alidated by GLI',
    'schema \u0076alidation, CMVP style', `schema \u0076alidation, ${C} later`, 'schema \u0076alidation in the lab', 'Schema \u0056alidation', 'schema \u0076alidations',
    'schema \u0076alidating', 'JSON-schema-\u0076alidated', 'schema\u00a0\u0076alidation'].forEach((t, i) => add(`F-16 term plant ${i}`, t, 'red'));
  // M-112: cryptographic module variants
  ['\u0063ryptographic module', '\u0043ryptographic Module', '\u0043RYPTOGRAPHIC MODULE', '\u0063ryptographic modules', '\u0063ryptographic-module',
    '\u0063ryptographic  module', '\u0063ryptographic\tmodule', '\u0063ryptographic\u00a0module', 'a \u0063ryptographic\nmodule here', `${SH} Not a \u0063ryptographic module.`].forEach((t, i) => add(`M-112 plant ${i}`, t, 'red'));
  // M-113: CMVP
  ['\u0043MVP', '\u0063mvp', '\u0043mvp', '\u0043MVP-listed', '\u0043MVP #4282', '(\u0043MVP)', `${SH} \u0043MVP`].forEach((t, i) => add(`M-113 plant ${i}`, t, 'red'));
  // M-114: PH0 README paraphrase + controls
  [`It is not a ${V} \u0063ryptographic module.`, `- It is not a ${V} \u0063ryptographic module.`, `NOT A ${V.toUpperCase()} \u0043RYPTOGRAPHIC MODULE`].forEach((t, i) => add(`M-114 plant ${i}`, t, 'red'));
  [`- ${SH}`, `- ${FI}`].forEach((t, i) => add(`M-114 control ${i}`, t, 'clean'));
  // CPO-R101 LF-8 (M-112 stays must-kill): Unicode spaces, zero-width, soft hyphen, dashes, and line splits incl. wrappers
  for (const [w, sep] of [['en space', '\u2002'], ['thin space', '\u2009'], ['narrow NBSP', '\u202f'], ['ideographic space', '\u3000'],
    ['figure space', '\u2007'], ['zero-width space', '\u200b'], ['word joiner', '\u2060'], ['soft hyphen', '\u00ad'], ['non-breaking hyphen', '\u2011'],
    ['en dash', '\u2013'], ['NBSP + space', '\u00a0 '], ['BOM', '\ufeff']]) add(`LF-8 crypto module: ${w}`, `Not a \u0063ryptographic${sep}module.`, 'red');
  for (const [w, t] of [['bare split', 'a \u0063ryptographic\nmodule'], ['NBSP before split', 'a \u0063ryptographic\u00a0\nmodule'],
    ['comment-wrapped split', '// a \u0063ryptographic\n// module'], ['JSDoc split', ' * a \u0063ryptographic\n * module'],
    ['blockquote split', '> a \u0063ryptographic\n> modules'], ['indented split', 'a \u0063ryptographic\n    module'], ['hyphen at break', 'a \u0063ryptographic-\nmodule']])
    add(`LF-8 crypto module across lines: ${w}`, t, 'red');
  // CPO-R101 F-23: strict phrase boundaries (no [A-Za-z0-9_-] touching either side)
  for (const [w, t] of [['hyphen right', 'schema \u0076alidation-pass'], ['underscore right', 'schema \u0076alidation_ok'], ['letter right', 'schema \u0076alidationx'],
    ['digit right', 'schema \u0076alidation2'], ['hyphen left', 'json-schema \u0076alidator'], ['underscore left', 'x_schema \u0076alidation'],
    ['letter left', 'xschema-\u0076alidated'], ['digit left', '2schema \u0076alidation'], ['plural', 'schema \u0076alidators'], ['hyphen right of -validated', 'schema-\u0076alidated-module']])
    add(`F-23 boundary: ${w}`, t, 'red');
  for (const [w, t] of [['space', 'a schema \u0076alidation step'], ['period', 'Run schema \u0076alidation.'], ['parens', '(schema \u0076alidator)'],
    ['backticks', 'the `schema-\u0076alidated` context'], ['comma', 'schema \u0076alidation, then hashing'], ['line edges', 'schema \u0076alidator']])
    add(`F-23 boundary control: ${w}`, t, 'clean');
  // CPO-R101 F-24: every lab name is a co-term for the phrase rule
  for (const n of LAB_NAMES) add(`F-24 lab co-term: ${n}`, `schema \u0076alidation as ${n} does it`, 'red');
  // CPO-R102 LF-10: every authority co-term blocks an allowed phrase on the same line
  for (const n of AUTHORITIES) add(`LF-10 authority co-term: ${n}`, `schema \u0076alidation as ${n} does it`, 'red');
  for (const [w, t] of [['lower-case nist', 'schema \u0076alidation per nist'], ['ISO/IEC 17025', 'schema-\u0076alidated ISO/IEC 17025 input'], ['Labs plural', 'Labs run schema \u0076alidation']]) add(`LF-10 authority form: ${w}`, t, 'red');
  // CPO-R102 F-27: GLI and ITL match document ids (hyphen + digits)
  for (const id of ['GLI-11', 'GLI-19', 'GLI-33', 'GLI-1', 'ITL-21', 'gli-19']) add(`F-27 ${id} is a lab co-term`, `schema \u0076alidation per ${id}`, 'red');
  add('F-27 control: no lab id on the line', 'schema \u0076alidation per RFC 8259', 'clean');
  // quality v5.5.6 M-124 / M-125 / M-138 / M-139 (exact case sets)
  const VD = '\u0076alidat';
  const PH = [`schema-${VD}ed`, `schema ${VD}or`, `schema ${VD}ion`];
  for (const t of [`The context data is schema-${VD}ed before hashing.`, `Run the schema ${VD}or first.`, `See schema ${VD}ion errors.`]) add(`M-124 control: ${t}`, t, 'clean');
  for (const t of [`Schema-${VD}ed`, `SCHEMA ${VD.toUpperCase()}OR`, `Schema ${VD[0].toUpperCase()}${VD.slice(1)}ion`, `schema ${VD}ed`, `schema-${VD}or`, `schema-${VD}ion`,
    `schema  ${VD}or`, `schema\t${VD}or`, `schema\u00a0${VD}ion`, `schema-${VD}ing`, `schema ${VD}ors`, `schema ${VD}ions`, `schema-${VD}edness`, `jsonschema ${VD}or`,
    `json-schema-${VD}ed`, `re-${VD}ed`, `un${VD}ed`, `${VD}ed schema`]) add(`M-124 plant: ${t}`, t, 'red');
  const CO = ['module', 'modules', 'submodule', 'crypto', 'cryptographic', 'node:crypto', 'Crypto', '\u0046IPS', 'fips', '\u0043MVP', '\u0063ertified', '\u0063ertification',
    'GLI', 'BMM', 'iTech Labs', 'eCOGRA', 'NMi', 'Trisigma', 'Gaming Associates', 'SIQ', 'QUINEL'];
  for (const ph of PH) for (const c of CO) add(`M-125 co-term: ${ph} + ${c}`, `The ${ph} step (${c}).`, 'red');
  for (const ph of PH) add(`M-125 control: co-term on the next line (${ph})`, `The ${ph} step.\nGLI and \u0043MVP are mentioned here.`, 'red'); // line 2 alone is a CMVP hit
  for (const ph of PH) add(`M-125 control: lab co-term on the next line (${ph})`, `The ${ph} step.\nSee GLI-19 for context.`, 'clean');
  for (const ph of PH) {
    for (const t of [`a${ph}`, `${ph}x`, `2${ph}`, `${ph}2`, `json-${ph}`, `${ph}-input`, `_${ph}`, `${ph}_x`]) add(`M-138 plant: ${t}`, t, 'red');
    for (const t of [ph, `(${ph})`, `"${ph}"`, `${ph}.`, `${ph},`, `${ph}:`, `\`${ph}\``, `\t${ph}`]) add(`M-138 control: ${JSON.stringify(t)}`, t, 'clean');
  }
  add('M-138 plant: schema_validation', `schema_${VD}ion`, 'red');
  const LABV = ['GLI', 'gli', 'GLI-19', 'GLI-11', 'GLI-33', 'Gaming Laboratories International', 'Gaming Laboratories', 'BMM', 'BMM Testlabs', 'BMM Test Labs', 'BMM Australia',
    'BMM Spain Testlabs', 'eCOGRA', 'ecogra', 'ECOGRA', 'Trisigma', 'trisigma', 'NMi', 'NMi Metrology & Gaming', 'Quinel', 'QUINEL', 'Quinel Ltd', 'iTech Labs', 'iTech', 'itechlabs',
    'iTechLabs', 'Gaming Associates', 'Gaming Associates Europe', 'GA Europe'];
  for (const ph of PH) for (const n of LABV) add(`M-139 lab veto: ${ph} + ${n}`, `${ph} as ${n} does it`, 'red');
  for (const ph of PH) add(`M-139 control: lab name on the next line (${ph})`, `${ph} as usual\nas BMM Testlabs does it`, 'clean');
  // M-119: trailing whitespace on an allowlisted line (incl. CR, F-15)
  for (const [id, s] of ALLOW) for (const [w, tail] of [['space', ' '], ['tab', '\t'], ['nbsp', '\u00a0'], ['two spaces', '  '], ['CR', '\r']]) add(`M-119 ${id} + ${w}`, `${s}${tail}`, 'red');
  add('M-119 space after closing wrapper', `/* ${R39} */ `, 'red');
  // M-120: leading whitespace without a wrapper (F-14: indentation before a marker is part of the wrapper)
  for (const [id, s] of ALLOW) for (const [w, lead] of [['spaces', '  '], ['tab', '\t'], ['4-space code indent', '    ']]) add(`M-120 ${id} + ${w}`, `${lead}${s}`, 'red');
  [`// ${R39}`, `  // ${R39}`, ` * ${R39}`, `- ${SH}`, `> ${PK}`, `<!-- ${R39} -->`, `\t// ${R39}`, `    - ${SH}`].forEach((t, i) => add(`M-120 control ${i}`, t, 'clean'));
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
  if (CONFIG_ERRORS.length) { CONFIG_ERRORS.forEach((e) => console.error(`claims-lint: CONFIG ${e}`)); process.exit(2); }
  const args = process.argv.slice(2);
  if (args[0] === '--self-test') {
    let bad = 0;
    const dir = mkdtempSync(join(tmpdir(), 'claims-lint-fixture-'));
    try {
      const f = join(dir, 'README.md');
      writeFileSync(f, KNOWN_BAD_README);
      const hits = lintText('scratch:README.md', readFileSync(f, 'utf8'));
      hits.forEach((h) => console.log(h));
      if (hits.length === 0) { console.error('claims-lint: known-bad README fixture did NOT turn red (FAIL)'); bad++; }
      else console.log(`claims-lint: scratch known-bad README fixture turned red with ${hits.length} hit(s) (expected, PASS)`);
      const realA = readFileSync(join(ROOT, ALLOWLIST_PATH));
      const kbA = knownBadAllowlistConfig(realA);
      writeFileSync(join(dir, 'allow.json'), kbA);
      const la = loadAllowlist(readFileSync(join(dir, 'allow.json')));
      const lf = lintFile(ALLOWLIST_PATH, readFileSync(join(dir, 'allow.json')));
      if (!la.errors.length || !lf.length) { console.error('claims-lint: known-bad allowlist config did NOT fail (FAIL)'); bad++; }
      else console.log(`claims-lint: known-bad allowlist config fails closed (${la.errors.length} config error(s)) and lints red at the exempt path (${lf.length} hit(s)) (PASS)`);
      const kbT = knownBadTermsConfig(readFileSync(join(ROOT, TERMS_PATH)));
      writeFileSync(join(dir, 'terms.json'), kbT);
      const lt = loadTerms(readFileSync(join(dir, 'terms.json')));
      if (!lt.errors.length) { console.error('claims-lint: known-bad terms config did NOT fail (FAIL)'); bad++; }
      else console.log(`claims-lint: known-bad terms config fails closed (${lt.errors.length} error(s)) (PASS)`);
    } finally { rmSync(dir, { recursive: true, force: true }); }
    const { results, scratchRemoved } = runNearMiss();
    const fails = results.filter((r) => !r.pass);
    fails.forEach((r) => console.error(`  FAIL ${r.id}: expected ${r.expect}, got ${r.hits.length} hit(s)`));
    console.log(`claims-lint: C-10 near-miss ${results.length - fails.length}/${results.length} PASS; scratch removed: ${scratchRemoved && !existsSync(dir)}`);
    process.exit(bad || fails.length || !scratchRemoved ? 1 : 0);
  }
  if (args[0] === '--surface') {
    // Lint an external artefact read-only (CPO-R101 F-22 / F-25): `p8` = a published npm README (content rules + single-line
    // S-P1 presence); `repo-description` = a repo description value (content rules + must equal S-P1 exactly).
    const kind = args[1], f = args[2];
    const text = readFileSync(f, 'utf8');
    let hits;
    if (kind === 'p8') {
      hits = lintText(`${f}`, text);
      if (!text.split('\n').some((l) => allowlistedLine(l) === 'S-P1')) hits.push(`${f}:0: O67-p1-presence: no single-line byte-exact S-P1 (P8 reserved npm README)`);
    } else if (kind === 'repo-description') {
      const v = text.replace(/\n$/, '');
      hits = lintText(`${f}#description`, v);
      if (v !== SP1()) hits.push(`${f}#description:0: O67-p1-presence: does not equal S-P1 exactly (${Buffer.byteLength(v)} bytes)`);
    } else if (kind === 'p8-package') { // published package.json (M-129): every string value linted; description must equal S-P1
      let j = null;
      try { j = JSON.parse(text); } catch { j = null; }
      hits = j === null ? [`${f}:0: CONFIG: package.json does not parse`] : [...jsonStrings(j).flatMap(([at, v]) => lintText(`${f}#${at}`, v)), ...jsonKeys(j).flatMap(([at, k]) => lintText(`${f}#${at}(key)`, k))];
      if (j && j.description !== SP1()) hits.push(`${f}#/description:0: O67-p1-presence: does not equal S-P1 exactly`);
    } else { console.error('claims-lint: --surface p8|p8-package|repo-description FILE'); process.exit(2); }
    hits.forEach((h) => console.log(h));
    console.log(`claims-lint: --surface ${kind} ${f}: ${hits.length} hit(s)`);
    process.exit(hits.length ? 1 : 0);
  }
  if (args[0] === '--expect-red') {
    const f = args[1];
    const hits = lintText(f, readFileSync(f, 'utf8'));
    hits.forEach((h) => console.log(h));
    if (hits.length === 0) { console.error(`claims-lint: known-bad fixture ${f} did NOT turn red (FAIL)`); process.exit(1); }
    console.log(`claims-lint: known-bad fixture ${f} turned red with ${hits.length} hit(s) (expected, PASS)`);
    process.exit(0);
  }
  const { hits, report } = lintTree(trackedFiles(ROOT), builtFiles(ROOT), { symlinks: trackedSymlinks(ROOT) });
  hits.forEach((h) => console.log(h));
  const p1 = report.p1.map((r) => `${r.surface}=${r.ok === null ? 'n/a' : r.ok ? 'ok' : 'MISSING'}`).join('; ');
  console.log(`claims-lint: ${report.scoped} scope item(s) + ${report.codeFiles} shipped source file(s) + ${report.dtsFiles} .d.ts, ${hits.length} hit(s); built output: ${report.builtOutput}; labs ${LAB_NAMES.length} (${LAB_NAMES_SHA256.slice(0, 8)}), authorities ${AUTHORITIES.length} (${AUTHORITY_SHA256.slice(0, 8)}); LICENSE: ${report.license}; P1: ${p1}; allowlist ${report.allowlist}, terms ${report.terms}`);
  process.exit(hits.length ? 1 : 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
