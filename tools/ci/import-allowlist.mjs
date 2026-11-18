#!/usr/bin/env node
// CI rule 27, import allowlist for core src/ (quality.md v5.5.7 sha 0202a82b L596; QR-25 L228; PLAN R-44 L152, QR-25 L368, L671).
// Red (exit 1) if, in core src/:
//  - node:crypto is reached other than as named ESM imports, or the (symbol, directory) set differs in any way from
//    {(randomFillSync, entropy/), (createHash, evidence/), (getFips, identity/)} (missing or extra pairs are both red);
//  - any of: namespace import, default import, require('node:crypto'|'crypto'), dynamic import(), process.binding,
//    process.getBuiltinModule, globalThis.crypto incl. computed globalThis[...] access, the bare global crypto, the globals
//    global/self, any import of node:module, the identifier createRequire, appears (L596, read literally);
//  - a setFips or fips identifier or member appears;
//  - a file in audited/ imports anything other than core-internal modules (relative paths that stay inside src/);
//  - Object.defineProperty(globalThis, ...) appears in core src/ (the single R-58(6) exception is outside src/).
// HoQ ruling on rule 27 (relayed by CTO 2026-11-18 09:00 CET):
//  Q1 'no more' always blocks; 'no fewer' blocks once entropy/, evidence/ or identity/ exists under src/, is report-only
//     for a directory that does not exist yet, and is red for a missing directory under --phase-exit.
//  Q2 the all-import namespace/default ban stands; exceptions only as exact listed paths with a fixture (none today).
//  Q3 scope = every core production-build source: src/ (incl. src/verify/), packages/capability/src, packages/mapping,
//     plus a root verify/ tree if one exists. coreGuard.ts defineProperty is an exact-path entry (QR-25 L228). In verify
//     scopes only the documented deterministic-source binding may import packages/drbg: exact path
//     verify/src/testingBinding.ts (PLAN r4.9 L535 QR-57 row (h); R-58(1) L166). Anything else reaching drbg is red.
//  PH1-M1 erratum (HoQ rule-27 clarification, CTO 2026-11-18 09:04 CET): 'no fewer' for entropy/ blocks as soon as ANY
//     trigger holds (fail-closed), else it is report-only while the directory has no entropy read path:
//     (i) a file under src/entropy/ imports anything from node:crypto/crypto, re-exports from it, exports a name matching
//         /read|fetch|bytes|entropy|fill|draw/i (incl. aliases, types, export *, export default, destructured exports:
//         all red), or calls fill*/read*/randomBytes/randomFill*/getRandomValues/randomUUID/randomInt (bare or member).
//         Only carve-out (HoQ tighten ruling, 2026-11-18): the exact-name allow-list READ_NAME_ALLOW = { FINGERPRINT_BYTES },
//         allowed only as the declaration `export const FINGERPRINT_BYTES = 16;` (canonical decimal literal 16; no type
//         annotation, no 0x10/1_6/16n/'16'/16.0, no expression or identifier, not let/var, not a re-export). Any other
//         exported name matching the heuristic is red. Each future allow-list entry needs its own HoQ ruling plus its own
//         fixture. Comments and string contents are ignored; everything else errs red.
//     (ii) package.json has main/module/exports (package root exported), or a module reachable by static imports or
//         re-exports from a core entry (src/index.ts, src/audited/index.ts) exports createRng/createAuditedRng/randomInt/
//         shuffle/sample/weightedPick/randomBytes or any create*Rng / random* name;
//     (iii) --phase-exit (PH1 exit, any packed or release build).
//     evidence/ and identity/ keep the plain rule: blocking once the directory exists.
//  randomFillSync anywhere outside src/entropy/ is red; inside it only the exact `import { randomFillSync } from
//  'node:crypto'` is allowed (no alias, no other path).
//  HoQ coverage gaps on 2de685b2 (G-12, G-13, G-15, G-16), fail-closed:
//     G-12 globalThis may appear only as a member-access base (`globalThis.x`; `.crypto` and computed `[...]` stay red).
//          Any other reference (alias `const g = globalThis`, destructuring `const {crypto: c} = globalThis`, passing it to
//          Reflect.get / Object.getOwnPropertyDescriptor / any call) is red, except exactly `Object.hasOwn(globalThis,` and
//          `Object.defineProperty(globalThis,` in packages/capability/src/coreGuard.ts. `window` is red like global/self.
//          Function / eval (any use, incl. `new Function`, `Function('return this')()`) and `.constructor(` calls are red.
//     G-13 require('node:module') / require('module') are red (createRequire and import from node:module already are).
//     G-15 an `export const|let|var` statement with more than one declarator is an opaque export (trigger (i) red).
//  HoQ coverage gaps on 83aa9529 (G-17..G-20), fail-closed:
//     G-17 `globalThis.<member>` is red unless <member> is in GLOBALTHIS_MEMBERS_ALLOWED. The list holds exactly what real
//          core source uses today: NONE (2026-11-18 scan of src/, packages/capability/src, packages/mapping: the only
//          globalThis/process tokens are in comments). So globalThis.self/.window/.globalThis/.Function/.eval/.Reflect/
//          .process/... are all red. A new entry needs a HoQ ruling plus its own fixture.
//     G-18 `process` may appear only as `process.<member>` with <member> in PROCESS_MEMBERS_ALLOWED (NONE today, same
//          scan); any other reference (alias, destructuring, argument, computed access) is red. The members getBuiltinModule,
//          binding, _linkedBinding, dlopen and mainModule are red on ANY base (catches aliases such as p.getBuiltinModule).
//     G-19 module.require, any `.require(` member call, and `require` not immediately called (alias, destructuring key,
//          argument) are red; process.mainModule.require is red via the always-banned members.
//     G-20 --self-test also runs the M-152b/c/d/g cases (guard-exact control, guard forms at a non-guard path, window,
//          .constructor() and the MX-12 case: claims-lint --surface p8-package on an embedded key-only plant must be red.
// PENDING: the dist/ grep half (no packed core yet).
// Usage: node tools/ci/import-allowlist.mjs [root] [--phase-exit]   --self-test runs the known-bad fixtures.
import { readFileSync, readdirSync, statSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join, relative, dirname, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

export const REQUIRED_PAIRS = ['randomFillSync@entropy', 'createHash@evidence', 'getFips@identity'];
const EXT = /\.(ts|mts|cts|js|mjs|cjs)$/;
export const SCAN_ROOTS = ['src', 'packages/capability/src', 'packages/mapping', 'verify'];
// Exact-path exceptions (Q2: none for the namespace/default ban today).
export const GUARD_PATH = 'packages/capability/src/coreGuard.ts'; // QR-25 L228, PLAN R-58(6) L166
export const VERIFY_BINDING_PATH = 'verify/src/testingBinding.ts'; // PLAN L535 (QR-57 row h), R-58(1) L166
const DRBG_PKG = '@open-rng-engine/drbg';
export const GLOBALTHIS_MEMBERS_ALLOWED = Object.freeze([]); // G-17: none used by real core source (2026-11-18)
export const PROCESS_MEMBERS_ALLOWED = Object.freeze([]); // G-18: none used by real core source (2026-11-18)
const PROCESS_ALWAYS_BANNED = ['getBuiltinModule', 'binding', '_linkedBinding', 'dlopen', 'mainModule'];

function walk(d, out = []) {
  let names; try { names = readdirSync(d); } catch { return out; }
  for (const n of names.sort()) { if (n === 'node_modules') continue; const p = join(d, n); const s = statSync(p); if (s.isDirectory()) walk(p, out); else if (EXT.test(n)) out.push(p); }
  return out;
}

// Returns [noComments, noCommentsNoStrings]; both keep length and newlines so offsets map to lines.
export function strip(src) {
  let a = '', b = '', i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i], d = src[i + 1];
    if (c === '/' && d === '/') { while (i < n && src[i] !== '\n') { a += ' '; b += ' '; i++; } continue; }
    if (c === '/' && d === '*') { while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { const k = src[i] === '\n' ? '\n' : ' '; a += k; b += k; i++; } if (i < n) { a += '  '; b += '  '; i += 2; } continue; }
    if (c === '"' || c === "'" || c === '`') {
      a += c; b += c; i++;
      while (i < n && src[i] !== c) { if (src[i] === '\\') { a += src[i] + (src[i + 1] ?? ''); b += '  '; i += 2; continue; } a += src[i]; b += src[i] === '\n' ? '\n' : ' '; i++; }
      if (i < n) { a += c; b += c; i++; }
      continue;
    }
    a += c; b += c; i++;
  }
  return [a, b];
}

const lineOf = (s, idx) => s.slice(0, idx).split('\n').length;

export function scanFile(rel, src) {
  const hits = []; const pairs = [];
  const [a, b] = strip(src);
  const top = rel.startsWith('src/') ? (rel.split('/')[1] ?? '') : rel.split('/').slice(0, 2).join('/');
  const inVerify = rel.startsWith('src/verify/') || rel.startsWith('verify/');
  const add = (idx, code, msg) => hits.push(`${rel}:${lineOf(src, idx)}: rule27-${code} ${msg}`);
  const isCrypto = (s) => s === 'node:crypto' || s === 'crypto';
  const specs = [];
  for (const m of a.matchAll(/(^|[^\w$.])import\s+(?!\()([^'";]*?)\s*from\s*(['"])([^'"]+)\3/g)) specs.push({ idx: m.index + m[1].length, kind: 'import', clause: m[2].trim(), spec: m[4] });
  for (const m of a.matchAll(/(^|[^\w$.])import\s*(['"])([^'"]+)\2/g)) specs.push({ idx: m.index + m[1].length, kind: 'side', clause: '', spec: m[3] });
  for (const m of a.matchAll(/(^|[^\w$.])export\s+([^'";]*?)\s*from\s*(['"])([^'"]+)\3/g)) specs.push({ idx: m.index + m[1].length, kind: 'export', clause: m[2].trim(), spec: m[4] });
  for (const s of specs) {
    const clause = s.clause.replace(/^type\s+/, '');
    if (s.kind === 'import' && /^\*\s*as\b/.test(clause)) add(s.idx, 'namespace-import', `namespace import of '${s.spec}'`);
    else if (s.kind === 'import' && /^[A-Za-z_$][\w$]*\s*(,|$)/.test(clause)) add(s.idx, 'default-import', `default import of '${s.spec}'`);
    if (s.spec === 'node:module' || s.spec === 'module') add(s.idx, 'node-module', `import of '${s.spec}'`);
    if (isCrypto(s.spec)) {
      const named = /^\{([^}]*)\}$/.exec(clause);
      if (s.spec !== 'node:crypto') add(s.idx, 'bare-crypto-specifier', `'${s.spec}' (only 'node:crypto' named imports are allowed)`);
      if (s.kind !== 'import' || !named) add(s.idx, 'crypto-not-named', `node:crypto reached other than as a named ESM import`);
      else for (const part of named[1].split(',').map((x) => x.trim()).filter(Boolean)) {
        const [sym0, alias] = part.replace(/^type\s+/, '').split(/\s+as\s+/).map((x) => x.trim());
        const sym = sym0;
        if (alias !== undefined && alias !== sym) add(s.idx, 'crypto-alias', `node:crypto symbol ${sym} imported under alias ${alias} (only the exact named import is allowed)`);
        pairs.push({ pair: `${sym}@${top}`, at: `${rel}:${lineOf(src, s.idx)}` });
      }
    }
    if (!isCrypto(s.spec) && /(^|[\s,{])randomFillSync([\s,}]|$)/.test(s.clause)) add(s.idx, 'randomFillSync-other-path', `randomFillSync reached through '${s.spec}' (only node:crypto in src/entropy/)`);
    if (inVerify) {
      const drbg = s.spec === DRBG_PKG || s.spec.startsWith(DRBG_PKG + '/') || (s.spec.startsWith('.') && (resolve('/r', dirname(rel), s.spec) + sep).startsWith(resolve('/r', 'packages/drbg') + sep));
      if (drbg && rel !== VERIFY_BINDING_PATH) add(s.idx, 'verify-drbg-binding', `'${s.spec}' reached from ${rel}; only ${VERIFY_BINDING_PATH} (PLAN L535) may bind the deterministic source`);
    }
    if (top === 'audited') {
      const internal = s.spec.startsWith('.') && (resolve('/r', dirname(rel), s.spec) + sep).startsWith(resolve('/r', 'src') + sep);
      if (!internal) add(s.idx, 'audited-import', `audited/ imports '${s.spec}' (only core-internal modules and evidence/)`);
    }
  }
  const pat = [
    [b, /(^|[^\w$.])import\s*\(/g, 'dynamic-import', 'dynamic import()'],
    [a, /(^|[^\w$.])require\s*\(\s*(['"`])(node:)?crypto\2\s*\)/g, 'require-crypto', "require('node:crypto'|'crypto')"],
    [a, /(^|[^\w$.])process\s*(\?\.|\.)\s*(binding|getBuiltinModule)\b/g, 'process-binding', 'process.binding / process.getBuiltinModule'],
    [a, /(^|[^\w$.])process\s*(\?\.)?\s*\[\s*(['"`])(binding|getBuiltinModule)\3/g, 'process-binding', 'computed process.binding / getBuiltinModule'],
    [b, /(^|[^\w$.])globalThis\s*(\?\.|\.)\s*crypto\b/g, 'globalThis-crypto', 'globalThis.crypto'],
    [b, /(^|[^\w$.])globalThis\s*(\?\.)?\s*\[/g, 'globalThis-computed', 'computed globalThis[...] access'],
    [b, /(^|[^\w$.])crypto\b(?!\s*:)/g, 'bare-global-crypto', 'bare global crypto'],
    [b, /(^|[^\w$.])(global|self)\b(?!\s*:)/g, 'global-self', 'global / self'],
    [b, /(^|[^\w$])createRequire\b/g, 'createRequire', 'createRequire identifier'],
    [a, /(^|[^\w$.])require\s*\(\s*(['"`])(node:)?module\2\s*\)/g, 'node-module', "require('node:module'|'module')"],
    [b, /(^|[^\w$.])window\b(?!\s*:)/g, 'global-self', 'window'],
    [b, /(^|[^\w$.])(Function|eval)\b(?!\s*:)/g, 'function-eval', 'Function / eval (code-from-string can reach the global object)'],
    [b, /\.\s*constructor\s*\(/g, 'function-eval', '.constructor( call (Function-constructor reach)'],
    ...(rel.startsWith('src/entropy/') ? [] : [[b, /(^|[^\w$])randomFillSync\b/g, 'randomFillSync-outside-entropy', 'randomFillSync outside src/entropy/']]),
    [b, /(^|[^\w$])(setFips|fips)\b/g, 'fips', 'setFips / fips identifier or member'],
    [a, /\[\s*(['"`])(setFips|fips)\1\s*\]/g, 'fips', 'computed setFips / fips member'],
  ];
  for (const [text, re, code, msg] of pat) for (const m of text.matchAll(re)) add(m.index + (m[1]?.length ?? 0), code, msg);
  // G-17: globalThis.<member> only for allow-listed members.
  for (const m of b.matchAll(/(^|[^\w$.])globalThis\s*(\?\.|\.)\s*([A-Za-z_$][\w$]*)/g)) {
    if (!GLOBALTHIS_MEMBERS_ALLOWED.includes(m[3])) add(m.index + m[1].length, 'globalThis-member', `globalThis.${m[3]} (not in GLOBALTHIS_MEMBERS_ALLOWED)`);
  }
  // G-18: process only as process.<allowed member>; always-banned members on any base.
  for (const m of b.matchAll(/(^|[^\w$.])process\b/g)) {
    const at = m.index + m[1].length; const mm = /^process\s*(\?\.|\.)\s*([A-Za-z_$][\w$]*)/.exec(b.slice(at));
    if (!mm || !PROCESS_MEMBERS_ALLOWED.includes(mm[2])) add(at, 'process-reach', mm ? `process.${mm[2]} (not in PROCESS_MEMBERS_ALLOWED)` : 'process referenced other than as process.<allowed member> (alias, destructuring, argument)');
  }
  for (const m of b.matchAll(new RegExp(`(\\?\\.|\\.)\\s*(${PROCESS_ALWAYS_BANNED.join('|')})\\b`, 'g'))) add(m.index, 'process-banned-member', `.${m[2]} (always red, any base)`);
  for (const m of a.matchAll(new RegExp(`\\[\\s*(['"\`])(${PROCESS_ALWAYS_BANNED.join('|')})\\1\\s*\\]`, 'g'))) add(m.index, 'process-banned-member', `['${m[2]}'] (always red, any base)`);
  for (const m of b.matchAll(new RegExp(`[{,]\\s*(${PROCESS_ALWAYS_BANNED.join('|')})\\b\\s*[:,}]`, 'g'))) add(m.index, 'process-banned-member', `destructured ${m[1]} (always red)`);
  // G-19: module.require, .require( member calls, require not immediately called.
  for (const m of b.matchAll(/(^|[^\w$.])module\s*(\?\.|\.)\s*require\b/g)) add(m.index + m[1].length, 'module-require', 'module.require');
  for (const m of b.matchAll(/(\?\.|\.)\s*require\s*\(/g)) add(m.index, 'require-member-call', '.require( member call');
  for (const m of b.matchAll(/(^|[^\w$.])require\b(?!\s*\()/g)) add(m.index + m[1].length, 'require-alias', 'require referenced other than as a direct call (alias, destructuring, argument)');
  // G-12: globalThis only as a member-access base; the two guard forms are allowed only at GUARD_PATH.
  for (const m of b.matchAll(/(^|[^\w$.])globalThis\b(?!\s*(\?\.|\.|\[))/g)) {
    const at = m.index + m[1].length; const pre = b.slice(Math.max(0, at - 40), at);
    if (rel === GUARD_PATH && /Object\s*\.\s*(hasOwn|defineProperty)\s*\(\s*$/.test(pre) && /^globalThis\s*,/.test(b.slice(at))) continue;
    add(at, 'globalThis-alias', 'globalThis referenced other than as a member-access base (alias, destructuring or argument)');
  }
  // QR-25 L228 / R-58(6): exactly one Object.defineProperty(globalThis, "<literal>", { value, writable: false,
  // configurable: false, enumerable: false }) in GUARD_PATH only, preceded by an Object.hasOwn(globalThis, KEY) check that throws.
  const dps = [...b.matchAll(/(^|[^\w$.])Object\s*\.\s*defineProperty\s*\(\s*globalThis\b/g)];
  if (rel !== GUARD_PATH) for (const m of dps) add(m.index + m[1].length, 'defineProperty-globalThis', `Object.defineProperty(globalThis, ...) outside ${GUARD_PATH}`);
  else {
    if (dps.length > 1) for (const m of dps.slice(1)) add(m.index + m[1].length, 'defineProperty-globalThis', 'second Object.defineProperty(globalThis, ...) in the guard');
    if (dps.length >= 1) {
      const at = dps[0].index + dps[0][1].length;
      const call = /^Object\s*\.\s*defineProperty\s*\(\s*globalThis\s*,\s*(['"])[^'"`\\]+\1\s*,\s*\{\s*value\s*(:\s*[\w$.]+\s*)?,\s*writable\s*:\s*false\s*,\s*configurable\s*:\s*false\s*,\s*enumerable\s*:\s*false\s*,?\s*\}\s*\)/.exec(a.slice(at));
      if (!call) add(at, 'defineProperty-globalThis', 'guard defineProperty is not the exact R-58(6) form (fixed string literal key, value, writable/configurable/enumerable false)');
      const before = b.slice(0, at);
      if (!/Object\s*\.\s*hasOwn\s*\(\s*globalThis\s*,/.test(before) || !/\bthrow\b/.test(before)) add(at, 'defineProperty-globalThis', 'guard defineProperty is not preceded by an Object.hasOwn(globalThis, KEY) check that throws');
    }
    if (/Symbol\s*\.\s*for\b/.test(b)) add(b.search(/Symbol\s*\.\s*for\b/), 'defineProperty-globalThis', 'Symbol.for in the guard');
  }
  return { hits, pairs };
}

const READ_NAME = /read|fetch|bytes|entropy|fill|draw/i;
const READ_CALL = /(^|[^\w$])((fill|read)[\w$]*|randomBytes|randomFill[\w$]*|getRandomValues|randomUUID|randomInt)\s*\(/gi;
const ENTRY_NAME = /^(createRng|createAuditedRng|randomInt|shuffle|sample|weightedPick|randomBytes|create[\w$]*Rng|random[\w$]*)$/;

// Exported names of one module: [{ name, allowed }], plus opaque=true for export * / default / destructuring.
// allowed = true only for an exact READ_NAME_ALLOW declaration (HoQ tighten ruling; each entry needs a HoQ ruling + fixture).
export const READ_NAME_ALLOW = Object.freeze({ FINGERPRINT_BYTES: '16' });
export function exportsOf(src) {
  const [a, b] = strip(src); const out = []; let opaque = [];
  for (const m of b.matchAll(/(^|[^\w$.])export\s+(declare\s+)?(async\s+)?(function\s*\*?|class|const|let|var|type|interface|enum)\s*([A-Za-z_$][\w$]*)/g)) {
    const want = Object.hasOwn(READ_NAME_ALLOW, m[5]) ? READ_NAME_ALLOW[m[5]] : undefined;
    const allowed = want !== undefined && m[4] === 'const' && !m[2] && new RegExp(`^export\\s+const\\s+${m[5]}\\s*=\\s*${want}\\s*;`).test(a.slice(m.index + m[1].length));
    out.push({ name: m[5], allowed });
  }
  for (const m of a.matchAll(/(^|[^\w$.])export\s+(type\s+)?\{([^}]*)\}/g)) for (const part of m[3].split(',').map((x) => x.trim()).filter(Boolean)) {
    const ps = part.replace(/^type\s+/, '').split(/\s+as\s+/).map((x) => x.trim()); out.push({ name: ps[1] ?? ps[0], allowed: false });
  }
  for (const m of b.matchAll(/(^|[^\w$.])export\s*(\*|default\b|(const|let|var)\s*[\[{])/g)) opaque.push(m[2]);
  // G-15: more than one declarator in one exported declaration is opaque.
  for (const m of b.matchAll(/(^|[^\w$.])export\s+(const|let|var)\s+[A-Za-z_$]/g)) {
    let depth = 0; let multi = false;
    for (let i = m.index + m[0].length; i < b.length; i++) { const ch = b[i];
      if ('([{'.includes(ch)) depth++; else if (')]}'.includes(ch)) depth--; else if (depth === 0 && (ch === ';' || ch === '\n')) break; else if (depth === 0 && ch === ',') { multi = true; break; } }
    if (multi) opaque.push(`${m[2]} with several declarators`);
  }
  return { names: out, opaque };
}

const SPECS = (a) => [...a.matchAll(/(^|[^\w$.])(?:import|export)\s+[^'";]*?\s*from\s*(['"])([^'"]+)\2/g), ...a.matchAll(/(^|[^\w$.])import\s*(['"])([^'"]+)\2/g)].map((m) => m[3]);

export function entropyTriggers(root, { phaseExit = false } = {}) {
  const why = [];
  if (phaseExit) why.push('(iii) --phase-exit');
  for (const f of walk(join(root, 'src', 'entropy'))) {
    const rel = relative(root, f).split(sep).join('/'); const src = readFileSync(f, 'utf8'); const [a, b] = strip(src);
    if (SPECS(a).some((x) => x === 'node:crypto' || x === 'crypto')) why.push(`(i) ${rel} imports or re-exports from node:crypto`);
    const ex = exportsOf(src);
    for (const o of ex.opaque) why.push(`(i) ${rel} has an opaque export (${o.trim()}), treated as a read API`);
    for (const e of ex.names) if (READ_NAME.test(e.name) && !e.allowed) why.push(`(i) ${rel} exports ${e.name}`);
    for (const m of b.matchAll(READ_CALL)) why.push(`(i) ${rel}:${lineOf(src, m.index + m[1].length)} calls ${m[2]}(`);
  }
  try {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    for (const k of ['main', 'module', 'exports']) if (pkg[k] !== undefined) why.push(`(ii) package.json ${k} exports the package root`);
  } catch { /* no package.json: nothing exported */ }
  const seen = new Set(); const todo = ['src/index.ts', 'src/audited/index.ts'];
  while (todo.length) {
    const rel = todo.pop(); if (seen.has(rel) || !existsSync(join(root, rel))) continue; seen.add(rel);
    const src = readFileSync(join(root, rel), 'utf8'); const ex = exportsOf(src);
    for (const e of ex.names) if (ENTRY_NAME.test(e.name)) why.push(`(ii) ${rel} exports ${e.name}, reachable from the core entry`);
    for (const sp of SPECS(strip(src)[0])) if (sp.startsWith('.')) todo.push(relative('/r', resolve('/r', dirname(rel), sp)).split(sep).join('/'));
  }
  return why;
}

export function scanTree(root, { phaseExit = false } = {}) {
  const hits = []; const pairs = []; const reports = [];
  for (const f of SCAN_ROOTS.flatMap((r) => walk(join(root, r)))) {
    const rel = relative(root, f).split(sep).join('/');
    const r = scanFile(rel, readFileSync(f, 'utf8'));
    hits.push(...r.hits); pairs.push(...r.pairs);
  }
  const have = new Set(pairs.map((p) => p.pair));
  for (const p of pairs) if (!REQUIRED_PAIRS.includes(p.pair)) hits.push(`${p.at}: rule27-extra-pair (${p.pair.replace('@', ', ')}/) is not in the allowlist`);
  for (const p of REQUIRED_PAIRS) {
    if (have.has(p)) continue;
    const dir = p.split('@')[1];
    const line = `src/${dir}/:0: rule27-missing-pair (${p.replace('@', ', ')}/) required by L596 is absent`;
    if (dir === 'entropy' && existsSync(join(root, 'src', dir))) {
      const why = entropyTriggers(root, { phaseExit });
      if (why.length) hits.push(`${line} [PH1-M1 trigger: ${why.join('; ')}]`);
      else reports.push(`${line} [report-only: src/entropy/ has no entropy read path and no trigger (i)-(iii) holds (PH1-M1 erratum)]`);
    } else if (existsSync(join(root, 'src', dir)) || phaseExit) hits.push(line);
    else reports.push(`${line} [report-only: src/${dir}/ does not exist yet; red under --phase-exit]`);
  }
  return { hits, pairs, reports };
}

const GOOD = { 'src/entropy/a.ts': "import { randomFillSync } from 'node:crypto';\nexport const f = randomFillSync;\n",
  'src/evidence/a.ts': "import { createHash } from 'node:crypto';\nexport const h = () => createHash('sha256');\n",
  'src/identity/a.ts': "import { getFips } from 'node:crypto';\nexport const g = () => getFips();\n",
  'src/audited/a.ts': "import { h } from '../evidence/a.ts';\nexport const x = h;\n" };
export const BAD = {
  'namespace-import': "import * as c from 'node:crypto';\n", 'default-import': "import c from 'node:crypto';\n",
  'require-crypto': "const c = require('crypto');\n", 'dynamic-import': "const c = await import('node:crypto');\n",
  'process-binding': "process.binding('crypto');\n", 'process-getBuiltinModule': "process.getBuiltinModule('node:crypto');\n",
  'globalThis-crypto': 'globalThis.crypto.getRandomValues(b);\n', 'globalThis-computed': "globalThis['cry' + 'pto'];\n",
  'bare-global-crypto': 'crypto.getRandomValues(b);\n', 'global-crypto': 'global.crypto;\n', 'self-crypto': 'self.crypto;\n',
  'node-module': "import { createRequire } from 'node:module';\n", 'createRequire': 'const r = createRequire(import.meta.url);\n',
  'setFips': 'x.setFips(1);\n', 'fips-member': 'x.fips = 1;\n', 'extra-pair': "import { randomBytes } from 'node:crypto';\n",
  'createHash-outside-evidence': "import { createHash } from 'node:crypto';\n", 'audited-import': "import { readFileSync } from 'node:fs';\n",
  'defineProperty-globalThis': "Object.defineProperty(globalThis, 'k', { value: 1 });\n",
  'capability-crypto': "import { randomFillSync } from 'node:crypto';\n", 'mapping-namespace': "import * as m from './x.ts';\n",
  'verify-drbg': "import { d } from '@open-rng-engine/drbg';\n", 'verify-drbg-relative': "import { d } from '../../packages/drbg/src/index.ts';\n",
  'verify-binding-wrong-path': "import { d } from '@open-rng-engine/drbg';\n",
  'entropy-alias': "import { randomFillSync as rf } from 'node:crypto';\n",
  'entropy-other-path': "import { randomFillSync } from '../mapping/x.ts';\n",
  'randomFillSync-outside-entropy': "import { randomFillSync } from '../entropy/a.ts';\n",
  // HoQ tighten ruling: allow-list red cases (planted over src/entropy/a.ts, so entropy/ has no randomFillSync import).
  'allowlist-SEED_BYTES': 'export const SEED_BYTES = 32;\n',
  'allowlist-FINGERPRINT_BYTES-15': 'export const FINGERPRINT_BYTES = 15;\n',
  'allowlist-FINGERPRINT_BYTES-string': "export const FINGERPRINT_BYTES = '16';\n",
  'allowlist-FINGERPRINT_BYTES-let': 'export let FINGERPRINT_BYTES = 16;\n',
  'allowlist-FINGERPRINT_BYTES-reexport': 'const FINGERPRINT_BYTES = 16;\nexport { FINGERPRINT_BYTES };\n',
  // HoQ coverage gaps on 2de685b2.
  'allowlist-FINGERPRINT_BYTES-multi': 'export const FINGERPRINT_BYTES = 16, X_BYTES = 1;\n', // G-15
  'globalThis-destructure': 'const {crypto: c} = globalThis;\n', // G-12
  'globalThis-alias': 'const g = globalThis;\ng.crypto;\n', // G-12
  'globalThis-Reflect-get': "Reflect.get(globalThis,'crypto');\n", // G-12
  'globalThis-getOwnPropertyDescriptor': "Object.getOwnPropertyDescriptor(globalThis,'crypto');\n", // G-12
  'Function-return-this': "Function('return this')();\n", // G-12
  'require-node-module': "const m = require('node:module');\n", // G-13
  'require-module': "const m = require('module');\n", // G-13
  'fips-identifier': 'const v = fips;\n', // G-16
  'fips-computed': "x['fips'];\n", // G-16
  // HoQ coverage gaps on 83aa9529.
  'gt-self-crypto': 'globalThis.self.crypto;\n', 'gt-window-crypto': 'globalThis.window.crypto;\n', // G-17
  'gt-globalThis-crypto': 'globalThis.globalThis.crypto;\n', 'gt-Function': "globalThis.Function('return this')();\n", // G-17
  'gt-eval': "globalThis.eval('crypto');\n", 'gt-Reflect-get': "globalThis.Reflect.get(globalThis.self,'crypto');\n", // G-17
  'gt-process-getBuiltinModule': "globalThis.process.getBuiltinModule('crypto');\n", 'gt-process-binding': "globalThis.process.binding('crypto');\n", // G-17
  'process-alias': "const p = globalThis.process;\np.getBuiltinModule('crypto');\n", // G-18
  'process-destructure': "const {getBuiltinModule: g} = process;\ng('crypto');\n", // G-18
  'process-linkedBinding': "process._linkedBinding('x');\n", 'process-dlopen': 'process.dlopen(m, f);\n', // G-18
  'process-mainModule': 'process.mainModule;\n', 'process-plain-member': 'process.env;\n', // G-18
  'module-require': "module.require('crypto');\n", 'mainModule-require': "process.mainModule.require('crypto');\n", // G-19
  'require-alias': "const r = require;\nr('crypto');\n", 'require-destructure': 'const { require: r } = m;\n', // G-19
  'require-member-call': "x.require('crypto');\n", // G-19
  'window-alias': 'const w = window;\n', 'constructor-call': "(() => 1).constructor('return this')();\n", // G-20 (M-152d, M-152g)
  'guard-forms-non-guard-path': null, // G-20 (M-152c): GUARD_OK planted at a non-guard path; source filled in below
};
// Expected reason for fixtures whose hit is not at the planted file (self-test fails if the reason does not match).
const ALLOW_REASON = (n) => new RegExp(`^src/entropy/:0: rule27-missing-pair \\(randomFillSync, entropy/\\).*PH1-M1 trigger: \\(i\\) src/entropy/a\\.ts exports ${n}\\b`);
function GUARD_SRC() { return "const KEY = '__oreCoreGuard';\nexport function install(v) {\n  if (Object.hasOwn(globalThis, KEY)) throw new Error('GUARD_PRESENT');\n  Object.defineProperty(globalThis, '__oreCoreGuard', { value: v, writable: false, configurable: false, enumerable: false });\n}\n"; }
export const BAD_REASON = { 'allowlist-SEED_BYTES': ALLOW_REASON('SEED_BYTES'), 'allowlist-FINGERPRINT_BYTES-15': ALLOW_REASON('FINGERPRINT_BYTES'),
  'allowlist-FINGERPRINT_BYTES-string': ALLOW_REASON('FINGERPRINT_BYTES'), 'allowlist-FINGERPRINT_BYTES-let': ALLOW_REASON('FINGERPRINT_BYTES'),
  'allowlist-FINGERPRINT_BYTES-reexport': ALLOW_REASON('FINGERPRINT_BYTES'),
  'allowlist-FINGERPRINT_BYTES-multi': new RegExp(ALLOW_REASON('FINGERPRINT_BYTES').source.replace('exports FINGERPRINT_BYTES\\b', 'has an opaque export \\(const with several declarators\\)')),
  ...Object.fromEntries([['globalThis-destructure', 'globalThis-alias'], ['globalThis-alias', 'globalThis-alias'], ['globalThis-Reflect-get', 'globalThis-alias'],
    ['globalThis-getOwnPropertyDescriptor', 'globalThis-alias'], ['Function-return-this', 'function-eval'], ['require-node-module', 'node-module'],
    ['require-module', 'node-module'], ['fips-identifier', 'fips'], ['fips-computed', 'fips'],
    ...['gt-self-crypto', 'gt-window-crypto', 'gt-globalThis-crypto', 'gt-Function', 'gt-eval', 'gt-Reflect-get', 'gt-process-getBuiltinModule', 'gt-process-binding'].map((n) => [n, 'globalThis-member']),
    ['process-alias', 'process-banned-member'], ['process-destructure', 'process-reach'], ['process-linkedBinding', 'process-banned-member'],
    ['process-dlopen', 'process-banned-member'], ['process-mainModule', 'process-banned-member'], ['process-plain-member', 'process-reach'],
    ['module-require', 'module-require'], ['mainModule-require', 'process-banned-member'], ['require-alias', 'require-alias'],
    ['require-destructure', 'require-alias'], ['require-member-call', 'require-member-call'], ['window-alias', 'global-self'], ['constructor-call', 'function-eval']].map(([n, c]) => [n, new RegExp(`^src/mapping/bad\\.ts:\\d+: rule27-${c} `)])),
  'guard-forms-non-guard-path': /^packages\/capability\/src\/other\.ts:\d+: rule27-defineProperty-globalThis .*outside packages\/capability\/src\/coreGuard\.ts/ };
BAD['guard-forms-non-guard-path'] = GUARD_SRC();
// Control planted the same way: the single allow-listed declaration stays green (report-only).
export const ALLOW_CONTROL = 'export const FINGERPRINT_BYTES = 16;\n';
// Where each known-bad fixture is planted (default src/mapping/bad.ts).
export const BAD_PATH = { 'audited-import': 'src/audited/bad.ts', 'createHash-outside-evidence': 'src/entropy/bad.ts',
  'capability-crypto': 'packages/capability/src/bad.ts', 'mapping-namespace': 'packages/mapping/src/bad.ts',
  'verify-drbg': 'src/verify/bad.ts', 'verify-drbg-relative': 'src/verify/bad.ts', 'verify-binding-wrong-path': 'src/verify/testingBinding.ts',
  'entropy-alias': 'src/entropy/bad.ts', 'entropy-other-path': 'src/entropy/bad.ts', 'randomFillSync-outside-entropy': 'src/mapping/bad.ts',
  ...Object.fromEntries(Object.keys(BAD).filter((n) => n.startsWith('allowlist-')).map((n) => [n, 'src/entropy/a.ts'])),
  'guard-forms-non-guard-path': 'packages/capability/src/other.ts' };
export const GUARD_OK = "const KEY = '__oreCoreGuard';\nexport function install(v) {\n  if (Object.hasOwn(globalThis, KEY)) throw new Error('GUARD_PRESENT');\n  Object.defineProperty(globalThis, '__oreCoreGuard', { value: v, writable: false, configurable: false, enumerable: false });\n}\n";

export function writeFixture(dir, extra = {}) {
  for (const [p, s] of Object.entries({ ...GOOD, ...extra })) { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), s); }
}

export const SELF_TEST_EXTRA_CASES = ['allowlist-control', 'guard-control', 'MX-12 p8-package key plant', 'MX-12 clean control'];
function mx12Case(base) {
  const out = []; const here = dirname(new URL(import.meta.url).pathname); const lint = join(here, '..', 'claims-lint.mjs');
  const sp1 = JSON.parse(readFileSync(join(here, '..', 'claims-allowlist.json'), 'utf8')).entries.find((e) => e.id === 'S-P1')?.text;
  if (!sp1) return ['MX-12 case: S-P1 not found in tools/claims-allowlist.json'];
  const run = (name, obj) => { const f = join(base, name); writeFileSync(f, JSON.stringify(obj)); return spawnSync(process.execPath, [lint, '--surface', 'p8-package', f], { encoding: 'utf8' }); };
  const red = run('mx12-plant.json', { name: 'open-rng-engine', description: sp1, ['\u0063ertified-by']: 1 });
  if (red.status !== 1 || !red.stdout.split('\n').some((l) => l.includes('(key)'))) out.push(`MX-12 case: p8-package key-only plant not red with a (key) hit (status ${red.status}):\n${red.stdout}`);
  const clean = run('mx12-clean.json', { name: 'open-rng-engine', description: sp1 });
  if (clean.status !== 0) out.push(`MX-12 control: clean p8-package not green (status ${clean.status}):\n${clean.stdout}`);
  return out;
}

export function selfTest() {
  const fails = [];
  const base = mkdtempSync(join(tmpdir(), 'rule27-'));
  try {
    const g = join(base, 'good'); writeFixture(g);
    const gr = scanTree(g).hits; if (gr.length) fails.push(`good fixture not green:\n${gr.join('\n')}`);
    for (const [name, src] of Object.entries(BAD)) {
      const d = join(base, name); const file = BAD_PATH[name] ?? 'src/mapping/bad.ts';
      writeFixture(d, { [file]: src });
      const hits = scanTree(d).hits;
      if (hits.length === 0) fails.push(`known-bad fixture ${name} did not turn rule 27 red`);
      else if (BAD_REASON[name] && !hits.some((h) => BAD_REASON[name].test(h))) fails.push(`known-bad fixture ${name} is red for the wrong reason:\n${hits.join('\n')}`);
    }
    const c = join(base, 'allowlist-control'); writeFixture(c, { 'src/entropy/a.ts': ALLOW_CONTROL });
    const cr = scanTree(c).hits; if (cr.length) fails.push(`allow-list control (export const FINGERPRINT_BYTES = 16) not green:\n${cr.join('\n')}`);
    // G-20 / M-152b: the exact guard at GUARD_PATH stays green.
    const gd = join(base, 'guard-control'); writeFixture(gd, { [GUARD_PATH]: GUARD_SRC() });
    const gh = scanTree(gd).hits; if (gh.length) fails.push(`guard-exact control not green:\n${gh.join('\n')}`);
    // G-20 / MX-12: claims-lint --surface p8-package must lint keys (embedded escaped key-only plant red, clean control green).
    fails.push(...mx12Case(base));
  } finally { rmSync(base, { recursive: true, force: true }); }
  return fails;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv[2] === '--self-test') {
    const f = selfTest(); console.log(f.length ? f.join('\n') : `rule27 self-test: ${Object.keys(BAD).length} known-bad fixtures red, good fixture green, ${SELF_TEST_EXTRA_CASES.length} extra cases ok (${SELF_TEST_EXTRA_CASES.join(', ')})`); process.exit(f.length ? 1 : 0);
  }
  const args = process.argv.slice(2); const phaseExit = args.includes('--phase-exit');
  const root = args.find((x) => !x.startsWith('--')) ?? process.cwd();
  const { hits, reports } = scanTree(root, { phaseExit });
  for (const r of reports) console.log(r);
  for (const h of hits) console.log(h);
  console.log(`rule27 import-allowlist: ${hits.length} finding(s) (dist/ grep half PENDING)`);
  process.exit(hits.length ? 1 : 0);
}
