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
//         Only carve-out, so a pure constant is not an API: `export const UPPER_CASE = <numeric literal>` (e.g.
//         FINGERPRINT_BYTES = 16 in blockPlan.ts). Comments and string contents are ignored; everything else errs red.
//     (ii) package.json has main/module/exports (package root exported), or a module reachable by static imports or
//         re-exports from a core entry (src/index.ts, src/audited/index.ts) exports createRng/createAuditedRng/randomInt/
//         shuffle/sample/weightedPick/randomBytes or any create*Rng / random* name;
//     (iii) --phase-exit (PH1 exit, any packed or release build).
//     evidence/ and identity/ keep the plain rule: blocking once the directory exists.
//  randomFillSync anywhere outside src/entropy/ is red; inside it only the exact `import { randomFillSync } from
//  'node:crypto'` is allowed (no alias, no other path).
// PENDING: the dist/ grep half (no packed core yet).
// Usage: node tools/ci/import-allowlist.mjs [root] [--phase-exit]   --self-test runs the known-bad fixtures.
import { readFileSync, readdirSync, statSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join, relative, dirname, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';

export const REQUIRED_PAIRS = ['randomFillSync@entropy', 'createHash@evidence', 'getFips@identity'];
const EXT = /\.(ts|mts|cts|js|mjs|cjs)$/;
export const SCAN_ROOTS = ['src', 'packages/capability/src', 'packages/mapping', 'verify'];
// Exact-path exceptions (Q2: none for the namespace/default ban today).
export const GUARD_PATH = 'packages/capability/src/coreGuard.ts'; // QR-25 L228, PLAN R-58(6) L166
export const VERIFY_BINDING_PATH = 'verify/src/testingBinding.ts'; // PLAN L535 (QR-57 row h), R-58(1) L166
const DRBG_PKG = '@open-rng-engine/drbg';

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
    ...(rel.startsWith('src/entropy/') ? [] : [[b, /(^|[^\w$])randomFillSync\b/g, 'randomFillSync-outside-entropy', 'randomFillSync outside src/entropy/']]),
    [b, /(^|[^\w$])(setFips|fips)\b/g, 'fips', 'setFips / fips identifier or member'],
    [a, /\[\s*(['"`])(setFips|fips)\1\s*\]/g, 'fips', 'computed setFips / fips member'],
  ];
  for (const [text, re, code, msg] of pat) for (const m of text.matchAll(re)) add(m.index + (m[1]?.length ?? 0), code, msg);
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

// Exported names of one module: [{ name, numericConst }], plus opaque=true for export * / default / destructuring.
export function exportsOf(src) {
  const [a, b] = strip(src); const out = []; let opaque = [];
  for (const m of b.matchAll(/(^|[^\w$.])export\s+(declare\s+)?(async\s+)?(function\s*\*?|class|const|let|var|type|interface|enum)\s*([A-Za-z_$][\w$]*)/g)) {
    const numericConst = m[4] === 'const' && /^[A-Z][A-Z0-9_]*$/.test(m[5]) && new RegExp(`^export\\s+const\\s+${m[5]}\\s*(:\\s*number\\s*)?=\\s*-?[0-9][0-9_]*(\\.[0-9_]+)?\\s*;`, 'm').test(a.slice(m.index + m[1].length));
    out.push({ name: m[5], numericConst });
  }
  for (const m of a.matchAll(/(^|[^\w$.])export\s+(type\s+)?\{([^}]*)\}/g)) for (const part of m[3].split(',').map((x) => x.trim()).filter(Boolean)) {
    const ps = part.replace(/^type\s+/, '').split(/\s+as\s+/).map((x) => x.trim()); out.push({ name: ps[1] ?? ps[0], numericConst: false });
  }
  for (const m of b.matchAll(/(^|[^\w$.])export\s*(\*|default\b|(const|let|var)\s*[\[{])/g)) opaque.push(m[2]);
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
    for (const e of ex.names) if (READ_NAME.test(e.name) && !e.numericConst) why.push(`(i) ${rel} exports ${e.name}`);
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
};
// Where each known-bad fixture is planted (default src/mapping/bad.ts).
export const BAD_PATH = { 'audited-import': 'src/audited/bad.ts', 'createHash-outside-evidence': 'src/entropy/bad.ts',
  'capability-crypto': 'packages/capability/src/bad.ts', 'mapping-namespace': 'packages/mapping/src/bad.ts',
  'verify-drbg': 'src/verify/bad.ts', 'verify-drbg-relative': 'src/verify/bad.ts', 'verify-binding-wrong-path': 'src/verify/testingBinding.ts',
  'entropy-alias': 'src/entropy/bad.ts', 'entropy-other-path': 'src/entropy/bad.ts', 'randomFillSync-outside-entropy': 'src/mapping/bad.ts' };
export const GUARD_OK = "const KEY = '__oreCoreGuard';\nexport function install(v) {\n  if (Object.hasOwn(globalThis, KEY)) throw new Error('GUARD_PRESENT');\n  Object.defineProperty(globalThis, '__oreCoreGuard', { value: v, writable: false, configurable: false, enumerable: false });\n}\n";

export function writeFixture(dir, extra = {}) {
  for (const [p, s] of Object.entries({ ...GOOD, ...extra })) { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), s); }
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
      if (scanTree(d).hits.length === 0) fails.push(`known-bad fixture ${name} did not turn rule 27 red`);
    }
  } finally { rmSync(base, { recursive: true, force: true }); }
  return fails;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.argv[2] === '--self-test') {
    const f = selfTest(); console.log(f.length ? f.join('\n') : `rule27 self-test: ${Object.keys(BAD).length} known-bad fixtures red, good fixture green`); process.exit(f.length ? 1 : 0);
  }
  const args = process.argv.slice(2); const phaseExit = args.includes('--phase-exit');
  const root = args.find((x) => !x.startsWith('--')) ?? process.cwd();
  const { hits, reports } = scanTree(root, { phaseExit });
  for (const r of reports) console.log(r);
  for (const h of hits) console.log(h);
  console.log(`rule27 import-allowlist: ${hits.length} finding(s) (dist/ grep half PENDING)`);
  process.exit(hits.length ? 1 : 0);
}
