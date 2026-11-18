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
// PENDING: the dist/ grep half (no packed core yet); scope of packages/*/src (open question, CTO report).
// Usage: node tools/ci/import-allowlist.mjs [root]      --self-test runs the known-bad fixtures (each must be red).
import { readFileSync, readdirSync, statSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, relative, dirname, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';

export const REQUIRED_PAIRS = ['randomFillSync@entropy', 'createHash@evidence', 'getFips@identity'];
const EXT = /\.(ts|mts|cts|js|mjs|cjs)$/;

function walk(d, out = []) {
  let names; try { names = readdirSync(d); } catch { return out; }
  for (const n of names.sort()) { const p = join(d, n); const s = statSync(p); if (s.isDirectory()) walk(p, out); else if (EXT.test(n)) out.push(p); }
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
  const top = rel.split('/')[1] ?? '';
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
        const sym = part.replace(/^type\s+/, '').split(/\s+as\s+/)[0].trim();
        pairs.push({ pair: `${sym}@${top}`, at: `${rel}:${lineOf(src, s.idx)}` });
      }
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
    [b, /(^|[^\w$])(setFips|fips)\b/g, 'fips', 'setFips / fips identifier or member'],
    [a, /\[\s*(['"`])(setFips|fips)\1\s*\]/g, 'fips', 'computed setFips / fips member'],
    [b, /(^|[^\w$.])Object\s*\.\s*defineProperty\s*\(\s*globalThis\b/g, 'defineProperty-globalThis', 'Object.defineProperty(globalThis, ...) in core src/'],
  ];
  for (const [text, re, code, msg] of pat) for (const m of text.matchAll(re)) add(m.index + (m[1]?.length ?? 0), code, msg);
  return { hits, pairs };
}

export function scanTree(root) {
  const hits = []; const pairs = [];
  for (const f of walk(join(root, 'src'))) {
    const rel = relative(root, f).split(sep).join('/');
    const r = scanFile(rel, readFileSync(f, 'utf8'));
    hits.push(...r.hits); pairs.push(...r.pairs);
  }
  const have = new Set(pairs.map((p) => p.pair));
  for (const p of pairs) if (!REQUIRED_PAIRS.includes(p.pair)) hits.push(`${p.at}: rule27-extra-pair (${p.pair.replace('@', ', ')}/) is not in the allowlist`);
  for (const p of REQUIRED_PAIRS) if (!have.has(p)) hits.push(`src/${p.split('@')[1]}/:0: rule27-missing-pair (${p.replace('@', ', ')}/) required by L596 is absent`);
  return { hits, pairs };
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
};

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
      const d = join(base, name); const file = name === 'audited-import' ? 'src/audited/bad.ts' : name === 'createHash-outside-evidence' ? 'src/entropy/bad.ts' : 'src/mapping/bad.ts';
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
  const root = process.argv[2] ?? process.cwd();
  const { hits } = scanTree(root);
  for (const h of hits) console.log(h);
  console.log(`rule27 import-allowlist: ${hits.length} finding(s) (dist/ grep half PENDING)`);
  process.exit(hits.length ? 1 : 0);
}
