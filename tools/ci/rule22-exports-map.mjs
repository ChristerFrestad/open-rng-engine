#!/usr/bin/env node
// Rule 22 — core exports allowlist (LIVE, in check:ph0).
// Spec (read-only): PLAN r4.9 L136 R-28, L537, L825 item (22); quality v5.5.7 L278 QR-33, L584 CI 15.
// The core package.json `exports` keys must be exactly {".", "./audited", "./package.json"}
// and each key is pinned to exactly one target (EXPORT_TARGET_PINS). Targets that are
// absolute, '../', or under node_modules are red. `imports`, `browser` and `typesVersions`
// are red; `main` is red unless it equals the pinned '.' target.
//
// Interim exported-name scan (Q1, until api-report.md exists at the first packed build):
// follow '.' and './audited' through every export target, `export *` and re-export.
// Red on any export originating in src/entropy, on any raw-bytes API, and on any QR-33
// term appearing as a camelCase/_ name segment of a core export. The labkit and
// docs/examples import edge is in this rule. A 'card' identifier in docs/examples
// stays green when the core does not import or re-export it.
//
// PENDING: the api-extractor api-report.md half starts at the first packed build (PH3).
// The `files` field and `npm audit signatures` in CI are backlog preconditions for that
// first packed build; they are not added to package.json while the current G4 holds.

import { existsSync, mkdtempSync, readFileSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname, resolve, sep, isAbsolute, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

export const REQUIRED_EXPORT_KEYS = Object.freeze(['.', './audited', './package.json']);
export const EXPORT_TARGET_PINS = Object.freeze({
  '.': './src/index.ts',
  './audited': './src/audited/index.ts',
  './package.json': './package.json',
});
export const FORBIDDEN_EXPORT_SEGMENTS = Object.freeze([
  '-testing', '-edge-experimental', 'packages/drbg', 'packages/mapping', 'packages/capability',
]);
export const QR33_TERM_ESCAPES = Object.freeze([
  '\\u0064\\u0065\\u0063\\u006b',
  '\\u0063\\u0061\\u0072\\u0064',
  '\\u0073\\u0068\\u006f\\u0065',
  '\\u0072\\u0065\\u0065\\u006c',
  '\\u0073\\u0074\\u0072\\u0069\\u0070',
  '\\u0070\\u0061\\u0079\\u006c\\u0069\\u006e\\u0065',
  '\\u0070\\u0061\\u0079\\u0074\\u0061\\u0062\\u006c\\u0065',
  '\\u0072\\u0074\\u0070',
  '\\u0072\\u006f\\u0075\\u006c\\u0065\\u0074\\u0074\\u0065',
  '\\u0070\\u006f\\u0063\\u006b\\u0065\\u0074',
  '\\u0070\\u006f\\u006b\\u0065\\u0072',
  '\\u0068\\u006f\\u006c\\u0064\\u0065\\u006d',
  '\\u0068\\u0061\\u006e\\u0064',
  '\\u0062\\u0075\\u0072\\u006e',
]);
export const RAW_BYTES_APIS = Object.freeze([
  'randomFillSync', 'randomBytes', 'randomFill', 'getRandomValues', 'randomUUID', 'randomInt',
]);
export const PUBLIC_ENTRY_KEYS = Object.freeze(['.', './audited']);

export function uEscape(s) {
  return [...String(s)].map((c) => {
    const code = c.charCodeAt(0);
    return (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
      ? '\\u' + code.toString(16).padStart(4, '0')
      : c;
  }).join('');
}
export function uUnescape(s) {
  return String(s).replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}
export const QR33_TERMS = Object.freeze(QR33_TERM_ESCAPES.map(uUnescape));

function collectStrings(v, out = []) {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => collectStrings(x, out));
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => collectStrings(x, out));
  return out;
}

function pathReachesForbidden(p) {
  const n = String(p).split('\\').join('/');
  if (n.includes('*')) return false; // wildcard keys are a separate hit
  for (const seg of FORBIDDEN_EXPORT_SEGMENTS) {
    if (seg.startsWith('-')) {
      // package-name fragment: match as a path segment containing the suffix/name
      const parts = n.split('/');
      if (parts.some((part) => part.includes(seg))) return seg;
    } else if (n.includes(seg)) return seg;
  }
  return null;
}


function posix(p) { return String(p).split(sep).join('/'); }

export function nameSegments(id) {
  return String(id)
    .split(/_+/g)
    .flatMap((part) => part.split(/[0-9]+/))
    .flatMap((part) => part.split(/(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/))
    .map((s) => s.toLowerCase())
    .filter(Boolean);
}

function segmentMatchesTerm(seg, term) {
  const s = String(seg).toLowerCase();
  const t = String(term).toLowerCase();
  return s === t || s === t + 's' || s === t + 'es';
}

export function qr33Hit(name) {
  const lower = String(name).toLowerCase();
  const segs = nameSegments(name);
  for (const t of QR33_TERMS) {
    if (segs.some((s) => segmentMatchesTerm(s, t))) return t;
    if (lower.includes(t)) return t;
  }
  return null;
}

export const QR33_ALLOW_REL = 'tools/qr33-allow.json';
export const QR33_ALLOW_SHA256 = 'db2d0ab03ee56d327244ee982b0712dae4acc22f251927ed5437863f641b35ba';

export function loadQr33Allow(abs) {
  const data = JSON.parse(readFileSync(abs, 'utf8'));
  if (!data || !Array.isArray(data.entries)) {
    throw new Error(`qr33-allow: ${abs} must be { schema, entries: [...] }`);
  }
  for (const e of data.entries) {
    if (!e || typeof e.entry !== 'string' || typeof e.hoqRulingRef !== 'string' || typeof e.fixture !== 'string') {
      throw new Error(`qr33-allow: entry must be {entry, hoqRulingRef, fixture}`);
    }
  }
  return data.entries;
}

function allowSet(entries) {
  return new Set((entries ?? []).map((e) => e.entry));
}

function isPinnedScalar(val) {
  return typeof val === 'string';
}

export function targetIsBannedShape(t) {
  if (typeof t !== 'string' || t.length === 0) return 'empty or non-string';
  const n = t.split('\\').join('/');
  if (isAbsolute(n) || /^[A-Za-z]:\//.test(n) || n.startsWith('/')) return 'absolute';
  if (n === '..' || n.startsWith('../') || n.includes('/../')) return "'../'";
  if (n.split('/').includes('node_modules')) return 'node_modules';
  return null;
}

function resolveRel(fromRel, spec) {
  const base = posix(fromRel).split('/').slice(0, -1).join('/');
  return posix(join(base || '.', spec)).replace(/^\.\//, '');
}

function isLabkitOrExamplesSpec(fromRel, spec) {
  const n = posix(spec);
  if (n === 'labkit' || n.startsWith('labkit/') || n.split('/').includes('labkit')) return 'labkit';
  if (n.includes('docs/examples') || n.startsWith('docs/examples')) return 'docs/examples';
  if (n.startsWith('.')) {
    const dest = resolveRel(fromRel, n);
    if (dest === 'docs/examples' || dest.startsWith('docs/examples/')) return 'docs/examples';
    if (dest === 'labkit' || dest.startsWith('labkit/') || dest.split('/').includes('labkit')) return 'labkit';
  }
  return null;
}

function isSourceFile(rel) {
  return /\.(ts|mts|cts|js|mjs|cjs)$/.test(rel);
}

function exportedBindings(sf) {
  const out = [];
  for (const st of sf.statements) {
    if (ts.isExportDeclaration(st)) {
      const spec = st.moduleSpecifier && ts.isStringLiteral(st.moduleSpecifier) ? st.moduleSpecifier.text : null;
      if (st.exportClause && ts.isNamedExports(st.exportClause)) {
        for (const el of st.exportClause.elements) {
          out.push({ name: el.name.text, local: (el.propertyName ?? el.name).text, from: spec, star: false, typ: !!st.isTypeOnly });
        }
      } else if (st.exportClause && ts.isNamespaceExport(st.exportClause)) {
        out.push({ name: st.exportClause.name.text, local: st.exportClause.name.text, from: spec, star: false, ns: true });
      } else if (!st.exportClause && spec) {
        out.push({ name: '*', local: '*', from: spec, star: true });
      }
    }
    if (ts.isExportAssignment(st) && !st.isExportEquals) out.push({ name: 'default', local: 'default', from: null, star: false });
    const mods = st.modifiers ?? [];
    const exported = mods.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if (!exported) continue;
    if (ts.isFunctionDeclaration(st) || ts.isClassDeclaration(st) || ts.isInterfaceDeclaration(st) || ts.isTypeAliasDeclaration(st) || ts.isEnumDeclaration(st)) {
      if (st.name) out.push({ name: st.name.text, local: st.name.text, from: null, star: false });
    }
    if (ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) {
        for (const name of bindingNames(d.name)) out.push({ name, local: name, from: null, star: false });
      }
    }
    if (ts.isClassDeclaration(st)) {
      for (const name of classStaticNames(st)) out.push({ name, local: name, from: null, star: false, staticMember: true });
    }
  }
  return out;
}

function bindingNames(name) {
  if (!name) return [];
  if (ts.isIdentifier(name)) return [name.text];
  const out = [];
  const walk = (n) => {
    if (!n) return;
    if (ts.isIdentifier(n)) { out.push(n.text); return; }
    if (ts.isObjectBindingPattern(n) || ts.isArrayBindingPattern(n)) {
      for (const el of n.elements) {
        if (ts.isOmittedExpression(el)) continue;
        if (ts.isBindingElement(el)) walk(el.name);
        else walk(el);
      }
    }
  };
  walk(name);
  return out;
}

function classStaticNames(cls) {
  const out = [];
  for (const m of cls.members) {
    const mods = m.modifiers ?? [];
    if (!mods.some((x) => x.kind === ts.SyntaxKind.StaticKeyword)) continue;
    const n = m.name;
    if (n && ts.isIdentifier(n)) out.push(n.text);
  }
  return out;
}

function specifiersOf(sf) {
  const out = [];
  const take = (spec) => { if (spec && ts.isStringLiteral(spec)) out.push(spec.text); };
  const visit = (node) => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) take(node.moduleSpecifier);
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) take(node.arguments[0]);
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'require') take(node.arguments[0]);
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

export function walkPublicExports(root, entries, { qr33Allow = [] } = {}) {
  const hits = [];
  const allowed = allowSet(qr33Allow);
  const seen = new Set();
  const todo = entries.map((rel) => ({ rel: posix(rel), fromPublic: true }));
  const emit = (rel, name, originRel) => {
    if (RAW_BYTES_APIS.includes(name)) hits.push(`${rel}:1: rule22-exports raw-bytes API '${name}' is in the public core API`);
    const q = qr33Hit(name);
    if (q && !allowed.has(name)) hits.push(`${rel}:1: rule22-exports core export '${name}' contains QR-33 term '${q}'`);
    if (originRel && posix(originRel).startsWith('src/entropy/')) {
      hits.push(`${rel}:1: rule22-exports public API re-exports '${name}' originating in ${originRel}`);
    }
  };
  const visitFile = (rel, followExports) => {
    const abs = join(root, rel);
    if (!existsSync(abs)) return;
    if (!isSourceFile(rel)) return;
    const src = readFileSync(abs, 'utf8');
    const sf = ts.createSourceFile(rel, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    for (const spec of specifiersOf(sf)) {
      const edge = isLabkitOrExamplesSpec(rel, spec);
      if (edge) hits.push(`${rel}:1: rule22-exports core import edge to ${edge} ('${spec}')`);
      if (typeof spec === 'string' && spec.startsWith('.')) {
        const dest = resolveRel(rel, spec);
        const key = `walk:${dest}`;
        if (!seen.has(key)) { seen.add(key); visitFile(dest, false); }
      }
    }
    if (!followExports) return;
    for (const b of exportedBindings(sf)) {
      if (b.star && b.from && b.from.startsWith('.')) {
        const dest = resolveRel(rel, b.from);
        const destAbs = join(root, dest);
        if (existsSync(destAbs) && isSourceFile(dest)) {
          const destSf = ts.createSourceFile(dest, readFileSync(destAbs, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
          for (const inner of exportedBindings(destSf)) {
            if (inner.star) {
              const key = `star:${dest}:${inner.from}`;
              if (!seen.has(key) && inner.from && inner.from.startsWith('.')) {
                seen.add(key);
                visitFile(resolveRel(dest, inner.from), true);
              }
            } else {
              emit(rel, inner.name, dest);
              if (inner.from && inner.from.startsWith('.')) visitFile(resolveRel(dest, inner.from), true);
            }
          }
        }
        continue;
      }
      if (b.from && b.from.startsWith('.')) {
        const dest = resolveRel(rel, b.from);
        emit(rel, b.name, dest);
        visitFile(dest, true);
      } else {
        emit(rel, b.name, rel);
      }
    }
  };
  for (const { rel } of todo) {
    const key = `entry:${rel}`;
    if (seen.has(key)) continue;
    seen.add(key);
    visitFile(rel, true);
  }
  return hits;
}

export function scanExports(pkg, { path = 'package.json' } = {}) {
  const hits = [];
  if (!pkg || typeof pkg !== 'object') {
    hits.push(`${path}:1: rule22-exports missing or unreadable package.json`);
    return hits;
  }
  if (pkg.exports === undefined) {
    hits.push(`${path}:1: rule22-exports 'exports' is missing; keys must be exactly {".", "./audited", "./package.json"}`);
    return hits;
  }
  const exp = pkg.exports;
  if (typeof exp !== 'object' || exp === null || Array.isArray(exp)) {
    hits.push(`${path}:1: rule22-exports 'exports' must be an object whose keys are exactly {".", "./audited", "./package.json"}`);
    return hits;
  }
  const keys = Object.keys(exp);
  const missing = REQUIRED_EXPORT_KEYS.filter((k) => !keys.includes(k));
  const extra = keys.filter((k) => !REQUIRED_EXPORT_KEYS.includes(k));
  if (missing.length || extra.length) {
    hits.push(`${path}:1: rule22-exports keys are {${keys.join(', ')}} but must be exactly {".", "./audited", "./package.json"}` +
      (missing.length ? ` (missing ${missing.join(', ')})` : '') +
      (extra.length ? ` (extra ${extra.join(', ')})` : ''));
  }
  for (const k of keys) {
    if (k.includes('*')) hits.push(`${path}:1: rule22-exports key '${k}' is a wildcard`);
    if (k === './drbg' || k.startsWith('./drbg/')) hits.push(`${path}:1: rule22-exports key '${k}' is ./drbg`);
    const val = exp[k];
    const pin = EXPORT_TARGET_PINS[k];
    if (pin !== undefined) {
      if (!isPinnedScalar(val) || val !== pin) {
        hits.push(`${path}:1: rule22-exports key '${k}' must be pinned to exactly '${pin}' (got ${JSON.stringify(val)})`);
      }
    }
    for (const t of collectStrings(val)) {
      if (typeof t === 'string' && t.includes('*')) hits.push(`${path}:1: rule22-exports target '${t}' of key '${k}' is a wildcard`);
      const bad = pathReachesForbidden(t);
      if (bad) hits.push(`${path}:1: rule22-exports key '${k}' reaches ${bad} (${t})`);
      const shape = targetIsBannedShape(t);
      if (shape) hits.push(`${path}:1: rule22-exports key '${k}' target '${t}' is ${shape}`);
    }
  }
  for (const field of ['imports', 'browser', 'typesVersions']) {
    if (pkg[field] !== undefined) hits.push(`${path}:1: rule22-exports '${field}' is red`);
  }
  if (pkg.main !== undefined && pkg.main !== EXPORT_TARGET_PINS['.']) {
    hits.push(`${path}:1: rule22-exports 'main' must be absent or exactly the pinned '.' target '${EXPORT_TARGET_PINS['.']}'; found ${JSON.stringify(pkg.main)}`);
  }
  return hits;
}

export function publicEntryRels(pkg) {
  const exp = pkg && pkg.exports;
  const rels = [];
  if (exp && typeof exp === 'object' && !Array.isArray(exp)) {
    for (const key of PUBLIC_ENTRY_KEYS) {
      const val = exp[key];
      const pin = EXPORT_TARGET_PINS[key];
      const t = (typeof val === 'string' ? val : pin) ?? pin;
      if (typeof t === 'string' && t.startsWith('.')) rels.push(posix(t.replace(/^\.\//, '')));
    }
  }
  return [...new Set(rels)];
}

export function scanRoot(root, opts = {}) {
  const file = join(root, 'package.json');
  if (!existsSync(file)) return [`package.json:1: rule22-exports missing package.json`];
  let pkg;
  try { pkg = JSON.parse(readFileSync(file, 'utf8')); }
  catch (e) { return [`package.json:1: rule22-exports unreadable package.json (${e.message})`]; }
  const hits = scanExports(pkg, { path: 'package.json' });
  let qr33Allow = opts.qr33Allow;
  if (qr33Allow === undefined) {
    const allowPath = join(root, QR33_ALLOW_REL);
    qr33Allow = existsSync(allowPath) ? loadQr33Allow(allowPath) : [];
  }
  hits.push(...walkPublicExports(root, publicEntryRels(pkg), { qr33Allow }));
  return hits;
}

// Known-bad fixtures stored \u-escaped (CTO addendum 07:45), materialised only in scratch.
const GOOD_PKG = {
  name: 'open-rng-engine', version: '0.0.0', private: true, type: 'module',
  exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json' },
  dependencies: {},
};
export const BAD_FIXTURES = {
  'missing-exports': { pkg: { name: 'x', version: '0.0.0', private: true, type: 'module', dependencies: {} }, reason: /rule22-exports 'exports' is missing/ },
  'extra-drbg-key': { pkg: { ...GOOD_PKG, exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json', './drbg': './packages/drbg/src/index.ts' } }, reason: /rule22-exports/ },
  'wildcard-key': { pkg: { ...GOOD_PKG, exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json', './*': './src/*' } }, reason: /wildcard/ },
  'mapping-target': { pkg: { ...GOOD_PKG, exports: { '.': './packages/mapping/src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json' } }, reason: /packages\/mapping/ },
  'plain-extra-key': { pkg: { ...GOOD_PKG, exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json', './internal': './src/health/index.ts' } }, reason: /extra \.\/internal/ },
  'absolute-target': { pkg: { ...GOOD_PKG, exports: { '.': '/tmp/evil.ts', './audited': './src/audited/index.ts', './package.json': './package.json' } }, reason: /is absolute/ },
  'dotdot-target': { pkg: { ...GOOD_PKG, exports: { '.': '../evil.ts', './audited': './src/audited/index.ts', './package.json': './package.json' } }, reason: /is '\.\.\/'/ },
  'node-modules-target': { pkg: { ...GOOD_PKG, exports: { '.': './node_modules/typescript/lib/typescript.js', './audited': './src/audited/index.ts', './package.json': './package.json' } }, reason: /is node_modules/ },
  'imports-field': { pkg: { ...GOOD_PKG, imports: { '#x': './src/index.ts' } }, reason: /'imports' is red/ },
  'browser-field': { pkg: { ...GOOD_PKG, browser: './src/index.ts' }, reason: /'browser' is red/ },
  'typesVersions-field': { pkg: { ...GOOD_PKG, typesVersions: { '*': { '*': ['./src/index.ts'] } } }, reason: /'typesVersions' is red/ },
  'main-not-pinned': { pkg: { ...GOOD_PKG, main: './src/verify/index.ts' }, reason: /'main' must be absent or exactly the pinned/ },
  'wrong-pin-package-json': { pkg: { ...GOOD_PKG, exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './src/verify/index.ts' } }, reason: /key '\.\/package\.json' must be pinned to exactly '\.\/package\.json'/ },
};

function writeJson(dir, rel, obj) {
  const p = join(dir, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');
}

export function selfTest() {
  const fails = [];
  const base = mkdtempSync(join(tmpdir(), 'r22-'));
  try {
    const ctl = join(base, 'control');
    writeJson(ctl, 'package.json', GOOD_PKG);
    mkdirSync(join(ctl, 'src/audited'), { recursive: true });
    writeFileSync(join(ctl, 'src/index.ts'), 'export {};\n');
    writeFileSync(join(ctl, 'src/audited/index.ts'), 'export {};\n');
    const ch = scanRoot(ctl);
    if (ch.length) fails.push(`control not green:\n${ch.join('\n')}`);
    // 'card' in docs/examples stays green when the core does not import or re-export it.
    const cardName = uUnescape(QR33_TERM_ESCAPES[1]);
    const examples = join(ctl, 'docs/examples');
    mkdirSync(examples, { recursive: true });
    writeFileSync(join(examples, 'demo.ts'), `export const ${cardName} = 1;\n`);
    const exHits = scanRoot(ctl);
    if (exHits.length) fails.push(`docs/examples ${cardName} control not green:\n${exHits.join('\n')}`);
    const graphCases = [
      {
        name: 'export-star-entropy',
        files: { 'src/index.ts': "export * from './entropy/index.ts';\n", 'src/entropy/index.ts': 'export const randomFillSync = 1;\n', 'src/audited/index.ts': 'export {};\n' },
        reason: /originating in src\/entropy\//,
      },
      {
        name: 'qr33-export-name',
        files: { 'src/index.ts': `export const ${cardName} = 1;\n`, 'src/audited/index.ts': 'export {};\n' },
        reason: /QR-33 term/,
      },
      {
        name: 'labkit-import-edge',
        files: { 'src/index.ts': "import x from 'labkit';\nexport const n = 1;\n", 'src/audited/index.ts': 'export {};\n' },
        reason: /import edge to labkit/,
      },
      {
        name: 'docs-examples-import-edge',
        files: { 'src/index.ts': "import x from '../docs/examples/demo.ts';\nexport const n = 1;\n", 'src/audited/index.ts': 'export {};\n' },
        reason: /import edge to docs\/examples/,
      },
      {
        name: 'raw-bytes-api-name',
        files: { 'src/index.ts': 'export const randomBytes = 1;\n', 'src/audited/index.ts': 'export {};\n' },
        reason: /raw-bytes API 'randomBytes'/,
      },
      {
        name: 'qr33-deal-plural',
        files: { 'src/index.ts': `export const deal${cardName[0].toUpperCase()}${cardName.slice(1)}s = 1;\n`, 'src/audited/index.ts': 'export {};\n' },
        reason: /QR-33 term/,
      },
      {
        name: 'qr33-substring',
        files: { 'src/index.ts': `export const ${cardName}${uUnescape(QR33_TERM_ESCAPES[0])} = 1;\n`, 'src/audited/index.ts': 'export {};\n' },
        reason: /QR-33 term/,
      },
      {
        name: 'qr33-destructured-export',
        files: { 'src/index.ts': `const o = { deal${cardName[0].toUpperCase()}${cardName.slice(1)}s: 1 };\nexport const { deal${cardName[0].toUpperCase()}${cardName.slice(1)}s } = o;\n`, 'src/audited/index.ts': 'export {};\n' },
        reason: /QR-33 term/,
      },
      {
        name: 'qr33-class-static',
        files: { 'src/index.ts': `export class C { static ${cardName}${uUnescape(QR33_TERM_ESCAPES[0])} = 1; }\n`, 'src/audited/index.ts': 'export {};\n' },
        reason: /QR-33 term/,
      },
    ];
    for (const [name, { pkg, reason }] of Object.entries(BAD_FIXTURES)) {
      // Materialise from a \u-escaped form; the escaped source is what we keep in-repo as the fixture text.
      const escaped = uEscape(JSON.stringify(pkg));
      const d = join(base, name);
      writeJson(d, 'package.json', JSON.parse(uUnescape(escaped)));
      const hits = scanRoot(d);
      if (!hits.some((h) => reason.test(h))) fails.push(`${name} did not turn rule 22 red:\n${hits.join('\n')}`);
    }
    for (const c of graphCases) {
      const d = join(base, c.name);
      writeJson(d, 'package.json', GOOD_PKG);
      for (const [rel, src] of Object.entries(c.files)) {
        const fp = join(d, rel); mkdirSync(dirname(fp), { recursive: true }); writeFileSync(fp, src);
      }
      const hits = scanRoot(d);
      if (!hits.some((h) => c.reason.test(h))) fails.push(`${c.name} did not turn rule 22 red:\n${hits.join('\n')}`);
    }
    // Allow-list mechanism uses a scratch config, never the production file.
    const deal = `deal${cardName[0].toUpperCase()}${cardName.slice(1)}s`;
    const scratch = join(base, 'qr33-allow-scratch');
    writeJson(scratch, 'package.json', GOOD_PKG);
    mkdirSync(join(scratch, 'src/audited'), { recursive: true });
    writeFileSync(join(scratch, 'src/index.ts'), `export const ${deal} = 1;\n`);
    writeFileSync(join(scratch, 'src/audited/index.ts'), 'export {};\n');
    const redHits = scanRoot(scratch, { qr33Allow: [] });
    if (!redHits.some((h) => /QR-33 term/.test(h))) fails.push(`scratch allow: empty list must leave ${deal} red:\n${redHits.join('\n')}`);
    const greenHits = scanRoot(scratch, { qr33Allow: [{ entry: deal, hoqRulingRef: 'scratch', fixture: 'qr33-allow-scratch' }] });
    if (greenHits.some((h) => /QR-33 term/.test(h))) fails.push(`scratch allow: listed entry must be green:\n${greenHits.join('\n')}`);
  } finally { rmSync(base, { recursive: true, force: true }); }
  if (fails.length) {
    console.error(`rule22 self-test FAILED:\n${fails.join('\n')}`);
    process.exit(1);
  }
  console.log(`rule22 self-test: ${Object.keys(BAD_FIXTURES).length + 9} known-bad fixtures red, control green`);
}

const here = fileURLToPath(import.meta.url);
if (process.argv[1] && here === process.argv[1]) {
  const args = process.argv.slice(2);
  if (args.includes('--self-test')) selfTest();
  else {
    const root = args.find((a) => !a.startsWith('-')) ?? process.cwd();
    const hits = scanRoot(root);
    if (hits.length) { hits.forEach((h) => console.log(h)); console.log(`rule22 exports-map: ${hits.length} finding(s)`); process.exit(1); }
    console.log('rule22 exports-map: 0 finding(s)');
  }
}
