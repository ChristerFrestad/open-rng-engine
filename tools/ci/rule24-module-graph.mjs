#!/usr/bin/env node
// Rule 24 — production module-graph / RQ-FC-8 reachability (LIVE, in check:ph0).
// Spec (read-only): PLAN r4.9 L146 R-38, L198 R-88, L496, L825 item (24);
// quality v5.5.7 L593 CI 24, L616 RQ-FC-8; cto-g1-spec L74 P-a.
// Walk every exports-map target (G-31), including './package.json'. An unresolved
// import is red (G-35). Nothing under a `verify/` path segment is reachable from
// '.' or './audited'. The verification-binding symbol set is every export of any
// module under a verify/ segment, plus resetCht, testMinter and replaySource;
// reaching any of them from '.' or './audited' is red.
// The cycling-adapter name `open-rng-engine-cycling` is PROVISIONAL until the G1
// name freeze (held as a single constant; also forbidden as a future package path).
//
// PENDING: packed-tarball / dist metafile / text-grep backstop starts at the first
// packed build (same as rule 27's dist half). Official adapter name is named at G1.
// all-config-paths fixture (RQ-FC-8): process.env / argv / execArgv are AST-banned
// in core (PROCESS_MEMBERS_ALLOWED is empty; confirmed with fixtures). Binding AST
// / <= 40-line cap is PLAN rule 38, not repeated here. `files` and `npm audit
// signatures` in CI are backlog preconditions for the first packed build.

import { existsSync, mkdtempSync, readFileSync, rmSync, mkdirSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

export const PRODUCTION_ENTRY_FALLBACK = Object.freeze(['src/index.ts', 'src/audited/index.ts']);
export const PROPOSED_CYCLING_ADAPTER = 'open-rng-engine-cycling'; // PROVISIONAL until the G1 name freeze; not official
export const BINDING_SYMBOL_ALWAYS = Object.freeze(['resetCht', 'testMinter', 'replaySource']);
export const RESET_SYMBOLS = BINDING_SYMBOL_ALWAYS; // back-compat alias

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

function posix(p) { return String(p).split(sep).join('/'); }

function underVerify(rel) {
  return posix(rel).split('/').includes('verify');
}

function collectStrings(v, out = []) {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => collectStrings(x, out));
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => collectStrings(x, out));
  return out;
}

export function productionEntries(root) {
  const entries = [];
  const pkgPath = join(root, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
      const exp = pkg.exports;
      if (exp && typeof exp === 'object' && !Array.isArray(exp)) {
        for (const key of Object.keys(exp)) {
          if (exp[key] == null) continue;
          for (const t of collectStrings(exp[key])) {
            if (typeof t === 'string' && t.startsWith('.')) entries.push(posix(t.replace(/^\.\//, '')));
          }
        }
      }
    } catch { /* fall through to fallback */ }
  }
  if (!entries.length) entries.push(...PRODUCTION_ENTRY_FALLBACK);
  // unique, existing only
  return [...new Set(entries)].filter((rel) => existsSync(join(root, rel)));
}

function resolveRel(fromRel, spec) {
  const base = posix(fromRel).split('/').slice(0, -1).join('/');
  const joined = posix(join(base || '.', spec));
  // strip leading empty
  return joined.replace(/^\.\//, '');
}

export function specifiersOf(src, rel) {
  const sf = ts.createSourceFile(rel, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const out = [];
  const take = (node, spec) => {
    if (spec && ts.isStringLiteral(spec)) out.push({ spec: spec.text, node });
  };
  const visit = (node) => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) take(node, node.moduleSpecifier);
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) take(node, node.arguments[0]);
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'require') take(node, node.arguments[0]);
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

export function collectExportedNames(src, rel) {
  const sf = ts.createSourceFile(rel, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const names = [];
  for (const st of sf.statements) {
    if (ts.isExportDeclaration(st) && st.exportClause && ts.isNamedExports(st.exportClause)) {
      for (const el of st.exportClause.elements) names.push(el.name.text);
    }
    const mods = st.modifiers ?? [];
    if (!mods.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) continue;
    if ((ts.isFunctionDeclaration(st) || ts.isClassDeclaration(st) || ts.isInterfaceDeclaration(st)
      || ts.isTypeAliasDeclaration(st) || ts.isEnumDeclaration(st)) && st.name) names.push(st.name.text);
    if (ts.isVariableStatement(st)) {
      for (const d of st.declarationList.declarations) if (ts.isIdentifier(d.name)) names.push(d.name.text);
    }
  }
  return names;
}

export function verificationBindingSymbols(root) {
  const names = new Set(BINDING_SYMBOL_ALWAYS);
  const visit = (dirRel) => {
    const abs = dirRel ? join(root, dirRel) : root;
    let ents;
    try { ents = readdirSync(abs, { withFileTypes: true }); } catch { return; }
    for (const ent of ents) {
      if (ent.name === 'node_modules' || ent.name === '.git') continue;
      const rel = posix(dirRel ? join(dirRel, ent.name) : ent.name);
      if (ent.isDirectory()) visit(rel);
      else if (/\.(ts|mts|cts)$/.test(ent.name) && rel.split('/').includes('verify')) {
        const src = readFileSync(join(root, rel), 'utf8');
        for (const n of collectExportedNames(src, rel)) names.add(n);
      }
    }
  };
  visit('');
  return [...names];
}

export function hasIdentifier(src, rel, names) {
  const set = new Set(names);
  const sf = ts.createSourceFile(rel, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  let hit = null;
  const visit = (node) => {
    if (hit) return;
    if (ts.isIdentifier(node) && set.has(node.text)) hit = node.text;
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return hit;
}

function isCyclingSpec(spec) {
  return spec === PROPOSED_CYCLING_ADAPTER || spec.startsWith(PROPOSED_CYCLING_ADAPTER + '/');
}

function walkFrom(root, startEntries, { checkVerify, checkBinding, checkCycling, failUnresolved, bindingSymbols }) {
  const hits = [];
  const seen = new Set();
  const todo = [...startEntries];
  while (todo.length) {
    const rel = posix(todo.pop());
    if (seen.has(rel)) continue;
    const abs = join(root, rel);
    if (!existsSync(abs)) {
      if (failUnresolved) hits.push(`${rel}:1: rule24-graph unresolved import or export target '${rel}'`);
      continue;
    }
    seen.add(rel);
    if (!/\.(ts|mts|cts|js|mjs|cjs)$/.test(rel)) continue;
    const src = readFileSync(abs, 'utf8');
    if (checkVerify && underVerify(rel)) {
      hits.push(`${rel}:1: rule24-graph production entry reaches a module under verify/ (${rel})`);
    }
    if (checkBinding) {
      const reset = hasIdentifier(src, rel, bindingSymbols);
      if (reset) hits.push(`${rel}:1: rule24-graph verification-binding symbol '${reset}' is reachable from a production entry`);
    }
    for (const { spec } of specifiersOf(src, rel)) {
      if (checkCycling && isCyclingSpec(spec)) {
        hits.push(`${rel}:1: rule24-graph core imports the cycling adapter '${spec}'`);
        continue;
      }
      if (typeof spec === 'string' && spec.startsWith('.')) {
        const dest = resolveRel(rel, spec);
        if (failUnresolved && !existsSync(join(root, dest))) {
          hits.push(`${rel}:1: rule24-graph unresolved import '${spec}' -> '${dest}'`);
          continue;
        }
        todo.push(dest);
      }
    }
  }
  return { hits, reachable: [...seen] };
}

function publicEntries(root) {
  const entries = [];
  const pkgPath = join(root, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
      const exp = pkg.exports;
      if (exp && typeof exp === 'object' && !Array.isArray(exp)) {
        for (const key of ['.', './audited']) {
          if (exp[key] == null) continue;
          for (const t of collectStrings(exp[key])) {
            if (typeof t === 'string' && t.startsWith('.')) entries.push(posix(t.replace(/^\.\//, '')));
          }
        }
      }
    } catch { /* ignore */ }
  }
  if (!entries.length) entries.push(...PRODUCTION_ENTRY_FALLBACK);
  return [...new Set(entries)].filter((rel) => existsSync(join(root, rel)));
}

export function scanGraph(root) {
  const hits = [];
  const entries = productionEntries(root);
  if (!entries.length) {
    hits.push(`.:1: rule24-graph no production entry ('.' / './audited' / every exports target, or src/index.ts, src/audited/index.ts) was found`);
    return { hits, entries, reachable: [] };
  }
  const bindingSymbols = verificationBindingSymbols(root);
  const all = walkFrom(root, entries, { checkVerify: false, checkBinding: false, checkCycling: true, failUnresolved: true, bindingSymbols });
  hits.push(...all.hits);
  const pub = publicEntries(root);
  const pubWalk = walkFrom(root, pub, { checkVerify: true, checkBinding: true, checkCycling: false, failUnresolved: false, bindingSymbols });
  hits.push(...pubWalk.hits);
  return { hits, entries, reachable: [...new Set([...all.reachable, ...pubWalk.reachable])] };
}

export function scanRoot(root) {
  return scanGraph(root).hits;
}

const GOOD_PKG = {
  name: 'open-rng-engine', version: '0.0.0', private: true, type: 'module',
  exports: { '.': './src/index.ts', './audited': './src/audited/index.ts', './package.json': './package.json' },
};

export const BAD_FIXTURES = {
  'reaches-verify': {
    files: {
      'src/index.ts': "export { k } from '../verify/x.ts';\n",
      'verify/x.ts': 'export const k = 1;\n',
      'src/audited/index.ts': 'export {};\n',
    },
    reason: /rule24-graph production entry reaches a module under verify\//,
  },
  'reaches-src-verify': {
    files: {
      'src/index.ts': "import { k } from './verify/x.ts';\nexport { k };\n",
      'src/verify/x.ts': 'export const k = 1;\n',
      'src/audited/index.ts': 'export {};\n',
    },
    reason: /rule24-graph production entry reaches a module under verify\//,
  },
  'resetCht': {
    files: {
      'src/index.ts': "import { resetCht } from './h.ts';\nexport { resetCht };\n",
      'src/h.ts': 'export function resetCht() {}\n',
      'src/audited/index.ts': 'export {};\n',
    },
    reason: /verification-binding symbol 'resetCht'/,
  },
  'imports-cycling-adapter': {
    files: {
      'src/index.ts': "import { start } from 'open-rng-engine-cycling';\nexport { start };\n",
      'src/audited/index.ts': 'export {};\n',
    },
    reason: /cycling adapter/,
  },
  'unresolved-import': {
    files: {
      'src/index.ts': "import { k } from './missing.ts';\nexport { k };\n",
      'src/audited/index.ts': 'export {};\n',
    },
    reason: /unresolved import/,
  },
  'reaches-testMinter': {
    files: {
      'src/index.ts': "export { testMinter } from './h.ts';\n",
      'src/h.ts': 'export function testMinter() {}\n',
      'src/audited/index.ts': 'export {};\n',
    },
    reason: /verification-binding symbol 'testMinter'/,
  },
  'reaches-replaySource': {
    files: {
      'src/index.ts': "export { replaySource } from './h.ts';\n",
      'src/h.ts': 'export function replaySource() {}\n',
      'src/audited/index.ts': 'export {};\n',
    },
    reason: /verification-binding symbol 'replaySource'/,
  },
};

function writeTree(dir, files) {
  for (const [rel, src] of Object.entries(files)) {
    const p = join(dir, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, src);
  }
}

export function selfTest() {
  const fails = [];
  const base = mkdtempSync(join(tmpdir(), 'r24-'));
  try {
    const ctl = join(base, 'control');
    writeTree(ctl, { 'package.json': JSON.stringify(GOOD_PKG, null, 2) + '\n', 'src/index.ts': 'export {};\n', 'src/audited/index.ts': 'export {};\n' });
    const ch = scanRoot(ctl);
    if (ch.length) fails.push(`control not green:\n${ch.join('\n')}`);
    for (const [name, { files, reason }] of Object.entries(BAD_FIXTURES)) {
      const d = join(base, name);
      const materialised = {};
      for (const [rel, src] of Object.entries(files)) materialised[rel] = uUnescape(uEscape(src));
      writeTree(d, { 'package.json': JSON.stringify(GOOD_PKG, null, 2) + '\n', ...materialised });
      const hits = scanRoot(d);
      if (!hits.some((h) => reason.test(h))) fails.push(`${name} did not turn rule 24 red:\n${hits.join('\n')}`);
    }
  } finally { rmSync(base, { recursive: true, force: true }); }
  if (fails.length) {
    console.error(`rule24 self-test FAILED:\n${fails.join('\n')}`);
    process.exit(1);
  }
  console.log(`rule24 self-test: ${Object.keys(BAD_FIXTURES).length} known-bad fixtures red, control green`);
}

const here = fileURLToPath(import.meta.url);
if (process.argv[1] && here === process.argv[1]) {
  const args = process.argv.slice(2);
  if (args.includes('--self-test')) selfTest();
  else {
    const root = args.find((a) => !a.startsWith('-')) ?? process.cwd();
    const hits = scanRoot(root);
    if (hits.length) { hits.forEach((h) => console.log(h)); console.log(`rule24 module-graph: ${hits.length} finding(s)`); process.exit(1); }
    console.log('rule24 module-graph: 0 finding(s)');
  }
}
