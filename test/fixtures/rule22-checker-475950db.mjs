#!/usr/bin/env node
// Rule 22 — core exports allowlist (LIVE, in check:ph0).
// Spec (read-only): PLAN r4.9 L136 R-28, L537, L825 item (22); quality v5.5.7 L278 QR-33, L584 CI 15.
// The core package.json `exports` keys must be exactly {".", "./audited", "./package.json"}:
// 0 keys outside that set, 0 wildcards, 0 ./drbg; no export path reaches -testing,
// -edge-experimental, packages/drbg, packages/mapping or packages/capability internals.
//
// PENDING (not guessed):
// - L825(22) / QR-33 "core API report" and "game-pattern symbol" in the exports map or API report:
//   what artifact is the core API report, and what is the exact QR-33 game-pattern list to scan?
// - L825(22) "import edge to labkit or docs/examples": is that in scope of rule 22 (exports map)
//   or of the import-graph / rule 24 check? (Not implemented here.)

import { existsSync, mkdtempSync, readFileSync, rmSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

export const REQUIRED_EXPORT_KEYS = Object.freeze(['.', './audited', './package.json']);
export const FORBIDDEN_EXPORT_SEGMENTS = Object.freeze([
  '-testing', '-edge-experimental', 'packages/drbg', 'packages/mapping', 'packages/capability',
]);

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
    for (const val of collectStrings(exp[k])) {
      if (typeof val === 'string' && val.includes('*')) hits.push(`${path}:1: rule22-exports target '${val}' of key '${k}' is a wildcard`);
      const bad = pathReachesForbidden(val);
      if (bad) hits.push(`${path}:1: rule22-exports key '${k}' reaches ${bad} (${val})`);
    }
  }
  return hits;
}

export function scanRoot(root) {
  const file = join(root, 'package.json');
  if (!existsSync(file)) return [`package.json:1: rule22-exports missing package.json`];
  try {
    return scanExports(JSON.parse(readFileSync(file, 'utf8')), { path: 'package.json' });
  } catch (e) {
    return [`package.json:1: rule22-exports unreadable package.json (${e.message})`];
  }
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
    for (const [name, { pkg, reason }] of Object.entries(BAD_FIXTURES)) {
      // Materialise from a \u-escaped form; the escaped source is what we keep in-repo as the fixture text.
      const escaped = uEscape(JSON.stringify(pkg));
      const d = join(base, name);
      writeJson(d, 'package.json', JSON.parse(uUnescape(escaped)));
      const hits = scanRoot(d);
      if (!hits.some((h) => reason.test(h))) fails.push(`${name} did not turn rule 22 red:\n${hits.join('\n')}`);
    }
  } finally { rmSync(base, { recursive: true, force: true }); }
  if (fails.length) {
    console.error(`rule22 self-test FAILED:\n${fails.join('\n')}`);
    process.exit(1);
  }
  console.log(`rule22 self-test: ${Object.keys(BAD_FIXTURES).length} known-bad fixtures red, control green`);
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
