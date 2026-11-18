#!/usr/bin/env node
// B8 — zero runtime dependencies (LIVE, in check:ph0).
// Spec (read-only): PLAN r4.9 L87 R-1, L143 R-35, L815 B8, L825 item (7).
// `dependencies` must be {} on the core and on every packages/* package.json;
// each devDependency must be an exact pin (no ^ ~ > < * range); the root
// lockfile must list the same devDependencies, with no runtime dependencies
// and an integrity field on every locked package.
//
// PENDING (not guessed):
// - L815 / L825(7) "a new devDep needs a G4 PASS": what artifact is a G4 PASS,
//   and against which baseline is a devDependency "new"?

import { existsSync, mkdtempSync, readFileSync, rmSync, mkdirSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

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

const RANGE = /^[~^<>*]|^\s*$|\|\||\s/;

function packageJsonPaths(root) {
  const out = ['package.json'];
  const dir = join(root, 'packages');
  if (existsSync(dir)) {
    for (const name of readdirSync(dir)) {
      const p = `packages/${name}/package.json`;
      if (existsSync(join(root, p))) out.push(p);
    }
  }
  return out;
}

function depsEmpty(deps) {
  return deps !== undefined && typeof deps === 'object' && !Array.isArray(deps) && Object.keys(deps).length === 0;
}

function isExactPin(v) {
  return typeof v === 'string' && v.length > 0 && !RANGE.test(v);
}

export function scanManifest(pkg, { path = 'package.json', isRoot = false } = {}) {
  const hits = [];
  if (!pkg || typeof pkg !== 'object') {
    hits.push(`${path}:1: b8-dependencies unreadable package.json`);
    return hits;
  }
  if (!depsEmpty(pkg.dependencies ?? {})) {
    // missing key is treated as empty (zero runtime deps); a non-empty object is red
    if (pkg.dependencies === undefined) {
      // allowed: absent === empty. We still prefer an explicit {} but do not fail closed on absence
      // if the object would be empty. (Current repo writes explicit {}. A present non-object is red.)
    } else if (!depsEmpty(pkg.dependencies)) {
      hits.push(`${path}:1: b8-dependencies 'dependencies' must be {} (R-1); found ${JSON.stringify(pkg.dependencies)}`);
    }
  }
  const dev = pkg.devDependencies ?? {};
  if (typeof dev !== 'object' || Array.isArray(dev)) {
    hits.push(`${path}:1: b8-dependencies 'devDependencies' must be an object of exact pins`);
  } else {
    for (const [name, ver] of Object.entries(dev)) {
      if (!isExactPin(ver)) hits.push(`${path}:1: b8-dependencies devDependency '${name}' is not an exact pin (${JSON.stringify(ver)})`);
    }
  }
  return hits;
}

export function scanLockfile(root, rootPkg) {
  const hits = [];
  const lockPath = join(root, 'package-lock.json');
  if (!existsSync(lockPath)) {
    hits.push('package-lock.json:1: b8-dependencies missing package-lock.json');
    return hits;
  }
  let lock;
  try { lock = JSON.parse(readFileSync(lockPath, 'utf8')); }
  catch (e) { return [`package-lock.json:1: b8-dependencies unreadable package-lock.json (${e.message})`]; }
  const rootEntry = (lock.packages && lock.packages['']) || {};
  if (rootEntry.dependencies && Object.keys(rootEntry.dependencies).length) {
    hits.push(`package-lock.json:1: b8-dependencies lockfile records runtime dependencies ${JSON.stringify(rootEntry.dependencies)}`);
  }
  const pkgDev = rootPkg?.devDependencies ?? {};
  const lockDev = rootEntry.devDependencies ?? {};
  const pkgKeys = Object.keys(pkgDev).sort();
  const lockKeys = Object.keys(lockDev).sort();
  if (JSON.stringify(pkgKeys) !== JSON.stringify(lockKeys)) {
    hits.push(`package-lock.json:1: b8-dependencies lockfile devDependencies {${lockKeys.join(', ')}} do not match package.json {${pkgKeys.join(', ')}}`);
  }
  for (const [name, ver] of Object.entries(pkgDev)) {
    if (lockDev[name] && lockDev[name] !== ver) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile pins '${name}' at ${lockDev[name]} but package.json has ${ver}`);
    }
  }
  for (const [rel, ent] of Object.entries(lock.packages ?? {})) {
    if (rel === '') continue;
    if (ent && ent.dev === true && !ent.integrity) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' has no integrity field`);
    }
    if (ent && ent.dev !== true && rel.startsWith('node_modules/') && !ent.devOptional) {
      // a non-dev lock entry under node_modules is a runtime dependency
      if (!ent.link) hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' is a runtime dependency`);
    }
  }
  return hits;
}

export function scanRoot(root) {
  const hits = [];
  let rootPkg = null;
  for (const rel of packageJsonPaths(root)) {
    const abs = join(root, rel);
    try {
      const pkg = JSON.parse(readFileSync(abs, 'utf8'));
      if (rel === 'package.json') rootPkg = pkg;
      hits.push(...scanManifest(pkg, { path: rel, isRoot: rel === 'package.json' }));
    } catch (e) {
      hits.push(`${rel}:1: b8-dependencies unreadable package.json (${e.message})`);
    }
  }
  hits.push(...scanLockfile(root, rootPkg));
  return hits;
}

const GOOD_PKG = {
  name: 'open-rng-engine', version: '0.0.0', private: true, type: 'module',
  dependencies: {}, devDependencies: { typescript: '5.9.3' },
};
const GOOD_LOCK = {
  lockfileVersion: 3, name: 'open-rng-engine', packages: {
    '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } },
    'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' },
  },
};

export const BAD_FIXTURES = {
  'runtime-dep': {
    pkg: { ...GOOD_PKG, dependencies: { leftpad: '1.0.0' } },
    lock: GOOD_LOCK,
    reason: /'dependencies' must be \{\}/,
  },
  'unpinned-devdep': {
    pkg: { ...GOOD_PKG, devDependencies: { typescript: '^5.9.3' } },
    lock: { ...GOOD_LOCK, packages: { ...GOOD_LOCK.packages, '': { ...GOOD_LOCK.packages[''], devDependencies: { typescript: '^5.9.3' } } } },
    reason: /not an exact pin/,
  },
  'workspace-runtime-dep': {
    pkg: GOOD_PKG,
    extra: { 'packages/mapping/package.json': { name: '@open-rng-engine/mapping', version: '0.0.0', private: true, type: 'module', dependencies: { leftpad: '1.0.0' } } },
    lock: GOOD_LOCK,
    reason: /packages\/mapping\/package.json:1: b8-dependencies 'dependencies' must be \{\}/,
  },
  'lockfile-mismatch': {
    pkg: { ...GOOD_PKG, devDependencies: { typescript: '5.9.3', unusedcheck: '1.0.0' } },
    lock: GOOD_LOCK,
    reason: /lockfile devDependencies/,
  },
};

function writeJson(dir, rel, obj) {
  const p = join(dir, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');
}

export function selfTest() {
  const fails = [];
  const base = mkdtempSync(join(tmpdir(), 'b8-'));
  try {
    const ctl = join(base, 'control');
    writeJson(ctl, 'package.json', GOOD_PKG);
    writeJson(ctl, 'package-lock.json', GOOD_LOCK);
    const ch = scanRoot(ctl);
    if (ch.length) fails.push(`control not green:\n${ch.join('\n')}`);
    for (const [name, fix] of Object.entries(BAD_FIXTURES)) {
      const d = join(base, name);
      writeJson(d, 'package.json', JSON.parse(uUnescape(uEscape(JSON.stringify(fix.pkg)))));
      writeJson(d, 'package-lock.json', fix.lock);
      if (fix.extra) for (const [rel, obj] of Object.entries(fix.extra)) writeJson(d, rel, obj);
      const hits = scanRoot(d);
      if (!hits.some((h) => fix.reason.test(h))) fails.push(`${name} did not turn B8 red:\n${hits.join('\n')}`);
    }
  } finally { rmSync(base, { recursive: true, force: true }); }
  if (fails.length) {
    console.error(`b8 self-test FAILED:\n${fails.join('\n')}`);
    process.exit(1);
  }
  console.log(`b8 self-test: ${Object.keys(BAD_FIXTURES).length} known-bad fixtures red, control green`);
}

const here = fileURLToPath(import.meta.url);
if (process.argv[1] && here === process.argv[1]) {
  const args = process.argv.slice(2);
  if (args.includes('--self-test')) selfTest();
  else {
    const root = args.find((a) => !a.startsWith('-')) ?? process.cwd();
    const hits = scanRoot(root);
    if (hits.length) { hits.forEach((h) => console.log(h)); console.log(`b8 dependencies: ${hits.length} finding(s)`); process.exit(1); }
    console.log('b8 dependencies: 0 finding(s)');
  }
}
