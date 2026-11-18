#!/usr/bin/env node
// B8 — zero runtime dependencies (LIVE, in check:ph0).
// Spec (read-only): PLAN r4.9 L87 R-1, L143 R-35, L815 B8, L825 item (7).
// `dependencies` must be {} on the core and on every packages/* package.json;
// each devDependency must be an exact pin matching /^\d+\.\d+\.\d+$/; the root
// lockfile must list the same devDependencies, with no runtime dependencies.
// Every non-root lock entry's version equals the pin, resolved starts with
// https://registry.npmjs.org/, and integrity is sha512 (including devOptional).
// optional/peer/bundle(d)Dependencies and overrides must be {} or absent.
//
// G4: every current devDep name@version has a G4 PASS file under verification/g4/
// that names the package.json and package-lock.json sha256 values (HEAD and
// worktree must equal those hashes) and records provenance present/absent.
// A manifest change without a matching new G4 file is red. The `files` field
// and `npm audit signatures` in CI are backlog preconditions for the first
// packed build (do not add them to package.json while this G4 is current).

import { existsSync, mkdtempSync, readFileSync, rmSync, mkdirSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

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

export const EXACT_VERSION = /^\d+\.\d+\.\d+$/;
export const REGISTRY_RESOLVED_PREFIX = 'https://registry.npmjs.org/';
export const EMPTY_OR_ABSENT_FIELDS = Object.freeze([
  'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies', 'overrides',
]);
export const G4_DIR = 'verification/g4';
export const G4_TYPESCRIPT_5_9_3_SHA256 = '8b71c5d742379b8e1f1c8689102074e9da7359d1dee11a2bf8422486097af9e7';
export const G4_PINNED_PACKAGE_JSON_SHA256 = '9ed3c7bf4e3c125f4495169ef251b215ea28ef3d97828a13e008a006aa743ecb';
export const G4_PINNED_PACKAGE_LOCK_SHA256 = 'c694ed58401c2708e9c2dfd7732c8d379915b0d3d841faf08019f7389fca8e5c';

export function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

export function fileSha256(abs) {
  return sha256Hex(readFileSync(abs));
}

export function gitShowSha256(root, rel) {
  const r = spawnSync('git', ['-C', root, 'show', `HEAD:${rel}`], { encoding: 'buffer' });
  if (r.status !== 0) return null;
  return sha256Hex(r.stdout);
}

export function parseG4File(text, path = 'g4.md') {
  const issues = [];
  const pkg = /Package:\s*`([^@`\s]+)@([^`]+)`/.exec(text);
  const pkgSha = /package\.json sha256 `([0-9a-f]{64})`/.exec(text);
  const lockSha = /package-lock\.json sha256 `([0-9a-f]{64})`/.exec(text);
  const prov = /provenance is (ABSENT|PRESENT)/i.exec(text);
  if (!pkg) issues.push(`${path}:1: b8-g4 G4 file does not name a Package name@version`);
  if (!pkgSha) issues.push(`${path}:1: b8-g4 G4 file does not name a package.json sha256`);
  if (!lockSha) issues.push(`${path}:1: b8-g4 G4 file does not name a package-lock.json sha256`);
  if (!prov) issues.push(`${path}:1: b8-g4 G4 file does not record provenance present/absent (condition c)`);
  return {
    path,
    name: pkg ? pkg[1] : null,
    version: pkg ? pkg[2] : null,
    id: pkg ? `${pkg[1]}@${pkg[2]}` : null,
    packageJsonSha256: pkgSha ? pkgSha[1] : null,
    packageLockSha256: lockSha ? lockSha[1] : null,
    provenance: prov ? prov[1].toUpperCase() : null,
    issues,
  };
}

export function loadG4Files(root) {
  const dir = join(root, G4_DIR);
  const out = [];
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir).sort()) {
    if (!name.endsWith('.md')) continue;
    const rel = `${G4_DIR}/${name}`;
    out.push(parseG4File(readFileSync(join(root, rel), 'utf8'), rel));
  }
  return out;
}

export function coveringG4Markdown({ name, version, packageJsonSha256, packageLockSha256, provenance = 'ABSENT' }) {
  return [
    `# G4 dependency verdict: ${name}@${version}`,
    '',
    `- Package: \`${name}@${version}\``,
    `- package.json sha256 \`${packageJsonSha256}\``,
    `- package-lock.json sha256 \`${packageLockSha256}\``,
    '',
    `VERDICT: PASS`,
    '',
    `npm provenance is ${provenance} for this version.`,
    '',
  ].join('\n');
}

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
  return typeof v === 'string' && EXACT_VERSION.test(v);
}

function fieldEmptyOrAbsent(pkg, key) {
  if (!(key in pkg) || pkg[key] === undefined) return true;
  return depsEmpty(pkg[key]);
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
  if (pkg.dependencies === null) {
    hits.push(`${path}:1: b8-dependencies 'dependencies' must be {} (R-1); found null`);
  }
  const dev = pkg.devDependencies ?? {};
  if (typeof dev !== 'object' || Array.isArray(dev) || dev === null) {
    hits.push(`${path}:1: b8-dependencies 'devDependencies' must be an object of exact pins`);
  } else {
    for (const [name, ver] of Object.entries(dev)) {
      if (!isExactPin(ver)) hits.push(`${path}:1: b8-dependencies devDependency '${name}' is not an exact pin (${JSON.stringify(ver)})`);
    }
  }
  for (const key of EMPTY_OR_ABSENT_FIELDS) {
    if (!fieldEmptyOrAbsent(pkg, key)) {
      hits.push(`${path}:1: b8-dependencies '${key}' must be {} or absent; found ${JSON.stringify(pkg[key])}`);
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
  const pkgs = lock.packages ?? {};
  for (const [name, ver] of Object.entries(pkgDev)) {
    const rel = `node_modules/${name}`;
    if (!pkgs[rel]) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile is missing entry '${rel}'`);
      continue;
    }
    if (pkgs[rel].version !== ver) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' version ${JSON.stringify(pkgs[rel].version)} does not equal the pin ${ver}`);
    }
  }
  for (const [rel, ent] of Object.entries(pkgs)) {
    if (rel === '') continue;
    if (!ent || typeof ent !== 'object') {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' is unreadable`);
      continue;
    }
    if (ent.link) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' is a link entry`);
    }
    if (ent.dev !== true && rel.startsWith('node_modules/') && !ent.devOptional && !ent.link) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' is a runtime dependency`);
    }
    const integrity = ent.integrity;
    if (typeof integrity !== 'string' || !integrity.startsWith('sha512-')) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' integrity must be sha512 (including devOptional entries); found ${JSON.stringify(integrity)}`);
    }
    const resolved = ent.resolved;
    if (typeof resolved !== 'string' || !resolved.startsWith(REGISTRY_RESOLVED_PREFIX)) {
      hits.push(`package-lock.json:1: b8-dependencies lockfile entry '${rel}' resolved must start with ${REGISTRY_RESOLVED_PREFIX}; found ${JSON.stringify(resolved)}`);
    }
  }
  return hits;
}

export function scanG4(root, rootPkg) {
  const hits = [];
  const g4s = loadG4Files(root);
  for (const g of g4s) hits.push(...g.issues);
  const usable = g4s.filter((g) => g.id && g.packageJsonSha256 && g.packageLockSha256 && g.provenance);
  const byId = new Map(usable.map((g) => [g.id, g]));
  const dev = (rootPkg && rootPkg.devDependencies && typeof rootPkg.devDependencies === 'object') ? rootPkg.devDependencies : {};
  for (const [name, ver] of Object.entries(dev)) {
    const id = `${name}@${ver}`;
    if (!byId.has(id)) hits.push(`${G4_DIR}:1: b8-g4 no G4 PASS file covers devDependency ${id}`);
  }
  const pkgPath = join(root, 'package.json');
  const lockPath = join(root, 'package-lock.json');
  if (!existsSync(pkgPath) || !existsSync(lockPath)) return hits;
  const workPkg = fileSha256(pkgPath);
  const workLock = fileSha256(lockPath);
  const headPkg = gitShowSha256(root, 'package.json');
  const headLock = gitShowSha256(root, 'package-lock.json');
  const namedPkg = new Set(usable.map((g) => g.packageJsonSha256));
  const namedLock = new Set(usable.map((g) => g.packageLockSha256));
  const check = (label, sha, named, rel) => {
    if (!sha) return;
    if (![...named].some((h) => h === sha)) {
      hits.push(`${rel}:1: b8-g4 ${label} sha256 ${sha} is not named in a covering G4 file (manifest change without a matching new G4 file)`);
    }
  };
  if (usable.length) {
    check('worktree package.json', workPkg, namedPkg, 'package.json');
    check('worktree package-lock.json', workLock, namedLock, 'package-lock.json');
    if (headPkg) check('HEAD package.json', headPkg, namedPkg, 'package.json');
    if (headLock) check('HEAD package-lock.json', headLock, namedLock, 'package-lock.json');
  } else if (Object.keys(dev).length) {
    hits.push(`${G4_DIR}:1: b8-g4 no usable G4 PASS file is present for the current devDependencies`);
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
  hits.push(...scanG4(root, rootPkg));
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
  'pin-partial-x': {
    pkg: { ...GOOD_PKG, devDependencies: { typescript: '5.9.x' } },
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.x' } }, 'node_modules/typescript': { version: '5.9.x', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' } } },
    reason: /not an exact pin/,
  },
  'pin-latest': {
    pkg: { ...GOOD_PKG, devDependencies: { typescript: 'latest' } },
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: 'latest' } }, 'node_modules/typescript': { version: 'latest', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' } } },
    reason: /not an exact pin/,
  },
  'pin-equals': {
    pkg: { ...GOOD_PKG, devDependencies: { typescript: '=5.9.3' } },
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '=5.9.3' } }, 'node_modules/typescript': { version: '=5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' } } },
    reason: /not an exact pin/,
  },
  'optional-deps': {
    pkg: { ...GOOD_PKG, optionalDependencies: { leftpad: '1.0.0' } },
    lock: GOOD_LOCK,
    reason: /'optionalDependencies' must be \{\} or absent/,
  },
  'peer-deps': {
    pkg: { ...GOOD_PKG, peerDependencies: { typescript: '5.9.3' } },
    lock: GOOD_LOCK,
    reason: /'peerDependencies' must be \{\} or absent/,
  },
  'bundle-deps': {
    pkg: { ...GOOD_PKG, bundleDependencies: ['typescript'] },
    lock: GOOD_LOCK,
    reason: /'bundleDependencies' must be \{\} or absent/,
  },
  'bundled-deps': {
    pkg: { ...GOOD_PKG, bundledDependencies: ['typescript'] },
    lock: GOOD_LOCK,
    reason: /'bundledDependencies' must be \{\} or absent/,
  },
  'overrides': {
    pkg: { ...GOOD_PKG, overrides: { typescript: '5.9.3' } },
    lock: GOOD_LOCK,
    reason: /'overrides' must be \{\} or absent/,
  },
  'lock-version-mismatch': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } }, 'node_modules/typescript': { version: '5.8.0', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.8.0.tgz' } } },
    reason: /version .* does not equal the pin/,
  },
  'lock-resolved-non-registry': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } }, 'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://example.com/typescript-5.9.3.tgz' } } },
    reason: /resolved must start with https:\/\/registry\.npmjs\.org\//,
  },
  'lock-integrity-sha1': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } }, 'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha1-deadbeef', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' } } },
    reason: /integrity must be sha512/,
  },
  'lock-devOptional-no-integrity': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } }, 'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' }, 'node_modules/optional-tool': { version: '1.0.0', devOptional: true, resolved: 'https://registry.npmjs.org/optional-tool/-/optional-tool-1.0.0.tgz' } } },
    reason: /integrity must be sha512 \(including devOptional entries\)/,
  },
  'lock-missing-entry': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } } } },
    reason: /missing entry 'node_modules\/typescript'/,
  },
  'lock-link-entry': {
    pkg: GOOD_PKG,
    lock: { lockfileVersion: 3, name: 'open-rng-engine', packages: { '': { name: 'open-rng-engine', devDependencies: { typescript: '5.9.3' } }, 'node_modules/typescript': { version: '5.9.3', dev: true, integrity: 'sha512-fixture', resolved: 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz' }, 'node_modules/linked': { link: true, resolved: '../linked' } } },
    reason: /is a link entry/,
  },
  'mutated-manifest-no-g4': {
    pkg: { ...GOOD_PKG, description: 'mutated' },
    lock: GOOD_LOCK,
    reason: /manifest change without a matching new G4 file/,
    g4From: 'control',
  },
};

function writeJson(dir, rel, obj) {
  const p = join(dir, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');
}

function writeCoveringG4(dir, pkg, lock) {
  writeJson(dir, 'package.json', pkg);
  writeJson(dir, 'package-lock.json', lock);
  const packageJsonSha256 = fileSha256(join(dir, 'package.json'));
  const packageLockSha256 = fileSha256(join(dir, 'package-lock.json'));
  const dev = pkg.devDependencies ?? {};
  const first = Object.entries(dev)[0] || ['typescript', '5.9.3'];
  const md = coveringG4Markdown({ name: first[0], version: first[1], packageJsonSha256, packageLockSha256, provenance: 'ABSENT' });
  const p = join(dir, G4_DIR, 'g4-typescript-5.9.3.md');
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, md);
}

export function selfTest() {
  const fails = [];
  const base = mkdtempSync(join(tmpdir(), 'b8-'));
  try {
    const ctl = join(base, 'control');
    writeCoveringG4(ctl, GOOD_PKG, GOOD_LOCK);
    const ch = scanRoot(ctl);
    if (ch.length) fails.push(`control not green:\n${ch.join('\n')}`);
    const controlG4 = readFileSync(join(ctl, G4_DIR, 'g4-typescript-5.9.3.md'), 'utf8');
    for (const [name, fix] of Object.entries(BAD_FIXTURES)) {
      const d = join(base, name);
      writeJson(d, 'package.json', JSON.parse(uUnescape(uEscape(JSON.stringify(fix.pkg)))));
      writeJson(d, 'package-lock.json', fix.lock);
      if (fix.extra) for (const [rel, obj] of Object.entries(fix.extra)) writeJson(d, rel, obj);
      if (fix.g4From === 'control') {
        const p = join(d, G4_DIR, 'g4-typescript-5.9.3.md');
        mkdirSync(dirname(p), { recursive: true });
        writeFileSync(p, controlG4);
      } else if (isExactPin(Object.values(fix.pkg.devDependencies ?? {})[0] ?? '') && name !== 'lockfile-mismatch') {
        // Own covering G4 so the fixture is red for its intended reason, not only a missing G4.
        const packageJsonSha256 = fileSha256(join(d, 'package.json'));
        const packageLockSha256 = fileSha256(join(d, 'package-lock.json'));
        const first = Object.entries(fix.pkg.devDependencies)[0];
        const md = coveringG4Markdown({ name: first[0], version: first[1], packageJsonSha256, packageLockSha256, provenance: 'ABSENT' });
        const p = join(d, G4_DIR, 'g4-typescript-5.9.3.md');
        mkdirSync(dirname(p), { recursive: true });
        writeFileSync(p, md);
      }
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
