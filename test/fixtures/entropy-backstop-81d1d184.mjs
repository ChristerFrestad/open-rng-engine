#!/usr/bin/env node
// Runtime backstop (M-162 / G-26 companion): wrap CSPRNG entry points and fail
// if any user caller frame is not an exact, resolved, normalised path on the
// explicit allowed-caller list (default: the files under src/entropy/).
// Installed via `node --import ./tools/ci/entropy-backstop.mjs`. Hooks must be
// in place before any test file loads; counters are 0 at install; teardown
// fails if a wrapper was unwrapped or re-wrapped.

import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, normalize, resolve, sep } from 'node:path';

const require = createRequire(import.meta.url);
const { syncBuiltinESMExports } = require('node:module');

export const MARK = Symbol.for('open-rng-engine/entropy-backstop/v1');
export const ENTRY_POINT_IDS = Object.freeze([
  'randomFillSync',
  'randomBytes',
  'randomInt',
  'getRandomValues',
  'webcrypto.getRandomValues',
  'randomUUID',
  'subtle.generateKey',
  'globalThis.crypto.getRandomValues',
]);

const REPO_ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const SELF = resolve(fileURLToPath(import.meta.url));

export function defaultAllowedCallers() {
  // Explicit file list, not a directory prefix.
  return Object.freeze([
    resolve(REPO_ROOT, 'src/entropy/blockPlan.ts'),
    resolve(REPO_ROOT, 'src/entropy/index.ts'),
  ]);
}

function normalizePath(p) {
  if (typeof p !== 'string' || p.length === 0) return '';
  let s = p;
  if (s.startsWith('file:')) {
    try { s = fileURLToPath(s); } catch { return ''; }
  }
  // Strip query/hash that some traces attach
  s = s.replace(/[?#].*$/, '');
  return resolve(normalize(s));
}

export function parseAllowedFromEnv(env = process.env) {
  const raw = env.ENTROPY_BACKSTOP_ALLOWED;
  if (raw == null || raw === '') return [...defaultAllowedCallers()];
  return raw.split(':').filter(Boolean).map(normalizePath);
}

export function parseCallerFrames(stack, { selfPath = SELF } = {}) {
  const self = normalizePath(selfPath);
  const frames = [];
  if (!stack) return frames;
  for (const line of String(stack).split('\n')) {
    // Skip Node's own specifier frames. A regex that looks for "/..." would
    // otherwise treat `node:internal/modules/esm/module_job` as `/modules/...`.
    if (/\bnode:/.test(line)) continue;
    const fileUrl = /(?:\()?(file:\/\/[^:)\s]+):(\d+):(\d+)/.exec(line);
    const pathOnly = /(?:\()?(\/[^:)\s]+):(\d+):(\d+)/.exec(line);
    const raw = fileUrl ? fileUrl[1] : (pathOnly ? pathOnly[1] : null);
    if (!raw) continue;
    const pth = normalizePath(raw);
    if (!pth || pth === self) continue;
    frames.push(pth);
  }
  return frames;
}

export function isExactAllowed(path, allowed) {
  const n = normalizePath(path);
  const set = new Set(allowed.map(normalizePath));
  return set.has(n);
}

// Prefix matching (the hand-mutant form). Kept as a named export so tests can
// plant a file whose path starts with an allowed prefix and prove exact match
// is required. Production decision uses only isExactAllowed.
export function isPrefixAllowed(path, allowed) {
  const n = normalizePath(path);
  return allowed.map(normalizePath).some((a) => n === a || n.startsWith(a));
}

const counters = Object.fromEntries(ENTRY_POINT_IDS.map((id) => [id, 0]));
const wrappers = Object.create(null);
const originals = Object.create(null);
const hookSites = Object.create(null); // id -> { obj, key }
let allowed = parseAllowedFromEnv();
let installed = false;
let matchMode = 'exact'; // tests never flip this in-process; scratch mutants do

export function setMatchModeForTestOnly(mode) {
  matchMode = mode === 'prefix' ? 'prefix' : 'exact';
}

function frameAllowed(p) {
  return matchMode === 'prefix' ? isPrefixAllowed(p, allowed) : isExactAllowed(p, allowed);
}

function checkCaller(id) {
  const err = new Error();
  const frames = parseCallerFrames(err.stack);
  if (frames.length === 0) {
    throw new Error(`entropy-backstop: ${id} called with no user caller frame (fail-closed)`);
  }
  for (const f of frames) {
    if (!frameAllowed(f)) {
      const msg = `entropy-backstop: ${id} called from ${f} (not an exact allowed caller)`;
      // eslint-disable-next-line no-console
      console.error(msg);
      throw new Error(msg);
    }
  }
}

function wrapFn(id, orig) {
  if (typeof orig !== 'function') {
    throw new Error(`entropy-backstop: cannot wrap ${id}: not a function`);
  }
  const wrapped = function entropyBackstopWrapped(...args) {
    counters[id] += 1;
    checkCaller(id);
    return orig.apply(this, args);
  };
  try { Object.defineProperty(wrapped, 'name', { value: `backstop_${id}`, configurable: true }); } catch { /* ignore */ }
  wrapped._backstopId = id;
  return wrapped;
}

function installOn(obj, key, wrapped) {
  if (obj == null) throw new Error(`entropy-backstop: missing object for ${key}`);
  const own = Object.getOwnPropertyDescriptor(obj, key);
  if (!own || own.configurable) {
    try {
      Object.defineProperty(obj, key, { configurable: true, writable: true, enumerable: true, value: wrapped });
      if (obj[key] === wrapped) return { obj, key };
    } catch { /* fall through */ }
  }
  const proto = Object.getPrototypeOf(obj);
  if (proto && proto !== Object.prototype) {
    const pd = Object.getOwnPropertyDescriptor(proto, key);
    if (pd && pd.configurable) {
      Object.defineProperty(proto, key, { configurable: true, writable: true, enumerable: true, value: wrapped });
      if (proto[key] === wrapped) return { obj: proto, key };
    }
  }
  try {
    obj[key] = wrapped;
    if (obj[key] === wrapped) return { obj, key };
  } catch { /* non-writable getter, etc. */ }
  return null;
}

function currentOf(id) {
  const s = hookSites[id];
  if (!s || s.obj == null) return undefined;
  return s.obj[s.key];
}

export function snapshotIdentities() {
  const out = Object.create(null);
  for (const id of ENTRY_POINT_IDS) out[id] = currentOf(id);
  return out;
}

export function assertWrappersIntact(label = 'teardown') {
  const bad = [];
  for (const id of ENTRY_POINT_IDS) {
    const cur = currentOf(id);
    if (cur !== wrappers[id]) bad.push(`${id} was unwrapped or re-wrapped (${label})`);
  }
  if (bad.length) {
    const msg = `entropy-backstop: ${bad.join('; ')}`;
    // eslint-disable-next-line no-console
    console.error(msg);
    throw new Error(msg);
  }
}

function collectTargets(crypto) {
  const wc = crypto.webcrypto;
  const gt = globalThis.crypto;
  // webcrypto / prototype hookSites first so the non-configurable crypto.getRandomValues
  // getter can be aliased to the same wrapper it forwards to.
  return [
    { id: 'randomFillSync', obj: crypto, key: 'randomFillSync' },
    { id: 'randomBytes', obj: crypto, key: 'randomBytes' },
    { id: 'randomInt', obj: crypto, key: 'randomInt' },
    { id: 'randomUUID', obj: crypto, key: 'randomUUID' },
    { id: 'webcrypto.getRandomValues', obj: wc, key: 'getRandomValues' },
    { id: 'globalThis.crypto.getRandomValues', obj: gt, key: 'getRandomValues' },
    { id: 'subtle.generateKey', obj: wc && wc.subtle, key: 'generateKey' },
    { id: 'getRandomValues', obj: crypto, key: 'getRandomValues' },
  ];
}

export function install(opts = {}) {
  if (installed && !opts.force) return getMarker();
  if (opts.allowed) allowed = opts.allowed.map(normalizePath);
  const crypto = require('node:crypto');
  const targets = collectTargets(crypto);
  const seenFn = new WeakMap(); // original function -> wrapper
  const seenHost = new WeakMap(); // target object -> {key: wrapper}
  for (const t of targets) {
    if (t.obj == null || typeof t.obj[t.key] !== 'function') {
      throw new Error(`entropy-backstop: entry point ${t.id} is missing`);
    }
    const orig = t.obj[t.key];
    originals[t.id] = orig;
    let wrapped = seenFn.get(orig);
    const prior = seenHost.get(t.obj);
    if (!wrapped && prior && prior[t.key]) wrapped = prior[t.key];
    // Identical host object+key (webcrypto === globalThis.crypto)
    if (!wrapped) {
      for (const id of ENTRY_POINT_IDS) {
        const s = hookSites[id];
        if (s && s.obj === t.obj && s.key === t.key && wrappers[id]) { wrapped = wrappers[id]; break; }
      }
    }
    if (!wrapped) {
      wrapped = wrapFn(t.id, orig);
      const placed = installOn(t.obj, t.key, wrapped);
      if (placed) {
        hookSites[t.id] = placed;
        const bucket = seenHost.get(placed.obj) ?? {};
        bucket[placed.key] = wrapped;
        seenHost.set(placed.obj, bucket);
        seenFn.set(orig, wrapped);
      } else {
        // Non-configurable getter (Node's crypto.getRandomValues). Cover it by
        // aliasing the identity hook to the already-wrapped webcrypto method,
        // which the getter forwards to. Install webcrypto first (see collectTargets).
        const alias = hookSites['webcrypto.getRandomValues'];
        if (!alias || !wrappers['webcrypto.getRandomValues']) {
          throw new Error(`entropy-backstop: failed to install wrapper on ${t.id} and no webcrypto alias`);
        }
        hookSites[t.id] = alias;
        wrapped = wrappers['webcrypto.getRandomValues'];
      }
    } else {
      // Reuse an existing wrapper; keep a stable identity hook.
      const existing = Object.keys(hookSites).find((id) => wrappers[id] === wrapped);
      hookSites[t.id] = existing ? hookSites[existing] : { obj: t.obj, key: t.key };
    }
    wrappers[t.id] = wrapped;
  }
  try { syncBuiltinESMExports(); } catch { /* not fatal for CJS-only surfaces */ }
  for (const id of ENTRY_POINT_IDS) counters[id] = 0;
  const countersAtInstall = Object.freeze(Object.fromEntries(ENTRY_POINT_IDS.map((id) => [id, 0])));
  installed = true;
  const marker = {
    installed: true,
    installedAt: Date.now(),
    countersAtInstall,
    counters,
    wrappers,
    entryPointIds: ENTRY_POINT_IDS,
    allowed: Object.freeze([...allowed]),
    self: SELF,
  };
  globalThis[MARK] = marker;
  return marker;
}

export function getMarker() {
  return globalThis[MARK];
}

function onTeardown() {
  try {
    assertWrappersIntact('beforeExit');
  } catch (e) {
    if (process.exitCode == null || process.exitCode === 0) process.exitCode = 1;
  }
}

// Install at module evaluation time so --import hooks are in place before
// any test file is loaded. A late-install mutant (moving this behind a hook)
// is killed by test/entropy-backstop.test.mjs, which asserts the marker at
// top-level import time.
install();
process.on('beforeExit', onTeardown);
process.on('exit', onTeardown);
