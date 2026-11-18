#!/usr/bin/env node
// Runtime backstop (M-162 / G-29): wrap CSPRNG entry points (instance and prototype)
// and fail if the innermost frame under the repo's src/ is not in src/entropy/.
// Installed via `node --import ./tools/ci/entropy-backstop.mjs` and NODE_OPTIONS
// (so worker_threads inherit the preload). Hooks must be in place before any test
// file loads; counters are 0 at install; every wrapped call and teardown checks
// wrapper identity; teardown also checks counters. Stacks are captured with a
// saved native Error; Error.prepareStackTrace and stackTraceLimit must stay at
// their install-time values.

import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, normalize, resolve, sep } from 'node:path';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

const require = createRequire(import.meta.url);
const { syncBuiltinESMExports } = require('node:module');

export const MARK = Symbol.for('open-rng-engine/entropy-backstop/v1');

// G-29: the original 8, plus prototype originals and HoQ's complete unwrapped list.
export const ENTRY_POINT_IDS = Object.freeze([
  'randomFillSync',
  'randomBytes',
  'randomInt',
  'randomUUID',
  'getRandomValues',
  'webcrypto.getRandomValues',
  'subtle.generateKey',
  'globalThis.crypto.getRandomValues',
  'Crypto.prototype.getRandomValues',
  'SubtleCrypto.prototype.generateKey',
  'webcrypto.randomUUID',
  'randomFill',
  'generateKeySync',
  'generateKey',
  'generatePrime',
  'generatePrimeSync',
  'generateKeyPair',
  'generateKeyPairSync',
  'ECDH.prototype.generateKeys',
]);

const NativeError = Error;
const REPO_ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const SELF = resolve(fileURLToPath(import.meta.url));
const SRC_ROOT = resolve(REPO_ROOT, 'src');
const ENTROPY_ROOT = resolve(REPO_ROOT, 'src/entropy');

export function defaultAllowedCallers() {
  // Explicit file list, not a directory prefix (used when no frame is under the repo src/).
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
  s = s.replace(/[?#].*$/, '');
  return resolve(normalize(s));
}

export function refuseIfBackstopOverride(env = process.env) {
  if (Object.prototype.hasOwnProperty.call(env, 'ENTROPY_BACKSTOP_ALLOWED')) {
    const msg = 'entropy-backstop: ENTROPY_BACKSTOP_ALLOWED is set; the override was removed and check:ph0 refuses to run';
    console.error(msg);
    // Exit so `node --import` and check:ph0 stop immediately.
    process.exit(2);
  }
}

export function parseAllowedFromEnv(env = process.env) {
  refuseIfBackstopOverride(env);
  return [...defaultAllowedCallers()];
}

refuseIfBackstopOverride();

export function parseCallerFrames(stack, { selfPath = SELF } = {}) {
  const self = normalizePath(selfPath);
  const frames = [];
  if (!stack) return frames;
  for (const line of String(stack).split('\n')) {
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

export function isPrefixAllowed(path, allowed) {
  const n = normalizePath(path);
  return allowed.map(normalizePath).some((a) => n === a || n.startsWith(a));
}

export function isUnderDir(path, dir) {
  const n = normalizePath(path);
  const root = normalizePath(dir);
  return n === root || n.startsWith(root + sep);
}

export function isUnderRepoSrc(path) {
  return isUnderDir(path, SRC_ROOT);
}

export function isUnderEntropy(path) {
  return isUnderDir(path, ENTROPY_ROOT);
}

export function innermostSrcFrame(frames) {
  for (const f of frames) {
    if (isUnderRepoSrc(f)) return f;
  }
  return null;
}

const counters = Object.fromEntries(ENTRY_POINT_IDS.map((id) => [id, 0]));
const wrappers = Object.create(null);
const originals = Object.create(null);
const hookSites = Object.create(null);
let allowed = parseAllowedFromEnv();
let installed = false;
let matchMode = 'exact';
let savedPrepare;
let savedLimit;
let countersAtInstall;

export function setMatchModeForTestOnly(mode) {
  matchMode = mode === 'prefix' ? 'prefix' : 'exact';
}

function frameAllowedExactOrPrefix(p) {
  return matchMode === 'prefix' ? isPrefixAllowed(p, allowed) : isExactAllowed(p, allowed);
}

function checkCaller(id, stack) {
  const frames = parseCallerFrames(stack);
  if (frames.length === 0) {
    throw new NativeError(`entropy-backstop: ${id} called with no user caller frame (fail-closed)`);
  }
  // G-29: the innermost frame under the repo's src/ must be in src/entropy/.
  // Outer src frames (e.g. src/index.ts) are allowed. Frames outside repo src/
  // (tests, /tmp plants) fall back to the exact allowed-caller list applied to
  // the innermost user frame only.
  const innerSrc = innermostSrcFrame(frames);
  if (innerSrc) {
    if (!isUnderEntropy(innerSrc)) {
      const msg = `entropy-backstop: ${id} called from ${innerSrc} (innermost src/ frame is not in src/entropy/)`;
      console.error(msg);
      throw new NativeError(msg);
    }
    return;
  }
  const inner = frames[0];
  if (!frameAllowedExactOrPrefix(inner)) {
    const msg = `entropy-backstop: ${id} called from ${inner} (not an exact allowed caller)`;
    console.error(msg);
    throw new NativeError(msg);
  }
}

function wrapFn(id, orig) {
  if (typeof orig !== 'function') {
    throw new NativeError(`entropy-backstop: cannot wrap ${id}: not a function`);
  }
  const wrapped = function entropyBackstopWrapped(...args) {
    counters[id] += 1;
    assertIdentitiesAndStack(`call:${id}`);
    const err = new NativeError();
    checkCaller(id, err.stack);
    return orig.apply(this, args);
  };
  try { Object.defineProperty(wrapped, 'name', { value: `backstop_${id}`, configurable: true }); } catch { /* ignore */ }
  wrapped._backstopId = id;
  return wrapped;
}

function installFrozen(obj, key, wrapped) {
  if (obj == null) throw new NativeError(`entropy-backstop: missing object for ${key}`);
  const place = (target) => {
    try {
      Object.defineProperty(target, key, {
        configurable: false,
        writable: false,
        enumerable: true,
        value: wrapped,
      });
      if (target[key] === wrapped) {
        const pd = Object.getOwnPropertyDescriptor(target, key);
        if (pd && pd.configurable === false && pd.writable === false && pd.value === wrapped) {
          return { obj: target, key, frozen: true };
        }
        return { obj: target, key, frozen: false };
      }
    } catch { /* fall through */ }
    return null;
  };
  const own = Object.getOwnPropertyDescriptor(obj, key);
  if (!own || own.configurable) {
    const r = place(obj);
    if (r) return r;
  }
  const proto = Object.getPrototypeOf(obj);
  if (proto && proto !== Object.prototype) {
    const pd = Object.getOwnPropertyDescriptor(proto, key);
    if (pd && pd.configurable) {
      const r = place(proto);
      if (r) return r;
    }
  }
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
    console.error(msg);
    throw new NativeError(msg);
  }
}

export function assertCountersHealthy(label = 'teardown') {
  const marker = globalThis[MARK];
  if (!marker || marker.counters !== counters) {
    const msg = `entropy-backstop: counters object was replaced (${label})`;
    console.error(msg);
    throw new NativeError(msg);
  }
  for (const id of ENTRY_POINT_IDS) {
    const n = counters[id];
    if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) {
      const msg = `entropy-backstop: counter ${id} is ${n} (${label})`;
      console.error(msg);
      throw new NativeError(msg);
    }
  }
}

function assertIdentitiesAndStack(label) {
  if (Error.prepareStackTrace !== savedPrepare) {
    const msg = `entropy-backstop: Error.prepareStackTrace changed (${label})`;
    console.error(msg);
    throw new NativeError(msg);
  }
  if (Error.stackTraceLimit !== savedLimit) {
    const msg = `entropy-backstop: Error.stackTraceLimit changed (${label})`;
    console.error(msg);
    throw new NativeError(msg);
  }
  assertWrappersIntact(label);
}

function collectTargets(crypto) {
  const wc = crypto.webcrypto;
  const gt = globalThis.crypto;
  let ecdhProto = null;
  try { ecdhProto = Object.getPrototypeOf(crypto.createECDH('prime256v1')); } catch { /* missing curve */ }
  return [
    { id: 'Crypto.prototype.getRandomValues', obj: typeof Crypto === 'function' ? Crypto.prototype : null, key: 'getRandomValues' },
    { id: 'SubtleCrypto.prototype.generateKey', obj: typeof SubtleCrypto === 'function' ? SubtleCrypto.prototype : null, key: 'generateKey' },
    { id: 'webcrypto.getRandomValues', obj: wc, key: 'getRandomValues' },
    { id: 'globalThis.crypto.getRandomValues', obj: gt, key: 'getRandomValues' },
    { id: 'webcrypto.randomUUID', obj: wc, key: 'randomUUID' },
    { id: 'subtle.generateKey', obj: wc && wc.subtle, key: 'generateKey' },
    { id: 'getRandomValues', obj: crypto, key: 'getRandomValues' },
    { id: 'randomFillSync', obj: crypto, key: 'randomFillSync' },
    { id: 'randomBytes', obj: crypto, key: 'randomBytes' },
    { id: 'randomInt', obj: crypto, key: 'randomInt' },
    { id: 'randomUUID', obj: crypto, key: 'randomUUID' },
    { id: 'randomFill', obj: crypto, key: 'randomFill' },
    { id: 'generateKeySync', obj: crypto, key: 'generateKeySync' },
    { id: 'generateKey', obj: crypto, key: 'generateKey' },
    { id: 'generatePrime', obj: crypto, key: 'generatePrime' },
    { id: 'generatePrimeSync', obj: crypto, key: 'generatePrimeSync' },
    { id: 'generateKeyPair', obj: crypto, key: 'generateKeyPair' },
    { id: 'generateKeyPairSync', obj: crypto, key: 'generateKeyPairSync' },
    { id: 'ECDH.prototype.generateKeys', obj: ecdhProto, key: 'generateKeys' },
  ];
}

function installNodeOptions() {
  const flag = `--import ${pathToFileURL(SELF).href}`;
  const cur = process.env.NODE_OPTIONS || '';
  if (cur.includes('entropy-backstop.mjs') || cur.includes(pathToFileURL(SELF).href) || cur.includes(SELF)) return;
  process.env.NODE_OPTIONS = cur ? `${flag} ${cur}` : flag;
}

function hasBackstopImport(execArgv) {
  const list = execArgv ?? [];
  for (let i = 0; i < list.length; i++) {
    const a = String(list[i]);
    if (a.includes('entropy-backstop.mjs')) return true;
    if (a === '--import' && String(list[i + 1] ?? '').includes('entropy-backstop.mjs')) return true;
  }
  return false;
}

function installWorkerHook() {
  const wt = require('node:worker_threads');
  const Orig = wt.Worker;
  if (Orig && Orig._backstopWorker) return;
  const flag = pathToFileURL(SELF).href;
  class HookedWorker extends Orig {
    constructor(entry, options = {}) {
      const execArgv = [...(options.execArgv ?? [])];
      if (!hasBackstopImport(execArgv)) execArgv.unshift('--import', flag);
      const opts = { ...options, execArgv };
      let filename = entry;
      if (opts.eval) {
        // Eval workers do not run NODE_OPTIONS/--import loaders on this Node.
        // Materialise the eval source as a file worker so the preload is active.
        const dir = mkdtempSync(join(tmpdir(), 'entropy-backstop-worker-'));
        const file = join(dir, 'eval-worker.cjs');
        writeFileSync(file, String(entry));
        filename = file;
        delete opts.eval;
      }
      super(filename, opts);
    }
  }
  HookedWorker._backstopWorker = true;
  Object.defineProperty(wt, 'Worker', { configurable: false, writable: false, enumerable: true, value: HookedWorker });
  try { syncBuiltinESMExports(); } catch { /* ESM bindings may already be live */ }
}

export function install(opts = {}) {
  if (installed && !opts.force) return getMarker();
  if (opts.allowed) allowed = opts.allowed.map(normalizePath);
  savedPrepare = Error.prepareStackTrace;
  savedLimit = Error.stackTraceLimit;
  installNodeOptions();
  installWorkerHook();
  const crypto = require('node:crypto');
  const targets = collectTargets(crypto);
  const seenFn = new WeakMap();
  const seenHost = new WeakMap();
  for (const t of targets) {
    if (t.obj == null || typeof t.obj[t.key] !== 'function') {
      throw new NativeError(`entropy-backstop: entry point ${t.id} is missing`);
    }
    const orig = t.obj[t.key];
    originals[t.id] = orig;
    let wrapped = seenFn.get(orig);
    const prior = seenHost.get(t.obj);
    if (!wrapped && prior && prior[t.key]) wrapped = prior[t.key];
    if (!wrapped) {
      for (const id of ENTRY_POINT_IDS) {
        const s = hookSites[id];
        if (s && s.obj === t.obj && s.key === t.key && wrappers[id]) { wrapped = wrappers[id]; break; }
      }
    }
    if (!wrapped) {
      wrapped = wrapFn(t.id, orig);
      const placed = installFrozen(t.obj, t.key, wrapped);
      if (placed) {
        hookSites[t.id] = placed;
        const bucket = seenHost.get(placed.obj) ?? {};
        bucket[placed.key] = wrapped;
        seenHost.set(placed.obj, bucket);
        seenFn.set(orig, wrapped);
      } else {
        const alias = hookSites['webcrypto.getRandomValues'] || hookSites['Crypto.prototype.getRandomValues'];
        if (!alias || !wrapped) {
          // For the non-configurable crypto.getRandomValues getter, alias to the prototype/webcrypto wrapper.
        }
        const aliasId = hookSites['Crypto.prototype.getRandomValues'] ? 'Crypto.prototype.getRandomValues'
          : (hookSites['webcrypto.getRandomValues'] ? 'webcrypto.getRandomValues' : null);
        if (!aliasId || !wrappers[aliasId]) {
          throw new NativeError(`entropy-backstop: failed to install wrapper on ${t.id} and no webcrypto/prototype alias`);
        }
        hookSites[t.id] = hookSites[aliasId];
        wrapped = wrappers[aliasId];
      }
    } else {
      const existing = Object.keys(hookSites).find((id) => wrappers[id] === wrapped);
      hookSites[t.id] = existing ? hookSites[existing] : { obj: t.obj, key: t.key };
      // Same original already wrapped (prototype === instance method). Install that wrapper here too if possible.
      if (t.obj[t.key] !== wrapped) {
        const placed = installFrozen(t.obj, t.key, wrapped);
        if (placed) hookSites[t.id] = placed;
      }
    }
    wrappers[t.id] = wrapped;
  }
  try { syncBuiltinESMExports(); } catch { /* not fatal for CJS-only surfaces */ }
  for (const id of ENTRY_POINT_IDS) counters[id] = 0;
  countersAtInstall = Object.freeze(Object.fromEntries(ENTRY_POINT_IDS.map((id) => [id, 0])));
  installed = true;
  const marker = {
    installed: true,
    installedAt: Date.now(),
    countersAtInstall,
    counters,
    wrappers,
    hookSites,
    entryPointIds: ENTRY_POINT_IDS,
    allowed: Object.freeze([...allowed]),
    self: SELF,
    savedPrepare,
    savedLimit,
  };
  globalThis[MARK] = marker;
  return marker;
}

export function getMarker() {
  return globalThis[MARK];
}

function onTeardown() {
  try {
    assertIdentitiesAndStack('beforeExit');
    assertCountersHealthy('beforeExit');
  } catch (e) {
    if (process.exitCode == null || process.exitCode === 0) process.exitCode = 1;
  }
}

install();
process.on('beforeExit', onTeardown);
process.on('exit', onTeardown);
