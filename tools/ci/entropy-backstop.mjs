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
import { basename, delimiter, dirname, isAbsolute, join, normalize, resolve, sep } from 'node:path';
import { mkdtempSync, writeFileSync, writeSync, existsSync, realpathSync, statSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash, createHmac } from 'node:crypto';

const require = createRequire(import.meta.url);
const { syncBuiltinESMExports } = require('node:module');

export const MARK = Symbol.for('open-rng-engine/entropy-backstop/v1');

// G-29: the original 8, plus prototype originals and HoQ's complete unwrapped list.
const _cryptoForDetect = require('node:crypto');
export const RANDOMUUIDV7_PRESENT = typeof _cryptoForDetect.randomUUIDv7 === 'function';
export const BACKSTOP_NODE_VERSION = process.version;
const BASE_ENTRY_POINT_IDS = [
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
  'getDiffieHellman',
  'createDiffieHellman',
  'createDiffieHellmanGroup',
  'DiffieHellman.prototype.generateKeys',
  'DiffieHellmanGroup.prototype.generateKeys',
  // G-39 (HoQ a43a432c): constructors that generate a random prime or key, and the prototype randomUUID.
  'DiffieHellman',
  'DiffieHellmanGroup',
  'Crypto.prototype.randomUUID',
  // G-39 (HoQ 4c7adda0/f575fe1f §3.4): randomised encrypt and sign outputs. RSA-OAEP / PKCS#1 v1.5
  // encryption pads with fresh bytes; ECDSA, DSA and RSA-PSS signing draw a nonce or salt; the WebCrypto
  // versions (encrypt, sign, wrapKey with RSA-OAEP) do the same. Deterministic algorithms behind the same
  // functions (Ed25519, HMAC, PKCS#1 v1.5 signing) are hooked too: the hook is by caller, not by algorithm.
  'publicEncrypt',
  'sign',
  'Sign.prototype.sign',
  'SubtleCrypto.prototype.encrypt',
  'SubtleCrypto.prototype.sign',
  'SubtleCrypto.prototype.wrapKey',
  'subtle.encrypt',
  'subtle.sign',
  'subtle.wrapKey',
];
const CONSTRUCTOR_IDS = new Set(['DiffieHellman', 'DiffieHellmanGroup']);
export const ENTRY_POINT_IDS = Object.freeze(
  RANDOMUUIDV7_PRESENT ? [...BASE_ENTRY_POINT_IDS, 'randomUUIDv7'] : BASE_ENTRY_POINT_IDS,
);

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
    // G-39 proof: the backstop is loaded and refuses; no user code runs, so this child proves itself.
    const pf = env === process.env ? process.env.ENTROPY_BACKSTOP_PROOF_FILE : undefined;
    if (pf) { try { writeFileSync(pf, `refused ${process.pid}`, { flag: 'wx' }); } catch { /* parent sees no proof */ } }
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
    assertMarkerIdentity(`call:${id}`);
    assertIdentitiesAndStack(`call:${id}`);
    const err = new NativeError();
    checkCaller(id, err.stack);
    return orig.apply(this, args);
  };
  try { Object.defineProperty(wrapped, 'name', { value: `backstop_${id}`, configurable: true }); } catch { /* ignore */ }
  // G-39: a wrapped constructor keeps the original prototype, so instanceof and prototype hooks still hold.
  if (CONSTRUCTOR_IDS.has(id)) { try { wrapped.prototype = orig.prototype; } catch { /* ignore */ } }
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
  let signProto = null;
  try { signProto = Object.getPrototypeOf(crypto.createSign('sha256')); } catch { /* no Sign */ }
  const targets = [
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
    { id: 'getDiffieHellman', obj: crypto, key: 'getDiffieHellman' },
    { id: 'createDiffieHellman', obj: crypto, key: 'createDiffieHellman' },
    { id: 'createDiffieHellmanGroup', obj: crypto, key: 'createDiffieHellmanGroup' },
    { id: 'DiffieHellman.prototype.generateKeys', obj: crypto.DiffieHellman ? crypto.DiffieHellman.prototype : null, key: 'generateKeys' },
    { id: 'DiffieHellmanGroup.prototype.generateKeys', obj: crypto.DiffieHellmanGroup ? crypto.DiffieHellmanGroup.prototype : null, key: 'generateKeys' },
    { id: 'Crypto.prototype.randomUUID', obj: typeof Crypto === 'function' ? Crypto.prototype : null, key: 'randomUUID' },
    { id: 'DiffieHellman', obj: crypto, key: 'DiffieHellman' },
    { id: 'DiffieHellmanGroup', obj: crypto, key: 'DiffieHellmanGroup' },
    { id: 'publicEncrypt', obj: crypto, key: 'publicEncrypt' },
    { id: 'sign', obj: crypto, key: 'sign' },
    { id: 'Sign.prototype.sign', obj: signProto, key: 'sign' },
    { id: 'SubtleCrypto.prototype.encrypt', obj: typeof SubtleCrypto === 'function' ? SubtleCrypto.prototype : null, key: 'encrypt' },
    { id: 'SubtleCrypto.prototype.sign', obj: typeof SubtleCrypto === 'function' ? SubtleCrypto.prototype : null, key: 'sign' },
    { id: 'SubtleCrypto.prototype.wrapKey', obj: typeof SubtleCrypto === 'function' ? SubtleCrypto.prototype : null, key: 'wrapKey' },
    { id: 'subtle.encrypt', obj: wc && wc.subtle, key: 'encrypt' },
    { id: 'subtle.sign', obj: wc && wc.subtle, key: 'sign' },
    { id: 'subtle.wrapKey', obj: wc && wc.subtle, key: 'wrapKey' },
  ];
  if (RANDOMUUIDV7_PRESENT) targets.push({ id: 'randomUUIDv7', obj: crypto, key: 'randomUUIDv7' });
  return targets;
}

// G-39b (HoQ a43a432c): only an exact `--import <this file>` counts as the preload. A decoy that merely
// contains the file name (another path, --title=..., a comment) does not stop injection.
function isSelfRef(x) {
  const v = String(x ?? '').replace(/^['"]|['"]$/g, '');
  if (!v) return false;
  if (v === pathToFileURL(SELF).href) return true;
  try { if (v.startsWith('file:')) return resolve(fileURLToPath(v)) === SELF; } catch { return false; }
  return resolve(v) === SELF;
}

function hasBackstopImport(list) {
  const a = (list ?? []).map(String);
  for (let i = 0; i < a.length; i++) {
    if ((a[i] === '--import' || a[i] === '--require' || a[i] === '-r') && isSelfRef(a[i + 1])) return true;
    if (a[i].startsWith('--import=') && isSelfRef(a[i].slice('--import='.length))) return true;
  }
  return false;
}

export function nodeOptionsHasBackstop(str) {
  return hasBackstopImport(String(str ?? '').trim().split(/\s+/).filter(Boolean));
}

function installNodeOptions() {
  const flag = `--import ${pathToFileURL(SELF).href}`;
  const cur = process.env.NODE_OPTIONS || '';
  if (nodeOptionsHasBackstop(cur)) return;
  process.env.NODE_OPTIONS = cur ? `${flag} ${cur}` : flag;
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

const IMPORT_HREF = pathToFileURL(SELF).href;

function injectBackstopExecArgv(execArgv) {
  const list = [...(execArgv ?? [])];
  if (!hasBackstopImport(list)) list.unshift('--import', IMPORT_HREF);
  return list;
}

function injectBackstopEnv(env) {
  const flag = `--import ${IMPORT_HREF}`;
  const next = { ...env };
  const cur = typeof next.NODE_OPTIONS === 'string' ? next.NODE_OPTIONS : '';
  if (!nodeOptionsHasBackstop(cur)) {
    next.NODE_OPTIONS = cur ? `${flag} ${cur}` : flag;
  }
  return next;
}

function normalizeChildOptions(options) {
  const opts = { ...(options || {}) };
  opts.execArgv = injectBackstopExecArgv(opts.execArgv);
  if (Object.prototype.hasOwnProperty.call(opts, 'env')) opts.env = injectBackstopEnv(opts.env || {});
  else opts.env = injectBackstopEnv({ ...process.env });
  return opts;
}

// G-39a (HoQ a43a432c): an intermediate process (env, a shell) can drop NODE_OPTIONS for the node it
// starts, where this hook cannot follow. Such command lines are refused, fail-closed.
const STRIP_SHELL = [
  /\bNODE_OPTIONS\s*=/,
  /\bunset\s+(?:-v\s+)?NODE_OPTIONS\b/,
  /\benv\b(?:\s+[^\s;|&]+)*?\s+(?:-[a-zA-Z]*[iu]|--ignore-environment|--unset|-)(?=\s|=|$)/,
  /\bNODE_OPTIONS\b[^|;&]*\bdelete\b/,
];
export function childCommandStripsPreload(args) {
  const strs = [];
  if (typeof args[0] === 'string') strs.push(args[0]);
  if (Array.isArray(args[1])) for (const a of args[1]) strs.push(String(a));
  const base = typeof args[0] === 'string' ? args[0].split(/[\\/]/).pop() : '';
  if (base === 'env' && Array.isArray(args[1])) {
    for (const a of args[1].map(String)) {
      if (a === '-' || a === '-i' || a === '--ignore-environment' || /^-[a-zA-Z]*[iu]/.test(a) || a.startsWith('--unset') || /^NODE_OPTIONS=/.test(a)) return `env ${a}`;
    }
  }
  const joined = strs.join(' ');
  for (const re of STRIP_SHELL) if (re.test(joined)) return joined.slice(0, 120);
  return null;
}

// G-39 at the source (HoQ 4c7adda0/f575fe1f report, gap G-39; CTO D): two independent fail-closed rules.
// (1) Child executable allowlist: a child may only be node (process.execPath, or `node` resolved in a
//     trusted directory) or an allowlisted tool resolved in a trusted directory. Shells, interpreters,
//     `env`, script files and anything else are refused, and so is every shell command line that is not one
//     plain allowlisted command (no quotes, expansions, operators, redirections or VAR= prefixes).
// (2) Proof of preload: every node child gets a per-call proof path; the backstop in the child writes it at
//     install. A node child that exits without the proof is red (sync: throws; async: exit code 1).
// G-45 (HoQ report c9d7c93..dbd4e00, addendum 1 A7): the evidence entry guard is enforced HERE, at the
// spawn layer, not by source text. A battery tool (named as the executable, or as any argv / shell word) is
// refused unless it is launched by launchEvidenceTool inside an open grant; a grant exists only after
// openEvidenceGrant has itself run assertEvidenceRunReady and it returned OK. An interpreter is never
// spawned. There is no path or directory exemption: the caller's location is never consulted.
export const EVIDENCE_TOOLS = Object.freeze(['dieharder', 'tu01-driver', 'assess', 'RNG_test']);
export const INTERPRETER = /^(?:python[0-9.]*|pypy[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|lua[0-9.]*|luajit|tclsh[0-9.]*|wish[0-9.]*|Rscript|R|julia|deno|bun|osascript|pwsh|powershell|bash|sh|dash|zsh|ksh|mksh|csh|tcsh|fish|busybox|toybox|env|xargs|nohup|setsid|timeout|nice|stdbuf|awk|gawk|mawk|nawk|sed|expect|script|su|sudo|doas|chroot|unshare|nsenter|systemd-run|strace|ltrace|gdb|valgrind)$/;
const evidenceGrants = new WeakSet();
let activeGrant = null;
let launching = null;
let grantEntry = null;
let grantSeq = 0;

function evidenceNames(exe, argv) {
  const words = [String(exe), ...(argv || []).map(String)];
  const out = [];
  for (const w of words) for (const t of w.split(/[\s;|&()<>`'"=]+/)) if (t && EVIDENCE_TOOLS.includes(basename(t))) out.push(basename(t));
  return out;
}

function evidenceSpawnCheck(kind, exe, argv, opts) {
  const base = basename(String(exe));
  const names = evidenceNames(exe, argv);
  if (names.length) {
    const ok = launching !== null && kind === 'file' && !opts.shell && activeGrant !== null && launching.grant === activeGrant
      && exe === launching.file && EVIDENCE_TOOLS.includes(base) && names.length === 1;
    if (!ok) refuseChild(`evidence tool ${names[0]} spawned without an OK entry guard (G-45)`);
    let real;
    try { real = realpathSync(isAbsolute(exe) ? exe : resolve(exe)); } catch { refuseChild(`evidence tool ${exe} not found (G-45)`); }
    if (launching !== null && real !== launching.real) refuseChild(`evidence tool ${exe} resolves to ${real}, not its pinned binary (G-55)`);
    return { node: false, evidence: true };
  }
  if (INTERPRETER.test(base)) refuseChild(`interpreter ${base} is never spawned (G-45)`);
  return null;
}

// Opens a grant only if the evidence entry guard, run here, returns OK. Root is fixed by this file's URL.
export async function openEvidenceGrant() {
  const ev = await import(new URL('../../verification/harness/evidence-entry.mjs', import.meta.url).href);
  ev.assertEvidenceRunReady();
  const g = Object.freeze({ grant: ++grantSeq });
  evidenceGrants.add(g);
  activeGrant = g;
  grantEntry = ev;
  return g;
}

export function closeEvidenceGrant(g) {
  if (activeGrant === g) activeGrant = null;
  evidenceGrants.delete(g);
}

// G-60 (HoQ report 505599e..96aaf91): a grant opened directly (marker.evidence.open) must be closed. A grant
// still open when the process exits makes the exit code non-zero; nothing it produced may be relied on.
function onGrantLeak() {
  if (activeGrant !== null) {
    console.error(`entropy-backstop: evidence grant ${activeGrant.grant} still open at exit (G-60)`);
    process.exitCode = 1;
  }
}

// G-54 (HoQ report 505599e..96aaf91): collection results are stamped by the backstop while a grant is open.
// The stamp set is private to this module, so a process without the preload, or outside a grant, cannot
// produce a stamped result; the collector and checkCollected refuse unstamped results.
// G-65 (HoQ A9): the stamp binds a sha256 content digest of { id, n, records }; every stamp lookup recomputes it,
// so records or n changed after stamping (even after the grant closed) lose the stamp.
const stampedResults = new WeakMap();
export function resultContentDigest(result) {
  const canon = JSON.stringify([result.id ?? null, result.n ?? null, result.records ?? null], (k, v) => (typeof v === 'bigint' ? `${v}n` : v));
  return createHash('sha256').update(canon).digest('hex');
}
export function stampEvidenceResult(result) {
  if (activeGrant === null || !evidenceGrants.has(activeGrant)) refuseChild('result stamp outside an open evidence grant (G-54)');
  if (result === null || typeof result !== 'object') refuseChild('result stamp of a non-object (G-54)');
  const token = `grant-${activeGrant.grant}@${process.pid}`;
  stampedResults.set(result, { token, digest: resultContentDigest(result) });
  return token;
}
export function evidenceStamp(result) {
  const s = result !== null && typeof result === 'object' ? stampedResults.get(result) : undefined;
  return s && resultContentDigest(result) === s.digest ? s.token : null;
}

// G-64 (HoQ A9, MAJOR): the counting authority is OUTSIDE this process. verification/harness/evidence-launcher.mjs
// spawns the runner with this preload and ENTROPY_BACKSTOP_CHANNEL=1, writes a fresh secret to the child's stdin
// and reads fd 3. Here, at preload (before any runner code), the flag is deleted and the secret is consumed from
// stdin into this closure; nothing else can read it. Only reportEvidenceResult writes authenticated lines
// (HMAC-SHA256 over id, n, content digest and grant token); the launcher counts nothing else. A process started
// any other way (plain node, a forged marker) has no channel and no secret, so nothing it does can count.
let channelSecret = null;
function initEvidenceChannel() {
  if (process.env.ENTROPY_BACKSTOP_CHANNEL !== '1') return;
  delete process.env.ENTROPY_BACKSTOP_CHANNEL;
  let s = null;
  try { s = readFileSync(0); } catch { s = null; }
  if (s && s.length >= 32) channelSecret = Buffer.from(s);
}
export function reportEvidenceResult(result) {
  if (channelSecret === null) refuseChild('evidence report without a launcher channel (G-64)');
  const t = evidenceStamp(result);
  if (t === null || result.grant !== t) refuseChild('evidence report of a result not stamped inside an open evidence grant (G-64)');
  const line = { id: result.id, n: result.n, digest: resultContentDigest(result), grant: t };
  line.mac = createHmac('sha256', channelSecret).update(`${line.id}\n${line.n}\n${line.digest}\n${line.grant}`).digest('hex');
  writeSync(3, `${JSON.stringify(line)}\n`);
  return line.digest;
}
export function evidenceGrantActive() { return activeGrant !== null && evidenceGrants.has(activeGrant); }

// G-55 (HoQ report 505599e..96aaf91): a battery binary is launched only if its real path and sha256 equal an
// entry of verification/harness/tool-binaries.json, whose source pin equals the frozen tool-pins-v1.1.json
// entry (rule 15), and it is not a script (no '#!'). Both files are read from this tree (root by URL).
export const TOOL_SOURCE_NAMES = Object.freeze({ dieharder: 'Dieharder', 'tu01-driver': 'TestU01', assess: 'NIST STS', RNG_test: 'PractRand' });
const PIN_ROOT = fileURLToPath(new URL('../..', import.meta.url));
function pinnedBinary(file) {
  const tool = basename(file);
  let bins, srcs;
  try {
    bins = JSON.parse(readFileSync(join(PIN_ROOT, 'verification/harness/tool-binaries.json'), 'utf8')).binaries;
    srcs = JSON.parse(readFileSync(join(PIN_ROOT, 'verification/tool-pins-v1.1.json'), 'utf8')).tools;
  } catch (e) { refuseChild(`evidence tool pins unreadable: ${e.message} (G-55)`); }
  if (!Array.isArray(bins) || !Array.isArray(srcs)) refuseChild('evidence tool pins malformed (G-55)');
  let real;
  try { real = realpathSync(file); } catch { refuseChild(`evidence tool ${file} not found (G-55)`); }
  const pin = bins.find((b) => b && b.tool === tool && b.path === real);
  if (!pin) refuseChild(`evidence tool ${real} is not a pinned binary path for ${tool} (G-55)`);
  const src = srcs.find((t) => t && t.name === TOOL_SOURCE_NAMES[tool]);
  if (!src || !pin.source || pin.source.name !== src.name || pin.source.sha256 !== src.sha256) refuseChild(`evidence tool ${tool}: source pin does not equal tool-pins-v1.1.json (G-55)`);
  const bytes = readFileSync(real);
  if (bytes.subarray(0, 2).toString('latin1') === '#!') refuseChild(`evidence tool ${real} is a script (G-55)`);
  if (createHash('sha256').update(bytes).digest('hex') !== pin.sha256) refuseChild(`evidence tool ${real}: sha256 differs from its pin (G-55)`);
  return real;
}

// The only way to start a battery tool: an open grant, the guard re-run, an absolute path, no shell.
export function launchEvidenceTool(g, file, args = [], options = {}) {
  if (!evidenceGrants.has(g) || activeGrant !== g || grantEntry === null) refuseChild('evidence tool launch without an open grant (G-45)');
  grantEntry.assertEvidenceRunReady();
  if (typeof file !== 'string' || !isAbsolute(file) || !EVIDENCE_TOOLS.includes(basename(file))) refuseChild(`launchEvidenceTool: ${String(file)} is not an absolute path to an evidence tool (G-45)`);
  const real = pinnedBinary(file);
  const cp = require('node:child_process');
  launching = { grant: g, file, real };
  try { return cp.spawnSync(file, args, { ...options, shell: false }); } finally { launching = null; }
}

export const CHILD_EXECUTABLE_ALLOWLIST = Object.freeze(['node', 'git', 'mkdir', 'ln']);
const TRUSTED_DIRS = Object.freeze([...new Set(['/usr/bin', '/bin', '/usr/local/bin', dirname(process.execPath)].map((d) => { try { return realpathSync(d); } catch { return d; } }))]);
const PLAIN_WORD = /^[A-Za-z0-9_./:,@%+=-]+$/;
const PROOF_ENV = 'ENTROPY_BACKSTOP_PROOF_FILE';
let proofDir = null;
let proofSeq = 0;
export const proofFailures = [];

function refuseChild(why) {
  const msg = `entropy-backstop: child process refused (${why})`;
  console.error(msg);
  throw new NativeError(msg);
}

function resolveExecutable(file, envPath) {
  if (file.includes('/')) {
    const abs = isAbsolute(file) ? file : resolve(file);
    try { return realpathSync(abs); } catch { return null; }
  }
  for (const d of String(envPath ?? '').split(delimiter)) {
    if (!d) continue;
    const c = join(d, file);
    try { if (statSync(c).isFile()) return realpathSync(c); } catch { /* next */ }
  }
  return null;
}

let execReal = null;
function isNodeBinary(real) {
  if (execReal === null) { try { execReal = realpathSync(process.execPath); } catch { execReal = process.execPath; } }
  return real === execReal;
}

// Returns { node: boolean } for an allowed child, or throws. kind: 'file' | 'shell' | 'fork'.
export function classifyChild(kind, file, argv, options) {
  const opts = options || {};
  if (kind === 'fork') {
    if (opts.execPath !== undefined && opts.execPath !== process.execPath) refuseChild(`fork execPath ${String(opts.execPath)}`);
    return { node: true };
  }
  let exe = file;
  if (kind === 'shell' || opts.shell) {
    if (opts.shell !== undefined && opts.shell !== true && opts.shell !== false && opts.shell !== '/bin/sh') refuseChild(`shell ${String(opts.shell)}`);
    const words = [String(file), ...(argv || []).map(String)].join(' ').trim().split(/\s+/);
    if (!words.every((w) => PLAIN_WORD.test(w)) || words[0].includes('=')) refuseChild('shell command line is not one plain allowlisted command');
    exe = words[0];
  }
  if (typeof exe !== 'string' || exe === '') refuseChild('no executable');
  const ev = evidenceSpawnCheck(kind, exe, argv, opts);
  if (ev) return ev;
  if (exe === process.execPath) return { node: true };
  const base = basename(exe);
  if (!CHILD_EXECUTABLE_ALLOWLIST.includes(base)) refuseChild(`executable ${base} is not on the child allowlist`);
  const envPath = Object.prototype.hasOwnProperty.call(opts, 'env') && opts.env ? opts.env.PATH : process.env.PATH;
  const real = resolveExecutable(exe, envPath);
  if (!real) refuseChild(`executable ${exe} not found`);
  if (!TRUSTED_DIRS.includes(dirname(real)) && !isNodeBinary(real)) refuseChild(`executable ${real} is outside the trusted directories`);
  if (basename(real) !== base && !isNodeBinary(real)) refuseChild(`executable ${exe} resolves to ${real}`);
  if (base === 'git') {
    if (kind === 'shell' || opts.shell) refuseChild('git through a shell');
    checkGitChild(argv, opts);
    return { node: false, git: true };
  }
  return { node: base === 'node' || isNodeBinary(real) };
}

// git can run other programs (hooks, aliases, filters, pagers, ssh, external diff). Rule (1) for git:
// only -C before the subcommand; the subcommand is on GIT_SUBCOMMANDS; `git config` only sets user.name or
// user.email; options that run a program are refused; the repo's own config may only hold GIT_CONFIG_KEYS;
// the child gets no system/global config, no GIT_* variables, hooks off and no ext:: transport.
export const GIT_SUBCOMMANDS = Object.freeze(['add', 'cat-file', 'check-attr', 'check-ignore', 'checkout', 'clone', 'config', 'init', 'ls-files', 'rev-parse', 'rm', 'show', 'status']);
const GIT_CONFIG_KEYS = [/^core\.(repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode|symlinks)$/,
  /^user\.(name|email)$/, /^remote\.[^.]+\.(url|fetch)$/, /^branch\.[^.]+\.(remote|merge)$/, /^extensions\.objectformat$/];
const GIT_EXEC_OPTS = /^(-c|--config|--config-env|-u|--upload-pack|--receive-pack|--template|--separate-git-dir|--exec|--ext-diff|--textconv|--filters|--ext|-p|--paginate|--exec-path|--git-dir|--work-tree|--namespace|--super-prefix|--list-cmds|-x)(=|$)/;
export const GIT_SAFE_PREFIX = Object.freeze(['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'core.pager=cat', '-c', 'protocol.allow=never', '-c', 'protocol.file.allow=always']);

function gitConfigFiles(start) {
  let d = resolve(start);
  for (;;) {
    const g = join(d, '.git');
    try {
      const st = statSync(g);
      if (st.isDirectory()) return [join(g, 'config')];
      const m = /^gitdir:\s*(.+)$/m.exec(readFileSync(g, 'utf8'));
      if (!m) return [];
      const gd = resolve(d, m[1].trim());
      const out = [join(gd, 'config'), join(gd, 'config.worktree')];
      try { out.push(join(resolve(gd, readFileSync(join(gd, 'commondir'), 'utf8').trim()), 'config')); } catch { /* no commondir */ }
      return out;
    } catch { /* not here */ }
    const up = dirname(d);
    if (up === d) return [];
    d = up;
  }
}

function gitConfigKeys(text) {
  const keys = [];
  let sec = null;
  for (const raw of String(text).split(/\r?\n/)) {
    const l = raw.trim();
    if (!l || l.startsWith('#') || l.startsWith(';')) continue;
    const h = /^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]\s*(.*)$/.exec(l);
    if (h) { sec = h[2] !== undefined ? `${h[1].toLowerCase()}.${h[2]}` : h[1].toLowerCase(); if (!h[3]) continue; }
    const body = h ? h[3] : l;
    const k = /^([A-Za-z][A-Za-z0-9-]*)\s*(=|$)/.exec(body);
    keys.push(sec === null || !k ? `?${body}` : `${sec}.${k[1].toLowerCase()}`);
  }
  return keys;
}

export function checkGitChild(argv, opts) {
  const a = (argv || []).map(String);
  let i = 0;
  let dir = opts && opts.cwd ? String(opts.cwd) : process.cwd();
  while (i < a.length && a[i].startsWith('-')) {
    if (a[i] === '-C' && i + 1 < a.length) { dir = resolve(dir, a[i + 1]); i += 2; continue; }
    refuseChild(`git global option ${a[i]}`);
  }
  const sub = a[i];
  if (!GIT_SUBCOMMANDS.includes(sub)) refuseChild(`git subcommand ${String(sub)} is not on the allowlist`);
  const rest = a.slice(i + 1);
  if (sub === 'config' && !(rest.length === 2 && /^user\.(name|email)$/.test(rest[0]))) refuseChild('git config may only set user.name or user.email');
  for (const x of rest) if (GIT_EXEC_OPTS.test(x)) refuseChild(`git option ${x}`);
  if (sub !== 'clone' && sub !== 'init') {
    for (const f of gitConfigFiles(dir)) {
      let t;
      try { t = readFileSync(f, 'utf8'); } catch { continue; }
      for (const k of gitConfigKeys(t)) if (!GIT_CONFIG_KEYS.some((r) => r.test(k))) refuseChild(`git repo config key ${k} is not on the allowlist (${f})`);
    }
  }
}

function gitChildEnv(env) {
  const e = {};
  for (const [k, v] of Object.entries(env || {})) if (!/^GIT_/i.test(k)) e[k] = v;
  e.GIT_CONFIG_NOSYSTEM = '1';
  e.GIT_CONFIG_GLOBAL = '/dev/null';
  e.GIT_TERMINAL_PROMPT = '0';
  return e;
}

function childShape(name, args) {
  if (name === 'exec' || name === 'execSync') {
    const o = args.find((a, i) => i > 0 && a && typeof a === 'object' && !Array.isArray(a));
    return { kind: 'shell', file: args[0], argv: [], options: o };
  }
  if (name === 'fork') {
    const o = args.find((a, i) => i > 0 && a && typeof a === 'object' && !Array.isArray(a));
    return { kind: 'fork', file: args[0], argv: [], options: o };
  }
  const argv = Array.isArray(args[1]) ? args[1] : [];
  const o = args.find((a, i) => i > 0 && a && typeof a === 'object' && !Array.isArray(a));
  return { kind: 'file', file: args[0], argv, options: o };
}

function newProofPath() {
  if (proofDir === null) proofDir = mkdtempSync(join(tmpdir(), 'ebs-proof-'));
  proofSeq += 1;
  return join(proofDir, `${process.pid}-${proofSeq}`);
}

function checkProof(path, label) {
  if (existsSync(path)) return true;
  const msg = `entropy-backstop: node child did not prove the backstop is loaded (${label})`;
  console.error(msg);
  proofFailures.push(msg);
  if (process.exitCode == null || process.exitCode === 0) process.exitCode = 1;
  return false;
}

// Child side: write the proof the parent asked for (first install only).
function writeProof() {
  const p = process.env[PROOF_ENV];
  if (!p) return;
  try { writeFileSync(p, String(process.pid), { flag: 'wx' }); } catch { /* the parent will see no proof: red */ }
  delete process.env[PROOF_ENV];
}

function mapChildArgs(args, name = 'spawn') {
  const strip = childCommandStripsPreload(args);
  if (strip) {
    const msg = `entropy-backstop: child command would drop the preload (${strip})`;
    console.error(msg);
    throw new NativeError(msg);
  }
  const shape = childShape(name, args);
  const cls = classifyChild(shape.kind, shape.file, shape.argv, shape.options);
  const out = args.slice();
  let idx = -1;
  for (let i = out.length - 1; i >= 0; i--) {
    const a = out[i];
    if (typeof a === 'function') continue;
    if (a && typeof a === 'object' && !Array.isArray(a)) { idx = i; break; }
  }
  if (idx === -1) { out.push(normalizeChildOptions({})); idx = out.length - 1; } else out[idx] = normalizeChildOptions(out[idx]);
  let proof = null;
  if (cls.git) {
    const env = gitChildEnv(out[idx].env);
    const o = { ...out[idx], env };
    if (Array.isArray(out[1])) { out[1] = [...GIT_SAFE_PREFIX, ...out[1]]; out[idx] = o; }
    else { out[idx] = o; out.splice(1, 0, [...GIT_SAFE_PREFIX]); }
  }
  if (cls.node) {
    proof = newProofPath();
    out[idx].env = { ...out[idx].env, [PROOF_ENV]: proof };
  }
  return { args: out, proof };
}

// G-39: process.binding('spawn_sync') and ('process_wrap') spawn a child without going through the
// child_process module, so they skip both rules above. They are refused outright.
export const REFUSED_BINDINGS = Object.freeze(['spawn_sync', 'process_wrap', 'pipe_wrap', 'tcp_wrap', 'stream_wrap', 'tty_wrap', 'udp_wrap', 'js_stream']);
function installBindingGuard() {
  const orig = process.binding;
  if (typeof orig !== 'function' || orig._backstopBinding) return;
  const guarded = function (name) {
    if (REFUSED_BINDINGS.includes(String(name))) {
      const msg = `entropy-backstop: process.binding('${String(name)}') refused (G-39)`;
      console.error(msg);
      throw new NativeError(msg);
    }
    return orig.call(this, name);
  };
  guarded._backstopBinding = true;
  Object.defineProperty(process, 'binding', { configurable: false, writable: false, enumerable: true, value: guarded });
  // A native addon can call any C API (fork/exec, RAND_bytes) behind every hook: refused in tests.
  if (typeof process.dlopen === 'function' && !process.dlopen._backstopBinding) {
    const dl = function () {
      const msg = 'entropy-backstop: process.dlopen refused (G-39: native addons bypass every hook)';
      console.error(msg);
      throw new NativeError(msg);
    };
    dl._backstopBinding = true;
    Object.defineProperty(process, 'dlopen', { configurable: false, writable: false, enumerable: true, value: dl });
  }
  // G-46 (HoQ report 5f7f4ad7, B8/B16): process.execve replaces this process with an unhooked program
  // (node without the preload, or a shell). Refused outright.
  if (typeof process.execve === 'function' && !process.execve._backstopBinding) {
    const ex = function () {
      const msg = 'entropy-backstop: process.execve refused (G-46: replaces the process with an unhooked program)';
      console.error(msg);
      throw new NativeError(msg);
    };
    ex._backstopBinding = true;
    Object.defineProperty(process, 'execve', { configurable: false, writable: false, enumerable: true, value: ex });
  }
}

function installChildProcessHook() {
  const cp = require('node:child_process');
  for (const name of ['spawn', 'spawnSync', 'fork', 'execFile', 'execFileSync', 'exec', 'execSync']) {
    const orig = cp[name];
    if (typeof orig !== 'function' || orig._backstopChild) continue;
    const sync = name.endsWith('Sync');
    const hooked = function (...args) {
      const { args: mapped, proof } = mapChildArgs(args, name);
      if (!proof) return orig.apply(this, mapped);
      if (sync) {
        let r, err = null;
        try { r = orig.apply(this, mapped); } catch (e) { err = e; }
        if (!checkProof(proof, `${name} ${String(args[0]).slice(0, 80)}`)) throw new NativeError(`entropy-backstop: node child did not prove the backstop is loaded (${name})`);
        if (err) throw err;
        return r;
      }
      const child = orig.apply(this, mapped);
      if (child && typeof child.once === 'function') child.once('exit', () => checkProof(proof, `${name} ${String(args[0]).slice(0, 80)}`));
      return child;
    };
    hooked._backstopChild = true;
    try {
      Object.defineProperty(cp, name, { configurable: false, writable: false, enumerable: true, value: hooked });
    } catch {
      cp[name] = hooked;
    }
  }
  try { syncBuiltinESMExports(); } catch { /* already live */ }
}

export function install(opts = {}) {
  if (installed && !opts.force) return getMarker();
  if (opts.allowed) allowed = opts.allowed.map(normalizePath);
  savedPrepare = Error.prepareStackTrace;
  savedLimit = Error.stackTraceLimit;
  installNodeOptions();
  installWorkerHook();
  installChildProcessHook();
  installBindingGuard();
  writeProof();
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
    nodeVersion: BACKSTOP_NODE_VERSION,
    randomUUIDv7Present: RANDOMUUIDV7_PRESENT,
    evidence: Object.freeze({ open: openEvidenceGrant, launch: launchEvidenceTool, close: closeEvidenceGrant, active: evidenceGrantActive, stamp: stampEvidenceResult, stamped: evidenceStamp, report: reportEvidenceResult }),
  };
  Object.defineProperty(marker, 'wrappers', { value: wrappers, writable: false, configurable: false, enumerable: true });
  Object.defineProperty(marker, 'counters', { value: counters, writable: false, configurable: false, enumerable: true });
  Object.defineProperty(marker, 'entryPointIds', { value: ENTRY_POINT_IDS, writable: false, configurable: false, enumerable: true });
  Object.preventExtensions(marker);
  Object.defineProperty(globalThis, MARK, {
    value: marker,
    writable: false,
    configurable: false,
    enumerable: false,
  });
  installedMarker = marker;
  initEvidenceChannel();
  return marker;
}

let installedMarker = null;
export function assertMarkerIdentity(label = 'call') {
  const cur = globalThis[MARK];
  const desc = Object.getOwnPropertyDescriptor(globalThis, MARK);
  if (!installedMarker || cur !== installedMarker || !desc || desc.writable || desc.configurable || desc.value !== installedMarker) {
    const msg = `entropy-backstop: marker identity changed (${label})`;
    console.error(msg);
    throw new NativeError(msg);
  }
}

// G-39 (marker no-op mutant): lets check:ph0 prove that a changed marker identity is caught per call
// and at exit. It can only make the backstop fail, never pass.
export function breakMarkerIdentityForTestOnly() {
  installedMarker = Object.freeze({ broken: true });
}

export function getMarker() {
  return globalThis[MARK];
}

function onTeardown() {
  try {
    assertMarkerIdentity('beforeExit');
    assertIdentitiesAndStack('beforeExit');
    assertCountersHealthy('beforeExit');
    if (proofFailures.length) throw new NativeError(proofFailures[0]);
  } catch (e) {
    if (process.exitCode == null || process.exitCode === 0) process.exitCode = 1;
  }
}

install();
process.on('beforeExit', onTeardown);
process.on('exit', onTeardown);
process.on('exit', onGrantLeak);
