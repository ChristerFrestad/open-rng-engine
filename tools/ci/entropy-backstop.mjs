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
import { createHash } from 'node:crypto';
// A25-2 (split note v1 + Addenda A-D): helper-mode manifest check and post-boot lockdown. Both modules are pure (no
// backstop import, no CSPRNG use) and are loaded before any hook exists, like this file.
import { EXIT_A25_MANIFEST_DIGEST, EXIT_A25_MANIFEST_OUTSIDE, MANIFEST_ENV, makeIsManifestUrl, parseGrant, readManifest, verifyLoad } from './a25-manifest.mjs';
import { ADDON_BUILTINS, EXIT_A25_ADDON, EXIT_A25_CODEGEN, EXIT_A25_FORBIDDEN_MODULE, EXIT_A25_IMPORT, FORBIDDEN_BUILTINS, installLockdown } from './a25-lockdown.mjs';

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


// ---------------- A25-3 / A25-4: evidence-helper mode (HoQ addendum 1 A25; CTO GO 2026-11-25 13:50) ----------------
// Only an evidence helper started by stream-launcher.mjs runs in this mode (ENTROPY_BACKSTOP_HELPER=a25, refused by the
// launcher unless the H frame reports it with this file's digest and the plan's k). Dev, test and every non-evidence
// path keep the per-call stack walk above unchanged.
//  - A25-3: the one approved entry is fillBuffer in src/entropy/index.ts. Its `import { randomFillSync } from
//    'node:crypto'` (and only that importer's) resolves to HELPER_GATE_URL, a preload-owned virtual module whose
//    randomFillSync is helperGate below. helperGate validates its argument WITHOUT running user code, runs the
//    integrity checks and the A25-4 sampled walk, then sets the gate instance's private token (makeHelperGate closure), calls the ORIGINAL primitive and
//    clears the token in finally. Every wrapped primitive (any route: import, require, createRequire,
//    process.getBuiltinModule, webcrypto, globalThis.crypto) aborts in this mode: token clear is the A25-3 abort; token
//    set means re-entry from inside the native fill, which cannot happen legitimately, and aborts too.
//  - The gate is handed over only through this module's own export, and the resolve hook lets nothing but the virtual
//    module resolve this file in helper mode. No global holds it at any time (CTO change 1).
//  - A25-4: the full checkCaller walk runs on the first HELPER_FIRST_WALK gate calls and then whenever
//    (index & (2^HELPER_SAMPLE_K - 1)) === 0. A failed walk aborts with its own exit code; the launcher voids the run.
export const HELPER_MODE_ENV = 'ENTROPY_BACKSTOP_HELPER';
export const HELPER_MODE_ID = 'a25';
export const HELPER_FIRST_WALK = 10000;
export const HELPER_SAMPLE_K = 12;
// A25-4b: a counted part must reach >= 20 sampled walks after the first F gate calls: F + 20 * 2^k = 91920 (k = 12, A29-1).
export const HELPER_MIN_SAMPLED_HITS = 20;
export const HELPER_PART_FLOOR = 91920;
export const EXIT_A25_TOKEN = 86;   // a wrapped CSPRNG primitive called in helper mode (token clear, or re-entry)
export const EXIT_A25_GATE = 87;    // the gate refused: bad argument, tampered intrinsics, wrong importer, leak
export const EXIT_A25_WALK = 88;    // A25-4 sampled stack walk failed
export const HELPER_GATE_URL = 'rng-backstop-gate:node-crypto';
const HELPER_MODE = process.env[HELPER_MODE_ENV] === HELPER_MODE_ID;
// A25-1 (G-54; design v2): the launcher hands each helper spawn a FRESH token (grant-<n>@<pid>#<nonce>). The preload
// reads it once and removes it from the environment, writes it into this process's G-39 proof file together with
// its own sha256 (writeProof), and, in helper mode, reports it in the H frame (helperState().grant). The token alone
// is not a proof of preload (a child without the preload could echo it); the proof file, written by the preload
// itself and checked per spawn by the launcher, is.
export const HELPER_GRANT_ENV = 'ENTROPY_BACKSTOP_GRANT';
// A25-2: in helper mode the grant is '<token>|m=<manifest sha256>' (helperSpawnEnv); the sha reaches the preload ONLY
// here. The token part is what the proof and the H frame carry (A25-1 unchanged). The preload does not verify the
// token (the launcher does, from the proof file). A missing or malformed m= part exits 90 before any module loads.
const RAW_GRANT = typeof process.env[HELPER_GRANT_ENV] === 'string' ? process.env[HELPER_GRANT_ENV] : null;
const GRANT_PARTS = HELPER_MODE ? parseGrant(RAW_GRANT) : null;
// F-W5 (found while re-running W5 under the preload): an exit before install still leaves the parent's G-39 proof,
// marked early_exit with no token or digest, so a preloaded parent sees the preload ran (the exit code voids the run).
function earlyExit(code, why) {
  try { writeSync(2, `entropy-backstop[A25]: ${why} (exit ${code})\n`); } catch { /* stderr closed */ }
  const pf = process.env.ENTROPY_BACKSTOP_PROOF_FILE;
  if (pf) { try { writeFileSync(pf, JSON.stringify({ pid: process.pid, preload_sha256: null, token: null, manifest_sha256: null, early_exit: code }), { flag: 'wx' }); } catch { /* no proof: red */ } }
  (typeof process.reallyExit === 'function' ? process.reallyExit.bind(process) : process.exit.bind(process))(code);
}
if (HELPER_MODE && GRANT_PARTS === null) earlyExit(EXIT_A25_MANIFEST_DIGEST, 'grant carries no manifest digest');
const SPAWN_TOKEN = HELPER_MODE ? GRANT_PARTS.token : RAW_GRANT;
const HELPER_GRANT = HELPER_MODE ? SPAWN_TOKEN : null;
const MANIFEST_SHA256 = HELPER_MODE ? GRANT_PARTS.sha256 : null;
const MANIFEST_PATH = HELPER_MODE && typeof process.env[MANIFEST_ENV] === 'string' ? process.env[MANIFEST_ENV] : null;
delete process.env[HELPER_GRANT_ENV];
delete process.env[MANIFEST_ENV];
// CTO 22:12 binding ruling: the grant digest is the authority. ENTROPY_BACKSTOP_MANIFEST_SHA256 is advisory only;
// if present in helper mode it must equal the grant digest, else exit 90 before any module loads. Never trusted.
export const MANIFEST_SHA256_ADVISORY_ENV = 'ENTROPY_BACKSTOP_MANIFEST_SHA256';
const ADVISORY_SHA256 = Object.prototype.hasOwnProperty.call(process.env, MANIFEST_SHA256_ADVISORY_ENV) ? process.env[MANIFEST_SHA256_ADVISORY_ENV] : null;
delete process.env[MANIFEST_SHA256_ADVISORY_ENV];
if (HELPER_MODE && ADVISORY_SHA256 !== null && ADVISORY_SHA256 !== MANIFEST_SHA256) earlyExit(EXIT_A25_MANIFEST_DIGEST, 'advisory manifest digest differs from the grant digest');
// Addendum B: one-shot refusal hook. Each backstop refusal site (dlopen, spawn_sync/process_wrap and the other refused
// bindings, execve) calls it before its throw, so in helper mode the lockdown turns the refusal into an abort.
let REFUSE_HOOK = null;
export function registerRefuseHook(fn) {
  if (REFUSE_HOOK !== null || typeof fn !== 'function') {
    try { writeSync(2, `entropy-backstop[A25]: registerRefuseHook ${REFUSE_HOOK !== null ? 'called twice' : 'needs a function'} (exit ${EXIT_A25_GATE})\n`); } catch { /* stderr closed */ }
    (typeof process.reallyExit === 'function' ? process.reallyExit.bind(process) : process.exit.bind(process))(EXIT_A25_GATE);
  }
  REFUSE_HOOK = fn;
}
function refused(kind, detail) { const h = REFUSE_HOOK; if (h !== null) h(kind, detail); }
if (process.env[HELPER_MODE_ENV] !== undefined && !HELPER_MODE) {
  writeSync(2, `entropy-backstop: ${HELPER_MODE_ENV}=${process.env[HELPER_MODE_ENV]} is not a known helper mode\n`);
  process.exit(EXIT_A25_GATE);
}
// R-A25-2-SEC item 7: in helper mode the helper-mode variable leaves process.env too (grant, locator and advisory are
// deleted above). /proc/self/environ keeps the exec-time environment: a named residual (design v1.5).
if (HELPER_MODE) delete process.env[HELPER_MODE_ENV];
const SELF_URL = import.meta.url;
const ENTROPY_URL = pathToFileURL(join(ENTROPY_ROOT, 'index.ts')).href;
const INDEX_URL = pathToFileURL(join(SRC_ROOT, 'index.ts')).href;
export const BACKSTOP_SHA256 = createHash('sha256').update(readFileSync(SELF)).digest('hex');
const HELPER_MASK = (2 ** HELPER_SAMPLE_K) - 1;
const reallyExit = typeof process.reallyExit === 'function' ? process.reallyExit.bind(process) : process.exit.bind(process);
function helperAbort(code, why) {
  if (HELPER) HELPER.clearToken();
  try { writeSync(2, `entropy-backstop[A25]: ${why} (exit ${code})\n`); } catch { /* stderr closed */ }
  reallyExit(code);
}
// Intrinsics saved at install, before any user code. Every check below is a slot or own-property read on a
// non-proxy object, so none of them can run user code.
const U8 = Uint8Array;
const U8P = Uint8Array.prototype;
const TAP = Object.getPrototypeOf(U8P);
const TA_BYTELENGTH = Object.getOwnPropertyDescriptor(TAP, 'byteLength').get;
const isView = ArrayBuffer.isView;
const getProto = Object.getPrototypeOf;
const hasOwn = Object.hasOwn;
const gopd = Object.getOwnPropertyDescriptor;
let origFill = null;
let HELPER = null; // the one installed gate instance (installHelperMode); never exported
let HELPER_LOADED = () => Object.freeze([]); // R-A25-2-SEC item 1: D22-4 load digests (installHelperMode)
// R-A25-2-SEC item 2: helper-mode process.binding allowlist, active once the lockdown is installed. Empty: the helper
// closure makes no process.binding call and node's own modules use internalBinding (design v1.5, with evidence).
export const HELPER_BINDING_ALLOW = Object.freeze([]);
let BINDING_ALLOWLIST_ON = false;
function helperWalk(i) {
  assertMarkerIdentity('helper-walk');
  assertIdentitiesAndStack('helper-walk');
  checkCaller('randomFillSync', new NativeError().stack);
}
// Builds a gate around `fill`. installHelperMode is the only caller in this file and passes only the saved original
// randomFillSync (test/r-g64-a25.test.mjs pins that). Each instance has its own token and counters in its closure, so
// an instance built elsewhere (test/r-g64-a25-bare.mjs, normal mode, to inject a throwing fill) cannot reach the
// installed gate's token; in helper mode no module may import this file after the main entry starts (resolve hook).
export function makeHelperGate(fill, { walk = helperWalk } = {}) {
  if (typeof fill !== 'function' || typeof walk !== 'function') throw new NativeError('entropy-backstop: makeHelperGate needs a fill and a walk function');
  let token = false, calls = 0, walks = 0;
  function helperGate(target) {
    // CTO change 2: nothing but a real Uint8Array with intrinsic byteLength / BYTES_PER_ELEMENT, and no offset or
    // size arguments (fillBuffer passes only the target), so node's randomFillSync coerces nothing user-defined.
    if (arguments.length !== 1) helperAbort(EXIT_A25_GATE, `gate: ${arguments.length} arguments (only the target is allowed)`);
    if (!isView(target) || getProto(target) !== U8P) helperAbort(EXIT_A25_GATE, 'gate: target is not a plain Uint8Array');
    // %TypedArray%.prototype and Uint8Array.prototype are frozen at install in helper mode (installHelperMode), so
    // their byteLength getter, BYTES_PER_ELEMENT and prototype link cannot change; only an own property on the
    // instance could shadow them.
    if (hasOwn(target, 'byteLength') || hasOwn(target, 'BYTES_PER_ELEMENT')) helperAbort(EXIT_A25_GATE, 'gate: target shadows byteLength or BYTES_PER_ELEMENT');
    if (token) helperAbort(EXIT_A25_TOKEN, 'gate re-entered while the token is set');
    const i = calls++;
    if (i < HELPER_FIRST_WALK || (i & HELPER_MASK) === 0) {
      walks++;
      try { walk(i); } catch (e) { helperAbort(EXIT_A25_WALK, `sampled walk failed at gate call ${i}: ${e && e.message}`); }
    }
    token = true;
    try { fill(target); } finally { token = false; }
    return target;
  }
  return Object.freeze({ gate: helperGate, fill, tokenSet: () => token, clearToken: () => { token = false; }, counts: () => Object.freeze({ gate_calls: calls, walks }) });
}
export let HELPER_GATE = null;
export function helperState() {
  return HELPER_MODE ? Object.freeze({ mode: HELPER_MODE_ID, sample_k: HELPER_SAMPLE_K, first_walk: HELPER_FIRST_WALK, part_floor: HELPER_PART_FLOOR, backstop_sha256: BACKSTOP_SHA256, grant: HELPER_GRANT }) : null;
}
// CTO change 3: after importing src/index.ts the helper hands its namespace here; no export may be the gate.
function helperAssertNoGateLeak(ns) {
  if (!HELPER_MODE) return false;
  if (ns === null || typeof ns !== 'object') helperAbort(EXIT_A25_GATE, 'leak check: not a module namespace');
  for (const k of Reflect.ownKeys(ns)) {
    const v = gopd(ns, k)?.value;
    if (v === HELPER.gate || v === origFill) helperAbort(EXIT_A25_GATE, `leak check: src/index.ts export ${String(k)} is the gated primitive`);
  }
  return true;
}
function helperCounts() { return HELPER ? HELPER.counts() : Object.freeze({ gate_calls: 0, walks: 0 }); }
function installHelperMode(cryptoMod) {
  if (!HELPER_MODE) return;
  origFill = originals.randomFillSync ?? cryptoMod.randomFillSync;
  if (typeof origFill !== 'function' || origFill === wrappers.randomFillSync) throw new NativeError('entropy-backstop: helper mode needs the original randomFillSync');
  // Freeze the two prototypes node's randomFillSync reads through (byteLength, BYTES_PER_ELEMENT), and check the
  // getter is still the intrinsic one, so the per-call gate needs no descriptor read.
  if (gopd(TAP, 'byteLength')?.get !== TA_BYTELENGTH || getProto(U8P) !== TAP || hasOwn(U8P, 'byteLength')) throw new NativeError('entropy-backstop: helper mode found a changed Uint8Array prototype chain at install');
  Object.freeze(TAP); Object.freeze(U8P);
  if (!Object.isFrozen(TAP) || !Object.isFrozen(U8P)) throw new NativeError('entropy-backstop: helper mode could not freeze the TypedArray prototypes');
  HELPER = makeHelperGate(origFill);
  HELPER_GATE = HELPER.gate;
  // A25-2: the manifest the grant binds (exits 90 on a missing, unreadable, swapped or malformed file).
  const VIEW = readManifest(MANIFEST_PATH, MANIFEST_SHA256, (c) => helperAbort(c, 'manifest header check failed'));
  const nodeModule = require('node:module');
  const { registerHooks } = nodeModule;
  const MAIN_URL = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : null;
  const STARTUP_CWD_URL = pathToFileURL(process.cwd() + sep).href;
  let mainStarted = false;
  // A25-2 (W1): the lockdown refuses forbidden builtins at resolve; the load step re-checks every node: URL as well.
  const FORBIDDEN_SET = new Set(FORBIDDEN_BUILTINS), ADDON_SET = new Set(ADDON_BUILTINS);
  const builtinLoadCheck = (url, where) => {
    const b = String(url).slice(5);
    if (FORBIDDEN_SET.has(b)) helperAbort(EXIT_A25_FORBIDDEN_MODULE, `${where}: forbidden builtin ${url}`);
    if (ADDON_SET.has(b)) helperAbort(EXIT_A25_ADDON, `${where}: addon builtin ${url}`);
  };
  const GATE_SOURCE = `import { HELPER_GATE as g } from ${JSON.stringify(SELF_URL)};\nif (typeof g !== 'function') throw new Error('gate missing');\nexport const randomFillSync = g;\nexport default Object.freeze({ randomFillSync: g });\n`;
  // A25-2 (CTO 22:20 ruling): in helper mode a resolved URL may only be file: (then held to the manifest at load),
  // node: (builtin checks) or the virtual gate. data:, blob:, http(s): and any other scheme are code outside the
  // manifest: 89, wherever the resolve came from (our hook or the lockdown chain).
  const SCHEME_OK = (u) => u === HELPER_GATE_URL || u.startsWith('file:') || u.startsWith('node:');
  const schemeCheck = (u, where) => {
    if (typeof u !== 'string' || !SCHEME_OK(u)) helperAbort(EXIT_A25_MANIFEST_OUTSIDE, `${where}: scheme not allowed in helper mode: ${String(u).slice(0, 40)}`);
  };
  // R-A25-2-SEC item 1 (D22-4 moved here): the evidence helper's observing load hook is now ours. For the helper main
  // only, every src/ file is recorded with the digest of the bytes node compiles; helper.loaded() hands the list over.
  const HELPER_MAIN_REL = 'verification/harness/evidence-helper.mjs';
  const mainIsHelper = MAIN_URL !== null && VIEW.entries.has(HELPER_MAIN_REL) && MAIN_URL === pathToFileURL(join(VIEW.root, HELPER_MAIN_REL)).href;
  const loaded = [];
  HELPER_LOADED = () => Object.freeze(loaded.map((e) => Object.freeze([...e])));
  const recordLoaded = (rel) => { if (mainIsHelper && rel.startsWith('src/')) loaded.push([rel, VIEW.entries.get(rel)]); };
  registerHooks({
    resolve(specifier, context, nextResolve) {
      const parent = context.parentURL;
      if (specifier === HELPER_GATE_URL) helperAbort(EXIT_A25_GATE, `resolve: ${HELPER_GATE_URL} requested by ${parent}`);
      if (parent === ENTROPY_URL && (specifier === 'node:crypto' || specifier === 'crypto')) return { url: HELPER_GATE_URL, format: 'module', shortCircuit: true };
      const r = nextResolve(specifier, context);
      schemeCheck(r && r.url, 'resolve');
      // Before the main entry resolves, a second top-level --import of the preload (NODE_OPTIONS and argv both name it)
      // is resolved from undefined or the startup cwd; from the main entry on, only the gate URL may import it.
      if (r.url === MAIN_URL) mainStarted = true;
      if (r.url === SELF_URL && parent !== HELPER_GATE_URL && (mainStarted || (parent !== undefined && parent !== STARTUP_CWD_URL))) helperAbort(EXIT_A25_GATE, `resolve: the preload is not importable in helper mode (from ${parent})`);
      if (r.url === ENTROPY_URL && parent !== INDEX_URL) helperAbort(EXIT_A25_GATE, `resolve: src/entropy/index.ts imported by ${parent}, only src/index.ts may`);
      return r;
    },
    load(url, context, nextLoad) {
      if (url === HELPER_GATE_URL) {
        return { format: 'module', shortCircuit: true, source: GATE_SOURCE };
      }
      // A25-2: every non-builtin load must be a manifest file whose bytes match its entry. The check runs on the
      // bytes node will compile (r.source), not on a second read, so a swap between check and compile is caught.
      schemeCheck(url, 'load');
      if (typeof url === 'string' && url.startsWith('node:')) {
        builtinLoadCheck(url, 'load');
        // R-A25-2-SEC item 4: a builtin must come back as node's builtin, with no source a hook could have swapped in.
        const rb = nextLoad(url, context);
        if (!rb || rb.format !== 'builtin' || rb.source != null) helperAbort(EXIT_A25_MANIFEST_OUTSIDE, `load: ${url} came back as ${rb && rb.format}${rb && rb.source != null ? ' with a source' : ''}, not the builtin`);
        return rb;
      }
      const v = verifyLoad(VIEW, url);
      if (!v.ok) helperAbort(v.code, `load: ${v.why}`);
      const r = nextLoad(url, context);
      if (r && r.source != null) {
        const src = typeof r.source === 'string' ? Buffer.from(r.source, 'utf8') : Buffer.from(r.source.buffer ?? r.source, r.source.byteOffset ?? 0, r.source.byteLength);
        if (createHash('sha256').update(src).digest('hex') !== VIEW.entries.get(v.rel)) helperAbort(EXIT_A25_MANIFEST_DIGEST, `load: compiled bytes of ${v.rel} differ from the manifest`);
        recordLoaded(v.rel);
        return r;
      }
      // A6ii-M3 (CTO, int-v8): CommonJS with no source from nextLoad. Node compiles exactly the bytes handed here, never
      // a re-read from fs; those bytes are hashed against the manifest at this hand-off too (not only inside
      // verifyLoad), so the compiled bytes of a manifest .cjs either match its digest or the helper exits 90.
      if (!Buffer.isBuffer(v.bytes) || createHash('sha256').update(v.bytes).digest('hex') !== VIEW.entries.get(v.rel)) helperAbort(EXIT_A25_MANIFEST_DIGEST, `load: CommonJS bytes of ${v.rel} differ from the manifest`);
      recordLoaded(v.rel);
      return { ...r, source: v.bytes };
    },
  });
  // A25-2: the lockdown is the LAST preload hook (Addendum B). After it, installHookGuard (install()) refuses every
  // runtime registerHooks/register call with 94 (R-A25-2-SEC item 1: no late-hook allowance).
  installLockdown({ isManifestUrl: makeIsManifestUrl(VIEW, A25_DYNAMIC_BUILTINS), abort: helperAbort, registerRefuseHook });
  // R-A25-2-SEC item 2: from here on process.binding is an allowlist (HELPER_BINDING_ALLOW, empty: design v1.5).
  BINDING_ALLOWLIST_ON = true;
  // R-A25-2-SEC item 3: the inspector entry points on process (SIGUSR1-style attach, Sec p9) give 92.
  for (const k of ['_debugProcess', '_debugEnd', '_startProfilerIdleNotifier', '_stopProfilerIdleNotifier']) {
    const d = gopd(process, k);
    if (d && d.configurable === false) helperAbort(EXIT_A25_FORBIDDEN_MODULE, `process.${k} cannot be locked`);
    const stub = function () { helperAbort(EXIT_A25_FORBIDDEN_MODULE, `process.${k} refused in helper mode (inspector entry point)`); };
    Object.defineProperty(process, k, { value: stub, writable: false, configurable: false, enumerable: false });
  }
  // Residual found while closing item 3 (design v1.5 L-SEC-2): a SIGUSR1 sent from outside starts the inspector even
  // with the stubs above. A JS listener replaces Node's default handler, so the signal now gives 92 instead. Helper
  // code that removes every SIGUSR1 listener restores the default; --disable-sigusr1 on the helper spawn would close
  // that too and is proposed to CTO (it changes the launcher's exact spawn arguments, A25-6 iv).
  process.on('SIGUSR1', function backstopSigusr1() { helperAbort(EXIT_A25_FORBIDDEN_MODULE, 'SIGUSR1 (inspector activation) received in helper mode'); });
  // R-A25-2-SEC item 5: WebAssembly compiles and runs code outside the manifest: 91. Node's own TypeScript stripping
  // (amaro, used for every src/*.ts load) instantiates a wasm module lazily through the same global, so it is primed
  // here first, once, with its experimental warning held back; later .ts loads reuse that instance.
  const WA = globalThis.WebAssembly;
  if (typeof nodeModule.stripTypeScriptTypes === 'function') {
    const ew = process.emitWarning;
    process.emitWarning = function () {};
    try { nodeModule.stripTypeScriptTypes('const a: number = 1;'); } catch { helperAbort(EXIT_A25_CODEGEN, 'could not prime TypeScript stripping before the WebAssembly lock'); } finally { process.emitWarning = ew; }
  }
  if (WA && typeof WA === 'object') {
    for (const k of ['compile', 'instantiate', 'Module', 'compileStreaming', 'instantiateStreaming']) {
      const stub = function () { helperAbort(EXIT_A25_CODEGEN, `WebAssembly.${k} called in helper mode`); };
      Object.defineProperty(WA, k, { value: stub, writable: false, configurable: false, enumerable: false });
    }
    Object.defineProperty(globalThis, 'WebAssembly', { value: WA, writable: false, configurable: false, enumerable: false });
  }
}
// R-A25-2-SEC item 1: module.registerHooks and module.register are refused at call time with 94, before any hook is
// installed, in BOTH modes. The preload owns the only hooks (helper mode: ours plus the lockdown's).
function installHookGuard() {
  const nodeModule = require('node:module');
  if (nodeModule.registerHooks && nodeModule.registerHooks._backstopHookGuard) return;
  const refuseHooks = function registerHooks() { helperAbort(EXIT_A25_IMPORT, 'module.registerHooks after the preload (A25-2: the preload owns the only hooks)'); };
  const refuseRegister = function register() { helperAbort(EXIT_A25_IMPORT, 'module.register after the preload (A25-2: the preload owns the only hooks)'); };
  refuseHooks._backstopHookGuard = true; refuseRegister._backstopHookGuard = true;
  try {
    Object.defineProperty(nodeModule, 'registerHooks', { value: refuseHooks, writable: false, configurable: false, enumerable: true });
    Object.defineProperty(nodeModule, 'register', { value: refuseRegister, writable: false, configurable: false, enumerable: true });
    nodeModule.syncBuiltinESMExports();
  } catch { helperAbort(EXIT_A25_IMPORT, 'could not install the hook guard'); }
  if (nodeModule.registerHooks !== refuseHooks || nodeModule.register !== refuseRegister) helperAbort(EXIT_A25_IMPORT, 'hook guard not in place');
}
// import() of a builtin in helper mode: none today (the helper's dynamic imports are manifest files); the trace at
// the A31 prereg re-pins this list together with the pinned helper closure (verification/harness/helper-closure.json).
const A25_DYNAMIC_BUILTINS = Object.freeze([]);

function wrapFn(id, orig) {
  if (typeof orig !== 'function') {
    throw new NativeError(`entropy-backstop: cannot wrap ${id}: not a function`);
  }
  const wrapped = function entropyBackstopWrapped(...args) {
    counters[id] += 1;
    if (HELPER_MODE) helperAbort(EXIT_A25_TOKEN, `${id} called in helper mode ${HELPER && HELPER.tokenSet() ? 'while the token is set (re-entry)' : 'with the token clear'}`);
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

// G-64 (HoQ A9, MAJOR; A11): the counting authority is OUTSIDE this process and holds no secret this process
// could read (K3a's HMAC key, kept in this closure, was recovered by a runner from /proc/self/mem; HoQ A11).
// verification/harness/evidence-launcher.mjs spawns the runner with this preload, ENTROPY_BACKSTOP_CHANNEL=1
// and fd 3, and counts only full results it re-checks itself. Here the flag is deleted at preload, and
// reportEvidenceResult (the honest path) writes the FULL stamped result (id, n, records) to fd 3. The stamp
// check below is hygiene for honest runners, not authority: anything this process writes is only a claim.
let channelOpen = false;
function initEvidenceChannel() {
  if (process.env.ENTROPY_BACKSTOP_CHANNEL !== '1') return;
  delete process.env.ENTROPY_BACKSTOP_CHANNEL;
  channelOpen = true;
}
export function reportEvidenceResult(result) {
  if (!channelOpen) refuseChild('evidence report without a launcher channel (G-64)');
  const t = evidenceStamp(result);
  if (t === null || result.grant !== t) refuseChild('evidence report of a result not stamped inside an open evidence grant (G-64)');
  const line = JSON.stringify({ id: result.id, n: result.n, records: result.records }, (k, v) => (typeof v === 'bigint' ? `${v}n` : v));
  writeSync(3, `${line}\n`);
  return resultContentDigest(result);
}
export function evidenceGrantActive() { return activeGrant !== null && evidenceGrants.has(activeGrant); }
// A25-1: the token of g while g is the open grant, else null. The launcher passes it to each helper and re-reads it
// to decide that the grant is still live.
export function evidenceGrantToken(g) {
  return g !== null && typeof g === 'object' && evidenceGrants.has(g) && activeGrant === g ? `grant-${g.grant}@${process.pid}` : null;
}
// A25-1 (design v2): a fresh per-spawn token, grant-<n>@<pid>#<128-bit nonce>, from the ORIGINAL randomFillSync (the
// launcher's own crypto calls would go through the wrapped entry points). null unless g is the open grant.
export function evidenceSpawnToken(g) {
  const t = evidenceGrantToken(g);
  const fill = originals.randomFillSync;
  if (t === null || typeof fill !== 'function') return null;
  const b = new Uint8Array(16); fill(b);
  return `${t}#${Buffer.from(b).toString('hex')}`;
}

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

// R-G64 (design §3, Q3 a): the same launch, asynchronous, so a battery tool can read one helper's outcomes as
// they are counted (stdin piped by the launcher). Every check above runs unchanged: open grant, guard re-run,
// absolute path, pinned binary (G-55), no shell; the spawn-layer G-45 check sees launching set for this call.
export function launchEvidenceToolStream(g, file, args = [], options = {}) {
  if (!evidenceGrants.has(g) || activeGrant !== g || grantEntry === null) refuseChild('evidence tool launch without an open grant (G-45)');
  grantEntry.assertEvidenceRunReady();
  if (typeof file !== 'string' || !isAbsolute(file) || !EVIDENCE_TOOLS.includes(basename(file))) refuseChild(`launchEvidenceToolStream: ${String(file)} is not an absolute path to an evidence tool (G-45)`);
  const real = pinnedBinary(file);
  const cp = require('node:child_process');
  launching = { grant: g, file, real };
  try { return cp.spawn(file, args, { ...options, shell: false }); } finally { launching = null; }
}

export const CHILD_EXECUTABLE_ALLOWLIST = Object.freeze(['node', 'git', 'mkdir', 'ln']);
const TRUSTED_DIRS = Object.freeze([...new Set(['/usr/bin', '/bin', '/usr/local/bin', dirname(process.execPath)].map((d) => { try { return realpathSync(d); } catch { return d; } }))]);
const PLAIN_WORD = /^[A-Za-z0-9_./:,@%+=-]+$/;
const PROOF_ENV = 'ENTROPY_BACKSTOP_PROOF_FILE';
// A25-1: the proof path of each async node child, so a caller can tie the G-39 proof to one child (a helper part).
const childProofs = new WeakMap();
// null: not a node child spawned through this hook; false: no proof file; otherwise the proof the child's preload
// wrote ({ pid, preload_sha256, token, manifest_sha256, sigusr1_disabled } or { invalid: true }) plus the file's mtime_ms.
// int-v8: sigusr1_disabled is passed through (without it every header-bound part would void at the launcher's check).
export function childPreloadProof(child) {
  const p = child !== null && typeof child === 'object' ? childProofs.get(child) : undefined;
  if (p === undefined) return null;
  if (!existsSync(p)) return false;
  let body;
  try { body = JSON.parse(readFileSync(p, 'utf8')); } catch { body = null; }
  const ok = body !== null && typeof body === 'object' && !Array.isArray(body);
  return Object.freeze({ ...(ok ? { pid: body.pid, preload_sha256: body.preload_sha256, token: body.token, manifest_sha256: body.manifest_sha256 ?? null, sigusr1_disabled: body.sigusr1_disabled ?? null } : { invalid: true }), mtime_ms: statSync(p).mtimeMs });
}
// N-PV-1 (Sec, int-v8 r7): the hook proof file path recorded for an async node child (null for any other value), so
// a caller binds the bare view of the proof by path, not by mtime. Read-only: the path is the one newProofPath() gave it.
export function childPreloadProofPath(child) {
  const p = child !== null && typeof child === 'object' ? childProofs.get(child) : undefined;
  return typeof p === 'string' ? p : null;
}
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
  // A25-1: the proof names this process, the preload's own digest and the spawn token it was started with. 'wx':
  // a file that already exists is never overwritten, so a stale proof keeps its old pid and token (and voids).
  // A25-2: the grant-bound manifest digest (null outside helper mode). int-v8 (CTO ruling (a), L-SEC-2): whether node
  // was started with --disable-sigusr1 (process.execArgv is fixed at startup; this runs at install, before any user code).
  const body = JSON.stringify({ pid: process.pid, preload_sha256: BACKSTOP_SHA256, token: SPAWN_TOKEN, manifest_sha256: MANIFEST_SHA256, sigusr1_disabled: process.execArgv.includes('--disable-sigusr1') });
  try { writeFileSync(p, body, { flag: 'wx' }); } catch { /* the parent will see no proof: red */ }
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
    if (BINDING_ALLOWLIST_ON && !HELPER_BINDING_ALLOW.includes(String(name))) {
      const msg = `entropy-backstop: process.binding('${String(name)}') refused in helper mode (not on the allowlist)`;
      refused('binding', msg);
      helperAbort(EXIT_A25_FORBIDDEN_MODULE, msg); // no refuse hook yet cannot happen (the lockdown registers it first)
    }
    if (REFUSED_BINDINGS.includes(String(name))) {
      const msg = `entropy-backstop: process.binding('${String(name)}') refused (G-39)`;
      refused(String(name) === 'spawn_sync' || String(name) === 'process_wrap' ? 'spawn' : 'binding', msg);
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
      refused('dlopen', msg);
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
      refused('spawn', msg);
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
      // R-A25-2-SEC item 3: no child in helper mode, through any holder of these exports (node:test's runner included).
      if (HELPER_MODE) helperAbort(EXIT_A25_FORBIDDEN_MODULE, `child_process.${name} refused in helper mode`);
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
      if (child && typeof child === 'object') childProofs.set(child, proof);
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
  installHelperMode(crypto);
  installHookGuard();
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
    helper: Object.freeze({ state: helperState(), assertNoGateLeak: helperAssertNoGateLeak, counts: helperCounts, loaded: () => HELPER_LOADED() }),
    evidence: Object.freeze({ open: openEvidenceGrant, launch: launchEvidenceTool, launchStream: launchEvidenceToolStream, close: closeEvidenceGrant, active: evidenceGrantActive, token: evidenceGrantToken, spawnToken: evidenceSpawnToken, childProof: childPreloadProof, childProofPath: childPreloadProofPath, stamp: stampEvidenceResult, stamped: evidenceStamp, report: reportEvidenceResult }),
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
