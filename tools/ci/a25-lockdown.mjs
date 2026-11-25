// A25-2 post-boot lockdown (HoQ addendum 1 A25-2; split v1, AI Engineer seat).
// installLockdown({ isManifestUrl, abort }) is called ONCE by the preload, after boot and before the main entry
// runs. From then on each of these aborts the process with its own exit code (abort() first, then reallyExit):
//   91 EXIT_A25_CODEGEN          eval, new Function / Function(), the Async/Generator/AsyncGenerator Function
//                                constructors, Module.prototype._compile from outside node's loader, and the
//                                contextify binding (process.binding('contextify') compileFunction/Script/makeContext)
//   92 EXIT_A25_FORBIDDEN_MODULE vm, worker_threads, child_process, plus cluster, inspector(/promises) and repl, by
//                                import, import(), require or process.getBuiltinModule
//   93 EXIT_A25_ADDON            native addons: process.dlopen, a resolved .node file or 'addon' format,
//                                Module._extensions['.node'], process._linkedBinding, node:sqlite (loadExtension)
//   94 EXIT_A25_IMPORT           a dynamic import() whose resolved URL isManifestUrl() rejects (or that throws);
//                                also at install when node is not NODE_VERSION_PIN (the import() detection reads
//                                node-internal frame names, so another node version fails closed instead of silently)
// Under the backstop preload, process.dlopen / process.binding('spawn_sync'|'process_wrap') / process.execve are the
// backstop's non-configurable G-39/G-46 refusals, which throw (catchable). Each of them writes its refusal line with
// console.error before throwing, so the lockdown locks globalThis.console and console.error and turns those exact
// lines into an abort (93 dlopen, 92 the others) before the throw can be caught.
// Codegen is blocked in JS because argv is fixed (A25-1: exact helper argv, no NODE_OPTIONS), so the
// --disallow-code-generation-from-strings flag cannot be passed, and v8.setFlagsFromString() after boot does not
// change the already-created main context (checked on node v24.22.1: eval still runs).
// This file imports nothing from the backstop and never touches node:crypto or any wrapped CSPRNG entry point.
import { createRequire, registerHooks, syncBuiltinESMExports } from 'node:module';

const require = createRequire(import.meta.url);
const Module = require('node:module');

export const EXIT_A25_CODEGEN = 91;
export const EXIT_A25_FORBIDDEN_MODULE = 92;
export const EXIT_A25_ADDON = 93;
export const EXIT_A25_IMPORT = 94;
export const FORBIDDEN_BUILTINS = Object.freeze(['vm', 'worker_threads', 'child_process', 'cluster', 'inspector', 'inspector/promises', 'repl']);
export const ADDON_BUILTINS = Object.freeze(['sqlite']);
export const NODE_VERSION_PIN = 'v24.22.1';
// The backstop's refusal lines (tools/ci/entropy-backstop.mjs installBindingGuard) and the abort each one becomes.
export const BACKSTOP_REFUSALS = Object.freeze([
  Object.freeze(['entropy-backstop: process.dlopen refused', 93]),
  Object.freeze(["entropy-backstop: process.binding('spawn_sync') refused", 92]),
  Object.freeze(["entropy-backstop: process.binding('process_wrap') refused", 92]),
  Object.freeze(['entropy-backstop: process.execve refused', 92]),
]);

// Intrinsics saved at module evaluation (boot), before any main-entry code runs.
const SavedError = Error;
const captureStackTrace = Error.captureStackTrace;
const gopd = Object.getOwnPropertyDescriptor;
const defineProperty = Object.defineProperty;
const getProto = Object.getPrototypeOf;
const isArray = Array.isArray;
const SetCtor = Set;
const setHas = Set.prototype.has;
const strStartsWith = String.prototype.startsWith;
const strEndsWith = String.prototype.endsWith;
const strSlice = String.prototype.slice;
const reTest = RegExp.prototype.test;
const apply = Reflect.apply;
const FORBIDDEN = new SetCtor(FORBIDDEN_BUILTINS);
const ADDON = new SetCtor(ADDON_BUILTINS);
const starts = (s, p) => apply(strStartsWith, s, [p]);
const DYNAMIC_FRAME = /importModuleDynamically/i;
const LINK_FRAME = /^(?:#?syncLink|#?link|#?linkModule|ModuleJob|ModuleJobSync|#?instantiate\w*)$/;

let installed = false;

function builtinId(url) {
  if (typeof url !== 'string') return null;
  // isBuiltin on the URL as given covers node:-only modules (node:sqlite, node:test); the id is returned unprefixed.
  if (!Module.isBuiltin(url)) return null;
  return starts(url, 'node:') ? apply(strSlice, url, [5]) : url;
}

// Call sites of the current stack, read with a temporary prepareStackTrace and restored before return. Returns null
// when Error.prepareStackTrace / stackTraceLimit are not plain writable data properties (someone locked them) or the
// result is not a CallSite array (someone replaced globalThis.Error): callers treat null as fail-closed.
function callSites() {
  const p = gopd(SavedError, 'prepareStackTrace'), l = gopd(SavedError, 'stackTraceLimit');
  if (!p || !l || !('value' in p) || !('value' in l) || !p.writable || !l.writable) return null;
  const holder = {};
  let cs;
  try {
    SavedError.prepareStackTrace = (_e, sites) => sites;
    SavedError.stackTraceLimit = 200;
    captureStackTrace(holder, callSites);
    cs = holder.stack;
  } catch { cs = null; } finally {
    SavedError.prepareStackTrace = p.value;
    SavedError.stackTraceLimit = l.value;
  }
  return isArray(cs) ? cs : null;
}

function frameName(c) {
  try { return String(c.getFunctionName() || c.getMethodName() || ''); } catch { return ''; }
}
function frameFile(c) {
  try { return String(c.getFileName() || ''); } catch { return ''; }
}

// A resolve is a dynamic import() when, walking out from the hook, node's internal dynamic-import frame
// (default/importModuleDynamically*) comes before any module-link frame. Static dependencies of a module that was
// itself reached by import() are linked synchronously under that same frame, behind syncLink/link/ModuleJob, so they
// are NOT dynamic: they stay with the manifest load hook (89/90). require() is never import().
// Unreadable stack: fail closed (treated as dynamic).
function isDynamicImport(context) {
  const conds = context && context.conditions;
  if (isArray(conds) && conds.includes('require')) return false;
  const cs = callSites();
  if (cs === null) return true;
  for (const c of cs) {
    const f = frameFile(c);
    if (!starts(f, 'node:internal/modules/')) continue;
    const n = frameName(c);
    if (apply(reTest, LINK_FRAME, [n])) return false;
    if (apply(reTest, DYNAMIC_FRAME, [n])) return true;
  }
  return false;
}

function calledFromNodeLoader() {
  const cs = callSites();
  // callSites() drops its own frame: cs[0] is this function, cs[1] the _compile guard, cs[2] the guard's caller.
  return cs !== null && cs.length > 2 && starts(frameFile(cs[2]), 'node:internal/modules/');
}

function lockProperty(obj, key, value) {
  try { defineProperty(obj, key, { value, writable: false, enumerable: false, configurable: false }); } catch { /* checked below */ }
  const d = gopd(obj, key);
  return !!d && d.value === value && d.writable === false;
}
function canReplace(obj, key) {
  const d = gopd(obj, key);
  return !d || d.configurable === true || d.writable === true;
}

export function installLockdown({ isManifestUrl, abort } = {}) {
  if (typeof isManifestUrl !== 'function' || typeof abort !== 'function') throw new TypeError('installLockdown: isManifestUrl and abort must be functions');
  if (installed) throw new SavedError('installLockdown: already installed (one call, by the preload, after boot)');
  installed = true;
  const reallyExit = typeof process.reallyExit === 'function' ? process.reallyExit.bind(process) : process.exit.bind(process);
  // abort is expected not to return (the backstop's helperAbort exits); if it returns or throws, exit anyway.
  const die = (code, why) => {
    try { abort(code, `A25-2 lockdown: ${why}`); } catch { /* exit below regardless */ }
    reallyExit(code);
  };
  // (0) Node version pin, before anything else.
  const versions = process.versions;
  if (process.version !== NODE_VERSION_PIN || !versions || versions.node !== apply(strSlice, NODE_VERSION_PIN, [1])) {
    die(EXIT_A25_IMPORT, `install: node ${String(process.version)} is not the pinned ${NODE_VERSION_PIN} (import() detection is version-bound)`);
  }
  const manifestOk = (url) => { try { return isManifestUrl(url) === true; } catch { return false; } };

  // (1) Module resolution: covers static import, import(), require, require.resolve, import.meta.resolve.
  registerHooks({
    resolve(specifier, context, nextResolve) {
      const r = nextResolve(specifier, context);
      const url = r && typeof r.url === 'string' ? r.url : '';
      const b = builtinId(url);
      if (b !== null && apply(setHas, FORBIDDEN, [b])) die(EXIT_A25_FORBIDDEN_MODULE, `module ${url} (specifier ${String(specifier)} from ${context && context.parentURL})`);
      if (b !== null && apply(setHas, ADDON, [b])) die(EXIT_A25_ADDON, `module ${url} can load native extensions`);
      if ((r && r.format === 'addon') || (starts(url, 'file:') && apply(strEndsWith, url.split(/[?#]/)[0], ['.node']))) die(EXIT_A25_ADDON, `native addon ${url}`);
      if (isDynamicImport(context) && !manifestOk(url)) die(EXIT_A25_IMPORT, `dynamic import() of non-manifest ${url} from ${context && context.parentURL}`);
      return r;
    },
  });

  // (2) Codegen: eval and every Function constructor binding. Each stub keeps .prototype, so instanceof still works.
  const codegenStub = (name, proto) => {
    const f = function () { die(EXIT_A25_CODEGEN, `${name} called after boot`); };
    if (proto) f.prototype = proto;
    defineProperty(f, 'name', { value: name });
    return f;
  };
  const AsyncFunction = (async function () {}).constructor;
  const GeneratorFunction = (function* () {}).constructor;
  const AsyncGeneratorFunction = (async function* () {}).constructor;
  const locks = [
    [globalThis, 'eval', codegenStub('eval')],
    [globalThis, 'Function', null],
  ];
  const FnStub = codegenStub('Function', Function.prototype);
  locks[1][2] = FnStub;
  locks.push([Function.prototype, 'constructor', FnStub]);
  locks.push([AsyncFunction.prototype, 'constructor', codegenStub('AsyncFunction', AsyncFunction.prototype)]);
  locks.push([GeneratorFunction.prototype, 'constructor', codegenStub('GeneratorFunction', GeneratorFunction.prototype)]);
  locks.push([AsyncGeneratorFunction.prototype, 'constructor', codegenStub('AsyncGeneratorFunction', AsyncGeneratorFunction.prototype)]);
  for (const [obj, key, value] of locks) {
    if (!lockProperty(obj, key, value)) die(EXIT_A25_CODEGEN, `install: could not lock ${key}`);
  }
  // CJS compile: node's own loader calls _compile; any other caller compiles arbitrary source.
  const origCompile = Module.prototype._compile;
  const compileGuard = function _compile(...args) {
    if (!calledFromNodeLoader()) die(EXIT_A25_CODEGEN, 'Module.prototype._compile called outside node\'s module loader');
    return apply(origCompile, this, args);
  };
  if (!lockProperty(Module.prototype, '_compile', compileGuard)) die(EXIT_A25_CODEGEN, 'install: could not lock Module.prototype._compile');
  // The contextify binding compiles and runs source without vm. process.binding is locked by the backstop's G-39
  // guard (non-configurable) and forwards 'contextify', so the binding object's code entry points are replaced.
  let ctx = null;
  try { ctx = process.binding('contextify'); } catch { ctx = null; }
  if (ctx && typeof ctx === 'object') {
    for (const k of ['ContextifyScript', 'compileFunction', 'makeContext']) {
      if (k in ctx && !lockProperty(ctx, k, codegenStub(`contextify.${k}`))) die(EXIT_A25_CODEGEN, `install: could not lock contextify.${k}`);
    }
  }
  if (canReplace(process, 'binding')) {
    const origBinding = process.binding;
    lockProperty(process, 'binding', function binding(name) {
      const n = String(name);
      if (n === 'contextify') die(EXIT_A25_CODEGEN, 'process.binding(\'contextify\')');
      if (n === 'spawn_sync' || n === 'process_wrap') die(EXIT_A25_FORBIDDEN_MODULE, `process.binding('${n}')`);
      return apply(origBinding, process, [name]);
    });
  }

  // (3) Built-ins reached without the resolver.
  if (canReplace(process, 'getBuiltinModule')) {
    const origGet = process.getBuiltinModule;
    const guardGet = function getBuiltinModule(id) {
      const b = builtinId(String(id));
      if (b !== null && apply(setHas, FORBIDDEN, [b])) die(EXIT_A25_FORBIDDEN_MODULE, `process.getBuiltinModule('${String(id)}')`);
      if (b !== null && apply(setHas, ADDON, [b])) die(EXIT_A25_ADDON, `process.getBuiltinModule('${String(id)}')`);
      return apply(origGet, process, [id]);
    };
    if (typeof origGet === 'function' && !lockProperty(process, 'getBuiltinModule', guardGet)) die(EXIT_A25_FORBIDDEN_MODULE, 'install: could not lock process.getBuiltinModule');
  }
  if (canReplace(process, 'execve') && typeof process.execve === 'function') lockProperty(process, 'execve', function execve() { die(EXIT_A25_FORBIDDEN_MODULE, 'process.execve'); });

  // (4) Native addons. Under the backstop, process.dlopen is already a non-configurable refusal (G-39, throws), made
  // an abort by (5); the resolver (.node / addon format) and Module._extensions['.node'] give 93 before it is reached.
  const addonStub = (name) => function () { die(EXIT_A25_ADDON, `${name} called after boot`); };
  if (canReplace(process, 'dlopen')) lockProperty(process, 'dlopen', addonStub('process.dlopen'));
  if (canReplace(process, '_linkedBinding')) lockProperty(process, '_linkedBinding', addonStub('process._linkedBinding'));
  if (!lockProperty(Module._extensions, '.node', addonStub('Module._extensions[.node]'))) die(EXIT_A25_ADDON, 'install: could not lock Module._extensions[.node]');

  // (5) The backstop's catchable refusals become aborts. console and console.error are locked so main-entry code can
  // not swap the console out to silence the refusal line and then catch the throw.
  const con = globalThis.console;
  const origError = con && con.error;
  if (typeof origError !== 'function') die(EXIT_A25_FORBIDDEN_MODULE, 'install: console.error is not a function');
  const errorGuard = function error(...args) {
    const m = args[0];
    if (typeof m === 'string') {
      for (const [prefix, code] of BACKSTOP_REFUSALS) if (starts(m, prefix)) die(code, `backstop refusal is an abort after boot: ${m}`);
    }
    return apply(origError, this, args);
  };
  if (!lockProperty(globalThis, 'console', con) || !lockProperty(con, 'error', errorGuard)) die(EXIT_A25_FORBIDDEN_MODULE, 'install: could not lock console.error');

  try { syncBuiltinESMExports(); } catch { /* namespaces already live */ }
}
