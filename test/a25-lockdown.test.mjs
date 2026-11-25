// A25-2 post-boot lockdown (tools/ci/a25-lockdown.mjs). Each case writes a small script to a temp dir and runs it in
// a child node: the script installs the lockdown (as the preload will after boot), then does one forbidden thing
// inside try/catch, and must die with that thing's exit code: 91 codegen, 92 vm/worker_threads/child_process (and
// cluster/inspector/repl), 93 native addon, 94 non-manifest dynamic import(). A script that survives prints SURVIVED.
// The abort() handed in is a stand-in for the backstop's helperAbort (stderr line + reallyExit). Runs bare
// (node --test test/a25-lockdown.test.mjs) and under the backstop preload (npm test adds it to every node child).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildManifest } from '../tools/ci/a25-manifest.mjs';
import { helperSpawnEnv } from '../verification/harness/stream-launcher.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const LOCKDOWN = join(ROOT, 'tools/ci/a25-lockdown.mjs');
const BACKSTOP = join(ROOT, 'tools/ci/entropy-backstop.mjs');
const DIR = mkdtempSync(join(tmpdir(), 'a25-lockdown-'));
process.on('exit', () => { try { rmSync(DIR, { recursive: true, force: true }); } catch { /* best effort */ } });
const url = (f) => pathToFileURL(join(DIR, f)).href;
// Fixture tree: a.mjs is in the manifest and statically imports b.mjs (not in the manifest) and node:fs;
// d.cjs is a manifest CJS file that calls import() of b.mjs; fake.node is a file with the addon extension.
writeFileSync(join(DIR, 'a.mjs'), "import './b.mjs';\nimport 'node:fs';\nexport const a = 1;\n");
writeFileSync(join(DIR, 'b.mjs'), 'export const b = 2;\n');
writeFileSync(join(DIR, 'c.cjs'), 'module.exports = 3;\n');
writeFileSync(join(DIR, 'd.cjs'), "module.exports = import('./b.mjs');\n");
writeFileSync(join(DIR, 'e.mjs'), "import 'node:child_process';\nexport const e = 5;\n");
writeFileSync(join(DIR, 'fake.node'), 'not an addon\n');
writeFileSync(join(DIR, 'f.cjs'), "module.exports = require('./c.cjs');\n");
const MANIFEST = [url('a.mjs'), url('d.cjs'), url('e.mjs'), url('f.cjs')];

let n = 0;
function run(body, { manifest = MANIFEST, isManifest = null, env = {}, preload = false, pre = '', refuse = 'stub' } = {}) {
  const f = join(DIR, `case-${++n}.mjs`);
  const pred = isManifest ?? `(u) => M.has(u)`;
  writeFileSync(f, [
    `import { installLockdown } from ${JSON.stringify(pathToFileURL(LOCKDOWN).href)};`,
    `import { writeSync } from 'node:fs';`,
    `import { createRequire } from 'node:module';`,
    `import Module from 'node:module';`,
    `const require = createRequire(import.meta.url);`,
    `const M = new Set(${JSON.stringify(manifest)});`,
    refuse === 'backstop'
      ? `import { registerRefuseHook as R } from ${JSON.stringify(pathToFileURL(BACKSTOP).href)};`
      : `const __refuseHooks = globalThis.__refuseHooks = []; const R = ${refuse === 'stub' ? '(fn) => { __refuseHooks.push(fn); }' : refuse};`,
    `globalThis.__refuseSite = (kind, detail) => { for (const h of globalThis.__refuseHooks || []) h(kind, detail); throw new Error('refused ' + kind); };`,
    pre,
    `installLockdown({ isManifestUrl: ${pred}, abort: (code, why) => { writeSync(2, 'ABORT ' + code + ' ' + why + '\\n'); process.reallyExit(code); }, registerRefuseHook: R });`,
    `try {`, body, `} catch (e) { writeSync(1, 'CAUGHT ' + (e && e.message) + '\\n'); }`,
    `writeSync(1, 'SURVIVED\\n');`,
  ].join('\n'));
  const args = preload ? ['--import', pathToFileURL(BACKSTOP).href, f] : [f];
  const r = spawnSync(process.execPath, args, { cwd: DIR, encoding: 'utf8', env: { ...process.env, ...env }, timeout: 30000 });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
function expectAbort(code, body, opts) {
  const r = run(body, opts);
  assert.equal(r.code, code, `expected exit ${code}, got ${r.code}\nstdout: ${r.out}\nstderr: ${r.err}`);
  assert.match(r.err, new RegExp(`ABORT ${code} A25-2 lockdown: `));
  assert.doesNotMatch(r.out, /SURVIVED/);
  return r;
}
function expectSurvive(body, opts) {
  const r = run(body, opts);
  assert.equal(r.code, 0, `expected exit 0, got ${r.code}\nstdout: ${r.out}\nstderr: ${r.err}`);
  assert.match(r.out, /SURVIVED/);
  assert.doesNotMatch(r.out, /CAUGHT/);
  return r;
}

const CODEGEN = {
  'direct eval': "eval('1');",
  'indirect eval': "(0, eval)('1');",
  'globalThis.eval': "globalThis['eval']('1');",
  'new Function': "new Function('return 1')();",
  'Function()': "Function('return 1')();",
  'Reflect.construct(Function)': "Reflect.construct(Function, ['return 1']);",
  'fn.constructor': "(() => 0).constructor('return 1')();",
  'class constructor chain': "(class {}).constructor('return 1');",
  'AsyncFunction': "(async () => {}).constructor('return 1');",
  'GeneratorFunction': "(function* () {}).constructor('yield 1');",
  'AsyncGeneratorFunction': "(async function* () {}).constructor('yield 1');",
  'Module.prototype._compile': "new Module('x')._compile('module.exports = 1', '/tmp/x.js');",
  'contextify.compileFunction': "process.binding('contextify').compileFunction('return 1');",
  'contextify.ContextifyScript': "new (process.binding('contextify').ContextifyScript)('1');",
};
const FORBIDDEN = {
  "import('node:vm')": "await import('node:vm');",
  "import('vm')": "await import('vm');",
  "import('worker_threads')": "await import('worker_threads');",
  "import('node:child_process')": "await import('node:child_process');",
  "require('vm')": "require('vm');",
  "require('node:worker_threads')": "require('node:worker_threads');",
  "require('child_process')": "require('child_process');",
  "require.resolve('child_process')": "require.resolve('child_process');",
  "createRequire()('vm')": "Module.createRequire(import.meta.url)('vm');",
  "Module._load('child_process')": "Module._load('child_process');",
  "getBuiltinModule('child_process')": "process.getBuiltinModule('child_process');",
  "getBuiltinModule('node:vm')": "process.getBuiltinModule('node:vm');",
  "getBuiltinModule('worker_threads')": "process.getBuiltinModule('worker_threads');",
  "require('cluster')": "require('cluster');",
  "require('inspector')": "require('inspector');",
  "import('node:inspector/promises')": "await import('node:inspector/promises');",
  "require('repl')": "require('repl');",
  'static import inside a manifest module': `await import(${JSON.stringify(url('e.mjs'))});`,
};
const ADDONS = {
  'require(.node)': `require(${JSON.stringify(join(DIR, 'fake.node'))});`,
  "Module._extensions['.node']": `Module._extensions['.node']({ exports: {} }, ${JSON.stringify(join(DIR, 'fake.node'))});`,
  "require('node:sqlite')": "require('node:sqlite');",
  "getBuiltinModule('node:sqlite')": "process.getBuiltinModule('node:sqlite');",
};
const IMPORTS = {
  'non-manifest file': `await import(${JSON.stringify(url('b.mjs'))});`,
  'non-manifest file, relative': "await import('./b.mjs');",
  'data: URL': "await import('data:text/javascript,export default 1');",
  'non-manifest builtin (policy: builtins are asked too)': "await import('node:fs');",
  'import() from a manifest CJS module': "await require('./d.cjs');",
  'import() of a manifest URL with a query string': `await import(${JSON.stringify(url('a.mjs') + '?x=1')});`,
};

for (const [name, body] of Object.entries(CODEGEN)) test(`A25-2 codegen -> 91: ${name}`, () => { expectAbort(91, body); });
for (const [name, body] of Object.entries(FORBIDDEN)) test(`A25-2 forbidden module -> 92: ${name}`, () => { expectAbort(92, body); });
// Direct process.dlopen / binding('spawn_sync'|'process_wrap') / execve, bare: the lockdown's own stubs abort.
const DIRECT = {
  'process.dlopen': [93, `process.dlopen({ exports: {} }, ${JSON.stringify(join(DIR, 'fake.node'))});`],
  "process.binding('spawn_sync')": [92, "process.binding('spawn_sync');"],
  "process.binding('process_wrap')": [92, "process.binding('process_wrap');"],
  'process.execve': [92, "process.execve(process.execPath, [process.execPath, '-e', '0']);"],
};
test('A25-2 direct native/spawn entry points abort, not throw (bare)', () => {
  for (const [code, body] of Object.values(DIRECT)) expectAbort(code, body);
});
// Addendum B refuse hook, with a stub registerRefuseHook: __refuseSite(kind, detail) plays a backstop refusal site
// (call the registered hook, then throw the catchable refusal). The hook must exit before the throw.
test('A25-2 refuse hook (stub): dlopen -> 93, spawn -> 92, unknown kind -> 92, never catchable', () => {
  assert.match(expectAbort(93, "__refuseSite('dlopen', 'process.dlopen');").err, /backstop refused process\.dlopen/);
  for (const d of ['spawn_sync', 'process_wrap', 'execve']) assert.match(expectAbort(92, `__refuseSite('spawn', '${d}');`).err, new RegExp(`spawn entry point after boot [(]${d}[)]`));
  expectAbort(92, "__refuseSite('other', 'x');");
  expectAbort(93, "__refuseSite('dlopen', { toString() { throw new Error('x'); } });");
  expectSurvive("if (__refuseHooks.length !== 1) throw new Error('hook not registered exactly once');");
});
test('A25-2 refuse hook: install aborts 92 when registerRefuseHook is missing, not a function, or throws', () => {
  assert.match(expectAbort(92, "eval('1');", { refuse: 'undefined' }).err, /registerRefuseHook missing/);
  assert.match(expectAbort(92, "eval('1');", { refuse: '42' }).err, /registerRefuseHook missing/);
  expectAbort(92, "eval('1');", { refuse: "() => { throw new Error('already registered'); }" });
});
const BACKSTOP_HAS_HOOK = /^export function registerRefuseHook\(/m.test(readFileSync(BACKSTOP, 'utf8'));
// Normal mode only: in helper mode the backstop refuses being imported by user code (87), so there the preload itself
// passes its registerRefuseHook to installLockdown; that wiring is Backend's integration test.
test('A25-2 real backstop refusal sites abort through the hook (normal mode)', { skip: BACKSTOP_HAS_HOOK ? false : 'waits on Backend: entropy-backstop.mjs registerRefuseHook (Addendum B)' }, () => {
  for (const [code, body] of Object.values(DIRECT)) expectAbort(code, body, { preload: true, refuse: 'backstop' });
});
test('A25-2 node version pin: install aborts 95 (NODE_VERSION, Addendum D) unless node is v24.22.1', () => {
  // The pin fires first at install, before any hook or lock exists, with its own code (not 94 IMPORT).
  for (const pre of ["Object.defineProperty(process, 'version', { value: 'v24.22.2' });", "Object.defineProperty(process.versions, 'node', { value: '25.0.0' });", "Object.defineProperty(process, 'versions', { value: undefined });"]) {
    assert.match(expectAbort(95, "eval('1');", { pre }).err, /ABORT 95 A25-2 lockdown: install: node .* is not the pinned v24\.22\.1/);
  }
  expectSurvive("if (process.version !== 'v24.22.1') throw new Error('pin');");
});
for (const [name, body] of Object.entries(ADDONS)) test(`A25-2 addon -> 93: ${name}`, () => { expectAbort(93, body); });
for (const [name, body] of Object.entries(IMPORTS)) test(`A25-2 dynamic import -> 94: ${name}`, () => { expectAbort(94, body); });
test('A25-2 dynamic import -> 94: isManifestUrl throwing is a rejection (fail closed)', () => {
  expectAbort(94, `await import(${JSON.stringify(url('a.mjs'))});`, { isManifest: "() => { throw new Error('boom'); }" });
});
test('A25-2 dynamic import -> 94: isManifestUrl must return exactly true', () => {
  expectAbort(94, `await import(${JSON.stringify(url('a.mjs'))});`, { isManifest: '() => 1' });
});

test('A25-2 dynamic import -> 94: an unreadable stack (stackTraceLimit or prepareStackTrace locked) fails closed', () => {
  expectAbort(94, "Object.defineProperty(Error, 'stackTraceLimit', { value: 10, writable: false }); await import('./b.mjs');");
  expectAbort(94, "Object.defineProperty(Error, 'prepareStackTrace', { get() { return undefined; } }); await import('./b.mjs');");
});
test('A25-2 allowed: a require() run by a manifest CJS module reached through import() is not import()', () => {
  expectSurvive(`const m = await import(${JSON.stringify(url('f.cjs'))}); if (m.default !== 3) throw new Error('bad');`);
});
test('A25-2 allowed: manifest import() whose static deps are outside the manifest is left to the load hook (89/90)', () => {
  expectSurvive(`const m = await import(${JSON.stringify(url('a.mjs'))}); if (m.a !== 1) throw new Error('bad'); await import(${JSON.stringify(url('a.mjs'))});`);
});
test('A25-2 allowed: require is not import(), and node\'s CJS loader may still compile', () => {
  expectSurvive("if (require('./c.cjs') !== 3) throw new Error('bad'); require('node:path'); require('node:fs');");
});
test('A25-2 allowed: normal code keeps working (instanceof, async, generators, stacks, JSON)', () => {
  expectSurvive([
    'const f = function () {}; if (!(f instanceof Function) || !(async () => {}) instanceof Function) throw new Error("instanceof");',
    'if (f.constructor !== Function || Function.prototype !== Object.getPrototypeOf(f)) throw new Error("ctor");',
    'await (async () => 1)(); [...(function* () { yield 1; })()]; for await (const _ of (async function* () { yield 1; })()) {}',
    'if (!/at /.test(new Error("x").stack)) throw new Error("stack");',
    'JSON.parse(JSON.stringify({ a: 1 })); setTimeout(() => {}, 0); queueMicrotask(() => {});',
  ].join('\n'));
});
test('A25-2 aborts are not catchable and ignore a returning abort()', () => {
  // abort() that returns: the lockdown exits with the code itself.
  const r = run("eval('1');", { isManifest: '() => true' });
  assert.equal(r.code, 91);
  const f = join(DIR, 'ret.mjs');
  writeFileSync(f, `import { installLockdown } from ${JSON.stringify(pathToFileURL(LOCKDOWN).href)};\ninstallLockdown({ isManifestUrl: () => true, abort: () => {}, registerRefuseHook: () => {} });\ntry { new Function('1'); } catch {}\nconsole.log('SURVIVED');\n`);
  const s = spawnSync(process.execPath, [f], { cwd: DIR, encoding: 'utf8' });
  assert.equal(s.status, 91, s.stdout + s.stderr);
  assert.doesNotMatch(s.stdout, /SURVIVED/);
});
test('A25-2 install: one call only, a second call throws and weakens nothing; bad arguments throw', () => {
  const r = run("let t = 0; try { installLockdown({ isManifestUrl: () => true, abort: () => {} }); } catch { t = 1; } if (t !== 1) throw new Error('second install accepted'); eval('1');");
  assert.equal(r.code, 91, r.out + r.err);
  const f = join(DIR, 'args.mjs');
  writeFileSync(f, `import { installLockdown } from ${JSON.stringify(pathToFileURL(LOCKDOWN).href)};\nfor (const a of [undefined, {}, { isManifestUrl: () => true }, { abort: () => {} }]) { let ok = false; try { installLockdown(a); } catch (e) { ok = e instanceof TypeError; } if (!ok) process.exit(1); }\nconsole.log('OK');\n`);
  const s = spawnSync(process.execPath, [f], { cwd: DIR, encoding: 'utf8' });
  assert.equal(s.status, 0, s.stdout + s.stderr);
});
test('A25-2 under the backstop preload (normal mode): every class still aborts with its own code', () => {
  expectAbort(91, "eval('1');", { preload: true });
  expectAbort(91, "process.binding('contextify').compileFunction('return 1');", { preload: true });
  expectAbort(92, "require('child_process');", { preload: true });
  expectAbort(93, `require(${JSON.stringify(join(DIR, 'fake.node'))});`, { preload: true });
  // process.dlopen is the backstop's non-configurable refusal here (an abort once Backend wires the refuse hook).
  // The lockdown's own _extensions['.node'] stub must fire first (its reason names it), not the dlopen layer behind it.
  assert.match(expectAbort(93, `Module._extensions['.node']({ exports: {} }, ${JSON.stringify(join(DIR, 'fake.node'))});`, { preload: true }).err, /Module\._extensions\[\.node\] called after boot/);
  expectAbort(94, "await import('./b.mjs');", { preload: true });
  expectSurvive(`await import(${JSON.stringify(url('a.mjs'))}); require('./c.cjs');`, { preload: true });
});
// Helper mode (ENTROPY_BACKSTOP_HELPER=a25): the preload itself installs the lockdown last (Backend's wiring), with
// isManifestUrl from the manifest bound through the grant, so the case script does NOT call installLockdown and the
// abort is the backstop's helperAbort. The env comes from the launcher's one builder (helperSpawnEnv) and the manifest
// from buildManifest, rooted at '/' (the case files live in a temp dir outside the tree), listing the case file, the
// manifest fixtures (a.mjs, its static import b.mjs, c.cjs, fake.node) and every file under src/, tools/ci/ and
// verification/harness/. g.mjs is outside the manifest (the 94 target); a static import of it would be 89, not ours.
const HELPER_TOKEN = 'grant-1@1#a25-lockdown';
function listUnder(abs) {
  const out = [];
  for (const e of readdirSync(abs, { withFileTypes: true })) { const p = join(abs, e.name); if (e.isDirectory()) out.push(...listUnder(p)); else out.push(p); }
  return out;
}
writeFileSync(join(DIR, 'g.mjs'), 'export const g = 7;\n');
function runHelper(body) {
  const f = join(DIR, `helper-${++n}.mjs`);
  writeFileSync(f, [
    `import { writeSync } from 'node:fs';`,
    `import { createRequire } from 'node:module';`,
    `const require = createRequire(import.meta.url);`,
    `try {`, body, `} catch (e) { writeSync(1, 'CAUGHT ' + (e && e.message) + '\\n'); }`,
    `writeSync(1, 'SURVIVED\\n');`,
  ].join('\n'));
  const files = [f, ...['a.mjs', 'b.mjs', 'c.cjs', 'fake.node'].map((x) => join(DIR, x))];
  for (const d of ['src', 'tools/ci', 'verification/harness']) files.push(...listUnder(join(ROOT, d)));
  const { bytes, sha256 } = buildManifest('/', files.map((x) => x.slice(1)));
  const manifestPath = join(DIR, `helper-${n}.manifest.json`);
  writeFileSync(manifestPath, bytes);
  const env = helperSpawnEnv(process.env, { token: HELPER_TOKEN, manifestPath, manifestSha256: sha256 });
  const r = spawnSync(process.execPath, ['--import', BACKSTOP, f], { cwd: DIR, encoding: 'utf8', env, timeout: 30000 });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
function expectHelperAbort(code, body, reason) {
  const r = runHelper(body);
  assert.equal(r.code, code, `expected exit ${code}, got ${r.code}\nstdout: ${r.out}\nstderr: ${r.err}`);
  assert.match(r.err, reason);
  assert.doesNotMatch(r.out, /SURVIVED/);
}
test('A25-2 under the backstop preload in helper mode (ENTROPY_BACKSTOP_HELPER=a25, grant-bound manifest): codes unchanged, manifest import allowed', () => {
  expectHelperAbort(91, "new Function('return 1');", /A25-2 lockdown: /);
  expectHelperAbort(91, "eval('1');", /A25-2 lockdown: /);
  expectHelperAbort(92, "await import('node:vm');", /A25-2 lockdown: /);
  expectHelperAbort(93, `require(${JSON.stringify(join(DIR, 'fake.node'))});`, /A25-2 lockdown: /);
  expectHelperAbort(94, "await import('./g.mjs');", /A25-2 lockdown: /);
  const r = runHelper(`await import(${JSON.stringify(url('a.mjs'))}); require('./c.cjs');`);
  assert.equal(r.code, 0, `expected exit 0, got ${r.code}\nstdout: ${r.out}\nstderr: ${r.err}`);
  assert.match(r.out, /SURVIVED/);
  assert.doesNotMatch(r.out, /CAUGHT/);
});
test('A25-2 source rules: no import from the backstop, no node:crypto, no wrapped CSPRNG entry point', () => {
  const src = readFileSync(LOCKDOWN, 'utf8');
  const code = src.replace(/^\s*\/\/.*$/gm, '');
  assert.deepEqual([...code.matchAll(/^import .* from '([^']+)';$/gm)].map((m) => m[1]), ['node:module']);
  // No backstop import and no dependency on its strings (Addendum B: no abort keyed on log text, no console guard).
  assert.doesNotMatch(code, /entropy-backstop|console|node:crypto|['"]crypto['"]|randomBytes|randomFill|randomInt|randomUUID|getRandomValues|webcrypto|subtle|generateKey|generatePrime/);
  assert.match(code, /^export function installLockdown\(\{ isManifestUrl, abort, registerRefuseHook \} = \{\}\)/m);
  for (const [k, v] of [['EXIT_A25_CODEGEN', 91], ['EXIT_A25_FORBIDDEN_MODULE', 92], ['EXIT_A25_ADDON', 93], ['EXIT_A25_IMPORT', 94], ['EXIT_A25_NODE_VERSION', 95]]) assert.match(code, new RegExp(`^export const ${k} = ${v};$`, 'm'));
});
