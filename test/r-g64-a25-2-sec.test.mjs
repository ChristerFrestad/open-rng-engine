// R-A25-2-SEC (CTO ruling on Security review SEC-REVIEW-7f8908e): Security's probes p1-p7 as repo tests, plus one
// behavioural test per ruling item (1-5, 7) on its exact exit code. Each case runs a tiny tree under a temp root,
// under the real preload in helper mode with a grant-bound manifest (as in r-g64-a25-2-wiring.test.mjs), unless
// it says normal mode. Files under `extra` sit OUTSIDE the tree (not in the manifest). Single-process, light.
// No case may print "pwn": every probe's payload writes that word, so stdout === '' (or the exact control line) is
// the proof the payload never ran.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildManifest } from '../tools/ci/a25-manifest.mjs';
import { helperSpawnEnv } from '../verification/harness/stream-launcher.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url)).replace(/\/$/, '');
const PRELOAD = join(ROOT, 'tools/ci/entropy-backstop.mjs');
const LOCKDOWN = join(ROOT, 'tools/ci/a25-lockdown.mjs');
const HR = 'verification/harness/evidence-helper.mjs';
const OUT = 'process.stdout.write("survived\\n");\n';
const baseEnv = () => { const e = { ...process.env }; delete e.NODE_OPTIONS; for (const k of Object.keys(e)) if (k.startsWith('ENTROPY_BACKSTOP') || k.startsWith('NODE_TEST')) delete e[k]; return e; };

// files: { relpath: source } in the tree; extra: { name: source } beside the tree (outside the manifest).
// Returns status/stdout/stderr and `dir` facts read before cleanup (marker: the content of extra file 'marker', if written).
function run(files, main, { listed = Object.keys(files), extra = {}, preImport = null, normal = false } = {}) {
  const d = mkdtempSync(join(tmpdir(), 'a25sec-'));
  try {
    const root = join(d, 'tree');
    for (const [rel, src] of Object.entries(files)) { mkdirSync(dirname(join(root, rel)), { recursive: true }); writeFileSync(join(root, rel), src.replaceAll('@MARK@', JSON.stringify(join(d, 'marker')))); }
    for (const [p, src] of Object.entries(extra)) writeFileSync(join(d, p), src.replaceAll('@MARK@', JSON.stringify(join(d, 'marker'))));
    const { bytes, sha256 } = buildManifest(root, listed);
    const manifestPath = join(d, 'manifest.json');
    writeFileSync(manifestPath, bytes);
    const env = normal ? baseEnv() : helperSpawnEnv(baseEnv(), { token: 'grant-9@9#sec', manifestPath, manifestSha256: sha256 });
    const pre = preImport ? (() => { const f = join(d, 'pre-hooks.mjs'); writeFileSync(f, preImport); return ['--import', f]; })() : [];
    const r = spawnSync(process.execPath, [...pre, '--import', PRELOAD, join(root, main)], { cwd: root, env, encoding: 'utf8', timeout: 30000 });
    const marker = existsSync(join(d, 'marker')) ? readFileSync(join(d, 'marker'), 'utf8') : null;
    return { status: r.status, stdout: r.stdout, stderr: r.stderr, marker };
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const expect = (r, code, re = null) => {
  assert.equal(r.status, code, `exit ${r.status}, stdout ${JSON.stringify(r.stdout)}, stderr ${r.stderr}`);
  assert.doesNotMatch(r.stdout, /pwn/); assert.equal(r.marker, null, `payload ran: ${r.marker}`);
  if (code !== 0) assert.equal(r.stdout, '');
  if (re) assert.match(r.stderr, re);
};
const helperMain = (body, more = {}) => ({ [HR]: `import * as M from 'node:module';\n${body}`, ...more });
const swapHook = (b, fmt = 'module') => `M.registerHooks({ load: (u, c, n) => (u === ${JSON.stringify(b)} ? { format: '${fmt}', source: 'process.stdout.write("pwn-builtin-swap\\\\n");${fmt === 'module' ? ' export default 1;' : ''}', shortCircuit: true } : n(u, c)) });\n`;

// ---- item 1: late hooks (SEC-A25-4, SEC-A25-5, SEC-A25-7) ----
test('SEC p1/p1b/p2 (item 1): a late load hook swapping a builtin\'s source (node:os module/commonjs, zlib, dns, querystring) exits 94 at registerHooks', () => {
  for (const [b, fmt] of [['node:os', 'module'], ['node:os', 'commonjs'], ['node:zlib', 'module'], ['node:dns', 'module'], ['node:querystring', 'module']]) {
    expect(run(helperMain(`${swapHook(b, fmt)}await import('./x.mjs');\n${OUT}`, { 'verification/harness/x.mjs': `import ${JSON.stringify(b)};\n` }), HR), 94, /module\.registerHooks after the preload/);
  }
});
test('SEC p10 (item 1): a late .cjs load with no source plus a patched fs.readFileSync exits 94 at registerHooks; p10b without a late hook exits 90', () => {
  const late = run(helperMain(`import fs from 'node:fs';\nconst o = fs.readFileSync;\nfs.readFileSync = function (p, ...a) { if (String(p).endsWith('/y.cjs')) return 'process.stdout.write("pwn-toctou-cjs\\\\n")'; return o.call(this, p, ...a); };\nM.registerHooks({ load: (u, c, n) => (u.endsWith('/y.cjs') ? { format: 'commonjs', shortCircuit: true } : n(u, c)) });\nawait import('./y.cjs');\n${OUT}`, { 'verification/harness/y.cjs': 'module.exports = 1;\n' }), HR);
  expect(late, 94, /registerHooks after the preload/);
  const ctl = run({ 'm.mjs': `import fs from 'node:fs';\nimport { createRequire } from 'node:module';\nconst o = fs.readFileSync;\nfs.readFileSync = function (p, ...a) { if (String(p).endsWith('/y.cjs')) return 'process.stdout.write("pwn-fspatch\\\\n")'; return o.call(this, p, ...a); };\ncreateRequire(import.meta.url)('./y.cjs');\n${OUT}`, 'y.cjs': 'module.exports = 1;\n' }, 'm.mjs');
  expect(ctl, 90);
});
test('SEC s2 (item 1): a late resolve hook to a data: URL exits 94 at registerHooks', () => {
  expect(run(helperMain(`M.registerHooks({ resolve: (s, c, n) => (s === 'v:x' ? { url: 'data:text/javascript,process.stdout.write("pwn")', shortCircuit: true } : n(s, c)) });\nawait import('v:x');\n${OUT}`), HR), 94);
});
test('SEC item 1, normal mode: registerHooks and register after the preload exit 94 with no helper mode at all', () => {
  expect(run({ 'm.mjs': `import * as M from 'node:module';\nM.registerHooks({ load: (u, c, n) => n(u, c) });\n${OUT}` }, 'm.mjs', { normal: true }), 94, /module\.registerHooks after the preload/);
  expect(run({ 'm.mjs': `import * as M from 'node:module';\nM.register('data:text/javascript,');\n${OUT}` }, 'm.mjs', { normal: true }), 94, /module\.register after the preload/);
  expect(run({ 'm.cjs': `require('node:module').registerHooks({});\n${OUT}` }, 'm.cjs', { normal: true }), 94);
});
test('SEC item 1 (D22-4 moved into the preload): helper.loaded() lists the src/ files the helper main loaded, with manifest digests; other mains get []', () => {
  const body = `import { v } from '../../src/a.ts';\nconst A = globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')].helper;\nprocess.stdout.write(JSON.stringify(A.loaded()) + ' ' + v + '\\n');\n`;
  const files = { [HR]: body, 'src/a.ts': 'export const v: number = 7;\n' };
  const r = run(files, HR);
  expect(r, 0);
  const sha = createHash('sha256').update(files['src/a.ts']).digest('hex');
  assert.equal(r.stdout, `${JSON.stringify([['src/a.ts', sha]])} 7\n`, 'LOADED-HELPER: the helper main must see its src/ load list');
  const other = run({ 'm.mjs': body.replace('../../src/a.ts', './src/a.ts'), 'src/a.ts': files['src/a.ts'] }, 'm.mjs');
  expect(other, 0); assert.equal(other.stdout, '[] 7\n', 'LOADED-OTHER: a non-helper main must get []');
});

// ---- item 2: bindings (SEC-A25-1 inspector, SEC-A25-2 contextify, SEC-A25-9 allowlist) ----
test('SEC p5/p5b (item 2): process.binding(\'contextify\') exits 92, so compileFunctionForCJSLoader is unreachable', () => {
  expect(run({ 'm.mjs': `let k; try { k = Object.keys(process.binding('contextify')).join(','); } catch (e) { k = 'threw ' + e.message; }\nprocess.stdout.write('ctx ' + k + '\\n');\n` }, 'm.mjs'), 92, /process\.binding\('contextify'\) refused in helper mode/);
  expect(run({ 'm.mjs': `const c = process.binding('contextify');\nconst r = c.compileFunctionForCJSLoader('process.stdout.write("pwn-contextify\\\\n")', 'x.js', false, false);\nr.function && r.function();\n${OUT}` }, 'm.mjs'), 92);
});
test('SEC p7/p7b (item 2): process.binding(\'inspector\') exits 92, so no Connection / Runtime.evaluate', () => {
  expect(run({ 'm.mjs': `const i = process.binding('inspector');\nconst c = new i.Connection(() => {});\nc.dispatch(JSON.stringify({ id: 1, method: 'Runtime.evaluate', params: { expression: 'process.stdout.write("pwn-inspector\\\\n")' } }));\n${OUT}` }, 'm.mjs'), 92, /process\.binding\('inspector'\) refused in helper mode/);
});
test('SEC p8/p8b (item 2): the helper-mode allowlist is empty: every binding name Security found reachable exits 92', () => {
  for (const n of ['buffer', 'cares_wrap', 'config', 'constants', 'contextify', 'fs', 'fs_event_wrap', 'icu', 'inspector', 'natives', 'os', 'tls_wrap', 'util', 'uv', 'zlib', 'spawn_sync', 'process_wrap', 'worker']) {
    expect(run({ 'm.mjs': `process.binding(${JSON.stringify(n)});\nprocess.stdout.write('pwn-binding ${n}\\n');\n` }, 'm.mjs'), 92, new RegExp(`process\\.binding\\('${n}'\\)`));
  }
});
test('SEC item 2 (one guard): the lockdown aborts 92 at install when process.binding is non-configurable but not the backstop guard', (t) => {
  if (globalThis[Symbol.for('open-rng-engine/entropy-backstop/v1')]) { t.skip('needs a child without the backstop preload; run this file bare (node --test)'); return; }
  const d = mkdtempSync(join(tmpdir(), 'a25sec-ld-'));
  try {
    const f = join(d, 'm.mjs');
    writeFileSync(f, `Object.defineProperty(process, 'binding', { value: function binding() { return {}; }, writable: false, configurable: false });\nconst { installLockdown } = await import(${JSON.stringify(pathToFileURL(LOCKDOWN).href)});\ninstallLockdown({ isManifestUrl: () => true, abort: (c, w) => { process.stderr.write(String(w) + '\\n'); }, registerRefuseHook: () => {} });\n${OUT}`);
    const r = spawnSync(process.execPath, [f], { cwd: d, env: baseEnv(), encoding: 'utf8', timeout: 30000 });
    assert.equal(r.status, 92, r.stderr); assert.equal(r.stdout, ''); assert.match(r.stderr, /not the backstop G-39 guard/);
  } finally { rmSync(d, { recursive: true, force: true }); }
});

// ---- item 3: inspector entry points and node:test (SEC-A25-1, SEC-A25-3) ----
test('SEC L-SEC-2 (found closing item 3): SIGUSR1 in helper mode exits 92 instead of starting the inspector', () => {
  expect(run({ 'm.mjs': `process.kill(process.pid, 'SIGUSR1');\nsetTimeout(() => process.stdout.write('pwn-inspector ' + (globalThis.process.getBuiltinModule ? 'up' : '') + '\\n'), 500);\n` }, 'm.mjs'), 92, /SIGUSR1 \(inspector activation\)/);
});
test('SEC p9/p9b (item 3): process._debugProcess and process._debugEnd exit 92 (no ws inspector)', () => {
  expect(run({ 'm.mjs': `process.debugPort = 0; process._debugProcess(process.pid);\nawait new Promise((s) => setTimeout(s, 300));\nprocess.stdout.write('pwn-debug\\n');\n` }, 'm.mjs'), 92, /process\._debugProcess refused in helper mode/);
  expect(run({ 'm.mjs': `process._debugEnd();\nprocess.stdout.write('pwn-debugend\\n');\n` }, 'm.mjs'), 92, /process\._debugEnd refused in helper mode/);
});
test('SEC p6/p6b/p6c/p6d (item 3): node:test run() with process isolation (also with env and execArgv) exits 92 and its child never runs', () => {
  const evil = { 'evil.test.mjs': `import { writeFileSync } from 'node:fs'; writeFileSync(@MARK@, 'child ran ' + process.pid);\n` };
  for (const opts of ["{ files: [process.cwd() + '/../evil.test.mjs'], isolation: 'process' }", "{ files: [process.cwd() + '/../evil.test.mjs'], isolation: 'process', env: { PATH: process.env.PATH }, execArgv: [] }"]) {
    expect(run({ 'm.mjs': `import { run } from 'node:test';\nconst s = run(${opts});\nfor await (const _ of s) {}\n${OUT}` }, 'm.mjs', { extra: evil }), 92);
  }
});
test('SEC item 3: node:test is a forbidden builtin: process.getBuiltinModule(\'node:test\') and import \'node:test/reporters\' exit 92', () => {
  expect(run({ 'm.mjs': `const t = process.getBuiltinModule('node:test');\nprocess.stdout.write('pwn-gbm ' + typeof t + '\\n');\n` }, 'm.mjs'), 92, /getBuiltinModule\('node:test'\)/);
  expect(run({ 'm.mjs': `import 'node:test/reporters';\nprocess.stdout.write('pwn-reporters\\n');\n` }, 'm.mjs'), 92);
});
test('SEC item 3: in helper mode every child_process export dies 92 before spawning, for any holder of the exports object', () => {
  // The public path stops at resolve (92). The backstop-level refusal (child_process exports die 92 before spawning)
  // is what holds when a builtin such as node:test obtains the exports internally: mutant M60 removes node:test
  // from the forbidden list together with that refusal, and the node:test run() case above must then fail.
  expect(run({ 'm.cjs': `require('node:child_process').spawnSync(process.execPath, ['-e', 'process.stdout.write("pwn-child")'], { stdio: 'inherit' });\n${OUT}` }, 'm.cjs'), 92);
});

// ---- item 4: node: load results ----
test('SEC item 4: a node: load result carrying a source, or a format other than builtin, exits 89 (hook below ours)', () => {
  const pre = (ret) => `import { registerHooks } from 'node:module';\nregisterHooks({ load: (u, c, n) => (u === 'node:zlib' ? ${ret} : n(u, c)) });\n`;
  expect(run({ 'm.mjs': `import 'node:zlib';\n${OUT}` }, 'm.mjs', { preImport: pre(`{ format: 'module', source: 'process.stdout.write("pwn-swap\\\\n"); export default 1;', shortCircuit: true }`) }), 89, /load: node:zlib came back as module with a source/);
  expect(run({ 'm.mjs': `import 'node:zlib';\n${OUT}` }, 'm.mjs', { preImport: pre(`{ format: 'builtin', source: 'x', shortCircuit: true }`) }), 89, /with a source/);
  expect(run({ 'm.mjs': `import 'node:zlib';\n${OUT}` }, 'm.mjs', { preImport: pre(`{ format: 'commonjs', shortCircuit: true }`) }), 89, /came back as commonjs/);
  const ok = run({ 'm.mjs': `import 'node:zlib';\n${OUT}` }, 'm.mjs', { preImport: pre('n(u, c)') });
  expect(ok, 0); assert.equal(ok.stdout, 'survived\n');
});

// ---- item 5: WebAssembly (SEC-A25-6) ----
test('SEC p4 (item 5): WebAssembly.compile, instantiate, Module, compileStreaming and instantiateStreaming exit 91', () => {
  const wasm = 'new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,127,3,2,1,0,7,5,1,1,102,0,0,10,6,1,4,0,65,42,11])';
  const calls = {
    instantiate: `const { instance } = await WebAssembly.instantiate(${wasm}); process.stdout.write('pwn-wasm ' + instance.exports.f() + '\\n');`,
    compile: `await WebAssembly.compile(${wasm}); process.stdout.write('pwn-wasm\\n');`,
    Module: `new WebAssembly.Module(${wasm}); process.stdout.write('pwn-wasm\\n');`,
    compileStreaming: `await WebAssembly.compileStreaming(new Response(${wasm}, { headers: { 'content-type': 'application/wasm' } })); process.stdout.write('pwn-wasm\\n');`,
    instantiateStreaming: `await WebAssembly.instantiateStreaming(new Response(${wasm}, { headers: { 'content-type': 'application/wasm' } })); process.stdout.write('pwn-wasm\\n');`,
  };
  for (const [k, body] of Object.entries(calls)) expect(run({ 'm.mjs': body + '\n' }, 'm.mjs'), 91, new RegExp(`WebAssembly\\.${k} called in helper mode`));
});
test('SEC item 5: TypeScript src still loads after the WebAssembly lock (node\'s stripper is primed before it)', () => {
  const r = run({ 'm.mjs': `import { v } from './src/a.ts';\nprocess.stdout.write('ok ' + v + '\\n');\n`, 'src/a.ts': 'export const v: number = 3;\n' }, 'm.mjs');
  expect(r, 0); assert.equal(r.stdout, 'ok 3\n'); assert.equal(r.stderr, '');
});

// ---- item 7 (SEC-A25-8): env ----
test('SEC p11 (item 7): no ENTROPY_BACKSTOP_* variable is left in process.env in helper mode; /proc/self/environ is the named residual', () => {
  const r = run({ 'm.mjs': `import { readFileSync } from 'node:fs';\nconst live = Object.keys(process.env).filter((k) => k.startsWith('ENTROPY_BACKSTOP'));\nconst environ = readFileSync('/proc/self/environ', 'utf8').split('\\0').filter((x) => x.startsWith('ENTROPY_BACKSTOP')).map((x) => x.split('=')[0]).sort();\nprocess.stdout.write(JSON.stringify({ live, environ }) + '\\n');\n` }, 'm.mjs');
  expect(r, 0);
  const o = JSON.parse(r.stdout);
  assert.deepEqual(o.live, [], 'ENV-LIVE: grant, locator and helper env vars must be gone from process.env');
  assert.deepEqual(o.environ, ['ENTROPY_BACKSTOP_GRANT', 'ENTROPY_BACKSTOP_HELPER', 'ENTROPY_BACKSTOP_MANIFEST'], 'residual L-SEC-1: exec-time environ (named in design v1.5)');
});

// ---- holding (Security: holds at 7f8908e) ----
test('SEC p2/p3 holding: Module._extensions[\'.js\'] and Module.prototype.load on a file outside the manifest exit 89', () => {
  const evil = { 'evil.cjs': 'process.stdout.write("pwn-ext\\n");' };
  expect(run({ 'm.mjs': `import { createRequire } from 'node:module';\nconst Module = createRequire(import.meta.url)('node:module');\nconst f = process.cwd() + '/../evil.cjs';\nconst m = new Module(f); m.filename = f; m.paths = [];\nModule._extensions['.js'](m, f);\n${OUT}` }, 'm.mjs', { extra: evil }), 89);
  expect(run({ 'm.mjs': `import { createRequire } from 'node:module';\nconst Module = createRequire(import.meta.url)('node:module');\nconst f = process.cwd() + '/../evil.cjs';\nnew Module(f).load(f);\n${OUT}` }, 'm.mjs', { extra: evil }), 89);
});
test('SEC p7 s1/s3/s4 holding: static data: exits 89; require(data:) throws without running; a manifest file with a query loads once', () => {
  expect(run({ 'm.mjs': `import 'data:text/javascript,process.stdout.write("pwn-data\\\\n")';\n${OUT}` }, 'm.mjs'), 89);
  const s3 = run({ 'm.cjs': `try { require('data:text/javascript,process.stdout.write("pwn")'); } catch (e) { process.stdout.write('threw\\n'); }\n${OUT}` }, 'm.cjs');
  expect(s3, 0); assert.equal(s3.stdout, 'threw\nsurvived\n');
  const s4 = run({ 'm.mjs': `import './n.mjs?a';\n${OUT}`, 'n.mjs': '' }, 'm.mjs');
  expect(s4, 0); assert.equal(s4.stdout, 'survived\n');
});
