// A25-2 wiring tests (Backend): W1–W6 plus the CTO 22:14 late-hook, vm and dynamic-builtin rulings.
// Each case runs a tiny tree under a temp root whose main is (or is not) verification/harness/evidence-helper.mjs,
// under the real preload in helper mode, with a grant-bound manifest over that tree. Single-process, light.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildManifest } from '../tools/ci/a25-manifest.mjs';
import { helperSpawnEnv, runStreamCore } from '../verification/harness/stream-launcher.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url)).replace(/\/$/, '');
const PRELOAD = join(ROOT, 'tools/ci/entropy-backstop.mjs');
const HELPER_REL = 'verification/harness/evidence-helper.mjs';
const OUT = 'process.stdout.write("survived\\n");\n';
const baseEnv = () => { const e = { ...process.env }; delete e.NODE_OPTIONS; for (const k of Object.keys(e)) if (k.startsWith('ENTROPY_BACKSTOP')) delete e[k]; return e; };

// files: { relpath: source }; main: relpath to run. Opts: grant/env/manifest overrides for W4/W5.
function run(files, main, { listed = Object.keys(files), mutateEnv = (e) => e, swapManifest = null } = {}) {
  const d = mkdtempSync(join(tmpdir(), 'a25w-'));
  try {
    const root = join(d, 'tree');
    for (const [rel, src] of Object.entries(files)) { mkdirSync(dirname(join(root, rel)), { recursive: true }); writeFileSync(join(root, rel), src); }
    const { bytes, sha256 } = buildManifest(root, listed);
    const manifestPath = join(d, 'manifest.json');
    writeFileSync(manifestPath, swapManifest ? buildManifest(root, swapManifest).bytes : bytes);
    const env = mutateEnv(helperSpawnEnv(baseEnv(), { token: 'grant-9@9#wiring', manifestPath, manifestSha256: sha256 }), sha256);
    const r = spawnSync(process.execPath, ['--import', PRELOAD, join(root, main)], { cwd: root, env, encoding: 'utf8', timeout: 30000 });
    return { status: r.status, stdout: r.stdout, stderr: r.stderr };
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const helperMain = (body) => ({ [HELPER_REL]: `import * as M from 'node:module';\n${body}` });

test('W-late(a): the evidence-helper main may register one late hook; a second late registerHooks exits 94', () => {
  const ok = run(helperMain(`M.registerHooks({ load: (u, c, n) => n(u, c) });\n${OUT}`), HELPER_REL);
  assert.equal(ok.status, 0, ok.stderr); assert.equal(ok.stdout, 'survived\n');
  const r = run(helperMain(`M.registerHooks({ load: (u, c, n) => n(u, c) });\nM.registerHooks({ load: (u, c, n) => n(u, c) });\n${OUT}`), HELPER_REL);
  assert.equal(r.status, 94, r.stderr); assert.equal(r.stdout, ''); assert.match(r.stderr, /registerHooks after the preload/);
});
test('W-late(b): a non-helper main calling registerHooks exits 94, even its first call', () => {
  const r = run({ 'probe/main.mjs': `import * as M from 'node:module';\nM.registerHooks({ load: (u, c, n) => n(u, c) });\n${OUT}` }, 'probe/main.mjs');
  assert.equal(r.status, 94, r.stderr); assert.equal(r.stdout, '');
});
test('W-late(b2): a helper-named file that is not in the manifest does not get the allowance (it is not loadable at all)', () => {
  const files = { ...helperMain(`M.registerHooks({ load: (u, c, n) => n(u, c) });\n${OUT}`), 'x.mjs': '' };
  const r = run(files, HELPER_REL, { listed: ['x.mjs'] });
  assert.notEqual(r.status, 0); assert.equal(r.stdout, '');
});
test('W-late(c): module.register after the preload exits 94, for any main', () => {
  for (const [files, main] of [[helperMain(`M.register('data:text/javascript,');\n${OUT}`), HELPER_REL], [{ 'm.mjs': `import * as M from 'node:module';\nM.register('data:text/javascript,');\n${OUT}` }, 'm.mjs']]) {
    const r = run(files, main);
    assert.equal(r.status, 94, r.stderr); assert.equal(r.stdout, ''); assert.match(r.stderr, /module\.register after the preload/);
  }
});
test('W-late(d): the guard cannot be replaced (non-configurable, non-writable) and the CJS view is the same wrapper', () => {
  const r = run({ 'm.cjs': `const M = require('node:module');\nlet threw = 0;\ntry { Object.defineProperty(M, 'registerHooks', { value: () => {} }); } catch { threw++; }\ntry { M.registerHooks = () => {}; } catch { threw++; }\nM.registerHooks({});\nprocess.stdout.write('survived ' + threw + '\\n');\n` }, 'm.cjs');
  assert.equal(r.status, 94, r.stderr); assert.equal(r.stdout, '');
});
test('W1: a late resolve hook (the helper allowance) that maps a specifier to node:vm is still refused, 92', () => {
  const r = run({ ...helperMain(`M.registerHooks({ resolve: (s, c, n) => (s === 'virt:vm' ? { url: 'node:vm', shortCircuit: true } : n(s, c)) });\nawait import('virt:vm');\n${OUT}`) }, HELPER_REL);
  assert.equal(r.status, 92, r.stderr); assert.equal(r.stdout, ''); assert.match(r.stderr, /late resolve: forbidden builtin node:vm/);
});
test('W1 (load side): the late load hook cannot hand node bytes other than the manifest entry (90) nor short-circuit node:vm (92)', () => {
  const forged = run({ ...helperMain(`M.registerHooks({ load: (u, c, n) => (u.endsWith('/x.mjs') ? { format: 'module', source: 'process.stdout.write("forged\\n");', shortCircuit: true } : n(u, c)) });\nawait import('./x.mjs');\n${OUT}`), 'verification/harness/x.mjs': '' }, HELPER_REL);
  assert.equal(forged.status, 90, forged.stderr); assert.equal(forged.stdout, ''); assert.match(forged.stderr, /late load: bytes of verification\/harness\/x\.mjs differ from the manifest/);
  const vm = run(helperMain(`M.registerHooks({ resolve: (s, c, n) => (s === 'virt:vm' ? { url: 'node:vm', shortCircuit: true } : n(s, c)), load: (u, c, n) => (u === 'node:vm' ? { format: 'builtin', shortCircuit: true } : n(u, c)) });\nawait import('virt:vm');\n${OUT}`), HELPER_REL);
  assert.equal(vm.status, 92, vm.stderr); assert.equal(vm.stdout, '');
});
test('W1b (CTO ruling 2): in helper mode importing node:vm exits 92, statically and dynamically', () => {
  for (const src of [`import 'node:vm';\n${OUT}`, `await import('node:vm');\n${OUT}`]) {
    const r = run({ 'm.mjs': src }, 'm.mjs');
    assert.equal(r.status, 92, r.stderr); assert.equal(r.stdout, '');
  }
});
test('W1c (CTO ruling 3): a dynamic import() of a builtin not on the (empty) allowlist exits 94; the static import passes', () => {
  const dyn = run({ 'm.mjs': `await import('node:os');\n${OUT}` }, 'm.mjs');
  assert.equal(dyn.status, 94, dyn.stderr); assert.equal(dyn.stdout, '');
  const st = run({ 'm.mjs': `import 'node:os';\n${OUT}` }, 'm.mjs');
  assert.equal(st.status, 0, st.stderr); assert.equal(st.stdout, 'survived\n');
});
test('W2: registerRefuseHook is one-shot; a second call exits 87 (outside helper mode, where the preload has not used it)', () => {
  const d = mkdtempSync(join(tmpdir(), 'a25w2-'));
  try {
    const f = join(d, 'm.mjs');
    const u = JSON.stringify(pathToFileURL(PRELOAD).href);
    for (const [body, code, out] of [[`R(() => {});\n${OUT}`, 0, 'survived\n'], [`R(() => {});\nR(() => {});\n${OUT}`, 87, ''], [`R(42);\n${OUT}`, 87, '']]) {
      writeFileSync(f, `import { registerRefuseHook as R } from ${u};\n${body}`);
      const r = spawnSync(process.execPath, [f], { env: baseEnv(), encoding: 'utf8' });
      assert.equal(r.status, code, r.stderr); assert.equal(r.stdout, out);
    }
  } finally { rmSync(d, { recursive: true, force: true }); }
});
test('W3: ordering: the lockdown is the last hook, so it sees a dynamic import() first (94, lockdown) before the manifest load check (89)', () => {
  const files = { 'm.mjs': `await import('./outside.mjs');\n${OUT}`, 'outside.mjs': '' };
  const dyn = run(files, 'm.mjs', { listed: ['m.mjs'] });
  assert.equal(dyn.status, 94, dyn.stderr); assert.match(dyn.stderr, /A25-2 lockdown: /);
  const st = run({ 'm.mjs': `import './outside.mjs';\n${OUT}`, 'outside.mjs': '' }, 'm.mjs', { listed: ['m.mjs'] });
  assert.equal(st.status, 89, st.stderr); assert.equal(st.stdout, '');
});
test('W4: a swapped manifest file (other bytes than the grant digest) exits 90 before main', () => {
  const r = run({ 'm.mjs': OUT, 'n.mjs': '' }, 'm.mjs', { listed: ['m.mjs', 'n.mjs'], swapManifest: ['m.mjs'] });
  assert.equal(r.status, 90, r.stderr); assert.equal(r.stdout, '');
});
test('W5: a grant with no digest, or a malformed one, exits 90 before main', () => {
  for (const g of ['grant-9@9#wiring', 'grant-9@9#wiring|m=', `grant-9@9#wiring|m=${'A'.repeat(64)}`, `|m=${'0'.repeat(64)}`]) {
    const r = run({ 'm.mjs': OUT }, 'm.mjs', { mutateEnv: (e) => ({ ...e, ENTROPY_BACKSTOP_GRANT: g }) });
    assert.equal(r.status, 90, `${g}: ${r.stderr}`); assert.equal(r.stdout, '');
  }
});
