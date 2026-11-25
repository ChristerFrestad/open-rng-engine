#!/usr/bin/env node
// A25-2 wiring mutants M39–M55 (Backend). Each mutant is one exact, single-occurrence text edit in a copy of the
// tracked tree; it is KILLED when its named test(s) fail on the copy. HEAVY (one process tree per mutant): run only in a
// HoQ slot (Addendum A). `--dry` is light: it only checks that every edit applies exactly once on this tree.
// Usage: node tools/ci/a25-2-wiring-mutants.mjs [--dry] [--only M39,M40]
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url)).replace(/\/$/, '');
const BS = 'tools/ci/entropy-backstop.mjs', SL = 'verification/harness/stream-launcher.mjs';
const W = 'test/r-g64-a25-2-wiring.test.mjs', ST = 'test/r-g64-stream.test.mjs';
const BARE = 'test/r-g64-a25-bare.mjs', LD = 'tools/ci/a25-lockdown.mjs';
// killOn: the kill counts only if the test output shows that exact assertion failing (HoQ 22:22: "killed on its exit code").
const onCode = (c) => new RegExp(`expected: ${c}\\b`);
export const MUTANTS = Object.freeze([
  { id: 'M39', what: 'lateHookUsed never set (CTO ruling 1c)', file: BS, from: '    lateHookUsed = true;\n', to: '\n', test: [W, 'W-late\\(a\\)|W-late\\(e\\)'], killOn: onCode(94) },
  { id: 'M40', what: 'mainIsHelper always true (CTO ruling 1c)', file: BS, from: "const mainIsHelper = MAIN_URL !== null && VIEW.entries.has(HELPER_MAIN_REL) && MAIN_URL === pathToFileURL(join(VIEW.root, HELPER_MAIN_REL)).href;", to: 'const mainIsHelper = true;', test: [W, 'W-late\\(b\\)'], killOn: onCode(94) },
  { id: 'M41', what: 'late resolve hook result not checked for forbidden builtins (layer-specific; the load re-check still gives 92)', file: BS, from: "      if (r.url.startsWith('node:')) builtinLoadCheck(r.url, 'late resolve');\n", to: '', test: [W, '^W1:'], killOn: /late resolve: forbidden builtin node:vm/ },
  { id: 'M42', what: 'late load hook bytes not held to the manifest', file: BS, from: "if (createHash('sha256').update(src).digest('hex') !== VIEW.entries.get(v.rel)) helperAbort(EXIT_A25_MANIFEST_DIGEST, `late load:", to: "if (false) helperAbort(EXIT_A25_MANIFEST_DIGEST, `late load:", test: [W, 'W1 \\(load side\\)'], killOn: onCode(90) },
  { id: 'M43', what: 'module.register left unguarded', file: BS, from: "  Object.defineProperty(nodeModule, 'register', { value: lateRegister, writable: false, configurable: false, enumerable: true });\n", to: '', test: [W, 'W-late\\(c\\)'], killOn: onCode(94) },
  { id: 'M44', what: 'advisory manifest sha not compared with the grant digest', file: BS, from: 'if (HELPER_MODE && ADVISORY_SHA256 !== null && ADVISORY_SHA256 !== MANIFEST_SHA256) {', to: 'if (false) {', test: [ST, 'advisory'], killOn: onCode(90) },
  { id: 'M45', what: 'proof manifest_sha256 not compared in the launcher', file: SL, from: 'else if (ctx.helperExpect.manifest_sha256 !== null && pr.manifest_sha256 !== ctx.helperExpect.manifest_sha256)', to: 'else if (false)', test: [ST, '^W6'], killOn: /expected: false/ },
  { id: 'M46', what: 'registerRefuseHook not one-shot', file: BS, from: "  if (REFUSE_HOOK !== null || typeof fn !== 'function') {", to: "  if (typeof fn !== 'function') {", test: [W, '^W2:'], killOn: onCode(87) },
  { id: 'M47', what: 'manifest file digest not compared with the grant digest (swapped manifest passes)', file: 'tools/ci/a25-manifest.mjs', from: "  if (sha(bytes) !== expectedSha) return { ok: false, code: EXIT_A25_MANIFEST_DIGEST, why: 'manifest file digest differs from the bound digest' };\n", to: '', test: [W, '^W4:'], killOn: onCode(90) },
  { id: 'M48', what: 'lockdown not installed in helper mode', file: BS, from: '  installLockdown({ isManifestUrl: makeIsManifestUrl(VIEW, A25_DYNAMIC_BUILTINS), abort: helperAbort, registerRefuseHook });\n', to: '', test: [W, 'W1c'], killOn: onCode(94) },
  { id: 'M49', what: 'scheme check skips data: (CTO ruling c)', file: BS, from: "const SCHEME_OK = (u) => u === HELPER_GATE_URL || u.startsWith('file:')", to: "const SCHEME_OK = (u) => u === HELPER_GATE_URL || u.startsWith('data:') || u.startsWith('file:')", test: [W, 'W-scheme'], killOn: /late resolve: scheme not allowed in helper mode: data:/ },
  { id: 'M55', what: 'positional consumer window unwrap removed (F-MI-1)', file: SL, from: 'add: (win) => a.add(win[0])', to: 'add: (win) => a.add(win)', test: [ST, '^F-MI-1'], killOn: /positional: outcome is not a permutation of 52/ },
  // A25-M11 retirement: one kill per refusal on the parentless-code paths (HoQ 22:22 (2)).
  { id: 'M50', what: 'eval refusal removed (M11 replacement)', file: LD, from: "    [globalThis, 'eval', codegenStub('eval')],\n", to: '', test: [BARE, 'M50\\)'], killOn: onCode(91) },
  { id: 'M51', what: 'new Function refusal removed (M11 replacement)', file: LD, from: '  locks[1][2] = FnStub;\n  locks.push([Function.prototype, \'constructor\', FnStub]);\n', to: "  locks[1][2] = Function;\n", test: [BARE, 'M51\\)'], killOn: onCode(91) },
  { id: 'M52', what: "getBuiltinModule('vm') refusal removed (M11 replacement)", file: LD, from: "      if (b !== null && apply(setHas, FORBIDDEN, [b])) die(EXIT_A25_FORBIDDEN_MODULE, `process.getBuiltinModule('${String(id)}')`);\n", to: '', test: [BARE, 'M52\\)'], killOn: onCode(92) },
  { id: 'M53', what: 'helper node:vm refusal removed (lockdown resolve + backstop load re-check; M11 replacement)', edits: [[LD, "      if (b !== null && apply(setHas, FORBIDDEN, [b])) die(EXIT_A25_FORBIDDEN_MODULE, `module ${url}", "      if (false) die(EXIT_A25_FORBIDDEN_MODULE, `module ${url}"], [BS, "{ builtinLoadCheck(url, 'load'); return nextLoad(url, context); }", '{ return nextLoad(url, context); }']], test: [W, 'W1b'], killOn: onCode(92) },
  { id: 'M54', what: 'W1 fix removed: late-hook wrap and load re-check (the 2516680 state)', edits: [[BS, '    return realRegisterHooks(wrapped);', '    return realRegisterHooks(hooks);'], [BS, "{ builtinLoadCheck(url, 'load'); return nextLoad(url, context); }", '{ return nextLoad(url, context); }']], test: [W, '^W1:'], killOn: onCode(92) },
]);

const only = (() => { const i = process.argv.indexOf('--only'); return i > 0 ? new Set(process.argv[i + 1].split(',')) : null; })();
const list = MUTANTS.filter((m) => !only || only.has(m.id));
let bad = 0;
const editsOf = (m) => m.edits ?? [[m.file, m.from, m.to]];
for (const m of list) {
  for (const [file, from] of editsOf(m)) {
    const n = readFileSync(join(ROOT, file), 'utf8').split(from).length - 1;
    if (n !== 1) { bad++; process.stdout.write(`${m.id} BAD-EDIT: 'from' occurs ${n}x in ${file}\n`); }
  }
}
if (bad) process.exit(2);
if (process.argv.includes('--dry')) { process.stdout.write(`dry: ${list.length} edits apply exactly once\n`); process.exit(0); }

const files = spawnSync('git', ['-C', ROOT, 'ls-files', '-co', '--exclude-standard'], { encoding: 'utf8' }).stdout.split('\n').filter(Boolean);
const results = [];
for (const m of list) {
  const d = mkdtempSync(join(tmpdir(), `a25m-${m.id}-`));
  try {
    for (const f of files) { mkdirSync(dirname(join(d, f)), { recursive: true }); copyFileSync(join(ROOT, f), join(d, f)); }
    for (const [file, from, to] of editsOf(m)) { const p = join(d, file); writeFileSync(p, readFileSync(p, 'utf8').replace(from, to)); }
    const env = { ...process.env }; delete env.NODE_OPTIONS;
    const r = spawnSync(process.execPath, ['--test', '--test-name-pattern', m.test[1], m.test[0]], { cwd: d, env, encoding: 'utf8', timeout: 300000 });
    const pass = Number((/^ℹ pass (\d+)/m.exec(r.stdout) || [])[1] ?? -1), fail = Number((/^ℹ fail (\d+)/m.exec(r.stdout) || [])[1] ?? -1);
    // HoQ 22:22: a kill counts only on the named exit-code assertion (killOn), not on any failure.
    const onTarget = m.killOn ? m.killOn.test(r.stdout + r.stderr) : true;
    const verdict = pass + fail <= 0 ? 'NO-TESTS' : fail === 0 ? 'SURVIVED' : onTarget ? 'KILLED' : 'KILLED-OTHER';
    results.push({ id: m.id, what: m.what, verdict, pass, fail });
    process.stdout.write(`${m.id} ${verdict} (pass ${pass}, fail ${fail}) ${m.what}\n`);
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const killed = results.filter((r) => r.verdict === 'KILLED').length;
process.stdout.write(`${killed}/${results.length} killed\n`);
process.exit(killed === results.length ? 0 : 1);
