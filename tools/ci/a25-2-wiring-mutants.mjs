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
const SEC = 'test/r-g64-a25-2-sec.test.mjs';
// killOn: the kill counts only if the test output shows that exact assertion failing (HoQ 22:22: "killed on its exit code").
const onCode = (c) => new RegExp(`expected: ${c}\\b`);
export const MUTANTS = Object.freeze([
  { id: 'M40', what: 'mainIsHelper always true (v1.5: now gates helper.loaded(), D22-4 in the preload)', file: BS, from: "const mainIsHelper = MAIN_URL !== null && VIEW.entries.has(HELPER_MAIN_REL) && MAIN_URL === pathToFileURL(join(VIEW.root, HELPER_MAIN_REL)).href;", to: 'const mainIsHelper = true;', test: [SEC, 'helper\\.loaded\\(\\) lists'], killOn: /LOADED-OTHER/ },
  { id: 'M43', what: 'module.register left unguarded (v1.5: call-time refusal, both modes)', edits: [[BS, "    Object.defineProperty(nodeModule, 'register', { value: refuseRegister, writable: false, configurable: false, enumerable: true });\n", ''], [BS, ' || nodeModule.register !== refuseRegister) helperAbort(EXIT_A25_IMPORT, \'hook guard not in place\');', ") helperAbort(EXIT_A25_IMPORT, 'hook guard not in place');"]], test: [W, 'W-late\\(c\\)'], killOn: onCode(94) },
  { id: 'M44', what: 'advisory manifest sha not compared with the grant digest', file: BS, from: 'if (HELPER_MODE && ADVISORY_SHA256 !== null && ADVISORY_SHA256 !== MANIFEST_SHA256) earlyExit(', to: 'if (false) earlyExit(', test: [ST, 'advisory'], killOn: onCode(90) },
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
  { id: 'M53', what: 'helper node:vm refusal removed (lockdown resolve + backstop load re-check; M11 replacement)', edits: [[LD, "      if (b !== null && apply(setHas, FORBIDDEN, [b])) die(EXIT_A25_FORBIDDEN_MODULE, `module ${url}", "      if (false) die(EXIT_A25_FORBIDDEN_MODULE, `module ${url}"], [BS, "        builtinLoadCheck(url, 'load');\n", '']], test: [W, 'W1b'], killOn: onCode(92) },
  // R-A25-2-SEC (design v1.5): M39, M41, M42 and M54 are RETIRED, their code is gone with the late-hook allowance
  // (registerHooks/register now refuse at call time, 94). One kill per ruling item, each on its exact exit code.
  { id: 'M56', what: 'item 1: hook guard not installed (late registerHooks/register allowed again)', file: BS, from: '  installHookGuard();\n', to: '', test: [SEC, 'item 1, normal mode'], killOn: onCode(94) },
  { id: 'M57', what: 'item 2: binding allowlist not enforced in helper mode', file: BS, from: '    if (BINDING_ALLOWLIST_ON && !HELPER_BINDING_ALLOW.includes(String(name))) {', to: '    if (false) {', test: [SEC, 'p5/p5b'], killOn: onCode(92) },
  { id: 'M58', what: 'item 3: process._debugProcess/_debugEnd not locked', file: BS, from: "  for (const k of ['_debugProcess', '_debugEnd', '_startProfilerIdleNotifier', '_stopProfilerIdleNotifier']) {", to: '  for (const k of []) {', test: [SEC, 'p9/p9b'], killOn: onCode(92) },
  { id: 'M59', what: 'item 3: node:test allowed AND the helper-mode child_process refusal removed (spawn through node:test)', edits: [[LD, "'repl', 'test', 'test/reporters']);", "'repl']);"], [BS, '      if (HELPER_MODE) helperAbort(EXIT_A25_FORBIDDEN_MODULE, `child_process.${name} refused in helper mode`);', '      if (false) helperAbort(EXIT_A25_FORBIDDEN_MODULE, `child_process.${name} refused in helper mode`);']], test: [SEC, 'p6/p6b'], killOn: onCode(92) },
  { id: 'M60', what: 'item 3: node:test and node:test/reporters not forbidden', file: LD, from: "'repl', 'test', 'test/reporters']);", to: "'repl']);", test: [SEC, 'node:test is a forbidden builtin'], killOn: onCode(92) },
  { id: 'M61', what: 'item 4: node: load result not checked (source or non-builtin format passes)', file: BS, from: "        if (!rb || rb.format !== 'builtin' || rb.source != null) helperAbort(", to: '        if (false) helperAbort(', test: [SEC, 'item 4'], killOn: onCode(89) },
  { id: 'M62', what: 'item 5: WebAssembly not locked', file: BS, from: "  if (WA && typeof WA === 'object') {", to: '  if (false) {', test: [SEC, 'p4 \\(item 5\\)'], killOn: onCode(91) },
  { id: 'M63', what: 'item 7: helper mode env var not cleared after reading', file: BS, from: 'if (HELPER_MODE) delete process.env[HELPER_MODE_ENV];', to: '', test: [SEC, 'p11'], killOn: /ENV-LIVE/ },
  { id: 'M64', what: 'item 2: lockdown accepts a foreign non-configurable process.binding guard (one-guard check removed)', file: LD, from: "  } else if (!(typeof process.binding === 'function' && process.binding._backstopBinding === true)) {", to: '  } else if (false) {', test: [SEC, 'one guard'], killOn: onCode(92) },
  { id: 'M65', what: 'item 1 (D22-4 in the preload): helper.loaded() records nothing', file: BS, from: "  const recordLoaded = (rel) => { if (mainIsHelper && rel.startsWith('src/'))", to: "  const recordLoaded = (rel) => { if (false)", test: [SEC, 'helper\\.loaded\\(\\) lists'], killOn: /LOADED-HELPER/ },
  { id: 'M66', what: 'L-SEC-2: SIGUSR1 listener not installed (an outside SIGUSR1 starts the inspector)', file: BS, from: "  process.on('SIGUSR1', function backstopSigusr1()", to: "  if (false) process.on('SIGUSR1', function backstopSigusr1()", test: [SEC, 'L-SEC-2'], killOn: onCode(92) },
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
