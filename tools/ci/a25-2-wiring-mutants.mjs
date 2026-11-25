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
const SEC = 'test/r-g64-a25-2-sec.test.mjs', LDT = 'test/a25-lockdown.test.mjs';
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
  { id: 'M49', what: 'scheme check skips data: (CTO ruling c)', file: BS, from: "const SCHEME_OK = (u) => u === HELPER_GATE_URL || u.startsWith('file:')", to: "const SCHEME_OK = (u) => u === HELPER_GATE_URL || u.startsWith('data:') || u.startsWith('file:')", test: [W, 'W-scheme'], killOn: /resolve: scheme not allowed in helper mode: data:/ }, // slot 1: the static data: case is now the first to fail (load's file-URL check still exits 89, so the kill is on the scheme-check message assertion)
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
  { id: 'M58', what: 'item 3: process._debugProcess/_debugEnd not locked', file: BS, from: "  for (const k of ['_debugProcess', '_debugEnd', '_startProfilerIdleNotifier', '_stopProfilerIdleNotifier']) {", to: '  for (const k of []) {', test: [SEC, 'p9/p9b'], killOn: /process\\._debugProcess refused in helper mode/ }, // slot 1: the L-SEC-2 SIGUSR1 listener still exits 92, so the kill is on the _debugProcess message assertion
  { id: 'M59', what: 'item 3: node:test allowed AND the helper-mode child_process refusal removed (spawn through node:test)', edits: [[LD, "'repl', 'test', 'test/reporters']);", "'repl']);"], [BS, '      if (HELPER_MODE) helperAbort(EXIT_A25_FORBIDDEN_MODULE, `child_process.${name} refused in helper mode`);', '      if (false) helperAbort(EXIT_A25_FORBIDDEN_MODULE, `child_process.${name} refused in helper mode`);']], test: [SEC, 'p6/p6b'], killOn: onCode(92) },
  { id: 'M60', what: 'item 3: node:test and node:test/reporters not forbidden', file: LD, from: "'repl', 'test', 'test/reporters']);", to: "'repl']);", test: [SEC, 'node:test is a forbidden builtin'], killOn: onCode(92) },
  { id: 'M61', what: 'item 4: node: load result not checked (source or non-builtin format passes)', file: BS, from: "        if (!rb || rb.format !== 'builtin' || rb.source != null) helperAbort(", to: '        if (false) helperAbort(', test: [SEC, 'item 4'], killOn: onCode(89) },
  { id: 'M62', what: 'item 5: WebAssembly not locked', file: BS, from: "  if (WA && typeof WA === 'object') {", to: '  if (false) {', test: [SEC, 'p4 \\(item 5\\)'], killOn: onCode(91) },
  { id: 'M63', what: 'item 7: helper mode env var not cleared after reading', file: BS, from: 'if (HELPER_MODE) delete process.env[HELPER_MODE_ENV];', to: '', test: [SEC, 'p11'], killOn: /ENV-LIVE/ },
  { id: 'M64', what: 'item 2: lockdown accepts a foreign non-configurable process.binding guard (one-guard check removed)', file: LD, from: "  } else if (!(typeof process.binding === 'function' && process.binding._backstopBinding === true)) {", to: '  } else if (false) {', test: [SEC, 'one guard'], killOn: onCode(92) },
  { id: 'M65', what: 'item 1 (D22-4 in the preload): helper.loaded() records nothing', file: BS, from: "  const recordLoaded = (rel) => { if (mainIsHelper && rel.startsWith('src/'))", to: "  const recordLoaded = (rel) => { if (false)", test: [SEC, 'helper\\.loaded\\(\\) lists'], killOn: /LOADED-HELPER/ },
  { id: 'M66', what: 'L-SEC-2: SIGUSR1 listener not installed (an outside SIGUSR1 starts the inspector)', file: BS, from: "  process.on('SIGUSR1', function backstopSigusr1()", to: "  if (false) process.on('SIGUSR1', function backstopSigusr1()", test: [SEC, 'L-SEC-2 \\(found'], killOn: onCode(92) },
  // int-v8 (CTO rulings (a), (c); AI Eng review note 1; HoQ/CTO test-33 condition).
  { id: 'M67', what: 'CTO (c): node:test allowed AND the helper-mode child_process refusal falls through (catchable throw, not 92 at the spawn)', edits: [[LD, "'repl', 'test', 'test/reporters']);", "'repl']);"], [BS, '      if (HELPER_MODE) helperAbort(EXIT_A25_FORBIDDEN_MODULE, `child_process.${name} refused in helper mode`);', '      if (HELPER_MODE) throw new NativeError(`child_process.${name} refused in helper mode`);']], test: [SEC, 'p6/p6b'], killOn: onCode(92) },
  { id: 'M68', what: 'CTO (a): --disable-sigusr1 dropped from the launcher helper argv', file: SL, from: "  return ['--disable-sigusr1', '--import', BACKSTOP, HELPER,", to: "  return ['--import', BACKSTOP, HELPER,", test: [SEC, 'L-SEC-2b'], killOn: /SIGUSR1-SPAWN/ },
  { id: 'M69', what: 'CTO (a): launcher does not check the proof\'s sigusr1_disabled', file: SL, from: "    else if (ctx.helperExpect.manifest_sha256 !== null && pr.sigusr1_disabled !== true)", to: '    else if (false)', test: [ST, 'L-SEC-2 \\(int-v8\\)'], killOn: /PROOF-SIGUSR1/ },
  { id: 'M70', what: 'AI Eng note 1: lockdown registers its hooks through the live (guarded) registerHooks instead of the evaluation-time capture', file: LD, from: '  REGISTER_HOOKS({', to: '  registerHooks({', test: [LDT, 'evaluation-time registerHooks capture'], killOn: /LD-CAPTURE/, modes: { bare: /LD-CAPTURE: exit 7\b/, preloaded: /LD-CAPTURE: exit 94\b/ } }, // slot 1: survived on the SEC test (bare runner; helper mode installs the lockdown before the guard)
  { id: 'M71', what: 'test 33 cause: the stub-hook direct cases run in a child that carries the backstop preload', file: LDT, from: '    else expectAbort(code, body, { bare: true });', to: '    else expectAbort(code, body, { bare: true, preload: true });', test: [LDT, 'direct native/spawn entry points abort'], killOn: /NOT-BARE/ },
  { id: 'M72', what: 'int-v8 (found in the allowlist work): the backstop\'s childProof drops sigusr1_disabled, so the launcher reads none', file: BS, from: ', sigusr1_disabled: body.sigusr1_disabled ?? null } : { invalid: true }', to: ' } : { invalid: true }', test: [SEC, 'L-SEC-2c'], killOn: /CHILDPROOF-SIGUSR1/ },
  { id: 'M73', what: 'CTO int-v8 (1)(iii): one non-allowlisted launcher-facing field changes (T gains a field)', file: 'verification/harness/evidence-helper.mjs', from: 'out(jsonFrame(FRAME.T, { count, payload_sha256:', to: 'out(jsonFrame(FRAME.T, { count, extra: 0, payload_sha256:', test: [ST, 'CTO \\(1\\) on helper'], killOn: /SHAPE-9B7A1D8/ },
  { id: 'M74', what: 'CTO int-v8 r2: allowlist A4 accepts the parent pid', file: 'tools/ci/a25-2-launcher-shape.mjs', from: ' && pid !== parentPid && ', to: ' && ', test: [ST, 'allowlist A4/A5 are typed'], killOn: /A4-CHECK parent pid/ },
  { id: 'M75', what: 'CTO int-v8 r2: allowlist A4 accepts a non-integer pid', file: 'tools/ci/a25-2-launcher-shape.mjs', from: 'return Number.isInteger(pid) && pid > 1', to: 'return pid > 1', test: [ST, 'allowlist A4/A5 are typed'], killOn: /A4-CHECK non-integer/ },
  { id: 'M76', what: 'CTO int-v8 r2: allowlist A5 accepts a digest that does not match the recomputed manifest', file: 'tools/ci/a25-2-launcher-shape.mjs', from: ' && v === recomputed; }', to: '; }', test: [ST, 'allowlist A4/A5 are typed'], killOn: /A5-CHECK recompute mismatch/ },
  { id: 'M78', what: 'slot-1 A8: allowlist A8 accepts walks != gate_calls', file: 'tools/ci/a25-2-launcher-shape.mjs', from: ' && a25.walks === a25.gate_calls && ', to: ' && ', test: [ST, 'allowlist A4/A5 are typed'], killOn: /A8-CHECK walks differ/ },
  { id: 'M79', what: 'CTO A8 (2): allowlist A8 accepts gate_calls < calls (lower bound removed)', file: 'tools/ci/a25-2-launcher-shape.mjs', from: ' && a25.gate_calls >= A8_LOWER; }', to: '; }', test: [ST, 'allowlist A4/A5 are typed'], killOn: /A8-CHECK below calls/ },
  { id: 'M81', what: 'CTO r5 (Sec N-A8-UB): the A8 upper bound is removed, so gate_calls > U is no FINDING+HOLD', file: 'tools/ci/a25-2-launcher-shape.mjs', from: '{ if (a25.gate_calls > A8_UPPER) throw new Error(', to: '{ if (false) throw new Error(', test: [ST, 'allowlist A4/A5 are typed'], killOn: /A8-UB above U is a FINDING\+HOLD/ },
  { id: 'M82', what: 'CTO r5: the A8 lower bound goes back to >= calls instead of the exact minimum 2040', file: 'tools/ci/a25-2-launcher-shape.mjs', from: ' && a25.gate_calls >= A8_LOWER; }', to: ' && a25.gate_calls >= calls; }', test: [ST, 'allowlist A4/A5 are typed'], killOn: /A8-CHECK below the minimum 2040/ },
  { id: 'M80', what: 'CTO A8 (4b): the raw frame split reads the length big-endian', file: 'tools/ci/a25-2-launcher-shape.mjs', from: 'len = raw.readUInt32LE(o + 1)', to: 'len = raw.readUInt32BE(o + 1)', test: [ST, 'CTO \\(1\\) on helper'], killOn: /FRAME-SPLIT/ },
  { id: 'M77', what: 'AI Eng note 1: the lockdown test re-types a stale backstop marker key instead of reading it', file: LDT, from: '  return m[0][1];\n})();', to: "  return 'open-rng-engine/entropy-backstop/v0';\n})();", test: [LDT, 'marker key'], killOn: /MARK-KEY/ },
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
    // modes (AI Eng review, M70): a mutant with modes must be killed in EACH named mode, bare and under the backstop
    // preload, each on its own mode-specific assertion; the log names the mode of every kill.
    const runs = m.modes ? Object.entries(m.modes) : [['bare', m.killOn ?? null]];
    const per = runs.map(([mode, killOn]) => {
      const pre = mode === 'preloaded' ? ['--import', './tools/ci/entropy-backstop.mjs'] : [];
      const r = spawnSync(process.execPath, [...pre, '--test', '--test-name-pattern', m.test[1], m.test[0]], { cwd: d, env, encoding: 'utf8', timeout: 300000 });
      const pass = Number((/^ℹ pass (\d+)/m.exec(r.stdout) || [])[1] ?? -1), fail = Number((/^ℹ fail (\d+)/m.exec(r.stdout) || [])[1] ?? -1);
      // HoQ 22:22: a kill counts only on the named exit-code assertion (killOn), not on any failure.
      const onTarget = killOn ? killOn.test(r.stdout + r.stderr) : true;
      return { mode, pass, fail, verdict: pass + fail <= 0 ? 'NO-TESTS' : fail === 0 ? 'SURVIVED' : onTarget ? 'KILLED' : 'KILLED-OTHER' };
    });
    const verdict = per.every((x) => x.verdict === 'KILLED') ? 'KILLED' : (per.find((x) => x.verdict !== 'KILLED') ?? per[0]).verdict;
    const pass = per.reduce((a, x) => a + x.pass, 0), fail = per.reduce((a, x) => a + x.fail, 0);
    results.push({ id: m.id, what: m.what, verdict, pass, fail, per });
    const how = m.modes ? ` [${per.map((x) => `${x.mode}: ${x.verdict}`).join(', ')}]` : '';
    process.stdout.write(`${m.id} ${verdict} (pass ${pass}, fail ${fail})${how} ${m.what}\n`);
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const killed = results.filter((r) => r.verdict === 'KILLED').length;
process.stdout.write(`${killed}/${results.length} killed\n`);
process.exit(killed === results.length ? 0 : 1);
