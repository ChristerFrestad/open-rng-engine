# A25-2 design v1.5 addendum: CTO ruling R-A25-2-SEC (Security review SEC-REVIEW-7f8908e)

Base: 9b7a1d8 (int-v6, F-MI-1 already in). Numbering note: int-v6 and v1.4 were taken by F-MI-1, so this batch is
int-v7 / v1.5. Behavioural tests live in test/r-g64-a25-2-sec.test.mjs (Security's p1-p11 probes as repo tests) and
test/r-g64-a25-2-wiring.test.mjs. Every case runs under the real preload in helper mode with a grant-bound manifest
unless it says normal mode; every payload writes "pwn" or a marker file, so stdout '' / no marker proves it never ran.

## Item 1: late-hook allowance removed (exit 94, both modes)

`installHookGuard()` (tools/ci/entropy-backstop.mjs) runs in `install()` right after `installHelperMode`, in BOTH modes.
`module.registerHooks` and `module.register` become non-configurable, non-writable refusals that call `helperAbort(94)`
at call time, before any hook is installed; `syncBuiltinESMExports()` keeps the ESM view identical (checked).
The preload owns the only hooks: ours plus the lockdown's. The lockdown captures `REGISTER_HOOKS` at module evaluation
(it is imported before the guard), so its own install still works.

The evidence helper's D22-4 observing hook is gone. The preload's load hook records, for the helper main only, every
`src/` file with the manifest digest of the bytes node compiled (also on the CJS no-source path), and the marker
exposes it as `helper.loaded()`. The helper reads that list; the launcher's input and output are unchanged
(r-g64-stream "D22-4 + real helper" passes). Late-hook code removed: `lateHookUsed`, the hook wrap, the late
load/resolve re-checks, `checkLoadResult`.

Tests: SEC p1/p1b/p2 (builtin source swap), p10 (late CJS no-source + fs patch; p10b control 90), s2, normal mode
(registerHooks, register, CJS), loaded() helper/other; wiring W-late(a)-(e), W1 (both W1 hook objects now 94).

## Item 2: process.binding allowlist; one guard (exit 92)

After `installLockdown`, `BINDING_ALLOWLIST_ON = true` and the backstop's G-39 guard refuses every name not on
`HELPER_BINDING_ALLOW` with 92. The allowlist is EMPTY:

| Candidate | Needed by the harness? | Reason |
|---|---|---|
| any name | no | the helper closure (evidence-helper.mjs, src/**, the gate) makes no `process.binding` call (grep); node's own modules use `internalBinding`, which the guard does not see |
| contextify | no (refused) | the lockdown's own use happens during install, before `BINDING_ALLOWLIST_ON` |
| inspector, natives, spawn_sync, process_wrap, worker | no (refused) | named in the ruling; covered by p5/p7/p8 |

One guard: the lockdown no longer installs its own binding lock when `process.binding` is non-configurable; it accepts
it only if it is the backstop guard (`_backstopBinding === true`) and otherwise dies 92 ("not the backstop G-39 guard").
Header claims in tools/ci/a25-lockdown.mjs are corrected (91 contextify line, 92 list, 94 scope, one-guard paragraph).

Tests: p5/p5b (contextify), p7/p7b (spawn_sync, process_wrap), p8 (every name Security listed), "one guard"
(runs bare; skipped under the preload, where the backstop guard is already in place).

## Item 3: inspector and node:test (exit 92)

`process._debugProcess`, `_debugEnd`, `_startProfilerIdleNotifier`, `_stopProfilerIdleNotifier` are non-configurable
stubs giving 92. `node:test` and `node:test/reporters` join `FORBIDDEN_BUILTINS` (resolve, load re-check and
getBuiltinModule). Child processes through internal paths: in helper mode every child_process export dies 92 before
spawning (backstop cp hook), whoever holds the exports, so node:test's internal spawn is stopped even if node:test were
reachable (verified by hand: with 'test' unforbidden the run() case exits 92 "child_process.spawn refused"; with both
removed the child runs, which mutant M59 encodes). spawn_sync/process_wrap bindings: item 2.

L-SEC-2 (new, found while closing item 3): a SIGUSR1 from OUTSIDE the process started the inspector in helper mode
("Debugger listening on ws://127.0.0.1:9229", exit 0). The preload now installs a SIGUSR1 listener that gives 92
(a JS listener replaces Node's default handler). Residual: helper code that removes every SIGUSR1 listener restores the
default. Proposal for CTO ruling (not adopted): add `--disable-sigusr1` to the helper spawn; it closes this fully
(verified: exit 0, no inspector) but changes the launcher's exact spawn arguments (A25-6 iv, `assertHelperSpawn`).

Tests: p9/p9b, L-SEC-2 (self SIGUSR1), p6/p6b/p6c/p6d (node:test run() with process isolation, env, execArgv:
92, child marker absent), node:test forbidden (getBuiltinModule, node:test/reporters), cp exports (92).

Note for test authors: a child spawned from inside `node --test` inherits NODE_TEST_CONTEXT / NODE_TEST_WORKER_ID,
and node:test run() then skips files as "recursive". The sec tests strip NODE_TEST_* so the probe behaves as in a real
helper.

## Item 4: node: load results (exit 89)

In the helper load hook a `node:` URL passes `builtinLoadCheck`, then `nextLoad`; a result that is not
`{ format: 'builtin', source: null/undefined }` gives 89 ("came back as <format> [with a source], not the builtin").
Verified on v24.22.1: node's default load for node:zlib returns `{ format: 'builtin', source: null }`.
Tests: a hook registered BELOW ours (pre-preload `--import`) returning module+source, builtin+source, commonjs: 89;
pass-through: 0.

## Item 5: WebAssembly (exit 91)

`WebAssembly.compile`, `instantiate`, `Module`, `compileStreaming`, `instantiateStreaming` become non-configurable stubs
giving 91; `globalThis.WebAssembly` is locked. Node's TypeScript stripping (amaro) instantiates its own wasm lazily
through the same global, so the preload primes it first with `module.stripTypeScriptTypes('const a: number = 1;')`
(experimental warning held back for that call). Residual: that one amaro instance, created by node before the lock and
not reachable from user code. Tests: p4 (all five), "TS src still loads after the lock" (stderr '').

## Item 6: Node v24.22.1 --permission for the evidence helper: YES it runs; NOT adopted (needs CTO ruling)

Evidence (v24.22.1, no repo change; probe script and logs in the int-v7 mirror under permission/):
- r-g64-stream "D22-4 + real helper" with the helper spawned as `node --permission --allow-fs-read=<tree>/
  --allow-fs-read=<tmp manifest dir>/ --import <backstop> <helper> ...`: PASS (counted, load list matches).
  Bare `--permission` without fs-read: ERR_ACCESS_DENIED on the preload itself. The real launcher would also need
  `--allow-fs-write=<proof file>` (the test's grant view does not read the proof file).
- Probe under `--permission --allow-fs-read=/tmp/`: child_process.spawnSync, Worker, process.binding('spawn_sync'),
  process.binding('fs'), WASI, inspector.open, fs write, fs read outside the grant: ERR_ACCESS_DENIED; process.dlopen:
  ERR_DLOPEN_DISABLED. NOT covered: `WebAssembly.Module` and `new Function` (allowed), so 91/92 stay ours.
- Node's own docs (permissions.html, v24): "This feature does not protect against malicious code"; a "seat belt"
  approach that "does not provide security guarantees in the presence of malicious code"; symbolic links are followed
  outside granted paths.
Recommendation: defence in depth on the helper spawn only, never a replacement for the preload; it changes the exact
spawn arguments (A25-6 iv), so it waits for CTO.

## Item 7: env cleared (NIT)

The grant (ENTROPY_BACKSTOP_GRANT), locator (ENTROPY_BACKSTOP_MANIFEST), advisory digest and helper mode
(ENTROPY_BACKSTOP_HELPER) are deleted from process.env after reading. L-SEC-1 (named residual): /proc/self/environ
keeps the exec-time values. Test p11 asserts live env [] and the environ residual exactly.

## F-W5 (found running the wiring test under the preload)

An early exit 90 (grant without digest, advisory digest differs) left no proof file, so a preloaded parent saw a
child without proof and threw. `earlyExit()` now writes `{ pid, preload_sha256: null, token: null,
manifest_sha256: null, early_exit: code }` (flag wx) when ENTROPY_BACKSTOP_PROOF_FILE is set; the launcher voids it
(preload digest differs), so it can never count. No kill mutant: the mutant runner runs bare, where this path is not
exercised; it is covered by the preloaded run (npm test / gate).

## Mutants (tools/ci/a25-2-wiring-mutants.mjs; `--dry`: 24 edits apply exactly once)

Retired (code removed): M39 (lateHookUsed), M41 (late resolve check), M42 (late load bytes), M54 (late-hook wrap).
Kept and re-pointed: M40 (mainIsHelper true: now kills on LOADED-OTHER), M43 (register guard removed, two edits incl.
the identity check), M44 (advisory compare, now earlyExit), M53 (builtinLoadCheck line). M45-M52, M55 unchanged.

| Mutant | Item | Edit | Test | Kill on |
|---|---|---|---|---|
| M56 | 1 | installHookGuard() call removed | SEC item 1, normal mode | 94 |
| M57 | 2 | binding allowlist check off | SEC p5/p5b | 92 |
| M58 | 3 | _debugProcess/_debugEnd stubs off | SEC p9/p9b | 92 |
| M59 | 3 | node:test unforbidden AND helper cp refusal off | SEC p6 run() | 92 |
| M60 | 3 | node:test, node:test/reporters unforbidden | SEC node:test forbidden | 92 |
| M61 | 4 | node: load-result check off | SEC item 4 | 89 |
| M62 | 5 | WebAssembly lock off | SEC p4 | 91 |
| M63 | 7 | helper-mode env delete removed | SEC p11 | ENV-LIVE |
| M64 | 2 | lockdown one-guard check off | SEC one guard | 92 |
| M65 | 1 | helper.loaded() records nothing | SEC loaded() | LOADED-HELPER |
| M66 | L-SEC-2 | SIGUSR1 listener off | SEC L-SEC-2 | 92 |

Hand-checked kills (light, single file, temp copy): M59 (exit 0, child ran), M66 (exit 0, "Debugger listening").
The full run (24 mutants) is heavy: it waits for diag v3 'done' plus a HoQ slot.

## Files touched outside mine

tools/ci/a25-lockdown.mjs (AI Engineer's): FORBIDDEN_BUILTINS + test, test/reporters; REGISTER_HOOKS captured at
evaluation; foreign-guard check (die 92); header claims. Flagged to AI Engineer and CTO for review.
TE's files untouched.

## Known, not caused here

Under the preload (`node --import ./tools/ci/entropy-backstop.mjs --test`), test/a25-lockdown.test.mjs test 33
"direct native/spawn entry points abort, not throw (bare)" expects 93 and gets 0; it passes bare, and already failed
this way at 9b7a1d8.
