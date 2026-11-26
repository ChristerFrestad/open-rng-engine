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
(a JS listener replaces Node's default handler). int-v8 (CTO ruling (1), ADOPTED): the helper spawn argv now starts with
`--disable-sigusr1` (helperSpawnArgs, assertHelperSpawn, A25-1 exact-argv test, proof field sigusr1_disabled checked by the
launcher); the 92 listener stays as a second layer. Named residual R-SIGUSR1-LISTENER: helper code that removes every
SIGUSR1 listener loses the 92 layer; with the flag the signal still opens no inspector (test L-SEC-2b). Whether the
process then survives or dies by SIGUSR1 is accepted either way (no inspector, no 0 with a debugger); the exact outcome
is recorded from the slot run.

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

## Item 6: Node v24.22.1 --permission for the evidence helper: EVALUATED AND REJECTED for int-v7/int-v8 (CTO ruling (2))

CTO: Node calls it a seat belt, symlinks escape the grant, and it covers neither WebAssembly nor new Function, so the
argv churn is not justified now; evidence stays in permission/ of the int-v7 mirror; possible revisit after A31.

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
(ENTROPY_BACKSTOP_HELPER) are deleted from process.env after reading. R-ENVIRON (named residual, CTO; was L-SEC-1): /proc/self/environ
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

## int-v8 delta (on d75175d; CTO rulings (a)-(e), (1)-(3), A6ii-M3; HoQ/CTO test-33 condition; AI Eng review)

Written by code reading and editing only, during the diag isolation window: NOT YET RUN. Every claim below that
depends on node behaviour is marked (to verify) and is checked in the slot before the head is sent.

(a) --disable-sigusr1. The launcher's helper argv is now exactly `--disable-sigusr1 --import <bound backstop>
<helper> <args>` (helperSpawnArgs / assertHelperSpawn; the old d75175d shape is refused). The A25-1 exact-argv shape
changes ONCE here (AI Eng D10: no --from). The preload's proof gains `sigusr1_disabled` (process.execArgv at install,
before user code); with a header-bound manifest the launcher voids a part whose proof lacks `sigusr1_disabled: true`
('proof: helper was not started with --disable-sigusr1 (A25-1, L-SEC-2)'). The preload's SIGUSR1 listener (92) stays
as a second layer. Tests: r-g64-stream 'A25-1 ... exactly --disable-sigusr1 ...' (argv, incl. the old shape refused),
'L-SEC-2 (int-v8)' (proof void for false/undefined/null/'true'/1, counted for true), proof probe records false for a
child without the flag; SEC 'L-SEC-2b (CTO a)': flags taken from helperSpawnArgs, helper code removes the preload's
SIGUSR1 listener and signals itself, no 'Debugger listening' / ws:// (accepted end states: survived 0, SIGUSR1 signal, or
92; the exact one is recorded at the run), with a control proving the test sees an inspector without the flag.
Mutants: M68 (flag dropped, killOn /SIGUSR1-SPAWN/), M69 (proof check off, killOn /PROOF-SIGUSR1/).
(b) R-ENVIRON (renamed from L-SEC-1): /proc/self/environ keeps the exec-time grant, locator and helper vars.
(c) Spawn refusal aborts at the spawn. In helper mode every child_process export calls helperAbort(92) before
mapChildArgs, and process.binding aborts 92 at the call; nothing reaches the post-exit proof check. SEC p6 now names
both node:test variants (default env; PATH-only env + execArgv []) and asserts stderr never shows the proof-check
message (SPAWN-FALLTHROUGH). Mutant M67: node:test allowed AND the cp refusal turned into a catchable throw.
(d) SEC 'item 2 (CTO d)': require() of a manifest .cjs from the helper-mode main works under the contextify refusal
(stdout 'cjs 42', empty stderr).
(e) Lockdown header: helper-mode process.binding aborts 92 at the call for every name (contextify included: this
file's own compileFunction/Script guards are not reachable there); every node:child_process export aborts 92 before
spawning for any holder. AI Eng hunks to review: the header block "Under the backstop preload ... Addendum B".
(1) Launcher-facing output vs 9b7a1d8: tools/ci/a25-2-launcher-shape.mjs runs the real helper for one fixed fixture
(rep shuffle/adjacency-mod4/n-52, j 0, 40 calls, fixed token) and serialises H (all fields but `backstop`, plus the
sorted `backstop` key list), the D frame lengths and frame order, and T {count, src_after, a25}. The D payload (and so
T.payload_sha256) is fresh entropy on every run of any head and cannot be byte-compared; H.backstop binds the preload
digest, which differs per head by design. The golden test/fixtures/a25-2-launcher-shape-9b7a1d8.json is recorded once
from a 9b7a1d8 checkout in the slot; r-g64-stream 'CTO (1) ...' compares the bytes (SHAPE-9B7A1D8) and fails with
GOLDEN-MISSING until it exists.
(2) internalBinding: not reachable from helper code on node v24.22.1 without --expose-internals, which the exact argv
and the dropped NODE_OPTIONS exclude; process.binding is the only public alias and is the empty allowlist (Sec p1/p4/p8
are the check). (to verify by Sec's probes at the new head)
(3) Retired -> successor: M39 (lateHookUsed) -> M56 + M43; M41 (late resolve check) -> M56 (SEC s2 also fails) + M49;
M42 (late load bytes) -> M56 (SEC p10) + TE's A6ii-M3 tamper test; M54 (late-hook wrap, W1) -> M56 (registerHooks, 94)
+ M43 (register, 94). Per Sec finding (bypass test on its own code / kill mutant): item 1 p1/p1b/p2, p10, s2, normal
mode / M56, M43; item 2 p5/p5b, p7, p8, one guard / M57, M64; item 3 p9, p6, node:test forbidden, cp refusal, L-SEC-2,
L-SEC-2b / M58, M59, M60, M66, M67, M68, M69; item 4 / M61; item 5 p4 / M62; item 7 p11 / M63; D22-4 / M40, M65.
A6ii-M3 (CTO): the CJS null-source path is the preload load hook (entropy-backstop.mjs, after verifyLoad, which already
hashes the bytes it reads). int-v8 re-hashes v.bytes at the hand-off itself and aborts 90 on a mismatch; node is always
handed v.bytes and never re-reads from fs. The plain byte-tamper test (exit exactly 90) is TE's in
test/r-g64-a25-2.test.mjs with runner-v5 killOn; SEC p10b (patched fs.readFileSync -> 90) is the in-process variant.
AI Eng note 1 (capture order): M70 makes the lockdown call the live registerHooks; the SEC TypeScript test (exit 0)
must fail (to verify that the guard is what node:module's named export resolves to at install). AI Eng note 2 (guard
identity instead of `_backstopBinding === true`) is passed to Sec's hook-chain read.

Test 33 root cause (HoQ/CTO): HARNESS, not head. Test 33 runs the lockdown with the test's STUB registerRefuseHook
and expects the lockdown's own dlopen/binding/execve stubs (93/92). Under `node --import backstop --test` the G-39
hook gives every node child the preload, so the child is not bare: process.dlopen etc. are the backstop's
non-configurable refusals, which call only the backstop's registered refuse hook (none: the stub never reaches the
backstop) and throw catchably, so the case prints CAUGHT/SURVIVED and exits 0. In production the preload passes its
own registerRefuseHook, which the next test ('real backstop refusal sites ... (normal mode)') and the helper-mode SEC
tests cover. Minimal repro (kept out of the tree: G-45 forbids .sh scripts in the repo): /workspace/rng-backup/a25-2/backend/int-v8-slot1/t33-repro/ (repro.sh + case.mjs). Slot 1 result: bare exit 93 (ABORT 93, dlopen after boot), preloaded exit 0 (CAUGHT the backstop's G-39 refusal, SURVIVED), as predicted. Fix:
run() gains `bare` (the child exits 3 with NOT-BARE if the backstop is present); test 33 uses it and is skipped under a
preloaded parent (no bare child is possible there). Mutant M71 puts the preload into test 33's children (the cause):
killOn /NOT-BARE/.

### int-v8 r2 (CTO rulings on the int-v8 WIP, 2026-11-25)

(1) Launcher-shape test vs 9b7a1d8, accepted with conditions. tools/ci/a25-2-launcher-shape.mjs spawns the real helper
with each tree's OWN helperSpawnArgs/helperSpawnEnv and compares H, D, T and the preload proof byte for byte after
swapping only these closed allowlist values for `<ALLOW:id>` (each raw payload must first round-trip through JSON
byte-exactly, so the record is the helper's own bytes):
- A1 H.backstop.backstop_sha256 and proof.preload_sha256: the preload digest; the preload file differs per head by design.
- A2 D payload bytes: CSPRNG output, fresh every run; only frame count and lengths are compared.
- A3 T.payload_sha256: sha256 of A2.
- A4 proof.pid: OS pid of the helper, new on every spawn. CTO-approved (r2) as a TYPED substitution: integer > 1, not
  the parent pid, equal to the spawned child's pid (spawnSync result); else <REJECT:A4> and the compare fails (checkA4).
- A5 proof.manifest_sha256: digest of the manifest over the tree, which differs per head by design. CTO-approved (r2) as
  a TYPED substitution: 64 lowercase hex and equal to an independent recompute (node:crypto over the same sorted
  relpaths, not the tree's own a25-manifest.mjs, and equal to the sha256 of the manifest bytes given to the helper);
  else <REJECT:A5> (checkA5). Test 'allowlist A4/A5 are typed'; mutants M74 (A4 takes the parent pid), M75 (A4 takes a
  non-integer), M76 (A5 skips the recompute), each killed by its exact A4-CHECK/A5-CHECK message.
- A6 proof.sigusr1_disabled: absent at 9b7a1d8; must be exactly true at int-v8 (removed only when true, any other value fails).
- A7 spawn argv: `--disable-sigusr1` added (not output; each tree's own argv is used).
(ii) No test-only deterministic entropy source exists on this head (verification/harness/check.mjs's LCG is synthetic
and not wired to the helper), so none was built and A2/A3 stay allowlisted. (iii) M73 adds one field to the T frame;
killed only by /SHAPE-9B7A1D8/.

Found while doing (1): the backstop's childPreloadProof (what the launcher's grantView.proof returns) dropped
sigusr1_disabled, so the int-v8 launcher check would have voided EVERY header-bound part in a real run; the W6 test used
explicit proof views and could not see it. Fixed (passes the field through); new test SEC L-SEC-2c (a hook-recorded child
proof is true with the flag and false without); M72 drops the field, killed by /CHILDPROOF-SIGUSR1/.

(2) Test 33: harness root cause accepted pending the repro; NO SKIP. Genuine bareness is impossible under
`node --import backstop --test`: G-39 puts the preload into every node child and refuses commands that strip it (that is
the property, not a bug). So test 33 now runs in both modes: under a preloaded parent it asserts the same codes (93/92)
through the real backstop hook; from a bare parent it runs the lockdown's stubs with NOT-BARE asserted in each child.
The gate adds a separate bare run, tools/ci/a25-2-bare-gate.mjs --out <dir> (test/a25-lockdown.test.mjs and
test/r-g64-a25-2-sec.test.mjs from a bare parent; refuses to start if the parent is not bare; own bare-gate.log,
result.json, SHA256SUMS; exit 0 only with 0 fail, 0 skipped, 0 todo and test 33 reported passed). M71 now targets the
bare branch and stays killed by /NOT-BARE/.
Gate evidence (CTO r2): the main gate log and the bare-gate run's bare-gate.log, result.json and SHA256SUMS both go into
the gate evidence, and the gate passes only if both pass.

Other: tools/ci/j-calib-mutants.mjs A25-M37 had a stale 'from' (the proof body gained manifest_sha256 before int-v8, so it
no longer applied); updated to the int-v8 proof line, same mutation. Wiring mutants: 35 (M72-M77 added).

AI Eng review of the test-33 hunk (APPROVED, notes applied in r4): (1) the backstop marker key is read from the backstop
source (exactly one `export const MARK = Symbol.for('...')`), not re-typed; a run started with the backstop (execArgv or
NODE_OPTIONS names it) must see the marker (MARK-KEY), and a new test spawns a backstop-preloaded child and requires the
marker under that key; M77 re-types a stale key, killed by /MARK-KEY/. Bare children also drop NODE_OPTIONS. (2) test 33
renamed '... (bare or preloaded)' (bare-gate's T33 name follows).

## Findings from the HoQ int-v8 r4 run window (2026-11-25/26)

- A8 (CTO ruling 2026-11-26 ~00:19 CET: APPROVED as a typed substitution, CTO-approved, not final until Sec's code read at the committed head covers checkA8 and harness fixes (a) and (b)): launcher-facing `T.a25 {gate_calls, walks}` follows rejection sampling and varies per run; the golden carries `<ALLOW:A8>` only when `checkA8` holds (keys exactly `gate_calls,walks`, integers, `walks === gate_calls`, `gate_calls >= calls`), otherwise `<REJECT:A8>`. Killed by M78 (`A8-CHECK walks differ`).
- L-SEC-2: helper mode with `--disable-sigusr1` survives SIGUSR1 (status 0, no inspector); helper mode without the flag dies by SIGUSR1 (preload listener replaced the native handler; removing listeners resets to default), no inspector. Valid control is normal mode without the flag (inspector starts).
- R-ENVIRON: under a preloaded parent (npm test) the G-39 hook sets `ENTROPY_BACKSTOP_PROOF_FILE` in the child exec env, so it appears in `/proc/self/environ` and overrides a caller-set proof path.
- Foreign earlier `--import` under a preloaded parent is refused with 89 (`load: not in manifest`), because NODE_OPTIONS `--import backstop` loads before command-line `--import`.
- Wiring mutants: 36 (M78 added). killOn changes: M49 `/resolve: scheme not allowed in helper mode: data:/`, M58 `/process\._debugProcess refused in helper mode/`, M70 retargeted to the LD-CAPTURE test. Full run after fixes: 36/36 killed.
- CTO A8 conditions: A8-CHECK also covers an extra key, a missing key, key order and a non-object; M79 (gate_calls < calls accepted) is killed on 'A8-CHECK below calls'. The raw values each substitution replaced (T.a25, payload/backstop/preload/manifest digests, pid) are written to the run record (test diagnostic 'A8-RAW'; the golden CLI writes `<out>.raw.json`), never discarded.
- Harness fix (a): under a preloaded parent, launcherShape checks the childProof view field-equal, in key order, to the bare view of the hook's proof file after dropping mtime_ms ('PROOF-VIEWS-EQUAL'). Harness fix (b): the raw frame split must match the validated FrameReader frames (count, types, D bytes, H/T JSON) and consume every byte ('FRAME-SPLIT'); M80 (length read big-endian) is killed on it. Wiring mutants: 38.

## int-v8 r5/r6 additions (2026-11-26)
- A8 bounds (CTO r5, Sec N-A8-UB; Quant CONFIRMED, quant-a8-ub-check.md sha256 886f2eff): A8_LOWER 2040 (typed REJECT below), A8_UPPER 3084 (A8-UB FINDING+HOLD above), valid only for A8_CONFIG (shuffle n=52, 40 calls); any other configuration is a typed REJECT (A8-CONFIG, M83). M79, M81, M82 cover the bounds.
- A6ii-M3 CommonJS null-source hand-off (entropy-backstop.mjs load hook, after the r.source != null branch): backstop only; unreachable at pinned node 24.22.1 on product routes (TE probe 6b616da1; CTO/HoQ M3b ruling (b)); re-probe on any node or manifest change. Held by the CJS-GUARD test (no .cjs, .node, require( or createRequire under src/ or verification/harness; M84, one plant per run).
- Sec N-BG-1: the bare gate also refuses -r, --loader and --experimental-loader in NODE_OPTIONS.
- Sec N-LD-1 part 1 (CTO ruling (b), text narrowed; no code change, no mutant): Item 1's claim is narrowed to Sec's wording (SEC-REVIEW-72e8430.md, sha256 5f1a7107): "module.registerHooks/register refused; the lockdown's own fixed hooks may be installed once by in-process code". Normal mode is the npm test environment; helper mode is the boundary the counted runs use.
- CTO r6 (i): the CJS-GUARD .node check covers every manifest root (src, verification, tools/ci); the lockdown resolve (93) stays the enforcing layer. M84 gains a fifth plant (tools/ci/a25-plant.node), killed on its own assert 'CJS-GUARD .node in tools/ci'.
