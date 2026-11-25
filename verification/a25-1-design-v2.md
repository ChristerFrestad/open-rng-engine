# A25-1 design v2 (append-only amendment to DESIGN-A25-1-v1.md, sha256 556fce9a…)

Base: r-g64/impl at 55284904. v1 stands except where this file amends it. Inputs: CTO GO on v1 with three
amendments, the HoQ/CTO ruling (2), and CTO's note on WIP 3da94108 (renumbering allowed if mapped; old M27 may be
dropped if this file says why and points to the test).

## Amendment 1: full child argv, no NODE_OPTIONS (CTO cond 1)
- `helperSpawnArgs(plan, stream, j, calls)` builds exactly `['--import', BACKSTOP, HELPER, '--run', …, '--calls', n]`.
- `assertHelperSpawn(args, env, want)` refuses unless: args equals want element by element (same length), BACKSTOP is
  absolute, args[0] is `--import`, args[1] the bound backstop, args[2] the helper, and env is an object with no own
  `NODE_OPTIONS` (even empty). `realSpawnPart` passes every spawn through it.
- Caveat (stated, not hidden): the backstop's own G-39 hook (normalizeChildOptions/injectBackstopEnv) re-adds
  `NODE_OPTIONS=--import <backstop>` to the env node actually hands the child. The assert covers the launcher-built
  env; the only NODE_OPTIONS the child can receive is the hook's own `--import` of the same bound backstop, which the
  proof below then attests by digest. Anything else in the child's argv or env from the launcher is refused.

## Amendment 2: the proof is the preload's, per spawn, and content-checked (CTO cond 2)
- The proof path is a fresh mkdtemp name per spawn (`newProofPath`); it does not exist before the spawn. The child's
  preload writes it with flag `wx` (never overwrites), content `{pid, preload_sha256, token}`; the helper never writes it.
- `childPreloadProof(child)` (backstop, per-child WeakMap filled by the hooked spawn) returns null (unknown child),
  false (no file) or a frozen `{pid, preload_sha256, token, mtime_ms}` (`{invalid:true}` if unparsable).
- The launcher voids the part unless, in order: a proof exists and parses; its token is this spawn's token; its
  preload_sha256 equals the bound backstop digest (helperExpect.backstop_sha256 = bindings.files); its pid is this
  child's pid; its mtime ≥ spawn time − 20 ms (PROOF_CLOCK_SLACK_MS, for filesystem mtime granularity).

## Amendment 3: fresh per-spawn token with a nonce, recorded per part (ruling (2), CTO cond 3)
- Token = `grant-<n>@<pid>#<32 hex>`; the nonce comes from the backstop's ORIGINAL randomFillSync
  (`evidenceSpawnToken`), so the launcher makes no call through the wrapped entry points.
- runStreamCore takes a grant view `{base, live(), next(), proof(child)}`. Before each spawn: live() must hold, and
  next() must give a string `base#<non-empty>` never used in this stream; else the part voids with no spawn.
- The token goes to the child in env `ENTROPY_BACKSTOP_GRANT`; the helper-mode preload reads it once, deletes it
  from the env, and reports it in the H frame, which must equal this spawn's token; the grant must still be live at H.
- Every attempt records `tokens` per part (counted and void); each part records its token. The header records the
  preload `{path, sha256, helper_mode, grant}`.
- Token-alone limit: a token is unforgeable only together with the proof (pid + digest + post-spawn file). The token
  binds a frame and a proof to one spawn; it does not by itself prove what code produced the frame.

## Old M27 dropped (reuse compares the preload)
Checkpoint reuse already compares `tools/ci/entropy-backstop.mjs` through `bindings.files` (`reuseMismatches`), so a
separate preload comparison would be equivalent. Proving test: `D22-7: a checkpoint is reusable only when every bound
sha256, …` in test/r-g64-stream.test.mjs (it mutates each bound file digest, including the backstop, and expects the
mismatch). The header check `preload changed while binding (A25-1)` ties header.preload.sha256 to the same value.

## Final mutant list (all in tools/ci/j-calib-mutants.mjs, RS_TEST, run bare) → condition → killing test
| Mutant | Condition | Killed by |
|---|---|---|
| A25-M23 H grant not compared with the spawn token | 3 | D22-8 h-nogrant / h-badgrant |
| A25-M24 no liveness at H | 3 | grant closes after spawns |
| A25-M25 missing/invalid proof passes | 2 | each proof check voids |
| A25-M26 proof digest not checked | 2 | each proof check voids |
| A25-M27 proof of another process passes | 2 | each proof check voids |
| A25-M28 extra --import/--require passes | 1 (CTO M28) | exact argv test |
| A25-M29 stale proof (before spawn) passes | 2 (CTO M29) | each proof check voids |
| A25-M30 copied proof from another spawn passes | 3 (old M30) | each proof check voids |
| A25-M31 token reused across spawns passes | 3 (old M31) | token reuse test |
| A25-M32 NODE_OPTIONS in launcher env passes | 1 | exact argv test |
| A25-M33 no liveness before spawn | 3 | not live before spawn |
| A25-M34 runs without a grant view | 3 | refuses without view |
| A25-M35 helper preload leaves token in env | 3 | helper-mode probe |
| A25-M36 hook does not record proof per child | 2 | preload proof probe |
| A25-M37 preload proof has no digest/token | 2 | preload proof probe |
| A25-M38 token not base#nonce passes | 3 | non-fresh token test |
Plus RS-14 re-anchored (readiness before liveGrant). Targeted run (bare, /tmp copies): 17/17 killed.
