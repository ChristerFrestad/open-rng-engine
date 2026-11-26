# A25-2 design v1.1: manifest load hook and integration (Backend, integrator)

Supersedes v1 (verification/a25-2-design-v1.md, kept unchanged) where they differ. Covers the CTO rulings of 22:12 and 22:14 CET, 2026-11-25. Content stays ANTATT until the HoQ gate.

## 1. Carrier and binding (replaces v1 §2)

- The grant is the only authority: `ENTROPY_BACKSTOP_GRANT = '<token>|m=<manifest sha256>'`, built by `helperSpawnEnv(baseEnv, {token, manifestPath, manifestSha256})` in stream-launcher.mjs. `ENTROPY_BACKSTOP_MANIFEST` is only a locator.
- `ENTROPY_BACKSTOP_MANIFEST_SHA256` is advisory. The preload reads it once and deletes it. In helper mode, a value that differs from the grant digest exits 90 before main. It never replaces the grant digest. A grant with no digest, or a malformed one, exits 90 at the preload's module top.
- `readManifest(path, grantSha)` hashes the file and compares it with the grant digest. A mismatch, missing file or bad shape exits 90. The view is frozen.
- writeProof carries `manifest_sha256`. The launcher voids a part whose proof digest differs from the header's `preload.manifest_sha256` (W6).

## 2. Helper closure (replaces v1 §1 "trace" wording)

- `tools/ci/a25-trace-closure.mjs` runs each K rep once (2 calls, sequential) under the real preload with a broad manifest and records every file URL. The union is pinned in `verification/harness/helper-closure.json`; `--write` updates it. At 1627cdf this is 9 files: src/{index,errors,entropy/index,mapping/index}.ts plus collector, evidence-helper, n-floor, run-plan and stream-frames.
- `helperManifestRelpaths()` in run-plan.mjs reads the pinned file. `HELPER_PLAN` is unchanged, so the plan digest and the constants test stand.
- BOUND_FILES now also lists tools/ci/a25-manifest.mjs, tools/ci/a25-lockdown.mjs (both loaded by the preload before any hook, and not in the preload sha) and helper-closure.json. This changes the bindings set, so the A31 prereg and Platform's A25-5 rebase re-pin to the final integrated head.

## 3. Lockdown and late hooks (replaces v1 §5)

- Helper-mode order: readManifest, then registerHooks (gate + manifest load), then installLockdown (last), then the late-hook guard.
- `module.registerHooks` and `module.register` are replaced by non-configurable, non-writable wrappers, and the ESM view is synced. `register` always exits 94. `registerHooks` is allowed exactly once, only when the main entry is `<manifest root>/verification/harness/evidence-helper.mjs` and that file is a manifest entry. A second call, or any call from another main, exits 94.
- Residual (CTO ruling 1): the allowance keys on the main's identity plus first call, not on caller identity. Fail-closed reasoning: every loaded module is manifest-verified, and if any module calls before the helper, the helper's own call then aborts 94.
- New since v1, found by W1: a late hook runs above the lockdown, so a resolve hook that short-circuits to `node:vm` escaped the lockdown's resolve-time refusal (exit 0 at 2516680). Fix: the one allowed late hook is wrapped. Its resolve results are checked against the forbidden and addon builtin lists (92 or 93). Its load results for file URLs are held to the manifest (89 or 90). The virtual gate URL must come back with our exact gate source, or the run exits 87. Our own load hook also re-checks every `node:` URL.
- The dynamic-builtin allowlist is empty: `import()` of any builtin exits 94, and a static builtin import passes (W1c).

## 4. A25-3 and A25-M11 (CTO rulings 2 and 3)

- Token-clear tests: the dynamic forms became static imports. The assertion itself is unchanged: exit 86 after src has used the gate, with the same call per case. Diff (test/r-g64-a25.test.mjs, 150edc5d..HEAD):
  - `(await import('node:crypto')).randomBytes(4)` became `import * as C1 from 'node:crypto'; C1.randomBytes(4)`; the same change applies to randomFillSync and webcrypto.
  - `(await import('crypto')).default.randomInt(3)` became `import Cd from 'crypto'; Cd.randomInt(3)`.
  - createRequire now uses a static `node:module` import. The getBuiltinModule, globalThis.crypto and randomUUID cases are unchanged.
  - The dynamic forms are now tested to exit 94 (the "A25-2 over A25-3" cases, plus W1c).
- A25-M11 (parentless vm import of the preload after main): unreachable in helper mode, since node:vm exits 92 first (tested in r-g64-a25 and W1b). The mainStarted rule exists only in helper mode, so bare mode can't reach it either. The other parentless paths are also closed: eval and new Function give 91, and process.getBuiltinModule('vm') gives 92. Proposal to HoQ: retire A25-M11 for that reason, and have the "vm exits 92" tests replace it. HoQ rules on this.

## 5. Wiring tests (test/r-g64-a25-2-wiring.test.mjs, plus W6 and the advisory case in r-g64-stream)

W-late(a) second late call 94; W-late(b) non-helper main 94; W-late(b2) helper-named file outside the manifest not loadable; W-late(c) register 94; W-late(d) guard not replaceable; W1 late resolve to node:vm 92 ("late resolve"); W1 load-side forged bytes 90 and short-circuited vm 92; W1b vm static/dynamic 92; W1c dynamic builtin import() 94, static passes; W2 registerRefuseHook one-shot 87; W3 dynamic import of a non-manifest file 94 (lockdown, first) versus static 89 (manifest load); W4 swapped manifest 90; W5 missing or malformed grant digest 90; W6 proof digest mismatch voids. Stream advisory case: equal 0, forged 90, wrong grant plus matching advisory 90.

## 6. Mutants (tools/ci/a25-2-wiring-mutants.mjs, replaces v1 §7 numbering)

M39 lateHookUsed never set; M40 mainIsHelper always true (both CTO ruling 1c); M41 late resolve builtin check removed; M42 late load bytes not held to the manifest; M43 module.register unguarded; M44 advisory sha not compared; M45 proof manifest_sha256 not compared; M46 registerRefuseHook not one-shot; M47 manifest file digest not compared; M48 lockdown not installed. `--dry` (light) checks that each edit applies exactly once. The kill run is heavy and waits for a HoQ slot.
v1's M40 (node_modules skipped) has no such branch in the code. Every file URL goes through verifyLoad. v1's M41 (TOCTOU) needs a race to be detected, so it is a stated limit, not a mutant: the compiled-bytes hash check is in place but has no deterministic test. v1's M44 (lockdown not last) is approximated by M48. Reordering is not distinguishable by test, because only resolve order differs and every lockdown refusal is also enforced at load or by the late-hook wrapper.

## 7. Exit codes

86–88 entropy-backstop.mjs; 89/90 a25-manifest.mjs; 91 CODEGEN, 92 FORBIDDEN_MODULE, 93 ADDON, 94 IMPORT, 95 NODE_VERSION (Addendum D) a25-lockdown.mjs. 94 covers a non-manifest or builtin dynamic import() and a refused late registerHooks/register.
