# A25-2 design v1: manifest load hook and integration (Backend, integrator)

Status: DESIGN, not yet implemented. Base: r-g64/impl 150edc5d. Split note: A25-2-SPLIT-v1 (6e012211) + Addendum A (bb171356) + Addendum B (6fd20817).
Owners: Backend = manifest hook, refuse hook, launcher binding, integration, wiring tests. AI Engineer = tools/ci/a25-lockdown.mjs (v3 6c398554). Test Engineer = tools/ci/a25-2-mutants.mjs + test/r-g64-a25-2.test.mjs (v1.1 3371a9b9 + d18d28d7), A29-3.

## 1. Manifest file

- JSON: `{ "version": 1, "root": "<absolute repo root>", "entries": { "<posix path relative to root>": "<sha256 hex of exact file bytes>" } }`.
- Keys are sorted. The file bytes are `JSON.stringify(m, null, 1) + "\n"`, so the sha256 is stable.
- Built by `buildManifest(root, relpaths)` in tools/ci/a25-manifest.mjs. relpaths is the helper's module closure. It is collected by a traced boot of the helper in a non-evidence mode: the load hook records every file: URL. The traced set is frozen into the plan (HELPER_PLAN.manifest_relpaths) and re-pinned with A31. Every module counts, including src .ts, verification .mjs, node_modules .js/.mjs/.cjs and JSON.
- Builtins (node:*) are not files. They are allowed only if they are in a fixed boot allowlist in the manifest hook. The allowlist is the set the helper uses today, as given by the trace. vm, worker_threads, child_process and any addon are never on it; the lockdown refuses those as 92/93.

## 2. Locator and binding (CTO rule, 21:1x)

- The launcher builds the manifest itself, writes it to the per-spawn mkdtemp dir (the same dir as the proof), and sets `ENTROPY_BACKSTOP_MANIFEST=<path>` and `ENTROPY_BACKSTOP_MANIFEST_SHA256=<hex>`. It deletes any inherited value first, as it does for NODE_OPTIONS.
- The D22-7 header records `preload.manifest_sha256`, plus the relpath count.
- In helper mode the preload reads both env values once and deletes them from process.env. It reads the file and computes sha256. Exit 90 (EXIT_A25_MANIFEST_DIGEST) if the file is missing or unreadable, if the digest env is absent, or if the sha differs. This happens before the main entry resolves. That is the swapped-manifest mutant.
- writeProof adds `manifest_sha256` (the digest the preload actually verified). The launcher's finish check gains: proof.manifest_sha256 === the bound digest. A mismatch voids the part (A25-1 style).
- The env values only locate the file. Acceptance comes from the header digest + proof + HoQ re-hash of the mirrored manifest.

## 3. Load hook (in the helper-mode registerHooks block, entropy-backstop.mjs)

- `load(url)`: for `file:` URLs, map to a relpath under root. Not under root, or not in entries: exit 89 (EXIT_A25_MANIFEST_OUTSIDE). In entries: read the bytes, sha256. If they differ from the entry: exit 90.
- The source handed on to the next loader is the hashed bytes. We return `{ source: bytes, shortCircuit: false }` via nextLoad with the source pre-set, so a file changed between hash and read cannot slip through (TOCTOU).
- The existing srcDigest_before check stays. A25-6(ii) (bytes changed after srcDigest_before) is caught at load as 90 when it changes before load. If it changes after load it is caught by srcDigest_after, as today.
- CommonJS `require` of a .cjs/.js inside node_modules goes through the same registerHooks load hook (node 24 sync hooks cover require). Test: a manifest .cjs is required; a non-manifest .cjs gives 89.
- JSON imports and `require('x.json')` are the same path.
- `isManifestUrl(url)` is a one-argument closure over the frozen entries and the builtin allowlist. It returns exactly `true` or `false`. It is passed to installLockdown.
- `HELPER_GATE_URL` (virtual) is exempt. It is not a file.

## 4. Refuse hook (Addendum B)

- `export function registerRefuseHook(fn)`: one-shot. A second call, or a non-function, gives helperAbort 87. The hook is stored in a module-private slot.
- Each G-39/G-46 refusal site (dlopen, spawn_sync, process_wrap, execve) calls `REFUSE_HOOK?.(kind, detail)` before its existing throw. The refusal strings and the console.error line stay unchanged.

## 5. Hook order and lockdown wiring

- Preload order in helper mode: wrap primitives, install the helper gate, registerHooks (manifest + gate), installLockdown({ isManifestUrl, abort: helperAbort, registerRefuseHook }) LAST.
- After that, module.registerHooks and module.register are wrapped. One further registration is allowed: the helper main's own load hook, recognised by being registered from MAIN_URL before the H frame. Any other registration exits 94. Every registration after the H frame exits 94.
- Wiring tests (Backend):
  - (W1) A resolve hook registered after install that returns node:vm without nextResolve is refused (AI Eng R3 case).
  - (W2) A second registerRefuseHook gives 87.
  - (W3) Bypass of the lockdown ordering: install happens after manifest hooks.
  - (W4) A helper started with a swapped manifest file gives 90.
  - (W5) A missing digest env gives 90.
  - (W6) A proof with a different manifest_sha256 voids the part.

## 6. Exit codes (single export each)

- 89 and 90: tools/ci/a25-manifest.mjs.
- 91–94: tools/ci/a25-lockdown.mjs.
- 86–88: entropy-backstop.mjs, unchanged.

## 7. Mutants (Backend-owned, in j-calib-mutants.mjs; TE owns 6(i)(ii)(iii)(v))

- A25-M39: drop the manifest file sha check (swapped manifest passes).
- A25-M40: the load hook skips node_modules.
- A25-M41: the load hook hashes but does not pass the hashed bytes on (TOCTOU).
- A25-M42: no proof manifest_sha256 check.
- A25-M43: registerRefuseHook is not one-shot.
- A25-M44: lockdown not installed last.
- A25-M45: the launcher keeps an inherited ENTROPY_BACKSTOP_MANIFEST.

## 8. Limits (stated, not closed)

- The trace-derived closure covers modules the helper loads on the evidence path. A lazy branch never taken during the trace is outside the manifest and aborts 89 if it is ever taken. That is fail-closed, not silent.
- Builtins are trusted as node itself. The node version pin is 94 (AI Eng v2).
