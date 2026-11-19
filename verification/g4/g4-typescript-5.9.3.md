# G4 dependency verdict: typescript@5.9.3 (open-rng-engine devDependency)

- Reviewer: Security Engineer (AppSec)
- Date/time: 2026-11-18 11:23 CET (Europe/Copenhagen)
- Requested by: CTO. HoQ ruling: no grandfathering, so this is a retroactive G4 for every devDep.
- Repo: /home/box/company/rng-work/open-rng-engine (local only, 0 remotes)
- Reviewed commit (HEAD): `373873ae2d16f33a68437c9ebc8d080a077d9006` (committed 2026-11-18 11:15:35 CET, "HoQ 81d1d184: G-28/G-29/G-30, M-163..M-167, b1..b6 fixtures.")
- Package: `typescript@5.9.3` (package.json devDependencies spec: `"5.9.3"`, an exact pin)
- Lockfile integrity, verbatim from package-lock.json `packages["node_modules/typescript"].integrity`:
  `sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdiaUpFT4bXlb1RHhLpp8wtm6M5TgSw==`

VERDICT: PASS

The verdict is PASS. npm provenance is ABSENT for this version. That is recorded below as a non-blocking note with compensating evidence; provenance has not been claimed.

## Scope and working-tree state

- `git status --porcelain` at review time was NOT clean: ` M tools/ci/import-allowlist.mjs` and `?? test/fixtures/rule27-checker-373873ae.mjs`. These are uncommitted changes by another seat. They are outside the dependency manifests and are not part of this review.
- `package.json` and `package-lock.json` in the working tree are byte-identical to HEAD:
  - package.json sha256 `9ed3c7bf4e3c125f4495169ef251b215ea28ef3d97828a13e008a006aa743ecb` (HEAD and working tree match)
  - package-lock.json sha256 `c694ed58401c2708e9c2dfd7732c8d379915b0d3d841faf08019f7389fca8e5c` (HEAD and working tree match)
- The pack and audit checks ran on a `git archive HEAD` export in /tmp, so they reflect the committed tree exactly.

## Checks

| # | Check | Result | Grade | Evidence |
|---|---|---|---|---|
| 1 | Commit, remotes | HEAD 373873ae2d16f33a68437c9ebc8d080a077d9006; `git remote -v` printed nothing (0 remotes); tree dirty, but not in the manifests (see above) | VERIFISERT | `git rev-parse HEAD`, `git remote -v`, `git status --porcelain` |
| 2a | package.json spec | `devDependencies: {"typescript": "5.9.3"}`, an exact pin. `dependencies: {}` is empty. There are no peerDependencies, optionalDependencies or bundleDependencies keys. There is no `workspaces` key. The sub-manifests packages/{capability,drbg,mapping}/package.json each have `private: true`, `dependencies: {}` and no other dependency keys | VERIFISERT | package.json read at HEAD |
| 2b | Lock entry | lockfileVersion 3. The only packages are `""` and `node_modules/typescript`. The typescript entry has version `5.9.3`, resolved `https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz`, the integrity above and `dev: true`. It has no `dependencies` key and no `hasInstallScript`. bin is tsc and tsserver; engines node >=14.17 | VERIFISERT | package-lock.json |
| 3 | Registry integrity | Registry `dist.integrity` equals the lock integrity. Registry `dist.shasum` is `5b4f59e15310ab17a216f5d6cf53ee476ede670f`. The downloaded tarball (4,377,468 bytes) has sha512 base64 `sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdiaUpFT4bXlb1RHhLpp8wtm6M5TgSw==`, matching both the lock and the registry. Its sha1 is `5b4f59e15310ab17a216f5d6cf53ee476ede670f`, matching the registry. For reference, its sha256 is `10e108c9cf7d5f2879053dff18515fb405abf2ccef63eaaf017d9c571687a1d3`. Separately, `diff -r` of the extracted tarball against the repo's installed `node_modules/typescript` found the trees identical | VERIFISERT | `curl https://registry.npmjs.org/typescript/5.9.3`; `curl` of dist.tarball; `openssl dgst -sha512 -binary \| base64 -w0`; `sha1sum` |
| 4a | npm provenance / attestations | ABSENT. The version metadata has no `dist.attestations`. `GET https://registry.npmjs.org/-/npm/v1/attestations/typescript@5.9.3` returns HTTP 404 `{"error":"Not found"}`. So there is no SLSA provenance linking the tarball to microsoft/TypeScript CI | VERIFISERT (that it is absent) | metadata dist block; attestations endpoint |
| 4b | Registry signature (compensating) | `dist.signatures` has 1 ECDSA signature, keyid `SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U`. `npm audit signatures` in a /tmp scratch project with only typescript@5.9.3 (installed with `--ignore-scripts`) printed "1 package has a verified registry signature" and exited 0 | VERIFISERT | npm 11.21.1, node v24.22.1 |
| 4c | Publisher identity (compensating) | `_npmUser` is `typescript-bot <typescript@microsoft.com>`. The maintainers are typescript-bot, typescript-deploys (typescript-design@microsoft.com), weswigham, sanders_n, andrewbranch, sheetalkamat (shkamat@microsoft.com) and jakebailey. The repository is `git+https://github.com/microsoft/TypeScript.git`, and gitHead is `c63de15a992d37f0d6cec03ac7631872838602cb` | VERIFISERT that the metadata says this. ANTATT that the published bytes were built from that gitHead (no attestation; no reproducible build done) | registry metadata |
| 5 | Install scripts | None. The tarball package.json scripts are test, test:eslint-rules, build, build:compiler, build:tests, build:tests:notypecheck, clean, gulp, lint, knip, format and setup-hooks. There is no preinstall, install, postinstall or prepare. There is no `gypfile`, no binding.gyp and no `*.node` among the 132 files. Registry `hasInstallScript` is absent, and so is lock `hasInstallScript` | VERIFISERT | tarball `package/package.json`; `find` |
| 6 | Runtime deps of typescript | None. In the tarball package.json, dependencies, optionalDependencies, peerDependencies and bundle(d)Dependencies are all absent, and they are absent in the registry metadata too. The lock entry has no dependencies, and the lock has no packages other than typescript | VERIFISERT | tarball package.json; lock |
| 7a | Dev-only | Only in devDependencies; lock `dev: true`; `dependencies: {}` | VERIFISERT | package.json, lock |
| 7b | Not in packed output | `npm pack --dry-run --json --ignore-scripts` on the HEAD export produced open-rng-engine@0.0.0 with 78 entries. No `node_modules/` path and no typescript file is in it, and `bundled` is empty. The published package.json would carry `dependencies: {}`, so it has zero runtime deps | VERIFISERT | pack JSON |
| 7c | Not reachable from packed core | The exports map is `"."` → `./src/index.ts`, `"./audited"` → `./src/audited/index.ts`, and `./package.json`. There is no main or bin. A transitive import walk from both entry points reaches 2 files, both `export {}` skeletons, with 0 external specifiers. `rg typescript src packages` finds only a comment (src/entropy/index.ts:5). The only external import in src/ is `node:crypto` | VERIFISERT | /tmp reach.py walk; rg |
| 8 | Advisories | `npm audit --json --package-lock-only` gave 0 (info 0, low 0, moderate 0, high 0, critical 0). GitHub advisory DB `GET /advisories?ecosystem=npm&affects=typescript@5.9.3` (unauthenticated) gave HTTP 200 with 0 results. The same query for `affects=typescript` at any version also gave 0. OSV `POST /v1/query` for npm typescript 5.9.3 gave HTTP 200 `{}` (0), and for any version also 0 | VERIFISERT (as of 2026-11-18 11:22 CET) | commands below |
| 9 | Info: release | 5.9.3 was published 2025-09-30 23:19:38 CEST (21:19:38Z). It is the latest 5.9.x; no 5.9.4 exists. Newer majors exist: 6.0.2, 6.0.3 and 7.0.2, with the latest tag at 7.0.2 | VERIFISERT | `registry.npmjs.org/typescript` time and dist-tags |

## Reasons for PASS

1. The integrity chain is consistent: lock = registry = downloaded tarball for sha512, and registry = tarball for sha1. The installed node_modules copy is identical to the registry tarball.
2. There are no install-time code paths (no lifecycle install scripts, no native build).
3. typescript has zero runtime dependencies, and so does the lock tree as a whole (1 package total).
4. typescript is dev-only. It is not in the packed tarball and is not reachable from the exports-map entry points, which import nothing external.
5. There are 0 known advisories across npm audit, GHSA and OSV.

## Non-blocking notes

- N1. Provenance is ABSENT (VERIFISERT that it is absent). typescript@5.9.3 has no npm provenance or Sigstore attestation, so the claim "built from microsoft/TypeScript at gitHead c63de15" is ANTATT, not VERIFISERT. The compensating evidence is the verified npm registry signature (4b), the publisher being typescript-bot under Microsoft-domain accounts (4c), the exact pin with lock integrity matching the registry (3), and zero install scripts and zero deps, which limits install-time exposure. Missing provenance is not treated as blocking for a devDependency that never ships. If the project's G4 policy requires provenance even for devDeps, this becomes FAIL, and the remediation would be a typescript version that carries attestations, which I have not checked.
- N2. Dev tooling in the packed file list imports typescript. There is no `files` field in package.json, so `npm pack` includes tools/ and test/. Of those packed files, `tools/ci/rule24-module-graph.mjs:26` (`import ts from 'typescript'`), `tools/ci/import-allowlist.mjs:96` (`createRequire(...)('typescript')`) and `test/fixtures/rule27-checker-{41d5ca7a,81d1d184}.mjs` load typescript. These are CI scripts, not the core: none is reachable from the exports map. The package is also `private: true`, so `npm publish` would refuse. Recommendation before any real publish: add a `files` allowlist (for example src/, LICENSE, NOTICE, README.md) so that dev tooling, and any implicit typescript import, cannot ship. This does not block the G4.
- N3. `npm audit` metadata shows `dependencies.prod: 1`. That is npm counting the root project, not a prod dependency: the lock contains only `""` and `node_modules/typescript` (dev: true).
- N4. The working tree was dirty at review time (uncommitted tools/ci/import-allowlist.mjs and an untracked fixture). Neither touches the manifests. This verdict is bound to commit 373873ae… and to lock sha256 c694ed58…. Any change to package.json or package-lock.json needs a new G4.

## Commands used (no secrets, public registry reads only)

```
git -C <repo> rev-parse HEAD; git log -1; git status --porcelain; git remote -v; git diff --stat
git show HEAD:package.json | sha256sum; git show HEAD:package-lock.json | sha256sum
git archive HEAD | tar -x -C /tmp/sec-g4-ts/repo
timeout 120 curl -sS https://registry.npmjs.org/typescript/5.9.3
timeout 60  curl -sS https://registry.npmjs.org/-/npm/v1/attestations/typescript@5.9.3     # 404
timeout 120 curl -sS -o ts.tgz https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz
openssl dgst -sha512 -binary ts.tgz | base64 -w0; sha1sum ts.tgz; sha256sum ts.tgz
tar -xzf ts.tgz; inspect package/package.json; find -name binding.gyp -o -name '*.node'
diff -r x/package <repo>/node_modules/typescript      # identical
(scratch) timeout 120 npm install --ignore-scripts --save-exact typescript@5.9.3; timeout 120 npm audit signatures
(HEAD export) timeout 120 npm pack --dry-run --json --ignore-scripts
(HEAD export) timeout 120 npm audit --json --package-lock-only
timeout 60 curl 'https://api.github.com/advisories?ecosystem=npm&affects=typescript@5.9.3&per_page=100'
timeout 60 curl 'https://api.github.com/advisories?ecosystem=npm&affects=typescript&per_page=100'
timeout 60 curl -X POST https://api.osv.dev/v1/query -d '{"package":{"name":"typescript","ecosystem":"npm"},"version":"5.9.3"}'
timeout 60 curl -X POST https://api.osv.dev/v1/query -d '{"package":{"name":"typescript","ecosystem":"npm"}}'
python3 import walk from exports entry points; rg over packed files for typescript imports
```

All scratch work was in /tmp/sec-g4-ts, which was deleted afterwards. No repo edits, no installs in the repo, no publish, no push, no secrets.
