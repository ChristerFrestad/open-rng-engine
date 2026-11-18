# CI rule stubs (PH1 skeleton)

Each script below is a **stub**: it prints `STUB` and exits 2, so it can never be mistaken for a green check. PH1 replaces every stub with the real check and its scratch-materialised known-bad fixture.

| Stub | PLAN rule | What it will check |
|---|---|---|
| `rule22-exports-map.mjs` | 22 | `exports` has exactly `"."`, `"./audited"`, `"./package.json"` |
| `rule24-module-graph.mjs` | 24, RQ-FC-8 | nothing under `src/verify/`, no reset entry, and no cycling-adapter package reachable from production entries |
| `rule40-protected-names.mjs` | 40 | **LIVE** (not a stub): protected names per the C-9 format, CPO approval pin, exact-path self-exemption, product positions, references allowlist |
| `rule46-license-integrity.mjs` | quality CI 46 (CPO-R101 LF-7) | **LIVE** (not a stub): the tracked `LICENSE` (index and worktree) hashes to the pinned unmodified Apache-2.0 sha256 cfc7749b; missing or changed bytes exit 1 |
| `b8-dependencies.mjs` | B8, R-35 | `dependencies` is `{}` in every published package |
| `import-allowlist.mjs` | R-44 and others | per-module `node:` import allowlist (for example, `evidence/` imports only `createHash`) |

Already live (PH0): `tools/claims-lint.mjs` (B10, R-16) and `tools/qiu05-check.mjs` (DOD-PH0-QIU05).
Live (G1/PH1): `tools/ci/rule40-protected-names.mjs` (PLAN rule 40 / quality CI 31): `npm run check:rule40` scans the staged index bytes; `--self-test` materialises the escaped known-bad fixture in scratch. `tools/license-guard.mjs`: LICENSE is skipped only by exact path + sha256 cfc7749b; altered bytes are red.
The interim O-55 gate (g1-tools/o55-staged-wrapper.py around o55-scan.py 156340f7, outside the repo) stays recorded in SEAT-LOG until CTO retires it.
Claims lint (CPO-R99..R102): scope = claims surfaces (README*, docs/, ARCHITECTURE, SECURITY, NOTICE, CHANGELOG/CONTRIBUTING/release notes, every string value of every package.json, the REMOTE-PENDING repo description/topics), plus shipped .d.ts, JSDoc and every string literal in shipped source (src/, packages/*/src/). The built-output half (dist/) is PENDING until a build exists. Pinned configs: tools/claims-allowlist.json, tools/claims-terms.json, tools/lab-names.txt, tools/authority-terms.txt (exact path + sha256 in tools/claims-lint.mjs; any change is a config error, exit 2).
