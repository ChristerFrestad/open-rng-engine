# CI rule stubs (PH1 skeleton)

Each script below is a **stub**: it prints `STUB` and exits 2, so it can never be mistaken for a green check. PH1 replaces every stub with the real check and its scratch-materialised known-bad fixture.

| Stub | PLAN rule | What it will check |
|---|---|---|
| `rule22-exports-map.mjs` | 22 | `exports` has exactly `"."`, `"./audited"`, `"./package.json"` |
| `rule24-module-graph.mjs` | 24, RQ-FC-8 | nothing under `src/verify/`, no reset entry, and no cycling-adapter package reachable from production entries |
| `rule40-protected-names.mjs` | 40 | protected names per the C-9 format; exact-path self-exemption |
| `b8-dependencies.mjs` | B8, R-35 | `dependencies` is `{}` in every published package |
| `import-allowlist.mjs` | R-44 and others | per-module `node:` import allowlist (for example, `evidence/` imports only `createHash`) |

Already live (PH0): `tools/claims-lint.mjs` (B10, R-16) and `tools/qiu05-check.mjs` (DOD-PH0-QIU05).
