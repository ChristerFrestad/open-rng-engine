# A25-2 design v1.2 addendum: URL scheme check (CTO ruling, 22:20 CET 2026-11-25)

Adds to v1.1 (verification/a25-2-design-v1.1.md, unchanged).

- In helper mode a resolved or loaded URL may only be `file:` (then held to the manifest at load), `node:` (builtin checks: forbidden 92, addon 93, dynamic import() not on the empty allowlist 94) or the virtual gate URL. Any other scheme (data:, blob:, http:, https: and so on) exits 89 EXIT_A25_MANIFEST_OUTSIDE.
- This is checked at four points: our resolve hook (after nextResolve, so it covers the whole chain below the late hook), the wrapper around the one allowed late resolve, our load hook, and the wrapper around the late load.
- Test: W-scheme in test/r-g64-a25-2-wiring.test.mjs. A late resolve to data:text/javascript gives 89 "late resolve: scheme", a static data: import gives 89 "resolve: scheme", and a late resolve to https: gives 89.
- Mutant M49, "scheme check skips data:", is added to tools/ci/a25-2-wiring-mutants.mjs. It is killed by W-scheme's message assertion, since the load-side verifyLoad would otherwise still give 89 ("not a file URL").
