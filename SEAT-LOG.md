# SEAT-LOG

One line per commit, written before the commit by the committing seat. Columns: time (box `date`, CET) | seat | commit subject | O-55 hits (staged tree) | O-55 scanner sha256 | claims-lint hits (R-16) | QIU-05 factor hits.

| time | seat | commit subject | O-55 hits | scanner sha256 | claims-lint hits | QIU-05 hits |
|---|---|---|---|---|---|---|
| 2026-11-18 07:43:32 CET | CTO via executor | PH0: add Apache-2.0 LICENSE (unmodified), NOTICE, .gitignore, SEAT-LOG | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 07:43:37 CET | CTO via executor | PH0: README placeholder, package.json (dependencies {}), SECURITY stub, claims lint + QIU-05 check with known-bad fixtures | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 07:44:09 CET | CTO via executor | PH0: REMOTE-PENDING with exact intended remote values (awaiting CoS go) | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 07:46:18 CET | CTO via executor | PH0: known-bad fixtures materialised in scratch from u-escaped source; drop literal fixture files | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 07:50:13 CET | CTO via executor | PH0: record DoD status (local PASS items; remote items pending CoS go) | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 07:50:37 CET | CTO via executor | PH1 skeleton: strict tsconfig, src/ and packages/ layout per PLAN 3.1, CI rule stubs (no logic) | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 07:56:22 CET | CTO via executor | PH0 RP-7 follow-up: SECURITY.md live-channel wording (local; remote pending separate go) | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

## C-12 remote record (CoS C-12 GO, Principal widget answer 07:52 CET 2026-11-18)

- Seat: CTO via executor. Fresh clone /tmp/oreng-c12; remote main before = 449acd9548871be9952662cabe35f5efa5551596 (as expected).
- Branch ph0/remote-fixes, commit 92c36916ac6b72cc457bec960de48e1d45d37bff: LICENSE cfc7749b…3d30, NOTICE aa855cfb…3a40, README.md f5969137…fe43, package.json f2a3465b…847a, SECURITY.md ed42e491…3510 (all byte-identical to local HEAD 121b089).
- Pre-commit scans on full clone tree: O-55 0 hits (scanner 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882), claims-lint 0, QIU-05 0.
- PR https://github.com/ChristerFrestad/open-rng-engine/pull/2 ("Refs C-12 / RP-1, RP-5, RP-6, RP-7"). Checks: no checks configured (0 workflows, 0 check runs, main unprotected).
- Merged 2026-11-18T06:55:32Z (UTC) with --merge --match-head-commit 92c36916…; merge commit b019e37756269607a0724c6d7bffb1455033e131.
- Settings: PUT private-vulnerability-reporting (204); PATCH description; PUT topics (scope-block values).
- GETs: license.spdx_id Apache-2.0; licenseInfo.spdxId Apache-2.0; PVR {"enabled":true}; remote README claims-lint 0; dependencies {}; description and topics as set; main = b019e377….
- RP-7 live wording: local commit bd2b018, pending remote (separate go needed).

| 2026-11-18 07:56:35 CET | CTO via executor | PH0: REMOTE-PENDING applied status after C-12 (RP-1..RP-6 applied, RP-7 live wording pending) | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

## C-13 local history rewrite (CoS C-13 GO, local only)

- Time: 2026-11-18 07:58:16 CET. Seat: CTO via executor. Method: `git filter-branch --index-filter` removing `tools/fixtures/claims-lint/README.known-bad.md` and `tools/fixtures/qiu05/README.known-bad.md` from every commit (they were added by 2219f94 and deleted by 76f63b4); no other content changed. Remotes: 0 before and after.
- Evidence kept untouched: /workspace/rng-backup/open-rng-engine-0750.bundle (sha256 f8d765b4562c1fbdb2b8e2654bea7767b26751fb04a59fff1a3515130d685dfc).
- Old -> new (full sha):
  - 83595214571f72478ef87d90f1cf26bffc3041ed -> 83595214571f72478ef87d90f1cf26bffc3041ed (unchanged)
  - 2219f94a896c8d5972f36266eec81aff8eef418c -> eaa0fd7ce21b0b4ac56f98355c5fe055defa71ad
  - ddad16198e7db9fdc9ff8a8132726ed7a7181296 -> ed2665026ba02352d1aaec82d8c3e7874f19ab1c
  - 76f63b4b3c955aa64989730b87c7e8363780caac -> 801c55c06970001bdbe97e878b3552fda203ccc2
  - 0221274c39b4c83166dcdcd0d63a8193cfe0f817 -> d0940c9d00eec387883076e2d0b3293d486985e7
  - 121b089d51747ae2fa249e0b7896e09282cd9b40 -> c07889ec5061c7c59012c45ec9d100a56df12ffd
  - bd2b0188d5ba85789955c052a71e61fcfc25ee71 -> b575d94f30d029c98373811b2369e9325c63ed02
  - a9845fd5979a19c824f91123f58db77f8bc0f754 -> f9e0143c16cd5823b72a469695945920e56d8c1f
- Per-tree scans of every rewritten commit (HEAD tools claims-lint 2170cb05…, qiu05 806e274b…): O-55 0 hits each (scanner 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882); claims-lint 0 and QIU-05 0 on each tree that has README/package.json; 8359521 (no README/package.json) is unchanged and has 0 per-file hits.
- Proof: decoded fixture literals (taken in a scratch process from the 0750 bundle; 6 patterns) occur 0 times in `git log -p --all` and 0 times in the object store; control count in the 0750 bundle is non-zero. refs/original deleted, reflog expired, `git gc --prune=now --aggressive`, `git fsck --unreachable` empty.

| 2026-11-18 07:58:16 CET | CTO via executor | PH0: SEAT-LOG C-13 record (local history rewrite, old->new sha map) | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

## C-10 claims-lint allow-list (CPO-R97; rulings bdde9834…, DECISIONS L75)

- Allow-list S-P1, S-P1-short, S-R39, S-FIPS-1.0 (plain + typographic), S-PACK: \u-escaped, sha256-pinned to the CPO pins (pin mismatch exits 2). Exempts only certif*/complian* hits wholly inside an occurrence that is the whole line apart from comment/markdown wrappers. align* and FIPS never exempt. /drbg reserved sentence (L633) red via C10-drbg-reserved (NIST SP 800-90A / CAVP tokens). ARCHITECTURE.md disclaimer red (C-14).
- Tests: `node --test test/claims-lint.test.mjs` 133 pass / 0 fail; `--self-test` known-bad red + 127/127 near-miss; scratch removed.

| 2026-11-18 08:04:15 CET | CTO via executor | G1 C-10 (CPO-R97): claims-lint byte-exact allow-list, align/FIPS unconditional, near-miss tests | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
