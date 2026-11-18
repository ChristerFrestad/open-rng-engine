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

## C-11 R-93 replay invariant checker (CPO-R98; DECISIONS L77)

- blockPlan check before coding: PLAN L164 (R-56: MAX_DATA 65,520, fetch data+16 while remaining > 0) gives Σ widths = n + 16·⌈n/65520⌉ for n ≥ 1, identical to the CPO-R98 formula and cto-g1-spec.md L268. PLAN L605 pins n ≥ 1; n = 0 is RANGE_INVALID (R1 fail in replay). No discrepancy.
- src/entropy/blockPlan.ts (pure, SHARED-shaped) and src/verify/replayRandomBytes.ts (verification build only): R1 schema (§5.2 minus the hex pattern), R2 2n hex chars, R3 lowercase even-length hex, R4 reads.length + widths vs blockPlan(n), R5 count===width, R6 Σcount===bytesFetched, R7 bytesFetched===n+16·⌈n/65520⌉. First failure in spec order plus all failing invariants (R7 is implied by R4+R5+R6, so it is reported with R6).
- .ts sources run under Node 24 type stripping; no tsc on the box (not installed, no network installs), so the strict type-check is pending. tsconfig gains allowImportingTsExtensions + rewriteRelativeImportExtensions (TS ≥ 5.7) and erasableSyntaxOnly (TS ≥ 5.8).
- Corrects eb3d52a: its `npm test` script `node --test test/` does not run on Node 24; now `node --test "test/**/*.test.mjs"`.
- Tests: `npm test` 183 pass / 0 fail (claims-lint 133, replay 50).

| 2026-11-18 08:06:11 CET | CTO via executor | G1 C-11 (CPO-R98): R-93 randomBytes replay invariant checker (pure) + blockPlan(n), negative tests; fix npm test glob | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

## C-9 protected-names list commit (CPO-owned; CTO CONFIRMED)

- tools/protected-names.txt sha256 7f56688ee17193182f47cc7e048b2bc2b25baa7f3c0a1ea678cfa5c77144277b, format open-rng-engine/protected-names/v1, version 1, 38 entries (PN-001..PN-038). Validator g1-tools/pn-validate.py afe76d15… RESULT PASS; format inputs/cto-c9-protected-names-format.md dadae96e. No content change by CTO; file committed byte-identical to CPO's.
- Interim gate for this and later commits: g1-tools/o55-staged-wrapper.py (sha c99fe0b43af49537a58223e781187309821eb66ddef45b12ea3040507d1fd35b) around o55-scan.py 156340f7 (unmodified). Scans index bytes of every tracked path; the ONLY content exclusion is the exact path tools/protected-names.txt AND staged sha 7f56688e AND pn-validate PASS AND version 1 AND 38 entries; its path is still scanned; LICENSE not excluded. Scratch controls: good list 0; sibling .bak 38 hits; tools/other.txt 38; altered list 39; plant elsewhere 1; same name in another dir 38; worktree-only change ignored (index bytes) 0.

| 2026-11-18 08:09:00 CET | CTO via executor | C-9: add CPO protected-names list v1 (38 entries, sha 7f56688e, CTO CONFIRMED) on its own | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

## CPO-R97b tests (strict whole-line confirmed; C10-drbg-reserved confirmed; LICENSE exact-path+sha accepted)

- Added near-miss cases: every stem-bearing allowlisted sentence wrapped at every space is red; S-P1 soft-wrapped / indented continuation red. One case is green by construction and recorded as such: S-P1 split exactly before "Not c…ified. Not a validated module." leaves line 2 == S-P1-short (allowlisted alone) and line 1 with no stem token.
- S-FIPS-1.0 (plain + typographic) with SP 800-90B stays green; 800-90B->800-90A, ->NIST SP 800-90A, +CAVP are red. Rule C10-drbg-reserved widened from `NIST SP 800-90A` to any `800-90A` citation (bare "SP 800-90A" previously passed) plus CAVP. No relaxation of any lint decision.
- Tests: npm test 242 pass / 0 fail; --self-test known-bad red + 186/186 near-miss; scratch removed.

| 2026-11-18 08:09:39 CET | CTO via executor | C-10 tests (CPO-R97b): wrapped-sentence and one-line S-P1 hits; S-FIPS-1.0 800-90B green, 800-90A/CAVP red | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

## Rule 40 product scanner (not yet wired into scripts; integration is the next commit)

- tools/ci/rule40-protected-names.mjs sha256 d99ccb482f36c3c76da8dbc281aa369918fde1aa0a8c4fcdb934054bcbf4f45b (replaces the PH1 stub). Scans index bytes of every tracked path plus path names. Exactly two content exemptions by exact path string: tools/protected-names.txt (parsed as config; C-9 §4 + v1.1 errata parser; sha must equal the CPO approval pin in tools/protected-names.config.json: 7f56688e, version 1, 38 entries, CPO-R96a) and tools/protected-names.known-bad.json (escaped; decodes; materialised in scratch it hits 9/9 groups and both product-only entries). Config closed schema; any further exemption key red. References allowlist (R-79) supported with exact path, line, line sha, source tag on the line, CPO approver and begin/end anchors; empty today. LICENSE not exempt (scanned normally). Non-UTF-8 red (binary allowlist empty).
- Strict readings (for CPO/HoQ awareness): product positions = package.json name/description/keywords (any package.json), headings in any tracked .md, every path segment under docs/examples/; in a product position a bare singular/plural is red even inside a TECHNICAL_TERM form. JS casefold = toUpperCase().toLowerCase() after NFKC.
- Parity: one-off corpus of 2747 strings vs o55-scan.py 156340f7: identical except 3 strings that contain the CPO-R95 extra entry (expected). All o55 positive/negative controls plus the CPO-R95 positive control reproduce.
- Tests: test/rule40.test.mjs 181 pass / 0 fail; npm test 423 pass / 0 fail. Tracked R-81 fixture test/x13-fixtures/generic-vocabulary/ (README.md, package.json) scans 0.
- Scans on this commit: interim wrapper 0 hits (list excluded by exact path+sha after pn-validate), product scanner 0 hits / 0 config errors.

| 2026-11-18 08:15:06 CET | CTO via executor | Rule 40 product scanner (R-79/R-81, quality 7.5, C-9): list parser, approval pin, exact-path self-scan, product positions, references allowlist, M-60/M-61/M-71 tests | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

## Rule 40 integration + LICENSE guard

- package.json: check:rule40, check:rule40:fixture; check:ph0 now also runs rule40 (staged index) and its self-test. tools/ci/README marks rule40 LIVE. Interim O-55 wrapper gate stays recorded per commit until CTO retires it.
- tools/license-guard.mjs: LICENSE skipped only at exact path 'LICENSE' with sha256 cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30; altered/missing = red; same bytes at any other path not exempt. QIU-05 uses it (previously unconditional exclusion). Rule 40 does not exempt LICENSE at all.
- Tests: test/license-guard.test.mjs 12 pass / 0 fail (incl. scratch-clone end-to-end: altered LICENSE turns QIU-05 red). npm test 435 pass / 0 fail. check:ph0 exit 0.

| 2026-11-18 08:16:04 CET | CTO via executor | Integrate rule 40 scanner (npm check:rule40, check:ph0) and LICENSE exact-path+sha guard in QIU-05 | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

| 2026-11-18 08:31:59 CET | CTO via executor | Claims lint for CPO-R99/R100/R101/R102: pinned allowlist/terms/lab (45)/authority (36) configs; claims-surface scope incl. CHANGELOG/CONTRIBUTING/release notes, all package.json string values, .d.ts/JSDoc/shipped string literals (built half PENDING); validat/crypto-module/CMVP; strict phrase boundaries; S-P1 presence on README, P8 README, package.json and repo description; LICENSE not scanned by exact path+sha; CI rule 46; .gitattributes LF; README/package.json/REMOTE-PENDING S-P1 | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
- Tests: npm test 860 pass / 0 fail (claims-lint near-miss 574/574). check:ph0 exit 0. Remotes 0.

| 2026-11-18 08:33:47 CET | CTO via executor | Replay R0 (CPO-R99 O-69; spec errata E-1): params.n safe integer >= 1 checked before R1; mutant kills M-100..M-105, M-106 (replay half), M-108..M-110 (incl. CSPRNG trap), M-117 (b)-(d) | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
- Tests: npm test (see commit report). Strict tsc still PENDING (no tsc on the box); sources run via Node 24 type stripping only.

| 2026-11-18 08:34:23 CET | CTO via executor | Claims lint: quality v5.5.6 M-124/M-125/M-138/M-139 case sets; validat stem now also matches un-/in-/underscore-prefixed forms (M-124 unvalidated, M-138 schema_validation were green before) | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

| 2026-11-18 08:39:48 CET | CTO via executor | Strict tsc (CPO-R103): devDependency typescript 5.9.3 exact (--ignore-scripts, public registry; lock integrity sha512-jl1vZzPD…M5TgSw== verified against the downloaded tarball); dependencies {} kept (npm had dropped the empty key; restored); tsc --noEmit exit 0 on 16 files with no source change; typecheck added to check:ph0; node_modules excluded from claims scope | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

| 2026-11-18 08:42:29 CET | CTO via executor | Mutant kills M-122 (path variants, symlinks incl. repo escape, rule40 list symlink, LICENSE symlink) and M-126..M-132; lint: non-canonical path and tracked-symlink hits, .gitattributes LF rule and CRLF-on-surface hits, --surface p8-package; PH0-DOD CA-1 statement | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

| 2026-11-18 08:42:47 CET | CTO via executor | Fix forward: ce889a1e was committed with 1 failing test (typecheck.test.mjs node_modules fixture lacked .gitattributes, which the new M-130 check requires). Fixture updated; npm test 1132/0 | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

| 2026-11-18 08:49:14 CET | CTO via executor | CPO-R104: D-1 package.json keys at any depth; D-2 prefix matching for lab-names/authority-terms (left boundary only; lab/labs whole-word); G-4 certif/complian/align without left boundary; G-6 comparative anchors on lab/labs + every list entry; G-10 tracked node_modules/ path is red; G-1 M-103/M-104 assert exact R1; E-5 bytesFetched >= 17 boundary test. Tracked-tree false positives: none (0 rewordings) | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

| 2026-11-18 08:54:12 CET | CTO via executor | CPO-R105 G-11: list entries <= 3 chars need no following letter (>= 4 bare prefix; lab/labs whole-word); lab-names + BMMTestlabs (46 entries, sha 1d9e087b, CPO re-approval pending); tests for G-11 controls, M-148 plants, glued-left survivor, M-150, M-145 next-line; L218/L44 confirmed inverted. Tracked tree 0 hits (0 rewordings). Frozen remote bundle re-linted: 0 (not touched) | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |

| 2026-11-18 08:55:37 CET | CTO via executor | CPO-R106: authority-terms.txt # header reworded to describe R104/R105 matching; non-# lines byte-identical to 5f4ff573 (diff of non-# lines empty; non-# sha256 69c1338f075722b6ee5efd2cd92b273a1f7910b5d31119eb7325648433f86d31 both sides); new file sha 43091c7a pinned in claims-lint.mjs | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 08:56:57 CET | CTO via executor | F-15: verification/decision-rule-v1.md (transcribes quality.md 0202a82b section 3.2 L426-L445 and PLAN R-25 L133 / section 4.4 L730-L746; NOT YET FROZEN, freeze is HoQ's) + test/decision-rule.test.mjs; committed before any evidence run (+ test/typecheck.test.mjs scratch-clone copy now creates parent dirs for staged files in new dirs) | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 08:59:01 CET | CTO via executor | PH1: tools/ci/import-allowlist.mjs stub replaced by the real quality CI rule 27 check (L596; QR-25 L228; PLAN R-44 L152) + 19 known-bad scratch fixtures + test/rule27-import-allowlist.test.mjs; npm scripts check:rule27(+self-test); not in check:ph0 (red today only for 3 missing pairs; open question to CPO/HoQ); dist/ grep half PENDING | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 09:06:51 CET | CTO via executor | Rule 27 per HoQ ruling (Q1 no-more/banned forms block, no-fewer per dir + --phase-exit; Q2 all-import ban; Q3 scope src/, packages/capability/src, packages/mapping, verify/ with PLAN L535 binding path only) + PH1-M1 erratum entropy/ triggers (i)-(iii); CTO option (b): src/evidence/ and src/identity/ placeholders removed; check:rule27 + self-test added to check:ph0; trigger (ii) not firing on current tree | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 09:08:27 CET | CTO via executor | Rule 27 trigger (i) per HoQ tighten ruling: UPPER_CASE numeric carve-out replaced by exact-name allow-list {FINGERPRINT_BYTES} valid only as `export const FINGERPRINT_BYTES = 16;` (0x10 etc. red); fixtures (e) SEED_BYTES, (f) values/initializers, (g) let/var; blockPlan.ts control green; header + tools/ci/README.md: each new entry needs a HoQ ruling + fixture | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 09:10:05 CET | CTO via executor | Rule 27 --self-test 27 -> 32 per HoQ: allow-list red cases SEED_BYTES=32, FINGERPRINT_BYTES=15, ='16', let, non-exported const + export {} re-export, each checked for its expected reason (trigger (i) on src/entropy/a.ts); allow-list control green; mutant (allow-list loosened) turns self-test red | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 09:20:21 CET | CTO via executor | HoQ 2de685b2 gaps: G-12 globalThis reach fail-closed (alias/destructure/argument, window, Function/eval/.constructor; coreGuard exact forms green), G-13 require('node:module'/'module'), G-15 multi-declarator export opaque + fixture, G-16 fips identifier/computed fixtures; rule-27 --self-test 32 -> 42 with expected reasons; G-14 test kills MX-12 (p8-package key scan); scratch mutants: each new detection removed -> self-test exit 1 | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 09:28:24 CET | CTO via executor | HoQ 83aa9529 gaps: G-17 globalThis.<member> allow-list (empty: real core source uses none), G-18 process member allow-list (empty) + always-banned members on any base + alias/destructure red, G-19 module.require / .require( / non-call require red, G-20 M-152b/c/d/g + MX-12 (claims-lint p8-package key plant) inside rule-27 --self-test; self-test 42 -> 64 fixtures + 4 extra cases, expected reasons; scratch mutant per new detection -> self-test exit 1 | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 09:35:59 CET | CTO via executor | B-4 inputs (CTO option (a), v1.1 neutral rewording, no allow-list): verification/k-tests-v1.1.json f75299de, tool-pins-v1.1.json 605e9a99, m153-harness-mutant.md 0b017faa copied byte-identical from b4-prep (downloads/ not copied) + test/b4-inputs.test.mjs | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 09:40:22 CET | CTO via executor | HoQ FROZEN decision rule v1: inputs/decision-rule-v1-FROZEN.md (sha256 5d09c75a, 87 lines) copied byte-identical over verification/decision-rule-v1.md; sha pinned in test/decision-rule.test.mjs; NIT path: frozen text pins m153 0b017faa (L76), so m153 untouched and verification/ERRATA.md E-B4-1 added | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 09:58:35 CET | CTO via executor | HoQ 06cb884b: rewrite rule 27 on TypeScript 5.9.3 AST; G-23 unicode-escape identifiers/string keys, G-24 positive specifier allow-list, G-21/22 constructor reach + Reflect.construct/getPrototypeOf/__proto__, G-25 M-152c hasOwn at non-guard path; self-test 64 -> 80 + 4 controls; M-155/156/157 killed (old-checker survival recorded) | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 10:32:36 CET | CTO via executor | HoQ 65233aac + addendum 2: G-26 Reflect identifier and computed-key rule (number / literal-union on an empty production allow-list), G-27 relative specifier resolve + git ls-files + ban js under src, M-160 parse error is red, M-161 8x6 computed-key matrix with test-only allow-list injection, M-162 entropy backstop via --import; self-test 80 -> 137 + 4; 06cb884b and 41d5ca7a checkers vendored; hand mutants killed by check:ph0 / npm test | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 10:47:03 CET | CTO via executor | Replace rule22/rule24/B8 stubs with live checks in check:ph0: core exports keys exactly {".", "./audited", "./package.json"} (PLAN L136/L537/L825(22), quality L278/L584); production module-graph from those entries (PLAN L146/L198/L496/L825(24), quality L593/L616, cto-g1-spec L74); dependencies {} plus exact devDeps and lockfile integrity (PLAN L87/L143/L815/L825(7)). Known-bad fixtures scratch-materialised from u-escaped source; previous stubs recorded as exit 2. Source: live exports map plus the exact entropy randomFillSync pair so rule 27 no-fewer stays green. PENDING items listed in the tools and the report. | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
| 2026-11-18 11:14:39 CET | CTO via executor | HoQ 81d1d184 (3bbf6fd2): G-28 constructor-reach closed (banned string literals constructor/__proto__/prototype anywhere; lookupGetter/Setter and defineGetter/Setter; Object GOPD/getPrototypeOf/setPrototypeOf/defineProperty outside coreGuard exact forms; computed keys in destructure/object literals unless numeric; element access only numeric literal or number-typed identifier; no as/<T>/any/unknown/non-null/ts-ignore/ts-nocheck; ts-expect-error pinned at the entropy import; Error.prepareStackTrace/captureStackTrace/stackTraceLimit red). G-29 backstop wraps 19 entry points including prototypes and HoQ unwrapped exports, frozen defineProperty, identity and counters at every call and exit, saved native Error, NODE_OPTIONS plus Worker execArgv (eval rewritten to a file), innermost src/ frame must be in src/entropy/. G-30 unparsed-tracked and js-under-src fixtures; tracked extensionless/.json under src red (allow-list empty). M-163..M-167 and b1..b6 fixtures. Self-test 137+4 -> 169+7. 81d1d184 checker and backstop vendored. Live blockPlan/replay rewritten to stay green (no unknown/as/!). | 0 | 156340f762ea1cdfff5866d8638e9cc82c75bcc53e531237b38cabb68d489882 | 0 | 0 |
