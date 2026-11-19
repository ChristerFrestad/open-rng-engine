# PH0 Definition of Done: local status

PLAN r4.9 FROZEN `206e0511…`, §7 PH0 row. Recorded by the CTO seat (via executor) on 2026-11-18 at about 07:50 CET. "Local" means this repo, which has 0 remotes. Remote-only items are listed in `REMOTE-PENDING.md`.

| DoD item | Local result | Remote | Evidence |
|---|---|---|---|
| DECISIONS records P1, P2, P4, P5, P8 and P3, P6, P7, P9, P10, P11 as approved | PASS (desk `DECISIONS.md` `64868584…`) | n/a | desk file |
| `test -f LICENSE` | PASS: the unmodified Apache-2.0 text, sha256 `cfc7749b…3d30`; copyright is in `NOTICE` | n/a | `LICENSE`, `NOTICE` |
| GitHub `licenseInfo` non-null | n/a locally | **FAIL observed** (`NOASSERTION`). Fix pending a CoS go | REMOTE-PENDING RP-1 |
| README, `package.json` description/keywords and the repo description pass R-16 (0 hits) | PASS: 0 hits over 5 scope items, including the intended repo description and topics | the remote README has 1 hit; fix pending a CoS go | `npm run check:ph0`; RP-3, RP-5 |
| `dependencies` = {} (B8, R-35) | PASS (`{}`; `"private": true`, which blocks accidental publish) | remote has 1 dependency; fix pending a CoS go | `package.json`; RP-6 |
| `SECURITY.md` stub with private reporting enabled | stub PASS; it says private reporting is *to be enabled* | PVR `enabled:false`; enabling it is pending a CoS go | `SECURITY.md`; RP-2 |
| `rng/CODE_QUALITY.md` pinned to v5.5 `afc63bac` + v5.5.1 `bb2caf63` + v5.5.2 `8eed0132` with both owner columns | PASS for PH0 (desk path per the PLAN's `rng/` prefix: `/home/box/company/rng/CODE_QUALITY.md`). It carries 114 QR/QIU/RQ-FC rows plus 18 GR rows. Unassigned cells are marked `OPEN-G1`, which blocks the G1 gate, not PH0 | n/a | desk file |
| DOD-PH0-QIU07: 0 claims-lint hits, and the known-bad fixture turns red | PASS: 0 hits; the scratch fixture (materialised from `\u`-escaped source, never a literal) turns red | n/a | `tools/claims-lint.mjs --self-test` |
| DOD-PH0-QIU05: 0 targeting factors (frame §3.3 classes F1–F4) | PASS: 0 factor hits over all tracked files; the P2 no-targeting sentence is present in the README; the scratch fixture turns red in all four classes. Listed for the record, not a project-material factor: the Principal's own nationality (frame §3.3). It appears in no repo material and is mitigated by P6 (pure OSS) and P2 | n/a | `tools/qiu05-check.mjs --self-test` |
| P8 placeholder README passes the claims lint before publish (R-31) | local README PASS. The P8 publish is reported done by CoS and was not checked here | not checked (npm read not done) | n/a |
| O-55 scrub (G1 precondition) | PASS: 0 hits on the staged tree at every commit (scanner sha256 `156340f7…9882`) | n/a | `SEAT-LOG.md` |

G-PH0 (CoS → Principal) cannot pass until RP-1, RP-2 and RP-5/RP-6 are applied remotely. Those need a CoS go and are not in this seat's remit.

**CA-1 statement (CPO-R100 CA-1, G-PH0 exit condition; M-131):** the claims lint does **NOT** scan `LICENSE`. It skips only the exact path `LICENSE` whose bytes hash to sha256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`; changed or missing bytes are red and the changed text is linted as content. Tests: `test/claims-lint.test.mjs` ("CA-1: unmodified LICENSE at the exact path is not scanned", "CA-1: changed LICENSE bytes are red and the changed text is linted as content", "CA-1: a missing LICENSE is red; a LICENSE-like sibling is linted, never exempt"). Integrity: CI rule 46 `tools/ci/rule46-license-integrity.mjs` (LF-7), tests in `test/rule46-gitattributes.test.mjs`.
