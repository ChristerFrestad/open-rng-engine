# REMOTE-PENDING

Remote-only PH0 items. **Status update 2026-11-18 (C-12):** RP-1 to RP-6 are applied on the remote under CoS C-12 GO (the Principal's own widget answer at 07:52 CET, quoted verbatim in the CoS transcript; not repeated here). RP-7 is applied with the stub wording; its live-channel wording is a local commit that is pending a separate go. The original text below records the pre-C-12 state. Every remote item waits for an explicit CoS go. This local repo has 0 remotes, and no seat working here pushes, publishes or changes repository settings.

Observed state comes from read-only `gh api` GETs on 2026-11-18 at about 07:42 CET, with the remote `main` head at `449acd95`.

| # | Item | Observed on remote | Intended exact value | PH0 DoD hook | Status |
|---|---|---|---|---|---|
| RP-1 | GitHub `licenseInfo` | `license.spdx_id` = `NOASSERTION`. The remote `LICENSE` (215 lines, sha256 `9ee5daa52c316d79ddb883c8811ad8b2d0255101a5153bab0e942cba51f3c3d8`) has a 13-line per-file boilerplate header added above the license text, and the appendix copyright line is filled in. GitHub's license detection does not match it. | Replace `LICENSE` with the unmodified Apache-2.0 text from this repo (sha256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`, 202 lines, from apache.org/licenses/LICENSE-2.0.txt). Move the copyright line to `NOTICE` (`Copyright 2026 Christer Frestad`). Expected result: `licenseInfo.spdxId` = `Apache-2.0`. | `test -f LICENSE` and `licenseInfo` non-null | APPLIED 2026-11-18 via PR #2 (merge `b019e377`); GET `license.spdx_id` = `Apache-2.0`, GraphQL `licenseInfo.spdxId` = `Apache-2.0` |
| RP-2 | Private vulnerability reporting (PVR) | `GET /repos/ChristerFrestad/open-rng-engine/private-vulnerability-reporting` returns `{"enabled":false}` | Enabled: `PUT /repos/ChristerFrestad/open-rng-engine/private-vulnerability-reporting`, then a GET returns `{"enabled":true}`. After that, update `SECURITY.md` to say the channel is live. | `SECURITY.md` stub with private reporting enabled | APPLIED 2026-11-18 (PUT 204); GET returns `{"enabled":true}` |
| RP-3 | Repo description | Already set. It passes the claims lint (0 hits). | The exact value in the scope block below, matching the `package.json` description. | Repo description passes R-16 | APPLIED 2026-11-18 (PATCH); GET description equals the scope-block value |
| RP-4 | Repo topics | `[]` | The exact list in the scope block below, matching the `package.json` keywords. | none (hygiene) | APPLIED 2026-11-18 (PUT topics); GET returns the 7 scope-block topics (GitHub reorders them) |
| RP-5 | Remote `README.md` | sha256 `25b8d22145355c3581c3a3ee5875158cf8f1e07ceb0c4937650257a50faf200b`. Line 7 has **1 hit for the R-16 certification-stem pattern**, so it fails PH0 "README passes the claims lint". | Replace it with this repo's `README.md` (0 hits). | README passes R-16 (0 hits); DOD-PH0-QIU07 | APPLIED 2026-11-18 via PR #2; remote README sha256 `f5969137…fe43`, claims lint 0 hits |
| RP-6 | Remote `package.json` | `"dependencies": {"@noble/hashes": "^1.7.1"}`, `version` `0.1.0`, `main` `dist/index.js` (no build exists) | Replace it with this repo's `package.json`: `dependencies` = `{}` (B8, R-35). | `dependencies` = {} | APPLIED 2026-11-18 via PR #2; remote `dependencies` = `{}` |
| RP-7 | Remote `SECURITY.md` | It points to the advisories URL, but PVR is disabled (RP-2), so that link is not a live private channel. | This repo's `SECURITY.md` until RP-2 is done, then the live wording. | SECURITY stub | STUB APPLIED 2026-11-18 via PR #2 (sha256 `ed42e491…3510`). Live-channel wording is committed locally, **pending remote**: it needs a separate go, because it is outside the C-12 yes |

Intended values that the claims lint checks (`tools/claims-lint.mjs` reads this block):

<!-- CLAIMS-LINT-SCOPE:BEGIN -->
description: General-purpose Node.js library for unbiased random integers, shuffles, samples and weighted picks on the platform CSPRNG. Pre-alpha.
topics: random, csprng, random-integer, shuffle, sampling, weighted-random, nodejs
<!-- CLAIMS-LINT-SCOPE:END -->

How these are applied, after the CoS go only: one PR from a seat that holds the remote, carrying `LICENSE`, `NOTICE`, `README.md`, `package.json` and `SECURITY.md` from this repo, followed by the RP-2, RP-3 and RP-4 settings calls. This file does not authorise any of it. C-12 (applied 2026-11-18): PR https://github.com/ChristerFrestad/open-rng-engine/pull/2, head `92c36916ac6b72cc457bec960de48e1d45d37bff`, merged as `b019e37756269607a0724c6d7bffb1455033e131` with `--merge --match-head-commit`; no checks are configured on the repo.
