# REMOTE-PENDING

Remote-only PH0 items. **None of these has been applied.** Every item waits for an explicit CoS go. This local repo has 0 remotes, and no seat working here pushes, publishes or changes repository settings.

Observed state comes from read-only `gh api` GETs on 2026-11-18 at about 07:42 CET, with the remote `main` head at `449acd95`.

| # | Item | Observed on remote | Intended exact value | PH0 DoD hook | Status |
|---|---|---|---|---|---|
| RP-1 | GitHub `licenseInfo` | `license.spdx_id` = `NOASSERTION`. The remote `LICENSE` (215 lines, sha256 `9ee5daa52c316d79ddb883c8811ad8b2d0255101a5153bab0e942cba51f3c3d8`) has a 13-line per-file boilerplate header added above the license text, and the appendix copyright line is filled in. GitHub's license detection does not match it. | Replace `LICENSE` with the unmodified Apache-2.0 text from this repo (sha256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`, 202 lines, from apache.org/licenses/LICENSE-2.0.txt). Move the copyright line to `NOTICE` (`Copyright 2026 Christer Frestad`). Expected result: `licenseInfo.spdxId` = `Apache-2.0`. | `test -f LICENSE` and `licenseInfo` non-null | awaiting CoS go |
| RP-2 | Private vulnerability reporting (PVR) | `GET /repos/ChristerFrestad/open-rng-engine/private-vulnerability-reporting` returns `{"enabled":false}` | Enabled: `PUT /repos/ChristerFrestad/open-rng-engine/private-vulnerability-reporting`, then a GET returns `{"enabled":true}`. After that, update `SECURITY.md` to say the channel is live. | `SECURITY.md` stub with private reporting enabled | awaiting CoS go |
| RP-3 | Repo description | Already set. It passes the claims lint (0 hits). | The exact value in the scope block below, matching the `package.json` description. | Repo description passes R-16 | awaiting CoS go (optional: the current value already passes) |
| RP-4 | Repo topics | `[]` | The exact list in the scope block below, matching the `package.json` keywords. | none (hygiene) | awaiting CoS go |
| RP-5 | Remote `README.md` | sha256 `25b8d22145355c3581c3a3ee5875158cf8f1e07ceb0c4937650257a50faf200b`. Line 7 has **1 hit for the R-16 certification-stem pattern**, so it fails PH0 "README passes the claims lint". | Replace it with this repo's `README.md` (0 hits). | README passes R-16 (0 hits); DOD-PH0-QIU07 | awaiting CoS go (needs a PR) |
| RP-6 | Remote `package.json` | `"dependencies": {"@noble/hashes": "^1.7.1"}`, `version` `0.1.0`, `main` `dist/index.js` (no build exists) | Replace it with this repo's `package.json`: `dependencies` = `{}` (B8, R-35). | `dependencies` = {} | awaiting CoS go (needs a PR) |
| RP-7 | Remote `SECURITY.md` | It points to the advisories URL, but PVR is disabled (RP-2), so that link is not a live private channel. | This repo's `SECURITY.md` until RP-2 is done, then the live wording. | SECURITY stub | awaiting CoS go |

Intended values that the claims lint checks (`tools/claims-lint.mjs` reads this block):

<!-- CLAIMS-LINT-SCOPE:BEGIN -->
description: General-purpose Node.js library for unbiased random integers, shuffles, samples and weighted picks on the platform CSPRNG. Pre-alpha.
topics: random, csprng, random-integer, shuffle, sampling, weighted-random, nodejs
<!-- CLAIMS-LINT-SCOPE:END -->

How these are applied, after the CoS go only: one PR from a seat that holds the remote, carrying `LICENSE`, `NOTICE`, `README.md`, `package.json` and `SECURITY.md` from this repo, followed by the RP-2, RP-3 and RP-4 settings calls. This file does not authorise any of it.
