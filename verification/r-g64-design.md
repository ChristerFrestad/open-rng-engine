# R-G64 design: trusted helpers make the counted calls (closes R-G64-SRC and R-G64-SCALE together)

Status: design only, for HoQ review (CTO request 2026-11-25). No code path changes in this PR. The only code
added is a bench under `verification/bench/`, which is not evidence, not a gate, and not run by `npm test`.
Refs the R-G64-SRC and R-G64-SCALE residuals in `verification/harness/README.md` (K3g section).

## 0. Decision being designed (CTO)

R-G64-SRC and R-G64-SCALE close together. The trusted launcher, or helper processes it starts, makes the
engine's public calls itself (`integer`, `shuffle`, `sample`, `weightedPick` from `src/index.ts`). It feeds the
outcomes straight into incremental collector checks and digests, and streams battery-tool input over pipes in
bounded chunks. Untrusted runners no longer supply records, and `spawnSync`/`maxBuffer` leaves the counted path.

What this note does not decide: the outcome count M per family or a staged cut (section 2 lists options for
HoQ and CPO), whether entries of one call shape may share one stream (section 2, option B), and how a
battery tool consumes a parallel stream (section 4.4, open question Q3).

## 1. Parallel trusted helper topology

### 1.1 Processes

- **Launcher**: `verification/harness/evidence-launcher.mjs`, entered only through `startEvidenceRun` under
  the backstop preload with an open grant, after `assertEvidenceRunReady(ROOT)` (as today, JL-1).
- **Helper** (new): `verification/harness/evidence-helper.mjs`. The launcher starts N helpers with
  `child_process.spawn` (async, never `spawnSync`), `stdio: ['ignore', 'ignore', 'inherit', 'pipe']`, so the only
  data channel is fd 3, which the launcher reads. A helper takes exactly three arguments: the K entry id, its
  part index j, and its outcome count n_j. It takes the K entry from its own read of
  `verification/k-tests-v1.1.json`, never from its arguments beyond the id (same rule as G64-M6).
- A helper imports `src/index.ts` itself, makes n_j × w public calls (w = `windowWidth(k)`), and writes
  fixed-width frames to fd 3 with `fs.writeSync`, so a full pipe blocks the helper (section 4.3).
- No untrusted runner exists on the counted path. `runCounted(runner, ...)` and the fd-3 JSON-line
  `reportEvidenceResult` path stay only until the helper path lands, then are retired in the same PR
  (section 5 lists which mutants move).

### 1.2 Trust base after the change

Node binary (`process.execPath`, the one the readiness guard already checks), `src/**` (the engine), the
backstop `tools/ci/entropy-backstop.mjs`, `verification/harness/{evidence-entry,evidence-launcher,
evidence-helper,collector,wave1-evidence}.mjs`, `verification/k-tests-v1.1.json`, and the pinned battery
binaries (G-55). Nothing a runner or test writes is in it. The launcher pins the helper's sha256 and its own
sha256 in the run header (section 1.3), so a changed helper is visible in every digest it contributes to.

### 1.3 Binding outcomes to the engine build (src digest)

`srcDigest` = sha256 over the sorted list of `relative path \0 sha256(file bytes) \n` for every file under
`src/` (the bench implements it as `srcDigest()`; today it reads
`fc6cc4f4bd53ef42c6900d579dfa27e653af0914b0be8e4a9f6ff62668d45c0e`, 12 files, at main `c65c2316`).

- The launcher computes `srcDigest` once before spawning and passes nothing about it to helpers.
- Each helper computes `srcDigest` before its `import()` of `src/index.ts` and again after its last call, and
  writes both into its header and trailer frames. The launcher voids the part unless both equal its own value.
- The readiness guard already requires a clean tracked tree; the launcher re-runs the clean-tree check after
  the last helper exits, and voids the run if `src/` changed.
- Residual, named: a file swapped and swapped back between the helper's first digest and the ESM loader's read
  is not caught by digests alone. The before/after digests plus the clean-tree checks narrow it to a process
  that can write `src/` during a run, which the trust base already excludes. HoQ to rule whether that is enough.

### 1.4 Deterministic partitioning and merge order

For a K entry with outcome target M (in the entry's `n_unit`, so tuples for w > 1) and N helpers:

- n_j = floor(M / N) + (j < M mod N ? 1 : 0), for j = 0..N-1. The plan (id, M, N, every n_j) is fixed before
  any spawn and written into the run header; it never depends on outcomes or timing.
- A tuple of width w never straddles parts: helper j makes exactly n_j × w calls and emits n_j tuples.
- Merge order is part order j = 0..N-1, regardless of finish order. The counted stream is defined as the
  concatenation part 0 ‖ part 1 ‖ … ‖ part N-1. Outcome content is random; only the assignment and the order
  are deterministic.
- Sequential statistics (runs, serial correlation, overlaps, coupon collector, the successive-call and
  t/t+1 contingency tables) are computed per part with a mergeable state: the accumulator plus the part's
  first and last (window − 1) outcomes, and for coupon collector the prefix up to the part's first complete
  segment. Merging j and j+1 adds the boundary contributions as if the parts were one stream. Unit tests must
  show, for every K statistic, that merge(parts) equals the one-pass statistic over the concatenation at
  small n (new tests, section 5).
- `duplicates` needs a global view: each part writes a sorted run of 128-bit outcome hashes to a temp file in
  the run directory; the launcher merges runs in part order and counts equal neighbours. At 10^9 outcomes this
  is about 16 GB of disk per entry, deleted after the statistic. (A 128-bit hash collision changes the count
  with probability about 10^18 / 2^129, which this note treats as zero; HoQ may require full outcomes instead.)

### 1.5 How n and the digests combine

- Launcher-side, per part: n_j' = number of outcomes the launcher itself decoded and shape-checked
  (`outcomeShapeError` per outcome), and d_j = sha256 of the data-frame payload bytes in order, computed by the
  launcher. The helper's trailer repeats its own count and payload sha256; any mismatch voids the part.
- Per entry: n = Σ n_j', and the entry is counted only if n_j' = n_j for every j. The content digest is
  sha256(header ‖ d_0 ‖ … ‖ d_{N-1}), where header = canonical JSON of {id, M, N, n_j list, srcDigest,
  launcher sha256, helper sha256, encoding}. This replaces today's sha256 of `[id, n, records]`.
- Duplicate-digest rejection (G64-M5) stays, now on this content digest.
- The digest is computed incrementally; no record array is ever held, so `statisticFromRecords` is replaced
  by the mergeable accumulators above (`evidenceStatistic` keeps its `launcherCounted` gate, GM-6).

## 2. Per-family budget at N helpers

Measured on this box (8 vCPU Intel Xeon, Node v24.22.1), stage C of the committed bench: the engine's public
call, the per-outcome shape check, incremental sha256, and 64 KiB frames into a pipe with back-pressure. Two
runs; the table uses their mean. "Own stream per entry" means every K entry gets its own 10^9 outcomes (today's
reading of `n` in `k-tests-v1.1.json`). "One stream per shape" means entries with the same call shape read the
same outcomes (option B below, not approved). Generated by `node verification/bench/r-g64-budget.mjs`.

| Call shape | K entries | Stage C ns, run 1 | Stage C ns, run 2 | Core-h per 10^9 calls | Core-h, own stream per entry | Core-h, one stream per shape |
|---|---|---|---|---|---|---|
| randomInt [0,2) | 6 | 1841 | 1766 | 0.50 | 3.0 | 0.5 |
| randomInt [1,7) | 6 | 2206 | 2319 | 0.63 | 3.8 | 0.6 |
| randomInt [1,38) | 6 | 2893 | 3016 | 0.82 | 4.9 | 0.8 |
| randomInt [1,53) | 6 | 2298 | 2310 | 0.64 | 3.8 | 0.6 |
| randomInt [0,100) | 6 | 2294 | 2365 | 0.65 | 3.9 | 0.6 |
| randomInt [0,2147483649) | 6 | 3421 | 3341 | 0.94 | 5.6 | 0.9 |
| randomInt [0,4294967296) | 6 | 1749 | 2097 | 0.53 | 3.2 | 0.5 |
| randomInt [0,38) | 7 (1 tuple, w 2) | 2730 | 3163 | 0.82 | 6.5 | 1.6 |
| randomInt [0,54) | 6 | 2165 | 2104 | 0.59 | 3.6 | 0.6 |
| randomInt [0,4294967297) | 6 | 4030 | 3547 | 1.05 | 6.3 | 1.1 |
| randomInt [0,281474976710656) | 6 | 2235 | 1961 | 0.58 | 3.5 | 0.6 |
| randomInt [0,37) | 1 (1 tuple, w 2) | 3131 | 3282 | 0.89 | 1.8 | 1.8 |
| shuffle n=52 | 14 | 130404 | 130029 | 36.17 | 506.4 | 36.2 |
| shuffle n=54 | 1 | 133649 | 148893 | 39.24 | 39.2 | 39.2 |
| shuffle n=104 | 1 | 250798 | 290167 | 75.13 | 75.1 | 75.1 |
| shuffle n=312 | 1 | 794771 | 911219 | 236.94 | 236.9 | 236.9 |
| shuffle n=416 | 1 | 1025181 | 1127136 | 298.93 | 298.9 | 298.9 |
| shuffle n=1000 | 1 | 2333135 | 2869217 | 722.55 | 722.5 | 722.5 |
| sample n=52 k=5 | 7 | 10673 | 11296 | 3.05 | 21.4 | 3.1 |
| sample n=52 k=9 | 11 | 21510 | 23283 | 6.22 | 68.4 | 6.2 |
| sample n=80 k=20 | 22 | 62435 | 63687 | 17.52 | 385.4 | 17.5 |
| weightedPick [1,3,6] | 6 | 2943 | 2920 | 0.81 | 4.9 | 0.8 |
| weightedPick W-A | 12 (11 tuple, w 2/5) | 4300 | 4326 | 1.20 | 63.5 | 6.0 |
| weightedPick W-B | 12 (11 tuple, w 2/5) | 2626 | 2593 | 0.72 | 38.4 | 3.6 |
| Total | 157 | | | | 2511 | 1457 |

Per primitive (core-h, own stream / one stream per shape):
- randomInt: 50 / 10
- shuffle: 1879 / 1409
- sample: 475 / 27
- weightedPick: 107 / 10

Measured stage-C scaling, shuffle n=52, P concurrent helpers on this box (total calls/s vs P=1):
- run 1: P=1 1.00x, P=2 1.96x, P=4 3.50x, P=8 4.90x
- run 2: P=1 1.00x, P=2 2.01x, P=4 3.34x, P=8 5.03x

Wall-clock at N helpers = core-hours / speedup(N). On this box the measured speedup is 4.9x to 5.0x at N = 8,
not 8x (the per-helper cost rose from about 130 µs to 160–300 µs per shuffle-52 call). Beyond 8 helpers no
scaling was measured; the figures below for N > 8 assume the same 0.61 efficiency on more cores and are
labelled as an assumption.

| Scope (10^9 outcomes per entry) | Core-h | N = 1 | N = 8 on this box (4.9x) | N = 64, assumed 0.61 efficiency |
|---|---|---|---|---|
| All 157 entries, own stream | 2511 | 105 days | 21.3 days | 2.7 days |
| All 157 entries, one stream per shape | 1457 | 61 days | 12.4 days | 1.6 days |
| shuffle n = 104, 312, 416, 1000 only (4 entries) | 1333 | 56 days | 11.3 days | 1.4 days |
| shuffle n = 1000 alone | 723 | 30 days | 6.1 days (all 8 helpers on it) | 18.5 h |
| Everything except those 4 shuffles, own stream | 1178 | 49 days | 10.0 days | 1.3 days |
| randomInt + sample + weightedPick, own stream | 632 | 26 days | 5.4 days | 16 h |

Plain statement: at M = 10^9 the four large shuffles (n ≥ 104) are infeasible on this box in any routine
cycle; shuffle n = 1000 alone needs about six days with all eight helpers. The engine call dominates
(stage A alone is 79 % or more of stage C for every shape in both runs), so moving checks or digests elsewhere will not change this.

### Options for HoQ and CPO to rule on (not chosen here)

- **A. Keep M = 10^9 for every entry** and run on a larger machine or over days, with the staged checkpoints
  of section 4.5. Cost as in the table.
- **B. One stream per call shape** instead of per entry: entries of one shape read the same outcomes
  (tuple entries read windows of it). Cuts 2511 to 1457 core-h, almost all of it from sample and shuffle-52.
  It makes the statistics of those entries dependent on each other, which the multiple-testing plan must
  allow. Needs HoQ.
- **C. Per-family M**: M = 10^9 for R, W, P and shuffle n ≤ 54, and a lower M for shuffle n ≥ 104
  (10^8 costs 133 core-h, 10^7 costs 13). This amends CPO-R107 B-3 for those entries and lowers their power;
  every χ² cell expectation must be rechecked at the lower M. Needs CPO and HoQ.
- **D. Staged**: stage 1 runs every entry at 10^8 (251 core-h own stream, about 2.1 days at N = 8 here);
  stage 2 takes a named subset to 10^9. Needs HoQ to name the subset and the decision rule between stages,
  fixed before stage 1 starts.
- **E. Engine throughput** (for CTO, outside this design): the engine draws entropy per call via
  `randomFillSync`. Buffered entropy would change `src/`, so its own PR, review and a new src digest, and
  this bench re-run.

## 3. Bench provenance

- Bench: `verification/bench/r-g64-throughput.mjs`, sha256
  `7c35d9e4d3484a9da5ada4096fa5309821fa9ebc3bf6bc5781ec539aa10d3d23` (printed by the bench in its own log
  header). Usage: `node verification/bench/r-g64-throughput.mjs --seconds 1.5 --scale 1,2,4,8 --json <file>`.
- Runs, committed: `r-g64-throughput-run1.{log,json}` (start load 1.43) and `r-g64-throughput-run2.{log,json}`
  (started right after run 1, start load 6.34, because the box is shared; its per-shape stage-C figures differ from run 1 by at most 23 %, the largest gap being shuffle n = 1000,
  2.33 ms vs 2.87 ms per call).
- Budget: `verification/bench/r-g64-budget.mjs` reads only those two JSON files.
- Not evidence: the bench keeps no outcomes, opens no grant, and is not in any gate or `npm test`.
- Earlier single-shape bench (outside the repo, 2026-11-25) gave shuffle-1000 at 718 h per 10^9 calls single
  core; this bench gives 723 h, consistent.

## 4. Protocol

### 4.1 Frames on fd 3 (helper to launcher)

Each frame is a 4-byte little-endian length, a 1-byte type, then the payload; payload ≤ 64 KiB.

- `H` header (once): canonical JSON {v: 1, id, j, n_j, w, encoding, srcDigest_before, helper_sha256}.
- `D` data: fixed-width little-endian values, 4 bytes each, or 8 bytes for randomInt ranges above 2^32; a
  shuffle or sample outcome is its values in order; a tuple is its w outcomes in call order. Only whole
  outcomes per frame.
- `T` trailer (once, last): {count, payload_sha256, srcDigest_after}.

The launcher rejects any frame out of order, any length above 64 KiB + 5, any trailing bytes after `T`, and
any frame from a part it did not plan.

### 4.2 Incremental n and digest

The launcher decodes each `D` frame, runs the shape check per outcome, feeds the outcomes to the entry's
accumulators and the payload to the part's sha256, then drops the frame. Memory per part is one frame plus
the accumulator; no record array exists.

### 4.3 Back-pressure

Helpers write with `fs.writeSync(3, ...)`, which blocks when the pipe is full. The launcher reads every
helper concurrently; while a downstream consumer (a battery tool's stdin) has not drained, the launcher
pauses the stream it is feeding from (`readable.pause()`), the pipe fills, and that helper blocks. Peak
launcher memory is bounded by N × (64 KiB + the pipe buffer) plus the tool's stdin high-water mark.

### 4.4 Battery tools (existing G-45 `launchEvidenceTool`)

`launchEvidenceTool` uses `cp.spawnSync` and therefore needs the whole input in memory. Proposed: a sibling
`launchEvidenceToolStream(g, file, args, options)` in `tools/ci/entropy-backstop.mjs` with the same checks
in the same order (open grant, readiness guard re-run, `EVIDENCE_TOOLS` membership, G-55 pinned binary,
`shell: false`), returning an async child whose stdin the launcher writes with `drain` back-pressure. The
sync function stays for small inputs. Every existing G-45 and G-55 refusal case must also run against the
stream variant.

Open question Q3 for HoQ: a battery tool reads one stream. Feeding it in part order serialises the helpers
behind the tool; giving each part its own tool run changes the battery's semantics (N p-values per test).

### 4.5 Crash and partial-run semantics

- A part counts only if its helper exits 0, its trailer is present and matches, its count equals n_j, and its
  digests match. An entry counts only if all N parts count; otherwise nothing of that entry counts.
- A voided entry is rerun from scratch with fresh helpers; no part is reused. Every attempt, voided ones
  included, is written to the run log with its reason, so retries are visible to review.
- Launcher crash: nothing is registered (HELD stays empty), temp hash runs are deleted on the next start.
- Optional checkpoints (option D or long runs): a checkpoint is a completed entry, never a completed part;
  a run directory may hold completed entries from an earlier launcher run only if their header srcDigest,
  launcher and helper sha256 equal the current ones.

## 5. Tests and mutants

Existing mutants and where they move:

| Mutant | Today | After |
|---|---|---|
| G64-M1 (claimed n without records) | runner line without records | launcher trusts the helper trailer's count instead of its own decode count |
| G64-M2 (report without stamp) | `reportEvidenceResult` stamp check | retired with `reportEvidenceResult` on the counted path; replaced by "launcher accepts a part whose header helper sha256 differs from its own pin" |
| G64-M3 (skips collector re-check) | `checkCollected` over records | launcher skips the per-outcome shape check of `D` frames |
| G64-M4 (counts a failed run) | runner exit ≠ 0 | one part exits ≠ 0 and the entry still counts |
| G64-M5 (digest counted twice) | duplicate content digest | same check, on the new content digest |
| G64-M6 (K entry from the line) | `o.kTest` | helper or launcher takes the K entry from arguments or the header |
| G65-M1 (stamp ignores digest) | stamp lookup | retired with the stamp path; recorded in the README, not silently |
| JL-1 (no readiness check) | before runner spawn | before helper spawn; stays |
| GM-3, GM-5 (record order, skipped record) | `statisticFromRecords` | the same faults injected in the accumulator feed (reversed shuffle outcome, one outcome per 4096 skipped) |
| GM-6 (in-process stamp) | `evidenceStatistic` gate | stays |
| MB-1, MB-2 (marker ban) | `tools/ci/marker-ban.mjs` | unchanged; must also scan `verification/bench/` (it already scans `verification/`) |

New mutants needed, each killed in a gating mode:

- part merge order follows finish order instead of j;
- n_j computed from outcomes received rather than the fixed plan;
- a tuple straddles two parts;
- srcDigest_after not compared (only before);
- a frame longer than 64 KiB + 5 accepted;
- trailing bytes after `T` accepted;
- a voided entry's completed parts reused on rerun;
- the stream tool launcher skips the readiness re-run, or the G-55 pin check;
- `spawnSync` reintroduced on the counted path (static check, like the marker ban);
- the sequential-statistic merge drops the boundary contribution (caught by the merge-equals-one-pass tests).

New tests: merge-equals-one-pass for every K statistic at small n with N ∈ {1, 2, 3, 7}; frame decoder fed
crafted frames (truncated, oversize, reordered, extra); a forged helper (sha mismatch) refused; a helper
killed mid-run voids the entry and leaves HELD empty.

## 6. Measured 10^9 throughput

Per K entry at 10^9 outcomes, one helper: from 0.50 core-h (randomInt [0,2)) to 723 core-h (shuffle n = 1000);
table in section 2. Whole K list: 2511 core-h own stream, 21.3 days at N = 8 on this box.

## 7. Open questions

- Q1 (HoQ, CPO): M per family or staged cut (section 2, options A to E).
- Q2 (HoQ): one stream per entry or per call shape (option B).
- Q3 (HoQ): battery tool feeding under parallel parts (section 4.4).
- Q4 (HoQ): whether the residual in 1.3 is acceptable, and whether `duplicates` may use 128-bit hashes (1.4).
