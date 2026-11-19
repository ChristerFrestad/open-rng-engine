# Evidence harness preconditions (decision rule v1, FROZEN 5d09c75a)

No evidence run has been made. HoQ verifies this harness before the first counted run.
Checked by `check:ph0` through the `tools/ci/b8-dependencies.mjs` step (package.json is frozen), and by `test/harness-preconditions.test.mjs`.

| Frozen rule | Item | File | State |
|---|---|---|---|
| 8 | df fixed for every `df: null` K entry (HoQ ruling: all 76) | `df-table.mjs` (table digest `1ed710bfb77b8e2a6736407386e60b70401398e88603b97b172d8df1d3817e63`) | 9 fixed, 67 OPEN; harness NOT-READY (below) |
| 15, 17(ii) | STS 2.1.2 answer file | `sts-answers.txt` (sha256 `f71ec11d82f83311666af9dc05707227b736f69d1ab768a5448c0ffcfb666383`) | pinned |
| 15, 17(ii) | TestU01 1.2.3 driver | `tu01-driver.c` (sha256 `5fa75bdd52a49c6fb812f511d97f40f7f0367c230f6a88408ad5ec07dc997c88`) | pinned |
| 15, 17(ii) | archives `sts-2_1_2.zip`, `TestU01-1.2.3.zip` | `pins.mjs`, cross-checked against the frozen text and `tool-pins-v1.1.json` | pinned; re-fetched 2026-11-18 22:55 CET, sha256 unchanged |
| 15, 17(ii) (H-5) | archives `dieharder-3.31.1.tgz`, `PractRand_0.96.zip`; commands `./assess 1000000`, `dieharder -a -Y 0 -g 201 -f RAW_UINT32_FILE`, `RNG_test stdin32 -tf 1 -te 0 -tlmin 10 -tlmax 40` (RC) / `-tlmax 34` (nightly) | `pins.mjs` `ARCHIVE_PINS`, `TOOL_COMMANDS`, cross-checked against the frozen text and `tool-pins-v1.1.json`; `checkToolCommand(name, argv)` is the exact-argv check for a runner | pinned (batch E) |
| 8, 15 (M-153) | refuse n < 10^9 and non-public-call units | `n-floor.mjs` | built |
| 17(i) | exact counts 188 / 2 x 160 / 110 (114 emitted) | `counts.mjs` | built (synthetic fixtures only) |

## STS answer file (rule 15: "driven by a fixed answer file")

`./assess 1000000` reads its answers with `scanf` in this order (STS 2.1.2 `src/utilities.c`, archive sha256 `0238d2f1…`):

| Line | Answer | Prompt (source) |
|---|---|---|
| 1 | `0` | generator: [0] Input File (`displayGeneratorOptions`, L26-27) |
| 2 | `raw-stream.bin` | User Prescribed Input File (`generatorOptions`, L45-46); the harness places the raw stream at this path in the STS working directory |
| 3 | `1` | apply all statistical tests (`chooseTests`, L117-118) |
| 4 | `0` | Select Test (0 to continue): default parameters (`fixParameters`, L165-166) |
| 5 | `1000` | How many bitstreams? (`openOutputStreams`, L406-407); rule 4 m = 1,000 |
| 6 | `1` | input mode [1] Binary (`fileBasedBitStreams`, L237-238) |

## TestU01 driver (rule 15: "a pinned C driver over unif01_CreateExternGenBits")

`tu01-driver <SmallCrush|Crush|BigCrush> <raw|u32> <out.tsv>`, input on stdin as little-endian 32-bit words. Input that runs out or ends in a partial word stops the driver (exit 3 or 4); it never wraps or pads. Output is one header line and one line per `bbattery_pVal[j]`, j < `bbattery_NTests`; `counts.mjs` reads it. On 2026-11-18 the source compiled with `gcc -std=c99 -Wall -Wextra -pedantic` (0 warnings) against the pinned TestU01 1.2.3 archive (sha256 `bc1d1dd2…`), built with direct `gcc` calls because the box has no `make`. Only the usage, empty-input (exit 3) and partial-word (exit 4) paths were exercised; no battery was run.

## Rule 8 df table and harness readiness

Frozen rule 8: "The df of 72 entries are marked `unspecified` or `proposed` in the list. The harness fixes each df with its test code, before any data". In `k-tests-v1.1.json` (f75299de) 76 entries have `df: null`. HoQ ruling (CTO relay, 2026-11-18 23:30 CET): the rule 8 set is all 76; the count is read from k-tests, never hard-coded.

- `shuffle/adjacency/n-52-i-{0,1,25,50}`: df 2651. The ordered pair (π[i], π[i+1]) takes one of 52×51 = 2652 cells; one observation per shuffle; a single multinomial goodness-of-fit, df = 2652 − 1, expected count 10^9/2652.
- `randomInt/chi2/min-0-max-{2147483649,4294967296,4294967297,281474976710656}` and `shuffle/chi2/lehmer-52`: df 999. Exactly 1000 contiguous bins over [0, r), bin k = [⌊k·r/1000⌋, ⌊(k+1)·r/1000⌋); exact BigInt cell probability width/r (unequal widths for r not divisible by 1000, never 1/1000); every expected count ≥ 5 at n = 10^9 asserted; df = bins − 1. The Lehmer-52 rank is computed in BigInt (identity → 0, bin 0; reversed → 52! − 1, bin 999).
- The other 67 (runs, serial correlation, overlaps, coupon collector and duplicates over the randomInt configs, the Lehmer-52 stream and weightedPick; shuffle mod-4 / div-4 adjacency counts) are OPEN. They are never filled with a placeholder. Design note: `verification/df-design-v1.md` (for HoQ ruling, not code).

Two separate checks:

1. Integrity (`checkDfTable`, part of `runChecks`, fails check:ph0): table digest, every table id is a df-null K entry, adjacency cells 2652 and df = cells − 1, binned `proposed_cells` 1000 and df = `proposed_df` = bins − 1, support r matches the K list, bins cover [0, r) with no empty bin, expected ≥ 5.
2. Readiness (`dfReadiness` / `evidence-entry.mjs`): every df-null K entry has a df after the table is applied. check:ph0 prints `harness readiness: NOT-READY (...)` and does not fail. `assertEvidenceRunReady()` throws while anything is open; every evidence-run start must call it first. No evidence-run entry point exists in this repo yet.

## Evidence-gate preconditions EG-1, EG-2, EG-3 (HoQ addendum 1 4195afbc; HoQ b15a2ff5 report)

- **EG-1 (`collector.mjs`).** M-153 B4–B12 is enforced on what the collector counts. The harness wraps the public call in a witness before the collector sees it. A collection is accepted only if collector n = number of records = witness returns / w (w = 1, 2 for pair/successive tuples, or the K entry's `window`), every record is one public-call outcome of the primitive (one integer in [min,max), one index, one permutation, one distinct k-set), and n ≥ 10^9. Inner draws, tries, bytes and Lehmer digits go to a diagnostic byte log and never feed n. The self-check runs the collector over synthetic primitives (LCG, no entropy) that log Fisher–Yates steps, rejected tries, bytes and digits. Collector mutants that count any of these (B4–B12) are killed.
- **EG-2 (`counts.mjs`).**
  - BigCrush: the 160 test names in row order (from the pinned TestU01 1.2.3 `bbattery.c` BigCrush, digest `02ddf54c…`).
  - Dieharder: the 114 `-a` rows in order with pinned ntup where the source fixes it (from the pinned 3.31.1 source, digest `9c5f7a5d…`; 110 counted).
  - The BigCrush u32 input must have a sha256 different from raw, and u32 p-values identical to raw are red.
  - No duplicated STS sequence.
  - Both lists are derived from source, not from a run (ANTATT until the first harness run).
- **EG-3 / G-45 (structural, HoQ report c9d7c93..dbd4e00, addendum 1 A7).** The text contract is removed. Enforcement is at the spawn layer in `tools/ci/entropy-backstop.mjs`: a battery tool (dieharder, tu01-driver, STS assess, PractRand RNG_test), named as the executable or as any argv or shell word, is refused unless it is started by `launchEvidenceTool` inside an open grant; a grant is opened only by the backstop's `openEvidenceGrant`, which runs `assertEvidenceRunReady` itself (root fixed by its own URL) and each launch re-runs it. Interpreters (python, perl, sh, env, ...) are never spawned. No path or directory is exempt. `startEvidenceRun(async ({ launch }) => ...)` is the guarded entry export: it refuses without the backstop preload, runs the guard, opens the grant, hands the callback a launcher bound to it and closes it afterwards. Static half (defence in depth): no interpreter scripts anywhere in the repo (`scriptFileFindings`, by extension and shebang). Fixtures: 19 evasions in check:ph0 (entropy-backstop-check), the READY-world grant path and G45-M1..M10 in `node tools/ci/g39-mutants.mjs`.

- **Batch E (HoQ 4c7adda0/f575fe1f H-3, H-4, H-5; b15a2ff5 D16, D17).** Every check HoQ found unproven now has a red fixture and a mutant: p = 1 + ε, BigCrush row order and header ntests, tu01 row width, duplicate plan, frozen-rule and tool-pins digests, rule-text cross-check and tool-pins field compare (each with the tampered file's own digest, so only the check under test sees it), checkArchiveFile and the archive size, upper-case hex, a df-null list over 76 (no hidden cap) and a wrong k-tests sha. The tu01 parser rejects empty, blank, hex, signed and non-decimal index or p fields as malformed (H-4). Self-test 140 fixtures, 81/81 mutants.

## Wave-1 calibration (A6) on the labkit reference stream (CTO commit H; HoQ addendum 1 A7 R-W1-METHOD)

Verification, NOT a counted evidence run: no battery tool is started and the evidence gate stays CLOSED.

- **Adapter** `verification/labkit/aes-ctr-ref.mjs`: AES-256-CTR over zero plaintext, pinned key
  `KEY_HEX` = sha256("open-rng-engine labkit reference AES-256-CTR key v1"), IV = BE32(stream) || BE32(rep) || 0^64,
  u32 = little-endian keystream words, `below(r)` by rejection. KATs: NIST SP 800-38A F.5.5 CTR-AES256 (4 blocks)
  and its own vectors (first words, 1 MiB digest, below()); the file digest is pinned in
  `test/labkit-calibration.test.mjs`. It is outside `src/` and the engine code path; rule 27 refuses a src import
  of it and the backstop's src scope is unchanged (same test). It never draws OS entropy.
- **Harness** `verification/calibration/{laws,wave1-entries,wave1-calibrate}.mjs`: the 26 accepted EBC entries
  (12 coupon, 12 duplicates with b per §6.2 / A7: [1,53) 8192, [0,54) 8448, [0,2^32+1) 8192, others 4096; adjacency
  mod-4/div-4), R = 1000 replications, n >= 10^6 outcomes per replication, Pearson X² over the §6.1-lumped exact
  law at M_cal, KS of the 1000 p-values vs U(0,1) at α = 0.001, flags at 0.01 inside [2, 22] of 1000, KS MDD
  D_crit = 0.0617 (A6). Laws: coupon/duplicates double DP with positive terms only [CL-1], adjacency EXACT BigInt;
  brute-force enumeration fixtures in the test.
- **Run**: `node verification/calibration/wave1-calibrate.mjs` (8 worker threads) writes
  `verification/calibration/wave1-results.json` (per entry: stream index, reps, M_cal, cells, df, min E,
  min outcomes, KS D, KS p, flag count, PASS/FAIL, sha256 of the p-value vector).
