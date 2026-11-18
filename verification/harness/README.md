# Evidence harness preconditions (decision rule v1, FROZEN 5d09c75a)

No evidence run has been made. HoQ verifies this harness before the first counted run.
Checked by `check:ph0` through the `tools/ci/b8-dependencies.mjs` step (package.json is frozen), and by `test/harness-preconditions.test.mjs`.

| Frozen rule | Item | File | State |
|---|---|---|---|
| 8 | df fixed for the 72 `unspecified`/`proposed` entries | none | OPEN: not built (ambiguity below) |
| 15, 17(ii) | STS 2.1.2 answer file | `sts-answers.txt` (sha256 `f71ec11d82f83311666af9dc05707227b736f69d1ab768a5448c0ffcfb666383`) | pinned |
| 15, 17(ii) | TestU01 1.2.3 driver | `tu01-driver.c` (sha256 `5fa75bdd52a49c6fb812f511d97f40f7f0367c230f6a88408ad5ec07dc997c88`) | pinned |
| 15, 17(ii) | archives `sts-2_1_2.zip`, `TestU01-1.2.3.zip` | `pins.mjs`, cross-checked against the frozen text and `tool-pins-v1.1.json` | pinned; re-fetched 2026-11-18 22:55 CET, sha256 unchanged |
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

## Open: rule 8 df table (not built)

Frozen rule 8: "The df of 72 entries are marked `unspecified` or `proposed` in the list. The harness fixes each df with its test code, before any data". In `k-tests-v1.1.json` (f75299de) 76 entries have `df: null`: 67 `unspecified`, 4 `unspecified-large-r` and 1 `unspecified-lehmer` (these 5 carry `proposed_df` 999), and 4 `cells-from-source-df-unspecified` (`shuffle/adjacency/n-52-i-{0,1,25,50}`). Which 72 the rule means, and whether the 5 `proposed_df` values are adopted, is for HoQ to state.
