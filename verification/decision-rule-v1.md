# Statistical evidence decision rule v1 (F-15): FROZEN

**Statistical evidence decision rule v1. FROZEN by HoQ 2026-11-18 09:38 CET, pinned to rng commit 6745f106, DECISIONS d5698f7a (R107/R108).**

rng commit `6745f106a79ed13539fc8ece204095d718dd67d1`; DECISIONS.md sha256 `d5698f7ae0176d9a2e580a4d07dcbfc7dd1bdbae2a9c615d185d436ad7613205` (CPO-R107 L112, CPO-R108 L114); built from HoQ freeze draft r3 `70ab8b48`. No evidence run may start until gate rule 18 is met.
Sources (q = quality.md v5.5.7 `0202a82b`; P = PLAN.md r4.9 `206e0511`; D = DECISIONS.md `d5698f7a`): q §3.2 L426–445, §7.4 L1067–1088, QR-41 L286; P R-25 L133, R-39 L147, R-40 L148, R-75 L185, §4.4 L730–746, §13.1 L1102–1115; D L112 (CPO-R107), D L114 (CPO-R108). Any change needs a CR-reviewed commit before the next run (q L428; P L732).

1. **Level.** α = 0.01 is the only significance level. It is applied at the decision level: P(release-blocking FAIL | perfect generator) ≤ 0.01 per RC, family-wise (R-39). **The split (owned by HoQ, R107):** this rule ≤ 0.0091; QR-41 α_RTP = **0.0005**; total **≤ 0.0096**.
2. **Data source.** The production entry point via labkit, with a fresh `randomFillSync` per draw. Record the run id, release SHA, runtime, Node and OpenSSL versions, adapter, the sha256 of every raw-output file, and each tool's version and sha (rule 15). A fresh run is a new process.
3. **Streams.**
   - (a) Raw `randomBytes`.
   - (b) Mapped:
     - `randomInt` over [0,2), [1,7), [1,38), [1,53), [0,100), [0,2^31+1), [0,2^32), [0,38), [0,54), [0,2^32+1), [0,2^48); plus `randomInt` [0,37) and [0,38) as consecutive-call ordered-pair streams (2 tests);
     - `shuffle` n ∈ {52 (also as a Lehmer-code stream), 54, 104, 312, 416, 1000};
     - `sample` (52,5), (52,9), (80,20);
     - `weightedPick` {1,3,6}, W-A, W-B.
   - There are no game or games-package streams (R-75).
4. **SP 800-22 r1a** (raw), default STS parameters (template m = 9). **188 p-values per sequence**. m = 1,000 sequences × 10^6 bits; per-sequence α = 0.01.
   - **Proportion:** flag if fewer than 981 of 1,000 pass (bound 0.9805607, one-sided). For random excursions (RE) and RE variant: bound = 0.99 − 3√(0.0099/m′) at the eligible count m′, and flag if the pass count is below ⌈bound·m′⌉.
   - **Uniformity:** 10-bin χ²; flag if P-value_T < 0.0001 (needs ≥ 55 sequences).
   - There is no failure band for 800-22.
5. **TestU01 1.2.3** on raw and [0,2^32): BigCrush (**160 statistics**) per RC; SmallCrush (**15**) nightly on both streams; Crush (144) weekly, outside the rule. Flag if p ∉ [0.001, 0.999]; **hard FAIL** if p < 10^-10 or p > 1 − 10^-10.
6. **Dieharder 3.31.1 `-a`** on raw per RC: 114 p-values, of which **110 are gated**.
   - **Excluded from gating** (run, logged, published, never counted): -d 5 OPSO, -d 6 OQSO, -d 7 DNA ("Suspect") and -d 14 Sums ("Do Not Use"), as labelled by 3.31.1 `dieharder -l` (`list_tests.c` L31–36).
   - No ambiguity-resolution re-runs (`-Y 0`). WEAK/FAILED labels are not used; the gated p-values use the bands of rule 5.
   - Any change of version repeats the exclusion step and re-freezes.
7. **PractRand `RNG_test`** (standard test set) on raw: ≥ 2^40 bytes per RC; 2^34 nightly. Any "FAIL" evaluation in any results summary = **hard FAIL**, with no re-run. Lesser evaluations are logged, not gated.
   - **Its false-FAIL rate (O-3) is NOT inside the bound of rule 10.** It is an **HoQ residual risk** (R107 B-2), listed in the G1/G-PH1 exit packet with the measurement plan of rule 13.
   - Once measured, it is added by union bound: rule-10 total + 0.0005 + p̂_PR (95% upper bound).
   - **If p̂_PR exceeds 0.00041** (= 0.01 − 0.00959, R107), this rule must be revised before the next RC; no silent carry.
8. **Mapped-output tests** (GLI 5.2.2(c)-style plus the §13.1 per-primitive tests).
   - **≥ 10^9 outcomes per usage per RC**. **One outcome = the result of one public call**: one full permutation for `shuffle`, one complete sample set for `sample`, one value for `randomInt` and `weightedPick` (R107 B-3; P L742).
   - **K = 157** (R 68 / S 19 / P 40 / W 30). Per-test flag threshold **0.01/K = 6.369×10^-5**; **hard FAIL** if p < 10^-10.
   - **K′ = 157, confirmed** by the harness list in rule 15 (V). The threshold stays 0.01/157.
   - The df of 72 entries are marked `unspecified` or `proposed` in the list. The harness fixes each df with its test code, before any data; df does not change K or the threshold.
9. **Decision (RC).**
   - **CLEAN:** 0 flags.
   - **SUSPECT:** 1–5 flags and no hard FAIL. Re-run each flagged test exactly once, as a fresh run with the same sample size. The same statistic flagged again → **FAIL**; otherwise → **PASS-WITH-NOTE** (both logged).
   - **Hard FAIL**, with no re-run: any failure-band p, any PractRand FAIL, or **≥ 6 flags** in one run.
   - There are no other re-runs and no seed or run selection; all outputs are kept.
10. **False-FAIL budget (perfect generator, per RC; union bound).**
    - E = **1.534** (P(≥ 1) = 78.4%); P(≥ 6 | Poisson E) = 0.00496; repeat term 0.00398; failure bands 1.0×10^-7.
    - **Rule total 0.00895.** **+ α_RTP 0.0005 = 0.00945 ≤ 0.0096 ≤ 0.01.**
    - The P(≥ 6) tail assumes independence across batteries (planning estimate; checked empirically by PH1-W2).
11. **Nightly.** 800-22 + SmallCrush (2 streams) + PractRand 2^34. E = 0.724. Same rule, with hard FAIL at **≥ 4 flags**: P(≥ 4) = 0.00647, total 0.00886 ≤ 0.01. A nightly FAIL freezes releases; SUSPECT triggers the one automatic re-run.
12. **RTP verifier (QR-41 / PRQ-08(b); R107 B-1 condition: no loss of power).**
    - **δ\* = 0.1 pp and the n formula below are RULED (CPO-R108).**
    - **Test and level:** α_RTP = 0.0005, two-sided, z = **3.4808** (Bonferroni over m configurations: z_{1 − 0.0005/(2m)}). Pass iff |RTP_sim − RTP_exact| ≤ z·σ/√n.
    - **Enumerable configurations:** n = the smallest n with π(n, z_new) ≥ π(10^9, z_old) at δ\* = 0.1 pp, where π(n, z) = Φ(δ\*√n/σ − z) + Φ(−δ\*√n/σ − z), z_old = z_{1 − 0.001/(2m)}, and σ is exact from the enumeration.
      - Closed-form cross-check: n = max(10^9·(z_new/z_old)², (√10^9 + (z_new − z_old)·σ/δ\*)²).
      - **Floor: n ≥ 1.12×10^9** at m = 1.
    - **Non-enumerable (R-40):** n ≥ the same n (with the 99.975% upper bound of σ, or σ ≤ M/2) **or** the batch-means half-width t_{0.99975, 999}·s_B/√1000 = **3.4922**·s_B/√1000 ≤ 0.10 pp, whichever is stricter. Labelled "adopter game math, simulated".
    - **Output requirement (E-R108-1, CPO-R108; must-kill M-154).** Every `rtp-verify` result (JSON fields `power_at_delta`, `mdd50`, `mdd80`, `sigma_basis`, plus the human summary) states, for the adopter's σ (exact, or its 99.975% upper bound) and n:
      - the achieved power π at δ\* = 0.1 pp;
      - MDD_50 = z·σ/√n and MDD_80 = (z + 0.8416)·σ/√n, with z = 3.4808 or the Bonferroni z.

      It never reports a bare PASS. If π < 0.5 at δ\*, the summary says that 0.1 pp is not resolvable at this n. Example (n = 1.119×10^9, m = 1): σ = 1 gives MDD50/MDD80 = 0.0104/0.0129 pp; σ = 10 gives 0.104/0.129 pp.
13. **PH1 work items and the residual-risk entry.**
    - **PH1-W1** [CTO harness, HoQ protocol]: PractRand empirical calibration on reference generators (AES-CTR, ChaCha20 via labkit), at 2^40 (N ≥ 30) and 2^34 (N ≥ 3,000). Report p̂_PR with a 95% Clopper–Pearson upper bound. With 0 FAILs at N = 3,000 the bound is 0.0010, which is above 0.00041. So the residual stays open unless N ≥ 7,306 nightly-size runs (bound ≤ 0.00041), or until the CPO rules.
    - **PH1-W2** [HoQ]: the same reference runs report the empirical flag rate per battery against rule 10, and the cross-battery correlation.
    - **G1/G-PH1 exit packet entry (owner HoQ):** "O-3 PractRand false-FAIL rate: residual risk, outside the 0.0096 bound; designer target ≈ 1 in 3×10^8 summaries (pinned command `-tlmin 10 -tlmax 40` gives 31 summaries, so ≈ 1.0×10^-7 per RC and ≈ 8.3×10^-8 nightly at 25 summaries; *Tests_overview.txt* §3.B, not an independent measurement); measurement plan PH1-W1; trigger 0.00041 (R107); calibration target ≥ 7,306 clean nightly (2^34) runs (R108)."
    - **O-43:** the power check for K before the K list is final.
14. **Release effect.** An RC needs CLEAN or PASS-WITH-NOTE on the exact SHA. Missing, aborted or inconclusive evidence = FAIL (RQ-FC-12).
15. **Freeze preconditions (B-4, R107): FILLED and checked by HoQ (V, copy at 6745f106, 2026-11-18).**
    - **TODO-CTO-1, harness test list:** `verification/k-tests-v1.1.json`, sha256 `f75299de7fa063b96e2a031ec7072ed4fe34f219a4bc04e3534125b973097c4c`, commit `6745f106`.
      - K′ = 157 (R 68 / S 19 / P 40 / W 30).
      - Ids are unique. Every entry has n = 10^9 in `public-call outcomes`, and every required field is present.
      - The v1 → v1.1 change is note-only (one `differences[2].summary` text). The v1 file is `965c200e`.
    - **TODO-CTO-2, tool pins:** `verification/tool-pins-v1.1.json`, sha256 `605e9a9973d754b1211c3d2e6ebe5202c28ee3656c988fa0203a0d68da899f8b`. The v1 → v1.1 change is note-only.
      - **NIST STS 2.1.2:** `sts-2_1_2.zip`, sha256 `0238d2f1d26e120e3cc748ed2d4c674cdc636de37fc4027c76cc2a394fff9157` (from csrc.nist.gov). There is **no official checksum** (ANTATT; R-PIN-1). Command: `./assess 1000000`, driven by a fixed answer file. The answer-file bytes are frozen with the harness.
      - **TestU01 1.2.3:** `TestU01-1.2.3.zip`, sha256 `bc1d1dd2aea7ed3b3d28eaad2c8ee55913f11ce67aec8fe4f643c1c0d2ed1cac`. There is **no official checksum**; it matches third-party Spack, Arch and FreshPorts hashes only (ANTATT; R-PIN-1). The command is `bbattery_BigCrush` / `SmallCrush` / `Crush` through a pinned C driver over `unif01_CreateExternGenBits`, on raw and on [0,2^32). The driver source is frozen with the harness.
      - **Dieharder 3.31.1:** `dieharder-3.31.1.tgz`, sha256 `6cff0ff8394c553549ac7433359ccfc955fb26794260314620dfa5e4cd4b727f`. This equals HoQ's independent fetch (V). Command: `dieharder -a -Y 0 -g 201 -f RAW_UINT32_FILE`.
        - Test indices (V against `libdieharder/dieharder_test_types.c` ADD_TEST order and `list_tests.c` L31–36): -d 5/6/7 = opso/oqso/dna ("Suspect"), -d 14 = sums ("Do Not Use"), -d 16 = the two-p-value diehard test after runs. The pin names it by index only (rule-40 naming); this is consistent.
        - Counted count 17 + 32 + 61 = **110**; total **114** (V: matches the source breakdown and the per-test row counts in a published 3.31.1 `-a` output, trezor/rng-test).
      - **PractRand 0.96:** `PractRand_0.96.zip`, sha256 `e4caf7fda98b2c597bbda3b576753cf5a0f6047aab837c82be370ab798a672e1`. This equals the SHA-256 on the official SourceForge files page (V, HoQ fetch). Commands: `RNG_test stdin32 -tf 1 -te 0 -tlmin 10 -tlmax 40` (RC) and `-tlmax 34` (nightly).
      - **M-153:** `verification/m153-harness-mutant.md`, sha256 `0b017faaecacc1cff74236b5f4d5ae1eab7bcea1ba4e76e69d2cbea92c72b275`. It matches M-153: B1–B3 refuse n < 10^9, and B4–B12 refuse counting draws, reads, tries, digits, bytes or window values instead of public calls.
16. **CI note (recorded).** The CTO accepted the rule-27 Q1/Q2/Q3 amendments: `check:rule27` joins `check:ph0`, and no-fewer is red under `--phase-exit`. HoQ verified this at `2de685b2`.
17. **Freeze conditions.**
    - (i) **First-harness-run count check.** The first harness run must emit exactly the following, or the run is FAIL and the rule is re-frozen:
      - 110 counted Dieharder p-values (114 emitted, 4 excluded per rule 6);
      - 188 STS p-values per sequence;
      - 160 × 2 BigCrush statistics (raw and [0,2^32)).

      The Dieharder 110 is source-derived and has not yet been run by the harness, so it is **ANTATT** until that first run.
    - (ii) **R-PIN-1 (HoQ residual).** NIST STS 2.1.2 and TestU01 1.2.3 have no official checksum or signature. The pin is the sha256 of the archive fetched from the official URL (rule 15). Any re-fetch with a different sha256 is a pin change and needs a re-freeze.
18. **Gate.** No evidence run starts until rule-27 gaps **G-23** (Unicode-escape identifiers) and **G-24** (named imports of node:vm / node:inspector / node:worker_threads / node:child_process) are fixed and HoQ-verified. Both are MAJOR (hoq-ph1-coverage-06cb884b `084c360c`); the CTO has deferred them until after 2026-11-24 18:30 CET.

