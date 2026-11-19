# Rule 8 df design note v2: WAVE 1 (DESIGN ONLY, NOT CODE)

Status: proposal for the Quant check and the HoQ ruling. This note changes nothing in K (K′ = 157), the
threshold or n. It contains no statistic code. The calibration harness is code and waits for HoQ's ruling
on this wave.

Basis: decision rule v1 (FROZEN 5d09c75a) rule 8; `verification/k-tests-v1.1.json` (f75299de); HoQ addendum 1
(`inputs/hoq-ph1-m1-addendum-1.md` 38d7e0ed): §A5 (df-design-v1 NOT accepted, all 67 OPEN), R-DF-1 (N-1 = option
(a)), R-DF-3 (variants), §A6 (closure standard v2, replaces R-DF-2, adopted as HoQ-R113-ADOPT); Quant check
`research/quant-df-check-1e3471e.md` (39c5ad1a) C-3, C-7, C-11. Supersedes `df-design-v1.md` for the entries
below; v1 stays in the tree as the record of what was not accepted.

Tags (A6):
- **EBC**: Pearson χ² over i.i.d. observations with exact BigInt or rational cell probabilities, every expected
  count ≥ 5, df = cells − 1, a brute-force enumeration fixture, and an independent Quant recomputation.
- **AC**: a cited asymptotic null (none in wave 1).
- **OPEN**: everything else.

No literature source is relied on in wave 1. Pearson's χ² over exactly computed cells is the whole null.
Kroese §§1.4.5 and 1.4.9 were read by Quant (C-7) and are noted only as corroboration.

## 0. Common to every wave-1 entry

- **Observations (R-DF-1 option (a)).** M i.i.d. observations are fixed before data, with M × (minimum outcomes per
  observation) ≥ 10^9, so at least 10^9 public-call outcomes are always consumed. The harness records the outcomes
  actually consumed (EG-1 witness count) next to M.
- **Exact cells.**
  - Cell probabilities are BigInt numerators over one common BigInt denominator.
  - Cells are lumped contiguously from each tail until every expected count M·p ≥ 5. The lumping is computed
    once, from the exact probabilities at the run's M, before any data, and pinned by sha256 in a df table
    entry together with M and the parameters.
  - df = cells − 1.
  - The p-value is the upper χ² tail at df.
- **Reduction to equiprobable categories.** cat(v) = ⌊v·d/r⌋ with d | r, so every category has probability
  exactly 1/d. This is exact BigInt integer arithmetic on the outcome.
- **Calibration (A6 (ii), required for every entry; it is verification, not evidence).**
  - Run the statistic as built against a pinned labkit AES-CTR or ChaCha20 reference stream, mapped to the
    primitive's outcomes by labkit's own reference mapping, outside the core code path.
  - R = 1000 independent replications at a reduced n ≥ 10^6 outcomes: M_cal = ⌈10^6 / minimum consumption⌉, with
    the lumping recomputed at M_cal by the same pinned procedure.
  - One-sample KS of the R p-values against U(0,1), rejecting at α = 0.001, with D_crit ≈ 1.949/√R = 0.0617 at
    R = 1000 (stated as the KS minimum detectable deviation).
  - Flag count at 0.01 inside its two-sided binomial 99.9% interval [2, 22] of 1000 (exact binomial, coverage
    0.99925).
  - Runs under the quota stop.
  - **Flag C-1:** the calibration checks the statistic code and the lumping procedure at M_cal. The cells at the
    counted M = 10^9 are coarser in the tails than at M_cal; that difference is by construction, not calibrated.
  - **Flag C-2:** labkit's AES-CTR/ChaCha20 reference adapter and its outcome mapping do not exist yet. They
    are part of the calibration harness, which waits for HoQ's ruling on this wave.
- **Quant recomputation (A6).** Quant recomputes every pinned cell table independently from the formulas
  below, and checks the brute-force enumeration fixtures.

## 1. Equal-p coupon collector: 12 entries, EBC

Entries:
- `randomInt/coupon-collector/<11 configs>` (min-0-max-2, min-1-max-7, min-1-max-38, min-1-max-53, min-0-max-100,
  min-0-max-2147483649, min-0-max-4294967296, min-0-max-38, min-0-max-54, min-0-max-4294967297,
  min-0-max-281474976710656);
- `shuffle/coupon-collector/lehmer-52`.

The weightedPick coupon entry is in wave 4 (see §5, flag W-1).

**Statistic.**
- Read consecutive outcomes, reduce each by cat(·) to d equiprobable categories, and record the segment length
  T = the number of outcomes needed to see all d categories.
- The next segment starts at the next outcome. Segments are disjoint, so the T's are i.i.d.
- Collect M segments and take Pearson χ² of the T counts over the lumped cells.

**Exact law.**
- P(T = k) = d!·S(k−1, d−1)/d^k for k ≥ d, with S = Stirling numbers of the second kind.
- Computed as integers over d^k by the DP on the number of distinct categories seen: from j distinct, the next
  outcome is new with weight d − j and old with weight j.
- Cross-check by inclusion–exclusion: P(T ≤ k) = Σ_{j=0}^{d} (−1)^j C(d, j) ((d − j)/d)^k.
- The upper tail cell is the exact complement 1 − Σ.

Parameters (d | r; d = r where r ≤ 100, as in v1):

| Config | r | d | M = ⌈10^9/d⌉ | mean T = d·H_d |
|---|---|---|---|---|
| [0,2) | 2 | 2 | 500000000 | 3.0 |
| [1,7) | 6 | 6 | 166666667 | 14.7 |
| [1,38) | 37 | 37 | 27027028 | 155.5 |
| [1,53) | 52 | 52 | 19230770 | 236.0 |
| [0,100) | 100 | 100 | 10000000 | 518.7 |
| [0,2^31+1) | 3·715827883 | 3 | 333333334 | 5.5 |
| [0,2^32) | 2^32 | 64 | 15625000 | 303.6 |
| [0,38) | 38 | 38 | 26315790 | 160.7 |
| [0,54) | 54 | 54 | 18518519 | 247.1 |
| [0,2^32+1) | 641·6700417 | 641 | 1560063 | 4513.3 |
| [0,2^48) | 2^48 | 64 | 15625000 | 303.6 |
| Lehmer-52 | 52! | 52 | 19230770 | 236.0 |

- Consumption is M × mean T ≫ 10^9 (≈ 7×10^9 for d = 641). It is random and recorded.
- Quant (C-3) found every equal-p row has a minimum lumped expected count ≥ 5 under option (a), with the minimum
  in the range 5.004 to 44.65.
- Engineering note: for d = 641 the inclusion–exclusion needs ~641 BigInt products per k, for k up to the upper
  lump (~10^4 values of k). That is estimated at minutes, once, offline, with the table pinned.

**Enumeration fixture.** For d ∈ {2, 3, 4} and L ≤ 10, enumerate all d^L sequences. For each, find the first
complete time and compare the exact frequencies of T = k, k ≤ L, with the DP and the inclusion–exclusion forms.
The reduction fixture checks that cat(·) is exactly equiprobable on the full range for small r with d | r
(e.g. r = 6, d = 3; r = 52, d = 13).

**K-intent flag.** None. The statistic is the named coupon collector. The choice of d for large r (3, 64, 641)
is a parameter judgement already shown in v1; d = 3 for [0,2^31+1) uses only the top ⌊log2 3⌋ bits of
information per value (flag P-1, power).

## 2. Equal-p duplicates (collision test): 12 entries, EBC

Entries:
- `randomInt/duplicates/<11 configs>`;
- `shuffle/duplicates/lehmer-52`.

The weightedPick duplicates entry is in wave 4.

**Statistic.**
- Blocks of b = 4096 balls thrown into m equiprobable urns.
- An urn is u consecutive outcomes reduced by cat(·) (m = d^u), or one outcome reduced to m | r (u = 1).
- C = the number of balls that land in an already occupied urn in the block. Blocks are disjoint, so the C's
  are i.i.d.
- M blocks; Pearson χ² of the C counts over the lumped cells.

**Exact law.**
- P(C = c) = m(m−1)⋯(m−(b−c)+1)·S(b, b−c)/m^b.
- Computed as integers over m^b by the DP on occupied urns: after k balls with c collisions, the next ball
  collides with weight k − c and opens a new urn with weight m − (k − c).
- States c > c_max go to an exact tail cell (complement).
- Cross-check against the Stirling form for small (m, b).

Parameters (b = 4096 for every config; λ ≈ b²/(2m)):

| Config | urn | m | u | M = ⌈10^9/(b·u)⌉ | λ |
|---|---|---|---|---|---|
| [0,2) | 20 values | 2^20 | 20 | 12208 | 8.0 |
| [1,7) | 8 values | 6^8 | 8 | 30518 | 5.0 |
| [1,38) | 4 values | 37^4 | 4 | 61036 | 4.5 |
| [1,53) | 4 values | 52^4 | 4 | 61036 | 1.1 |
| [0,100) | 3 values | 10^6 | 3 | 81381 | 8.4 |
| [0,2^31+1) | 13 ternary cats | 3^13 | 13 | 18781 | 5.3 |
| [0,2^32) | top 20 bits | 2^20 | 1 | 244141 | 8.0 |
| [0,38) | 4 values | 38^4 | 4 | 61036 | 4.0 |
| [0,54) | 4 values | 54^4 | 4 | 61036 | 1.0 |
| [0,2^32+1) | ⌊v·6700417/r⌋ | 6700417 | 1 | 244141 | 1.3 |
| [0,2^48) | top 20 bits | 2^20 | 1 | 244141 | 8.0 |
| Lehmer-52 | ⌊rank·2^20/52!⌋ | 2^20 | 1 | 244141 | 8.0 |

- 52! has 2^49 as a factor, so 2^20 | 52!.
- Consumption is exactly M·b·u ≥ 10^9.
- **Change from v1:** b = 4096 instead of 2^14. This keeps the exact denominators m^b at ≤ ~95 kbit, so the
  BigInt DP is seconds, not hours.
- The cells and the minimum expected count at these parameters are to be recomputed by Quant. C-3 covered the
  v1 parameters, not these.
- **Flag P-2 (power):** the smaller blocks lower λ for [1,53), [0,54) and [0,2^32+1) to about 1. HoQ may prefer
  b = 8192 there.

**Enumeration fixture.** For m ∈ {3, 4, 5} and b ≤ 7, enumerate all m^b ball sequences, count collisions, and
compare with the DP and the Stirling form exactly. Also check the urn-forming reductions as in §1.

**K-intent flag D-1.** "duplicates" is not defined in k-tests (`df_or_cells_basis`: "named … neither document
specifies …"). The collision test is our interpretation, as in v1. Under the HoQ-R113-ADOPT standing condition,
CPO should confirm this interpretation before HoQ rules.

## 3. Adjacency mod-4 and div-4: 2 entries, EBC

Entries: `shuffle/adjacency-mod4/n-52`, `shuffle/adjacency-div4/n-52`.

**Statistic.**
- Per shuffle of 52 (one public-call outcome), X = #{i < 51 : lab(π_i) = lab(π_{i+1})}.
- lab = v mod 4 (4 labels × 13) or ⌊v/4⌋ (13 labels × 4).
- M = 10^9 shuffles, i.i.d. Pearson χ² of the X counts over the lumped cells. Consumption is exactly 10^9.

**Exact law.** The integer DP of v1 §3.6, as verified by Quant (C-11): it counts arrangements of the labelled
multiset by the number of equal adjacencies, over the 52! permutations (exact totals). The means are 12 (mod-4)
and 3 (div-4). Quant's minimum lumped expected count is 12.89 (mod-4) and 18.28 (div-4) at M = 10^9.

**Enumeration fixture.** All permutations of small decks (2 labels × 3, 2 × 4, 3 × 2, 4 × 2) equal the DP law
exactly; the law sums to 1; E[X] = 51·(c − 1)/51 = c − 1 for label class size c (12 and 3 at n = 52).

**K-intent flag A-1.** k-tests says "adjacency counts vs exact expectation" and notes that 4 labels "would
suggest a 4×4 adjacency table". X is a single equal-label count, not the 4×4 / 13×13 transition table. That is a
narrower statistic. Under the standing condition it goes to CPO with the change stated: X tests clustering of
equal labels, while a full transition table would also test label-to-label preference.

## 4. Wave-1 totals

| Group | Entries | Tag |
|---|---|---|
| equal-p coupon (R × 11, S Lehmer-52) | 12 | EBC (pending the Quant recomputation, calibration and HoQ ruling) |
| equal-p duplicates (R × 11, S Lehmer-52) | 12 | EBC (pending the same; flag D-1 to CPO) |
| adjacency mod-4, div-4 | 2 | EBC (pending the same; flag A-1 to CPO) |
| **wave 1** | **26** | |

None of these is closed by this note. They become closable after the Quant recomputation, calibration and the
HoQ ruling.

## 5. Not in wave 1: 41 entries, all OPEN (held)

| Wave | Entries | Planned variant (R-DF-3) |
|---|---|---|
| 2 | runs × 13 (R × 11, S, W), serial correlation × 13 | runs R2 (discard after each run, exact per-r probabilities); serial as χ² on non-overlapping lag-1 pairs, binned exactly. Flag: both change the statistic from v1 R1/S1, and serial pairs change what "serial correlation" tests (CPO, standing condition). |
| 3 | overlaps × 12 (R × 11, S) | AC only for a prime alphabet with a page/equation citation from L'Ecuyer & Simard 2007 / TestU01 guide or NIST SP 800-22r1a, read by the checker; otherwise EBC non-overlapping t-tuples (flag: changes what "overlaps" tests). |
| 4 | weightedPick coupon, duplicates, overlaps | EBC only. |

Flag W-1: §A6's wave-1 line says "equal-p coupon collector: R ×11, plus S and W", while wave 4 lists
"weightedPick coupon". weightedPick (1,3,6) is not equal-p, so it is held for wave 4 here. HoQ may move it.

Total: 26 (wave 1) + 26 (wave 2) + 12 (wave 3) + 3 (wave 4) = 67.

---

## 6. Delta F (appended 2026-11-19; earlier sections unchanged): power/MDD of the wave-1 variants, CPO-R114, HoQ rulings

This section is appended. §0–§5 above stay as committed in 5dffcc06. Where this section changes a parameter, the
change is stated here and this section governs.

### 6.0 What was ruled (recorded, not re-argued)

- **HoQ:** deal_card as a red fixture is ACCEPTED and the green controls stay. W-1 is confirmed: weightedPick stays in
  wave 4. `tools/ci/g39-mutants.mjs` is ACCEPTED as interim on three conditions: (a) it is a release-gate step that
  the RM runs explicitly, with exit 0 required; (b) it moves into CI or `check:ph0` at the first manifest change;
  (c) HoQ re-runs it on every verification. These are recorded in `REMOTE-PENDING.md` (G39-1..G39-3).
- **CPO-R114** (DECISIONS.md, file sha256 85a51013…):
  - D-1 ACCEPTED: the collision count C is the definition of "duplicates". Every duplicates config runs at
    λ = b²/(2m) ≥ 4.
  - A-1 ACCEPTED AS NARROWER: X stays, with the report wording in §6.3. K′ = 157, the thresholds and 0.00945 are
    unchanged.

### 6.1 Method and approximation labels

The helper is `/workspace/rng-backup/dfv2-delta/power.py` (sha256
`4689c26de8c26b2e5adf0e537d77cddb16fb058ce9fa3593d06a1a70b215233c`). Its full output is
`/workspace/rng-backup/dfv2-delta/out-F.txt` (sha256 `89644d161e27a71a90675ba605c62bd7c5bcc15097e1d90ad96b465f6dec245f`).
To reproduce, run `python3 power.py` (about 9 minutes, no dependencies beyond the standard library).

- **Level.** α = 0.01/157 = 6.369427×10⁻⁵, the rule 8 per-test flag threshold of decision rule v1. The χ² critical
  value is computed for df = cells − 1. Consumption is n ≥ 10⁹ public-call outcomes.
- **Cells.** Contiguous lumping from both tails, merging while the outer cell or its inner neighbour has an expected
  count below 5. The laws are unimodal, so every cell is then ≥ 5 expected (asserted). The same index groups are used
  under the alternative.
- **Power.** Power = P(χ²′_df(λ_nc) > crit), with λ_nc = M·Σ(q_j − p_j)²/p_j over the lumped cells (p = null,
  q = alternative). MDD50/MDD80 is the smallest effect at which the power is 50% / 80%.
- **[A1] approximation.** The null and alternative laws of C and D used for power are computed by the same occupancy
  DP in double precision. The gated tables remain the exact BigInt DP of §2. The double law sums to 1 to double precision (checked for `[0,2)` at b = 16384: 1 + 3.3×10⁻¹⁵).
  The cell state above c_max = ⌊λ + 12√λ + 25⌋ is one tail cell.
- **[A2] approximation.** Power uses the noncentral χ² approximation to Pearson's statistic under a local
  alternative. For duplicates, λ_nc(δ) is taken as k·δ² with k measured at δ₀ = 0.01. Each solved MDD is then
  re-evaluated with the DP at that δ, and the achieved power is printed next to it in out-F.txt. All achieved values
  are 0.493–0.503 (target 0.5) and 0.794–0.805 (target 0.8).
- **[A3] model.** The duplicates alternative is an effective-m generator: a non-uniform urn distribution summarised
  by Σp_i² = (1+δ)/m. The collision process is then run with m′ = m/(1+δ). This is a model statement, not a claim
  about any particular defect.
- **Adjacency null laws.** These are EXACT (Fractions; the law sums to 1 exactly; E[X] = 12 and 3, as Quant C-11
  found). Their powers are [A2].

### 6.2 Duplicates: λ ≥ 4 block sizes (CPO-R114 (1)), P-2 and D-1

**Block sizes.** b = 4096 stays for 9 configs; every one of them has b²/(2m) ≥ 4.0231. Three configs change:

- `[1,53)`, m = 52⁴ = 7311616: b = 8192, so b²/(2m) = 67108864/14623232 = 4.5892.
- `[0,54)`, m = 54⁴ = 8503056: b = 8192 gives 67108864/17006112 = **3.9462 < 4**, which fails the requirement. The
  minimum is b ≥ ⌈√(8m)⌉ = 8248. The note takes **b = 8448** (= 33·256, the next multiple of 256 above 8248), so
  b²/(2m) = 71368704/17006112 = 4.1967. HoQ may take any b ≥ 8248.
- `[0,2^32+1)`, m = 6700417: b = 8192, so b²/(2m) = 67108864/13400834 = 5.0078.

CPO-R114 quoted "λ≈4.4/4.0/5.3" for these three at b = 8192. The exact values are 4.5892, 3.9462 and 5.0078, and the
second is below 4, hence b = 8448.

**Tractability.** The exact denominators m^b are b·log₂m bits: 186.8 kbit (52⁴, 8192), 194.5 kbit (54⁴, 8448) and
185.8 kbit (6700417, 8192). This is about 2× §2's 95 kbit bound and still a BigInt DP of b steps over ≤ c_max + 2
states.

**Re-derived M.** M = ⌈10⁹/(b·u)⌉ gives:
- `[1,53)`: M = ⌈10⁹/32768⌉ = 30518, consumption 1,000,013,824.
- `[0,54)`: M = ⌈10⁹/33792⌉ = 29593, consumption 1,000,006,656.
- `[0,2^32+1)`: M = ⌈10⁹/8192⌉ = 122071, consumption 1,000,005,632.

**Per-config table.** Statistic C. λ is b²/(2m); E[C] = b(b−1)/(2m) is in out-F.txt. v1 = original form
(b = 2¹⁴ = 16384); w1 = §2 (b = 4096); **F** = governing block size. MDD = δ in Σp² = (1+δ)/m at α = 6.369×10⁻⁵
[A1][A2][A3].

| Config | m | u | form | b | λ = b²/2m | M | consumption | cells | min E | MDD50 | MDD80 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [0,2) | 2^20 | 20 | v1 | 16384 | 128.0000 | 3052 | 1,000,079,360 | 57 | 5.59 | 0.01135 | 0.01298 |
| | | | **F** = w1 | 4096 | 8.0000 | 12208 | 1,000,079,360 | 19 | 7.51 | 0.01849 | 0.02147 |
| [1,7) | 6^8 | 8 | v1 | 16384 | 79.9098 | 7630 | 1,000,079,360 | 54 | 5.41 | 0.00900 | 0.01030 |
| | | | **F** = w1 | 4096 | 4.9944 | 30518 | 1,000,013,824 | 16 | 6.55 | 0.01436 | 0.01672 |
| [1,38) | 37^4 | 4 | v1 | 16384 | 71.6148 | 15259 | 1,000,013,824 | 54 | 6.94 | 0.00672 | 0.00770 |
| | | | **F** = w1 | 4096 | 4.4759 | 61036 | 1,000,013,824 | 15 | 14.03 | 0.01060 | 0.01236 |
| [1,53) | 52^4 | 4 | v1 | 16384 | 18.3568 | 15259 | 1,000,013,824 | 29 | 9.25 | 0.01180 | 0.01362 |
| | | | w1 (superseded) | 4096 | 1.1473 | 61036 | 1,000,013,824 | 8 | 11.57 | 0.01886 | 0.02221 |
| | | | **F** | 8192 | 4.5892 | 30518 | 1,000,013,824 | 15 | 9.15 | 0.01481 | 0.01727 |
| [0,100) | 10^6 | 3 | v1 | 16384 | 134.2177 | 20346 | 1,000,046,592 | 74 | 5.57 | 0.00452 | 0.00516 |
| | | | **F** = w1 | 4096 | 8.3886 | 81381 | 1,000,009,728 | 22 | 13.42 | 0.00718 | 0.00832 |
| [0,2^31+1) | 3^13 | 13 | v1 | 16384 | 84.1848 | 4696 | 1,000,210,432 | 52 | 5.28 | 0.01109 | 0.01270 |
| | | | **F** = w1 | 4096 | 5.2615 | 18781 | 1,000,050,688 | 16 | 6.90 | 0.01783 | 0.02076 |
| [0,2^32) | 2^20 | 1 | v1 | 16384 | 128.0000 | 61036 | 1,000,013,824 | 80 | 5.15 | 0.00272 | 0.00310 |
| | | | **F** = w1 | 4096 | 8.0000 | 244141 | 1,000,001,536 | 23 | 7.50 | 0.00428 | 0.00496 |
| [0,38) | 38^4 | 4 | v1 | 16384 | 64.3688 | 15259 | 1,000,013,824 | 52 | 6.12 | 0.00704 | 0.00806 |
| | | | **F** = w1 | 4096 | 4.0231 | 61036 | 1,000,013,824 | 14 | 17.06 | 0.01105 | 0.01290 |
| [0,54) | 54^4 | 4 | v1 | 16384 | 15.7846 | 15259 | 1,000,013,824 | 28 | 6.76 | 0.01264 | 0.01460 |
| | | | w1 (superseded) | 4096 | 0.9865 | 61036 | 1,000,013,824 | 7 | 33.52 | 0.01991 | 0.02350 |
| | | | **F** | 8448 | 4.1967 | 29593 | 1,000,006,656 | 14 | 12.46 | 0.01554 | 0.01814 |
| [0,2^32+1) | 6700417 | 1 | v1 | 16384 | 20.0312 | 61036 | 1,000,013,824 | 34 | 6.54 | 0.00582 | 0.00670 |
| | | | w1 (superseded) | 4096 | 1.2520 | 244141 | 1,000,001,536 | 9 | 11.92 | 0.00920 | 0.01081 |
| | | | **F** | 8192 | 5.0078 | 122071 | 1,000,005,632 | 17 | 8.37 | 0.00725 | 0.00843 |
| [0,2^48) | 2^20 | 1 | v1 | 16384 | 128.0000 | 61036 | 1,000,013,824 | 80 | 5.15 | 0.00272 | 0.00310 |
| | | | **F** = w1 | 4096 | 8.0000 | 244141 | 1,000,001,536 | 23 | 7.50 | 0.00428 | 0.00496 |
| Lehmer-52 | 2^20 | 1 | v1 | 16384 | 128.0000 | 61036 | 1,000,013,824 | 80 | 5.15 | 0.00272 | 0.00310 |
| | | | **F** = w1 | 4096 | 8.0000 | 244141 | 1,000,001,536 | 23 | 7.50 | 0.00428 | 0.00496 |

The v1 "min E" values are those of this note's lumping rule. v1 itself left the lumping to Quant (C-3).

**Reading (i), P-2.**
- Under [A3], the governing form's MDD80 is 1.24× to 1.65× the original v1 form's MDD80. For example, `[0,2)`
  goes from 0.01298 to 0.02147 (×1.65) and `[1,53)` from 0.01362 to 0.01727 (×1.27); the smallest ratio is `[0,54)` 0.01460 → 0.01814 (×1.24).
- At w1's b = 4096, the three superseded configs were ×1.61 to ×1.63 (`[0,54)` 0.01460 → 0.02350).
- So the power loss from smaller blocks is stated. It is bounded by a factor < 1.7 in δ at fixed n = 10⁹ for every
  config.
- P-2 is resolved as the λ ≥ 4 requirement (CPO-R114). HoQ still rules on the method.

**Reading (ii), D-1.**
- The alternative reading of "duplicates" computed here is D = the number of urns hit ≥ 2 times in the block. Its
  exact law is the 2-D occupancy DP over (c, d), with the double law [A1].
- Under the same [A3] alternative, at the governing block sizes, C and D have the same lumped cell count for every
  config. Their MDDs agree to within 2×10⁻⁵ (out-F.txt, D-1 table): for example, `[0,54)` b = 8448 gives C 0.01554 /
  0.01814 and D 0.01555 / 0.01814.
- At λ ≈ 4–8, triple hits are rare, so C ≈ D on most blocks. The definition chosen (C, CPO-R114) loses no power
  against this alternative compared with the D reading.
- No other reading (for example a spacings-based one) is evaluated, because its source has not been read for this
  note.

### 6.3 Adjacency: X vs the transition table (A-1, CPO-R114 (2))

**Setup.** M = 10⁹ shuffles (one public-call outcome each, consumption 10⁹), α = 6.369×10⁻⁵.

- **X** (§3): the equal-label adjacent-pair count per shuffle, with an EXACT null law.
- **T** (the alternative form): one adjacent pair per shuffle at a scheduled position, in an L×L table. Its EXACT
  cells are c_a·c_b/(52·51) for a ≠ b and c_a(c_a−1)/(52·51) for a = b.
- **π₀** = P(equal labels at one position) = (c−1)/(Lc−1), EXACT.

| | mod-4 (L = 4, c = 13) | div-4 (L = 13, c = 4) |
|---|---|---|
| E[X] (EXACT) | 12 | 3 |
| π₀ (EXACT) | 4/17 | 1/17 |
| X: lumped cells / df / min E | 32 / 31 / 12.89 | 17 / 16 / 18.28 |
| T: cells / df / min E | 16 / 15 / 5.88×10⁷ | 169 / 168 / 4.52×10⁶ |
| Clustering, X: ε at 50% / 80% power | 5.1×10⁻⁵ / 5.9×10⁻⁵ | 1.00×10⁻⁴ / 1.17×10⁻⁴ |
| Clustering, T: ε at 50% / 80% power | 3.20×10⁻⁴ / 3.72×10⁻⁴ | 1.134×10⁻³ / 1.282×10⁻³ |
| Cyclic preference, T: ε at 50% / 80% power | 2.48×10⁻⁴ / 2.89×10⁻⁴ | 7.16×10⁻⁴ / 8.09×10⁻⁴ |
| Cyclic preference, X | no first-order power (E[X] unchanged, exactly) | same |

**Alternative models** (model statements; powers are [A2]):

- **Clustering.** The per-position equal-label probability rises from π₀ to π₀(1+ε).
  - For X: the exponentially tilted null law with E[X] = 51·π₀·(1+ε).
  - For T: the diagonal cells ×(1+ε), with the off-diagonal cells scaled to keep the total at 1.
- **Cyclic label preference.** q(a, a+1 mod L) = p(1+ε) and q(a, a−1 mod L) = p(1−ε). The diagonal and every other
  cell are unchanged.
  - Marginals and every equal-label cell are unchanged, so by linearity E[X] = Σ_i P(equal at i) is EXACTLY
    unchanged. X has no first-order power against this alternative.
  - T has λ_nc = M·p_off·2L·ε², with p_off = 169/2652 (mod-4) or 16/2652 (div-4).

**Reading (iii).**
- Against clustering, X is 6.3× (mod-4) to 11.0× (div-4) more sensitive than T at 80% power.
- Against a label-to-label preference that keeps equal-label frequencies, X has no first-order power, and T detects
  ε ≈ 3×10⁻⁴ (mod-4) to 8×10⁻⁴ (div-4).
- This is the narrowing that CPO-R114 accepted.

**Report wording (exact, for both `shuffle/adjacency-mod4/n-52` and `shuffle/adjacency-div4/n-52`):**

> tests clustering of equal labels; does not test label-to-label transition preference.

**PH2 backlog.** A non-gating one-pair-per-shuffle transition diagnostic (T above; 16 or 169 exact cells) is recorded
in `REMOTE-PENDING.md` as PH2-1. It is not in K′, not in the rule total, and not gating.

### 6.4 CPO four-point acceptance test for wave 2–3 variants (note only; waves 2–4 not started)

Per CPO-R114 (3), a variant is acceptable if all four hold:

1. The original form is not computable exactly, or not citable under R113.
2. The variant still tests the property the entry's name promises.
3. Its power/MDD change against the original is stated, as in §6.2 and §6.3.
4. The limitation is named in the evidence report.

Expectations, which are not rulings:
- **Serial correlation** as lag-1 non-overlapping pairs likely passes (2).
- **Overlaps** should prefer AC, with a source actually read by the checker.
- **An EBC non-overlapping fallback** for overlaps goes to CPO with its power stated, as a named limitation only.

### 6.5 Totals (unchanged)

- 26 wave-1 entries: 12 coupon, 12 duplicates, 2 adjacency. All are EBC pending the Quant recomputation (now
  including the three new block sizes), calibration and the HoQ ruling.
- 41 entries are held OPEN in waves 2–4. The total is 67.
- K′ = 157, the per-test threshold 6.369×10⁻⁵, the hard FAIL at p < 10⁻¹⁰, n = 10⁹ and the rule total
  0.00895 + 0.0005 = 0.00945 are unchanged.
- No code changes. df-table.mjs is unchanged.


## 7. Delta H (appended 2026-11-19; earlier sections unchanged): A6 calibration results, NIT and cite refresh, report limitations

### 7.1 Calibration (verification on the labkit reference stream; NOT evidence; the evidence gate stays CLOSED)

- Adapter `labkit-ref/aes-256-ctr/v1` (`verification/labkit/aes-ctr-ref.mjs`, sha256 ae7a25d3d2a2529c746a6660af65efb816425786eb92cdcf546c8b793d0cc956), key 4e93c44f26d655731512adfe11534a18a0c25ec729259b092fdbb2228133f737, IV = BE32(stream) ‖ BE32(rep) ‖ 0^64, stream = entry index + 1, rep = 0..999.
- Harness `verification/calibration/` (laws.mjs 10b43729…, wave1-entries.mjs 5833d964…, wave1-calibrate.mjs 6e9690b4…). Rule: R = 1000 per entry, ≥ 10^6 outcomes per replicate, Pearson χ² over the §6.1-lumped exact law at M_cal, KS of the 1000 p-values against U(0,1) at α = 0.001 (KS MDD D_crit = 0.0617), flags at p < 0.01 required in [2, 22]. Duplicates use [0,54) at b = 8448.
- Run: one detached resumable invocation, 2026-11-19T03:31:52.889Z UTC end, node v24.22.1, OpenSSL 3.5.9, 2647 s. An earlier non-resumable invocation was stopped before any result was read (replaced by the resumable runner; not result selection). Results file `verification/calibration/wave1-results.json` (per-entry p-value digests included).
- **Outcome: 26/26 PASS, 0 FAIL.** Smallest KS p 0.07291 (entry 18), flags range 5–18, max D 0.04053 < D_crit = **0.061462** (exact KS critical value at R = 1000, α = 0.001; HoQ A8 C-2; the asymptotic 1.94947/√R is 0.06165). The stored KS p is the **asymptotic Kolmogorov series with the Stephens factor** [CL-3], not the exact KS p (Quant O-2: exact is lower by ≤ 0.0042; minimum exact 0.07278).

| # | entry | stream | M_cal | cells | outcomes per replication | KS D | KS p | flags@0.01 | verdict |
|---|---|---|---|---|---|---|---|---|---|
| 0 | `randomInt/coupon-collector/min-0-max-2` | 1 | 500000 | 17 | 1,497,297–1,503,102 (mean 1,500,038.3; ≥ 1,000,000) | 0.03402 | 0.194 | 9 | PASS |
| 1 | `randomInt/coupon-collector/min-1-max-7` | 2 | 166667 | 54 | 2,443,277–2,458,182 (mean 2,450,078.8; ≥ 1,000,002) | 0.02681 | 0.4635 | 7 | PASS |
| 2 | `randomInt/coupon-collector/min-1-max-38` | 3 | 27028 | 246 | 4,177,106–4,227,602 (mean 4,201,731.1; ≥ 1,000,036) | 0.02647 | 0.4799 | 12 | PASS |
| 3 | `randomInt/coupon-collector/min-1-max-53` | 4 | 19231 | 308 | 4,509,623–4,564,267 (mean 4,538,177.7; ≥ 1,000,012) | 0.01962 | 0.8325 | 7 | PASS |
| 4 | `randomInt/coupon-collector/min-0-max-100` | 5 | 10000 | 438 | 5,147,854–5,227,082 (mean 5,187,168.4; ≥ 1,000,000) | 0.02572 | 0.5173 | 5 | PASS |
| 5 | `randomInt/coupon-collector/min-0-max-2147483649` | 6 | 333334 | 27 | 1,828,641–1,840,012 (mean 1,833,259.8; ≥ 1,000,002) | 0.01896 | 0.8618 | 18 | PASS |
| 6 | `randomInt/coupon-collector/min-0-max-4294967296` | 7 | 15625 | 349 | 4,710,915–4,775,506 (mean 4,743,954.8; ≥ 1,000,000) | 0.03263 | 0.2335 | 14 | PASS |
| 7 | `randomInt/coupon-collector/min-0-max-38` | 8 | 26316 | 251 | 4,203,166–4,253,191 (mean 4,227,478.2; ≥ 1,000,008) | 0.03442 | 0.1834 | 10 | PASS |
| 8 | `randomInt/coupon-collector/min-0-max-54` | 9 | 18519 | 315 | 4,546,864–4,606,300 (mean 4,575,462.7; ≥ 1,000,026) | 0.0269 | 0.4595 | 12 | PASS |
| 9 | `randomInt/coupon-collector/min-0-max-4294967297` | 10 | 12488 | 1115 | 56,066,294–56,690,171 (mean 56,364,038.7; ≥ 8,004,808) | 0.01804 | 0.8982 | 12 | PASS |
| 10 | `randomInt/coupon-collector/min-0-max-281474976710656` | 11 | 15625 | 349 | 4,714,430–4,776,517 (mean 4,744,146.3; ≥ 1,000,000) | 0.02119 | 0.7559 | 11 | PASS |
| 11 | `shuffle/coupon-collector/lehmer-52` | 12 | 19231 | 308 | 4,509,359–4,567,038 (mean 4,537,531.7; ≥ 1,000,012) | 0.01482 | 0.9798 | 14 | PASS |
| 12 | `randomInt/duplicates/min-0-max-2` | 13 | 200 | 12 | 16,384,000 (fixed) | 0.02831 | 0.3945 | 12 | PASS |
| 13 | `randomInt/duplicates/min-1-max-7` | 14 | 200 | 10 | 6,553,600 (fixed) | 0.02018 | 0.8063 | 11 | PASS |
| 14 | `randomInt/duplicates/min-1-max-38` | 15 | 400 | 10 | 6,553,600 (fixed) | 0.02275 | 0.6738 | 9 | PASS |
| 15 | `randomInt/duplicates/min-1-max-53` | 16 | 400 | 10 | 13,107,200 (fixed) | 0.03481 | 0.1737 | 10 | PASS |
| 16 | `randomInt/duplicates/min-0-max-100` | 17 | 200 | 12 | 2,457,600 (fixed) | 0.02438 | 0.587 | 11 | PASS |
| 17 | `randomInt/duplicates/min-0-max-2147483649` | 18 | 200 | 10 | 10,649,600 (fixed) | 0.01446 | 0.9843 | 14 | PASS |
| 18 | `randomInt/duplicates/min-0-max-4294967296` | 19 | 245 | 12 | 1,003,520 (fixed) | 0.04053 | 0.07291 | 8 | PASS |
| 19 | `randomInt/duplicates/min-0-max-38` | 20 | 400 | 10 | 6,553,600 (fixed) | 0.02739 | 0.4362 | 10 | PASS |
| 20 | `randomInt/duplicates/min-0-max-54` | 21 | 400 | 10 | 13,516,800 (fixed) | 0.02671 | 0.4686 | 9 | PASS |
| 21 | `randomInt/duplicates/min-0-max-4294967297` | 22 | 200 | 10 | 1,638,400 (fixed) | 0.02698 | 0.4554 | 13 | PASS |
| 22 | `randomInt/duplicates/min-0-max-281474976710656` | 23 | 245 | 12 | 1,003,520 (fixed) | 0.03376 | 0.2009 | 12 | PASS |
| 23 | `shuffle/duplicates/lehmer-52` | 24 | 245 | 12 | 1,003,520 (fixed) | 0.02005 | 0.8125 | 13 | PASS |
| 24 | `shuffle/adjacency-mod4/n-52` | 25 | 1000000 | 27 | 1,000,000 (fixed) | 0.03569 | 0.1533 | 6 | PASS |
| 25 | `shuffle/adjacency-div4/n-52` | 26 | 1000000 | 14 | 1,000,000 (fixed) | 0.03498 | 0.1696 | 12 | PASS |

**Outcomes consumed (CTO check 04:37).** One outcome is counted as in HoQ's verified consumption column (coverage report 5f7f4ad7 (e): M × b × u randomInt outcomes, e.g. [0,2) 12208 × 4096 × 20 = 1,000,079,360); A6 reads "at a reduced n of 10^6 outcomes or more". Duplicates consume M_cal × b × u exactly (u = 20, 8, 3 and 13 for [0,2), [1,7), [0,100) and [0,2^31+1), so 200 blocks give 16,384,000, 6,553,600, 2,457,600 and 10,649,600; the smallest are [0,2^32), [0,2^48) and Lehmer at 245 × 4096 = 1,003,520). Adjacency consumes 10^6 shuffles. Coupon consumption is random (≥ M_cal × d); min/max/mean come from a recount of the same 1000 replications whose p-value digests equal the original run's. No entry is below 10^6, so none was re-run and none is superseded. `verification/calibration/wave1-outcomes.mjs` writes these fields into the results file.

### 7.2 NIT and cite refresh (no ruling changes)

- §6.2 duplicates F row (w1 config, b 4096): min E shown as 6.55 (read as "≥ 6.55") is exactly **6.545** (rounded up in the table).
- The CPO-R114 cite in §6 (DECISIONS.md "85a51013…") now refers to DECISIONS.md at sha256 **b9f2ecdab5f3fec7fc26d9600e9c8ec367507f6cbec1bfe8bbe3a73a3ab5e98d** (current, after the λ erratum).

### 7.3 Report limitations (to be named verbatim in the evidence report)

- **A-1 (adjacency mod-4 and div-4), CPO wording:** "tests clustering of equal labels; does not test label-to-label transition preference."
- **G-52 (all wave-1 reductions):** the reductions use leading bits or cards only (top 6/20 bits; first cards for Lehmer-52), so they are blind to low-bit and late-card defects.

### 7.4 Urns and blocks per replication; calibration-scale MDD (CTO batch J, HoQ A6-n / A8 R-A6n)

R-A6n counts public-call outcomes per replication (randomInt outcomes; shuffles for adjacency); urns and blocks
are stated for information. **The minimum outcomes per replication across all 26 entries is 1,000,000 (the two
adjacency entries, one shuffle = one outcome); the duplicates minimum is 1,003,520** (entries 18, 22, 23; HoQ A8 C-3).

Calibration-scale MDD of the duplicates entries: per replication (M = M_cal blocks, α = 0.01, the per-rep flag
level), δ in Σp² = (1+δ)/m detected with 50 % / 80 % power. Method and approximations as §6.2 [A1][A2][A3]
(helper /workspace/rng-backup/j-mdd/calib_mdd.py, sha256 8cfaa608…, importing dfv2-delta/power.py 4689c26d).

| Config | m | u | b | blocks/rep | urns/rep | outcomes/rep | cells | MDD50 | MDD80 |
|---|---|---|---|---|---|---|---|---|---|
| [0,2) | 2^20 | 20 | 4096 | 200 | 819,200 | 16,384,000 | 12 | 0.0960 | 0.1201 |
| [1,7) | 6^8 | 8 | 4096 | 200 | 819,200 | 6,553,600 | 10 | 0.1171 | 0.1470 |
| [1,38) | 37^4 | 4 | 4096 | 400 | 1,638,400 | 6,553,600 | 10 | 0.0873 | 0.1097 |
| [1,53) | 52^4 | 4 | 8192 | 400 | 3,276,800 | 13,107,200 | 10 | 0.0863 | 0.1083 |
| [0,100) | 10^6 | 3 | 4096 | 200 | 819,200 | 2,457,600 | 12 | 0.0939 | 0.1174 |
| [0,2^31+1) | 3^13 | 13 | 4096 | 200 | 819,200 | 10,649,600 | 10 | 0.1142 | 0.1434 |
| [0,2^32) | 2^20 | 1 | 4096 | 245 | 1,003,520 | 1,003,520 | 12 | 0.0868 | 0.1085 |
| [0,38) | 38^4 | 4 | 4096 | 400 | 1,638,400 | 6,553,600 | 10 | 0.0921 | 0.1156 |
| [0,54) | 54^4 | 4 | 8448 | 400 | 3,379,200 | 13,516,800 | 10 | 0.0902 | 0.1133 |
| [0,2^32+1) | 6700417 | 1 | 8192 | 200 | 1,638,400 | 1,638,400 | 10 | 0.1169 | 0.1469 |
| [0,2^48) | 2^20 | 1 | 4096 | 245 | 1,003,520 | 1,003,520 | 12 | 0.0868 | 0.1085 |
| Lehmer-52 | 2^20 | 1 | 4096 | 245 | 1,003,520 | 1,003,520 (shuffles) | 12 | 0.0868 | 0.1085 |

The KS MDD of the A6 rule itself is D_crit = 0.061462 (R = 1000, α = 0.001).


## 8. Wave-1 A6 calibration of THE statistic (J3, G-56; supersedes the §7 H2 table)

- Statistic `verification/statistic/wave1-statistic.mjs` (d4021fb7…, exact BigInt laws, exact §6.1 lumping), source `verification/calibration/wave1-source.mjs` (1a1c5573…), runner `wave1-calibrate.mjs` (632cb215…), adapter ae7a25d3…. Digests checked at run start (harness-at-start.sha256) and equal to the J2 commit f3d81687; the results test re-checks them against the current files (G-58).
- Same IV set as H2 (stream = entry index + 1, reps 0..999), committed before the run (H1). Not a re-roll: the statistic changed (G-56), so the H2 file `wave1-results.json` is kept and marked `superseded`; H2 per-rep p-values committed as `wave1-h2-pvalues.json` (G-59); J per-rep p-values are in the J results file.
- Rule unchanged: R = 1000, outcomes per replication ≥ 10^6, KS α = 0.001 (D_crit 0.061462 exact), flags at p < 0.01 in [2, 22]. KS p is asymptotic (Stephens).
- **Outcome: 26/26 PASS.** 25/26 rows reproduce H2 per-rep p-values to ≤ 1.1e-11 (law arithmetic). Entry 23 (Lehmer duplicates) differs in exactly one replication (rep 195, p 0.6423 → 0.0930): H2 completed a fallback shuffle with a 52nd `below(1)` draw, which consumes one stream word; the J source draws only the 51 forward Fisher–Yates draws (as the public shuffle and the adjacency entries do). Rep 195 has the only prefix fallback in that entry with H2 code, verified by replaying it both ways (the no-`below(1)` replay reproduces the J histogram exactly). Not a defect; both are valid null draws.

| # | entry | M_cal | blocks/rep | urns/rep | outcomes/rep min | max | cells | KS D | KS p | flags | verdict |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | `randomInt/coupon-collector/min-0-max-2` | 500,000 | – | – | 1,497,297 | 1,503,102 | 17 | 0.03402 | 0.194 | 9 | PASS |
| 1 | `randomInt/coupon-collector/min-1-max-7` | 166,667 | – | – | 2,443,277 | 2,458,182 | 54 | 0.02681 | 0.4635 | 7 | PASS |
| 2 | `randomInt/coupon-collector/min-1-max-38` | 27,028 | – | – | 4,177,106 | 4,227,602 | 246 | 0.02647 | 0.4799 | 12 | PASS |
| 3 | `randomInt/coupon-collector/min-1-max-53` | 19,231 | – | – | 4,509,623 | 4,564,267 | 308 | 0.01962 | 0.8325 | 7 | PASS |
| 4 | `randomInt/coupon-collector/min-0-max-100` | 10,000 | – | – | 5,147,854 | 5,227,082 | 438 | 0.02572 | 0.5173 | 5 | PASS |
| 5 | `randomInt/coupon-collector/min-0-max-2147483649` | 333,334 | – | – | 1,828,641 | 1,840,012 | 27 | 0.01896 | 0.8618 | 18 | PASS |
| 6 | `randomInt/coupon-collector/min-0-max-4294967296` | 15,625 | – | – | 4,710,915 | 4,775,506 | 349 | 0.03263 | 0.2335 | 14 | PASS |
| 7 | `randomInt/coupon-collector/min-0-max-38` | 26,316 | – | – | 4,203,166 | 4,253,191 | 251 | 0.03442 | 0.1834 | 10 | PASS |
| 8 | `randomInt/coupon-collector/min-0-max-54` | 18,519 | – | – | 4,546,864 | 4,606,300 | 315 | 0.0269 | 0.4595 | 12 | PASS |
| 9 | `randomInt/coupon-collector/min-0-max-4294967297` | 12,488 | – | – | 56,066,294 | 56,690,171 | 1115 | 0.01804 | 0.8982 | 12 | PASS |
| 10 | `randomInt/coupon-collector/min-0-max-281474976710656` | 15,625 | – | – | 4,714,430 | 4,776,517 | 349 | 0.02119 | 0.7559 | 11 | PASS |
| 11 | `shuffle/coupon-collector/lehmer-52` | 19,231 | – | – | 4,509,359 | 4,567,038 | 308 | 0.01482 | 0.9798 | 14 | PASS |
| 12 | `randomInt/duplicates/min-0-max-2` | 200 | 200 | 819,200 | 16,384,000 | 16,384,000 | 12 | 0.02831 | 0.3945 | 12 | PASS |
| 13 | `randomInt/duplicates/min-1-max-7` | 200 | 200 | 819,200 | 6,553,600 | 6,553,600 | 10 | 0.02018 | 0.8063 | 11 | PASS |
| 14 | `randomInt/duplicates/min-1-max-38` | 400 | 400 | 1,638,400 | 6,553,600 | 6,553,600 | 10 | 0.02275 | 0.6738 | 9 | PASS |
| 15 | `randomInt/duplicates/min-1-max-53` | 400 | 400 | 3,276,800 | 13,107,200 | 13,107,200 | 10 | 0.03481 | 0.1737 | 10 | PASS |
| 16 | `randomInt/duplicates/min-0-max-100` | 200 | 200 | 819,200 | 2,457,600 | 2,457,600 | 12 | 0.02438 | 0.587 | 11 | PASS |
| 17 | `randomInt/duplicates/min-0-max-2147483649` | 200 | 200 | 819,200 | 10,649,600 | 10,649,600 | 10 | 0.01446 | 0.9843 | 14 | PASS |
| 18 | `randomInt/duplicates/min-0-max-4294967296` | 245 | 245 | 1,003,520 | 1,003,520 | 1,003,520 | 12 | 0.04053 | 0.07291 | 8 | PASS |
| 19 | `randomInt/duplicates/min-0-max-38` | 400 | 400 | 1,638,400 | 6,553,600 | 6,553,600 | 10 | 0.02739 | 0.4362 | 10 | PASS |
| 20 | `randomInt/duplicates/min-0-max-54` | 400 | 400 | 3,379,200 | 13,516,800 | 13,516,800 | 10 | 0.02671 | 0.4686 | 9 | PASS |
| 21 | `randomInt/duplicates/min-0-max-4294967297` | 200 | 200 | 1,638,400 | 1,638,400 | 1,638,400 | 10 | 0.02698 | 0.4554 | 13 | PASS |
| 22 | `randomInt/duplicates/min-0-max-281474976710656` | 245 | 245 | 1,003,520 | 1,003,520 | 1,003,520 | 12 | 0.03376 | 0.2009 | 12 | PASS |
| 23 | `shuffle/duplicates/lehmer-52` | 245 | 245 | 1,003,520 | 1,003,520 | 1,003,520 | 12 | 0.01905 | 0.8579 | 13 | PASS |
| 24 | `shuffle/adjacency-mod4/n-52` | 1,000,000 | – | – | 1,000,000 | 1,000,000 | 27 | 0.03569 | 0.1533 | 6 | PASS |
| 25 | `shuffle/adjacency-div4/n-52` | 1,000,000 | – | – | 1,000,000 | 1,000,000 | 14 | 0.03498 | 0.1696 | 12 | PASS |

Smallest KS p 0.07291 (entry 18), max D 0.04053 < 0.061462, flags 5–18. **R-DEEP-TAIL (actual size ≤ nominal at α = 6.369e-5 per EBC entry) is NOT established** by this calibration (α = 0.01 / KS 0.001 scale); open item for HoQ/CPO.

### 8.1 R-DT-SCREEN hard-FAIL screen (K1; CPO-R116a = HoQ R-DT-SCREEN, ratified)

- In THE statistic module (`screen`, `klBernoulli`, `klSafe`, `screenFails`, `SCREEN`): b_i = 2·exp(−M·KL(q_i‖p_i)),
  q_i = x_i/M, p_i the exact lumped law cell; Bound = k·min_i b_i with k = the module's lumped cell count;
  **HARD FAIL iff Bound < 1e-10**. KL(0‖p) = −ln(1−p), KL(1‖p) = −ln p.
- Numerics: log space; KL_safe = max(0, KL·(1 − 10^-6) − 10^-15), so the Bound is rounded toward LARGER (a hard
  FAIL is never produced by rounding). Test: KL_safe ≤ a BigInt fixed-point (60-digit) KL on a 400+ point grid.
- **Size ≤ 1e-10 per entry** (union bound over the k cells, each b_i ≥ the two-sided Chernoff tail
  2·min(P[X≤x], P[X≥x]), checked exactly for M ≤ 40). **α ledger: 26 · 1e-10 = 2.6e-9** for wave 1, negligible
  against the per-entry α_e = 0.01/157.
- R-DT-MC item 8 (power of the MC flag at B + 1 = 1,004,800, flag iff #≥ ≤ 62): #≥ ~ Binomial(B, p_true);
  at p_true = α_e (6.369e-5) E[#≥] ≈ 64, so P(flag) ≈ 50 %; at p_true ≤ α_e/2, E[#≥] ≈ 32 and P(flag) is
  essentially 1 (P[Poisson(32) > 62] < 1e-6).

### 8.2 R-DT-MC framework and the duplicates exact sampler (K2; HoQ R-DT-MC / R-DT-SAMPLER)

- `verification/mc/dt-mc.mjs`: p_MC = (1 + #≥)/(B + 1), B + 1 = 1,004,800, ties counted as ≥, flag iff #≥ ≤ 62;
  no curtailment (1,005 blocks: 1,004 × 1,000 + 799). Exact per-observation categorical sampler for entries
  12–23 (binary search on 64-bit boundary prefixes, exact BigInt decision on a prefix tie, exact rejection
  above den); X² through THE module. Streams: labkit AES-256-CTR, IV = BE32(0x4d430001) ‖ BE32(entry·2^11 + block)
  ‖ 0^64, domain-separated from calibration IVs (BE32(stream 1..26) ‖ BE32(rep) ‖ 0^64).
- Null manifest (committed before an entry's evidence run) pins domain, IV scheme, key digest, B, block size,
  cell order digest and the statistic/sampler/adapter digests; it has NO observed X² (separate later commit).
  Resume re-checks all of these; blocks are written atomically and a recomputed block is digest-identical.
- Not done here: any MC run, any real key, the coupon/adjacency exact binomial chain (awaiting HoQ).

### 8.3 R-DT-MC integrity (K3b; HoQ A9 G-67, A10 G-71)

- The MC entry takes the OBSERVED count vector in the module's lumped cell order and computes X²_obs itself
  through `S.pearson` (same lumping, same M); a scalar is refused; manifest M must equal Σcounts; M > 10^9 is
  refused until Quant rechecks KL_safe at that scale.
- The manifest's B = 1,004,799, B + 1 = 1,004,800, block size 1,000 and 1,005 blocks must equal the constants.
- Every block file stores its per-rep X², the observed-vector digest and X²_obs; assembly re-verifies each
  block's X² digest, recomputes #≥ from the stored X², refuses a block made for another observed vector, and
  returns the sha256 chain head over all blocks (to be committed with the results).
