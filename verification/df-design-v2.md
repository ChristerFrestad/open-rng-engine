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
