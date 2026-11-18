# Rule 8 df design note v1: the 67 open entries (DESIGN ONLY, NOT CODE)

Status: proposal for HoQ ruling. This note changes nothing in K, the threshold or n. None of it is code
until HoQ rules on it. Per CPO R112a any null distribution below that is not verified against a published
source is marked **OPEN**. Sources are cited only where they were checked on 2026-11-18. "To check" items
must be confirmed against the primary text before any of this becomes code. No page or equation numbers
are given unless they were seen.

Basis: decision rule v1 (FROZEN 5d09c75a) rule 8; `verification/k-tests-v1.1.json` (f75299de), 76 `df: null`
entries; HoQ ruling relayed 2026-11-18 23:30 CET (all 76 in the rule 8 set; 9 fixed in
`verification/harness/df-table.mjs`, digest 1ed710bf). That leaves 67 entries.

## 1. Sources checked

| Ref | Source | What was checked (2026-11-18) | Still to check |
|---|---|---|---|
| K2 | D. E. Knuth, *The Art of Computer Programming*, Vol. 2, *Seminumerical Algorithms*, 3rd ed., Addison-Wesley 1997, §3.3.2 "Empirical tests" | Through secondary course material that reproduces §3.3.2 (M. Mascagni, FSU, "Testing Random Numbers: Theory and Practice"): the coupon collector's test, its cell probabilities p_r = (d!/d^r)·S(r−1, d−1) for d ≤ r < t and p_t = 1 − (d!/d^(t−1))·S(t−1, d) (S = Stirling numbers of the second kind); the run test with COUNT[1..6] (6 = "≥ 6"), the statistic Σ_ij (COUNT[i] − n·b_i)(COUNT[j] − n·b_j)·a_ij divided by n (or n − 6), the matrix a_ij (values as printed on the slide), a vector b_i and 6 df; the serial correlation coefficient C with μ_n = −1/(n−1) and σ_n = (1/(n−1))·√(n(n−3)/(n+1)), n > 2; the collision test and birthday spacings test are in §3.3.2 of the 3rd edition. | The primary text itself: subsection letters, the exact normalisation of the run statistic (n vs n − 6), whether the run-test b_i and a_ij assume continuous (tie-free) values, whether μ_n, σ_n for C are exact or asymptotic and for which distributions, the collision-test exact probabilities. The b_i values (recalled as 1/6, 5/24, 11/120, 19/720, 29/5040, 1/840; the slide rendering was garbled) MUST be checked. |
| G53 | I. J. Good, "The serial test for sampling numbers and other tests for randomness", *Math. Proc. Cambridge Philos. Soc.* 49(2), 1953, pp. 276–284, doi:10.1017/S030500410002836X | Abstract (Cambridge Core): the overlapping ψ² is not asymptotically χ²; its first and second differences in the tuple length are; the proof is for a prime number of equiprobable symbols. | The exact df statement (d^t − d^(t−1) for the first difference is the form used by NIST STS and stated in later literature; confirm in the paper), and what holds for a non-prime alphabet or unequal symbol probabilities. |
| KR | D. P. Kroese, *Monte Carlo Methods* course notes (Univ. of Queensland), §1.4.9 collision tests | Collision test: b balls into m equiprobable urns, P(C = c) = m(m−1)⋯(m−(b−c)+1)·S(b, b−c)/m^b; χ² over repeated collision counts with grouped classes. | Agreement with K2's collision test and its exact-probability algorithm. |
| HR48 | W. Hoeffding, H. Robbins, "The central limit theorem for dependent random variables", *Duke Math. J.* 15, 1948 | Not checked this session. | **To check** before use (m-dependent CLT for the lag-1 product sum). |

## 2. Common design rules (all 67)

- One test per K entry, as now. K, the threshold and n are unchanged.
- Each test reads the public-call outcomes as listed in k-tests (one randomInt value, one weightedPick value, or one shuffle = one outcome).
- Cell probabilities are exact rationals (BigInt numerator and denominator). Never 1/d approximations.
- Cells are lumped contiguously from each tail until every expected count is ≥ 5 at the observation count actually collected. The lumping is computed in code from the exact probabilities before any data and pinned. df = cells − 1 for a multinomial χ².
- Reduction of a value v ∈ [0, r) to d categories is cat(v) = ⌊v·d/r⌋, where d divides r, so every category has probability exactly 1/d. d is chosen per r below (it is a prime divisor of r where Good's prime condition matters).
- For a non-χ² null: `df_status: normal-z`, `df: 'n/a'`, a reference fixture plan, still one test in K.
- **Open issue N-1 (for HoQ):** the tests that collect i.i.d. *segments* (coupon collector, one runs option) produce a random number of observations from a fixed n. Option (a): fix the number of observations M in advance so that M × (minimum outcomes per observation) ≥ 10^9, so consumption is ≥ 10^9 for certain but larger than 10^9 and random. Option (b): use the segments completed within the first 10^9 outcomes and drop the partial one. This is only asymptotically exact (O(1/M) bias). Option (a) is recommended. HoQ to rule whether rule 8's n counts outcomes consumed (a) or a fixed 10^9 (b).

## 3. Per statistic

### 3.1 Runs (randomInt × 11, Lehmer-52, weightedPick): 13 entries

**Statistic (R1, as asked: Knuth's covariance-corrected run test, K2).** Runs up on the sequence X_0..X_{n−1} of outcomes (n = 10^9), as integers: randomInt value v, Lehmer-52 rank (BigInt), weightedPick index 0/1/2. A run up is a maximal strictly increasing block, so a tie ends a run. COUNT[i] for lengths i = 1..k−1, with the last cell for lengths ≥ k. V = (C − μ)ᵀ Σ⁻¹ (C − μ), where μ and Σ are the exact mean vector and covariance matrix of the counts at this n.
- **Discrete generalisation (proposal, NOT in K2):** for i.i.d. X, every run-pattern probability is an inclusion–exclusion sum of e_k = P(X_1 < ⋯ < X_k). For uniform r, e_k = C(r, k)/r^k (exact BigInt); for weightedPick, e_k = the k-th elementary symmetric polynomial of (1/10, 3/10, 6/10); for continuous U, e_k = 1/k!. Example: P(a run of length exactly k starts at an interior j) = e_k − 2e_{k+1} + e_{k+2}. μ and Σ follow mechanically. This derivation is ours. **OPEN** until it is checked against K2's derivation and against brute-force enumeration.
- Cells per config: k = min(6, r). That gives 6 for r ≥ 6, 2 for r = 2 ([0,2): lengths 1 and 2 only), and 3 for weightedPick. Lehmer-52: 6. Lumping is applied if any expected count is < 5.
- Null: asymptotically χ² with df = k (rank of Σ; the counts are not constrained to a fixed sum). df would be 6 for 10 configs and Lehmer-52, 2 for [0,2), 3 for weightedPick. **OPEN:** confirm the rank and df for the discrete case.
- Up/down: K holds one runs entry per config, so the options are (U) runs up only, as in K2 (recommended), or (UD) a joint up+down statistic with joint covariance (df 2k, **OPEN**). A separate runs-down test would change K and is not offered.
- Fixtures: the r → ∞ limit reproduces K2's published a_ij and b_i; exhaustive enumeration of all r^n sequences for small (r, n), e.g. (2, 10) and (3, 8), matches μ and Σ exactly; known-bad sequences (sorted, alternating) are red.
- Fallback R2 (K2, to check, believed to be an exercise of §3.3.2): discard the element after each run, which makes run lengths i.i.d. with P(L ≥ k) = e_k. That gives an exact multinomial χ², df = cells − 1, subject to N-1.

### 3.2 Serial correlation (randomInt × 11, Lehmer-52, weightedPick): 13 entries

- **Statistic (S1, proposal):** Z = Σ_{j=0}^{n−2} (X_j − m)(X_{j+1} − m) / (σ²·√(n−1)), with H0 moments known exactly: uniform on [0, r): m = (r−1)/2, σ² = (r²−1)/12; weightedPick: m = 3/2, σ² = 9/20; Lehmer-52: r = 52!. The terms are uncorrelated with variance σ⁴, so E[Z] = 0 and Var[Z] = 1 exactly. Accumulate in BigInt (products reach ~2^96 for r = 2^48 and ~2^452 for 52!).
- Null: N(0,1) by an m-dependent CLT (HR48, **to check**). `df_status: normal-z`, `df: 'n/a'`, two-sided p = erfc(|Z|/√2).
- Option S2: K2's C with μ_n and σ_n (checked via secondary source only). **OPEN:** whether these are exact for discrete r.
- Reference fixture plan: exhaustive small-(r, n) enumeration gives E[S] = 0 and Var[S] = (n−1)σ⁴ exactly; the erfc implementation matches tabulated Φ(1.96) = 0.9750021 to 1e−7; Xⱼ = Xⱼ₊₁ streams are red.
- The S1 null is **OPEN** until HR48 is checked. The moments are exact; the normal limit is the unverified part.

### 3.3 Overlaps (randomInt × 11, Lehmer-52, weightedPick): 13 entries

- **Statistic:** Good's first-difference overlapping serial statistic (G53): ψ²_t − ψ²_{t−1} on cyclic overlapping t-tuples of categories cat(v), with d equiprobable categories. Asymptotically χ², df = d^t − d^(t−1) (form to check in G53).
- d = a prime divisor of r (G53's prime condition), and t = the largest t with d^t ≤ 10^6, so the expected count per t-cell is ≥ 1000:

| Config | r | d | t | cells d^t | df d^t − d^(t−1) |
|---|---|---|---|---|---|
| [0,2) | 2 | 2 | 19 | 524288 | 262144 |
| [1,7) | 6 | 3 | 12 | 531441 | 354294 |
| [1,38) | 37 | 37 | 3 | 50653 | 49284 |
| [1,53) | 52 | 13 | 5 | 371293 | 342732 |
| [0,100) | 100 | 5 | 8 | 390625 | 312500 |
| [0,2^31+1) | 3·715827883 | 3 | 12 | 531441 | 354294 |
| [0,2^32) | 2^32 | 2 | 19 | 524288 | 262144 |
| [0,38) | 2·19 | 19 | 4 | 130321 | 123462 |
| [0,54) | 2·3^3 | 3 | 12 | 531441 | 354294 |
| [0,2^32+1) | 641·6700417 | 641 | 2 | 410881 | 410240 |
| [0,2^48) | 2^48 | 2 | 19 | 524288 | 262144 |
| Lehmer-52 | 52! | 47 | 3 | 103823 | 101614 |

  The df column is arithmetic on the proposed (d, t) and has not been checked against G53's df statement.
- Variation per r: the binary and ternary reductions use only part of each value, a deliberate trade-off for exact equiprobability. HoQ may prefer a larger d with unequal cells, but that null is **OPEN** (G53 does not cover it as checked).
- weightedPick (p = 1/10, 3/10, 6/10, not equiprobable): **OPEN.** Good's result as checked assumes equiprobable symbols. Options: (a) a covariance-corrected overlapping statistic for unequal p (to be found in the literature); (b) non-overlapping t-tuples, which are exactly multinomial with df = cells − 1 after lumping, but that is not an "overlaps" test.
- Fixtures: exhaustive cyclic enumeration of small d^n confirms the linear constraints (G53 / the iacr 2023/890 note); a reference p-value on a pinned short sequence; a period-d^t de Bruijn sequence is red.

### 3.4 Coupon collector (randomInt × 11, Lehmer-52, weightedPick): 13 entries

- **Statistic (K2):** segment lengths needed to collect all d categories; COUNT[r] for d ≤ r < t and COUNT[t] for ≥ t; p_r and p_t exactly as in K2 (§1), in BigInt rationals; lumping from both tails (p_d = d!/d^d is tiny for large d) until expected ≥ 5. χ², df = cells − 1.
- d = r for r ≤ 100 ([0,2): 2, [1,7): 6, [1,38): 37, [1,53): 52, [0,100): 100, [0,38): 38, [0,54): 54). For large r, d = a divisor: 2^31+1 → 3; 2^32+1 → 641; 2^32 and 2^48 → 64; 52! → 52. **For HoQ:** d for the large r is a judgement call. The expected segment length is d·H_d, e.g. ≈ 4513 outcomes for d = 641.
- Observations: per N-1 option (a), M = ⌈10^9 / d⌉ segments.
- weightedPick (unequal p): P(T ≤ k) = Σ_{S ⊆ {0,1,2}} (−1)^|S| (1 − p_S)^k, by standard inclusion–exclusion, exact with 8 terms. The textbook citation is **to check**, so this null is **OPEN** until it is cited. The fixture would be exhaustive enumeration for k ≤ 12.
- Fixtures: Σ p = 1 exactly; the Stirling form equals the inclusion–exclusion form for equal p; small-d enumeration.

### 3.5 Duplicates (randomInt × 11, Lehmer-52, weightedPick): 13 entries

- **Statistic (K2 collision test / KR):** blocks of b balls into m equiprobable urns; C_b = collisions in block b; χ² of the C_b over P(C = c) = m^(b−c falling)·S(b, b−c)/m^b, lumped, df = cells − 1. b = 2^14, except where noted.
- Urns per config. An urn is u consecutive outcomes reduced by cat(·), or one outcome reduced to m = a divisor of r:

| Config | urn | m |
|---|---|---|
| [0,2) | 20 values | 2^20 |
| [1,7) | 8 values | 6^8 |
| [1,38) | 4 values | 37^4 |
| [1,53) | 4 values | 52^4 |
| [0,100) | 3 values | 10^6 |
| [0,2^31+1) | 13 ternary cats | 3^13 |
| [0,2^32) | top 20 bits | 2^20 |
| [0,38) | 4 values | 38^4 |
| [0,54) | 4 values | 54^4 |
| [0,2^32+1) | ⌊v·6700417/r⌋ | 6700417 |
| [0,2^48) | top 20 bits | 2^20 |
| Lehmer-52 | ⌊rank·2^20/52!⌋ (52! has 2^49) | 2^20 |

- Blocks B = ⌈10^9/(b·u)⌉, so consumption is ≥ 10^9 (N-1 applies).
- weightedPick: urns of unequal probability, so the exact collision distribution is **OPEN** (no checked source). The option is u = 13 tuples with a computed exact distribution, which is not designed yet.
- Fixtures: Σ P(C = c) = 1; small (m, b) enumeration; a constant stream is red.
- The null form is to check against K2's primary text (only KR was seen).

### 3.6 Shuffle mod-4 / div-4 adjacency counts: 2 entries

- **Statistic (proposal A):** per shuffle of 52, X = #{i < 51 : lab(π_i) = lab(π_{i+1})}, with lab = v mod 4 (4 labels × 13) or ⌊v/4⌋ (13 labels × 4). The exact distribution of X comes from counting multiset arrangements by the number of equal adjacencies (BigInt DP or inclusion–exclusion). Exact means are 51·12/51 = 12 (mod-4) and 51·3/51 = 3 (div-4). χ² over 10^9 i.i.d. shuffles, lumped, df = cells − 1.
- Option B: a 4×4 / 13×13 label-transition table over all 51 positions. Its cells are dependent within a shuffle, so it would need covariance correction. **OPEN**, not recommended.
- No published source is cited for the distribution of X, so the null is **OPEN** (exact by construction, but the DP must be verified). Fixtures: brute-force enumeration of all arrangements of small decks (2 labels × 3, 2 × 4, 3 × 2, 4 × 2) equals the DP; Σ P = 1; E[X] matches.

## 4. Map of the 67 entries

| Entry ids | Statistic | Null / df | Status |
|---|---|---|---|
| randomInt/runs/<11 configs> | §3.1 R1 runs up, k = min(6, r) | χ², df k (6; 2 for [0,2)) | OPEN (discrete μ, Σ derivation) |
| shuffle/runs/lehmer-52 | §3.1 R1 on BigInt ranks | χ², df 6 | OPEN |
| weightedPick/runs/weights-1-3-6 | §3.1 R1, e_k from weights | χ², df 3 | OPEN |
| randomInt/serial-correlation/<11> | §3.2 S1 | normal-z, df n/a | OPEN (HR48 to check) |
| shuffle/serial-correlation/lehmer-52 | §3.2 S1, r = 52! | normal-z, df n/a | OPEN |
| weightedPick/serial-correlation/weights-1-3-6 | §3.2 S1, m 3/2, σ² 9/20 | normal-z, df n/a | OPEN |
| randomInt/overlaps/<11> | §3.3 G53, (d, t) per table | χ², df d^t − d^(t−1) | OPEN (df form to check in G53) |
| shuffle/overlaps/lehmer-52 | §3.3, d 47, t 3 | χ², df 101614 | OPEN |
| weightedPick/overlaps/weights-1-3-6 | §3.3, unequal p | none | OPEN (no checked null) |
| randomInt/coupon-collector/<11> | §3.4 K2 | χ², df cells − 1 (computed) | OPEN (primary K2 text, N-1) |
| shuffle/coupon-collector/lehmer-52 | §3.4, d 52 | χ², df cells − 1 | OPEN |
| weightedPick/coupon-collector/weights-1-3-6 | §3.4 inclusion–exclusion | χ², df cells − 1 | OPEN (citation) |
| randomInt/duplicates/<11> | §3.5 collision, urns per table | χ², df cells − 1 | OPEN (K2 primary text, N-1) |
| shuffle/duplicates/lehmer-52 | §3.5, m 2^20 | χ², df cells − 1 | OPEN |
| weightedPick/duplicates/weights-1-3-6 | §3.5, unequal urns | none | OPEN |
| shuffle/adjacency-mod4/n-52 | §3.6 A, 4 × 13 | χ², df cells − 1 | OPEN (DP unverified) |
| shuffle/adjacency-div4/n-52 | §3.6 A, 13 × 4 | χ², df cells − 1 | OPEN (DP unverified) |

The <11 configs> are min-0-max-2, min-1-max-7, min-1-max-38, min-1-max-53, min-0-max-100, min-0-max-2147483649,
min-0-max-4294967296, min-0-max-38, min-0-max-54, min-0-max-4294967297 and min-0-max-281474976710656.
Totals: 13 + 13 + 13 + 13 + 13 + 2 = 67. All 67 stay OPEN in the harness (NOT-READY) until HoQ rules and the
OPEN items are closed. Nothing here is written into `df-table.mjs`.

## 5. Questions for HoQ

1. N-1: observation count for segment tests: (a) fixed M with consumption ≥ 10^9 (recommended) or (b) fixed 10^9 outcomes.
2. Runs: U (up only, recommended) or UD.
3. Serial correlation: S1 (exact H0 moments, recommended) or S2 (K2's C).
4. Overlaps and duplicates: accept the prime- or divisor-reduced equiprobable categories (exact, lower resolution for large r) or require unequal cells (null OPEN).
5. weightedPick overlaps and duplicates: which option (both OPEN).
6. Adjacency mod-4/div-4: proposal A (single count, exact DP) or B.
