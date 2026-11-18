# Statistical evidence decision rule, v1 (F-15)

Status: COMMITTED-BEFORE-ANY-EVIDENCE-RUN, NOT YET FROZEN. Spec F-15 (inputs/cto-g1-spec.md L58, L381) requires this
file to be committed before the first evidence run id. The freeze itself belongs to HoQ in PH1, before any data
(quality.md L428; PLAN.md L732, L948), after the statistic counts are re-verified (PLAN.md O-2, O-3; alpha re-split O-43).
Until HoQ records the freeze, no evidence run may be started. Any change after the freeze needs a CR-reviewed commit before
the next run (quality.md L428).

This file transcribes the rule; it adds nothing. Where the two sources differ, both values are listed and the item is open.

## Sources (read-only, pinned)

- inputs/quality.md v5.5.7, sha256 0202a82b4f96e8129c4ae509eabe768bde8b9511a0f34a705ce6fd0f0646c690, section 3.2, L426-L445 (sha256 of those lines: 286e57337d493ef8cf370861a50b366f490bf88c8001ac85b3fcc03b0462cd72).
- PLAN.md r4.9, sha256 206e0511a76fe62712b6c7249497417bf77cad5faf64d4cb1ace570c70b21503, R-25 (L133) and section 4.4, L730-L746 (sha256 of those lines: 1f01d14a92e6ffb0b23354747365f6a12afea3992864373fc77273931e51e41d).

## Rule

| Item | Value | Source |
|---|---|---|
| Significance level | alpha = 0.01, the only level, applied at the decision level: P(release-blocking FAIL for a perfect generator) <= 0.01 per evidence run | quality L428; PLAN L732 |
| SP 800-22 r1a proportion | m = 1,000 sequences x 10^6 bits, per-sequence alpha 0.01; lower bound 0.9805607; a statistic is flagged if fewer than 981 of 1,000 pass (one-sided); random-excursion statistics recompute the bound for their m' with the same formula | quality L434; PLAN L737 |
| SP 800-22 r1a uniformity | 10-bin chi-square of the p-values; flagged if P-value_T < 0.0001 (>= 55 sequences) | quality L434; PLAN L737 |
| TestU01 | suspicious p outside [0.001, 0.999] = flag; p < 10^-10 or p > 1 - 10^-10 = hard FAIL | quality L435; PLAN L738 |
| Dieharder | WEAK/FAILED labels not used; p-values use the TestU01 bands | quality L436; PLAN L739 |
| PractRand | only a FAIL verdict counts, as hard FAIL; other lines logged, not gated | quality L437; PLAN L739 |
| Mapped-output tests | per-test threshold 0.01/k (Bonferroni) = flag; p < 10^-10 = hard FAIL; k fixed at the PH1 freeze | quality L438, L443; PLAN L741 |
| CLEAN | 0 flags | quality L440; PLAN L743 |
| SUSPECT | 1-5 flags and no hard FAIL: re-run each flagged test exactly once, as a fresh run with the same sample size; the same statistic flagged again = FAIL, otherwise PASS-WITH-NOTE (both results logged) | quality L440; PLAN L743 |
| Hard FAIL (no re-run) | any failure-band p, any PractRand FAIL, or >= 6 flags in one RC run | quality L440; PLAN L743 |
| Nightly rule | same rule with the hard-FAIL count lowered to >= 4 flags | quality L443; PLAN L746 |
| Discipline | no other re-runs, no seed or run selection, all outputs kept | quality L440; PLAN L743 |
| Release effect | an RC needs CLEAN or PASS-WITH-NOTE on the exact SHA; missing, aborted or inconclusive evidence = FAIL | quality L444 |

## Open before the freeze (not decided here)

1. Statistic counts 188 / 160 / 114 and E ~ 1.52 are ANTATT; re-verify, then recompute E and the false-FAIL total (quality L439, L441; PLAN L742, O-2).
2. PractRand thresholds and false-alarm rate are unknown (quality L437; PLAN L739, O-3).
3. Mapped-output sample size differs: >= 10^8 outcomes per usage (quality L438) vs >= 10^9 per usage per RC (PLAN L741). Which value does the frozen rule use?
4. Alpha re-split (section 7.4) recomputed at PH1 (PLAN L948, O-43).
