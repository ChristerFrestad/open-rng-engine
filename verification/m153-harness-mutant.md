# M-153 — harness mutant: outcome counting and the 10^9 floor

Spec only. There is no evidence-harness code yet. These fixtures are for the future harness, which must:

1. Refuse any mapped-test usage whose planned outcome count is below 10^9.
2. Refuse a usage that counts *draws* (index reads, rejection retries, Fisher–Yates steps, k items inside a sample) instead of *public-call outcomes*.

Authority: CPO-R107 B-3 (DECISIONS.md L112, sha256 `b7f14dcbf1bdace71067bdc9c4a8c514bb5b0ca40376337eb3e420aac431bc7b`): one outcome is the result of one public call (one full permutation for shuffle, one complete sample set for sample, one value for randomInt and weightedPick). The requirement is ≥10^9 outcomes per usage per RC (PLAN L742).

The mutant M-153 is: a harness that accepts n<10^9, or that treats a draw/read/retry as an outcome. Each fixture below is a known-good (must accept) or known-bad (must refuse) case the harness self-test should use once the harness exists. The self-test should fail if a mutated harness lets a known-bad case through.

## Outcome unit (frozen by CPO-R107 B-3)

| Primitive | One public-call outcome | What is *not* an outcome |
|---|---|---|
| `randomInt(min,max)` | The single returned integer | A rejected A.5.1 try; a 4- or 7-byte `randomFillSync` read; a retry inside the 128-try cap |
| `shuffle(items)` | One complete permutation (the returned array) | One Fisher–Yates index; one rejection retry; one swapped element |
| `sample(n,k)` | One complete k-set in draw order | One of the k index draws; one prefix step |
| `weightedPick(weights)` | One returned index | One rejected try over [0,T); one binary-search probe |

n counts outcomes, not bytes, not reads, not tries.

## Known-good fixtures (must accept)

| ID | Setup | Why it is good |
|---|---|---|
| G1 | `randomInt(0,37)`, n = 10^9 values | Floor met; one value = one outcome |
| G2 | `randomInt(0,2^48)`, n = 10^9 values, including rejected tries in the *byte* log but not in n | Floor met; retries are not outcomes |
| G3 | `shuffle` of 52, n = 10^9 permutations | Floor met; one permutation = one outcome (CPO-R107 corrected the 10^8 text in PRQ-02/05) |
| G4 | `sample(52,5)`, n = 10^9 complete 5-sets | Floor met; the 5 index draws inside one call are not extra outcomes |
| G5 | `sample(80,20)`, n = 10^9 complete 20-sets | Same as G4 for the larger k |
| G6 | `weightedPick` on W-A (64 symbols, T=2080), n = 10^9 returned indices | Floor met |
| G7 | `weightedPick` on `[2^52, 2^52-1]` (T=2^53-1, 7-byte reads, possible retries), n = 10^9 returned indices | Floor met; retries are not outcomes |
| G8 | Ordered-pair χ² on `randomInt(0,37)`, n = 10^9 *tuples* (each tuple is two consecutive public calls) | PRQ-06 / CPO-R107: n counts tuples/windows, each built from public calls, not from inner draws |
| G9 | n = 10^9 + 1 (or any n > 10^9) on any usage in `k-tests-v1.json` | Floor is a minimum, not a target cap |

## Known-bad fixtures (must refuse)

| ID | Setup | Why it is bad | What a correct harness does |
|---|---|---|---|
| B1 | Any usage, n = 10^9 − 1 | Below the floor | Refuse the usage; do not start the run |
| B2 | Any usage, n = 10^8 | The stale quality L438 / PRQ-02 / PRQ-05 figure; CPO-R107 superseded it | Refuse |
| B3 | Any usage, n omitted or 0 | Missing floor | Refuse |
| B4 | `shuffle` of 52, n = 10^9 × 51, described as "10^9 Fisher–Yates index draws" (or 52, or "reads") | Counts draws, not public calls. 10^9 shuffles produce ≥51×10^9 index draws; treating those as outcomes would let a run of only 10^9/51 shuffles look like it met the floor | Refuse. Require n to be a count of complete permutations |
| B5 | `shuffle` of 52, n = 10^9, but the collector increments n once per Fisher–Yates step | Same mutation, implemented in the collector rather than in the planned n | Refuse (or fail the collector self-check) |
| B6 | `sample(52,5)`, n = 5×10^9, described as "five draws per sample" | Counts the k index draws, not the complete sample set. A run of 10^9/5 calls could be mis-counted as 10^9 | Refuse |
| B7 | `sample(80,20)`, n = 20×10^9 "index draws" | Same as B6 for k=20 | Refuse |
| B8 | `randomInt(0,37)`, n = (accepted + rejected tries) with no separate public-call counter, planned so that n_tries ≥ 10^9 but public calls < 10^9 | Counts A.5.1 tries, not public calls. For r=37 the expected tries per call is 64/37 ≈ 1.73, so 6×10^8 calls can produce ≥10^9 tries | Refuse |
| B9 | `weightedPick` on T=2^48+1 (7-byte internal draw), n counted from `bytesConsumed` or from rejected tries | Counts reads or retries, not returned indices | Refuse |
| B10 | Lehmer-stream test on 52-card shuffle, n counted as "Lehmer digits" or "digits of the factorial-number-system encoding" rather than as one code per shuffle | One shuffle produces one Lehmer code (one outcome). Counting digits inflates n | Refuse |
| B11 | A "raw bytes" or `randomBytes(n)` length used as if it were a mapped-test outcome count | Mapped-test n is public-call outcomes, not raw bytes (raw batteries have their own length rules) | Refuse for the mapped-test family |
| B12 | Ordered-pair / five-call-pair usage with n counted as the number of *values* in the window (2n or 5n) rather than as the number of tuples/windows | Inflates n by the window size | Refuse |

## Self-test shape (once a harness exists)

- Load `k-tests-v1.json`. For each of the 157 IDs, a plan with n=10^9 in the correct unit (G1–G9 as applicable) must be accepted.
- Each of B1–B12 must be refused, with a reason that names either "n < 10^9 public-call outcomes" or "n is not a public-call count".
- A mutant that lowers the floor to 10^8 must be killed by B2.
- A mutant that increments n per `randomFillSync` / per Fisher–Yates step / per sampled index must be killed by B4, B5, B6 or B8.
- No fixture here is an evidence run. None of them generate 10^9 outcomes; they only describe the planned n and the unit the harness is asked to accept.

## Out of scope

- The α / Bonferroni threshold 0.01/K, tool pins, and battery decision rule.
- Changing K′. These fixtures do not add or remove mapped tests.
