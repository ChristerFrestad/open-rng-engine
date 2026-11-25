# A25-1 design v1: the preload is mandatory for every evidence helper (G-54)
Base: r-g64/impl 55284904. HoQ addendum 1, A25-1: "every evidence helper runs under the backstop preload. The launcher refuses a helper whose H frame does not carry the preload's digest and a live grant. The preload digest goes into the D22-7 header."

## What is already there (read at 55284904)
- realSpawnPart (stream-launcher L264-269) spawns `node --import BACKSTOP helper`. It deletes NODE_OPTIONS and sets ENTROPY_BACKSTOP_HELPER.
- H frame: b = helperState() from the helper's preload. The launcher compares b.backstop_sha256 with sha(BACKSTOP) (L49), plus mode/k/F/floor (L47-48), and fails if b is missing (L46).
- The header binds tools/ci/entropy-backstop.mjs through bindings().files (BOUND_FILES), so a checkpoint is reused only when the digest matches (reuseMismatches, D22-7).
- The G-39 proof of preload: the wrapped spawn gives each node child a proof path, which the child's backstop writes at install. If the proof is missing, the result goes to proofFailures (exit 1 at the end) but does NOT void the part.

## Gaps against A25-1
- G1 (live grant): runStreamPlan/realSpawnPart don't require an open evidence grant, and the H frame carries no grant.
- G2: the missing G-39 proof isn't tied to the part verdict.
- G3: the header has the digest only inside bindings.files, with no explicit field for the preload.
- G4: no launcher-side check that the spawn argv really carries `--import <BACKSTOP>` (A25-6 iv path).

## Changes
1. runStreamPlan(plan, { grant, ... }) requires the grant from openEvidenceGrant(). It is refused unless evidenceGrantActive() is true and grant is that open grant; the check is done again before every spawn (live).
2. The launcher passes ENTROPY_BACKSTOP_GRANT=`grant-<n>@<launcher pid>` (the same form as the G-54 stamp token). In helper mode the helper's preload reads it once and deletes it from the env, then returns it as helperState().grant.
3. H check, new, at L49: b.grant must equal the live grant token AND the grant must still be open when the H frame arrives. Otherwise the part is void: "H grant is not the live evidence grant (A25-1)".
4. The part verdict also requires the G-39 proof for that child. realSpawnPart returns the proof path, and st.finish voids the part with "helper did not prove the preload (A25-1)" when it's missing.
5. realSpawnPart asserts its own argv[0..1] is exactly ['--import', BACKSTOP], with BACKSTOP as the absolute bound path, and refuses otherwise.
6. header() gets `preload: { path: 'tools/ci/entropy-backstop.mjs', sha256, helper_mode, grant }`. reuseMismatches compares preload.sha256 (a header from a different preload means no reuse).

## Limits (stated honestly)
- The grant token is passed in the env, so a helper WITHOUT the preload could read it and echo it. The token on its own isn't a proof of preload. The binding proof is (4), the proof file written by the preload at install, combined with (3), the helper state that only the helper-mode preload produces. The grant adds liveness and binds the run, not authenticity. G-64 still holds: anything the child writes is a claim, and the launcher re-checks everything it counts.

## Tests and mutants (A25-6 iv is covered here)
- Tests:
  - a fake helper with no grant, a wrong grant, or a grant closed before H is void;
  - a fake helper with no proof is void;
  - runStreamPlan without an open grant is refused;
  - the header carries preload.sha256;
  - reuse with a different preload digest is refused;
  - a spawn without --import is refused.
- Mutants, each killed:
  - A25-M23: drop the H grant compare;
  - A25-M24: grant liveness not rechecked;
  - A25-M25: proof not tied to the part;
  - A25-M26: the argv --import assert removed;
  - A25-M27: the header preload not compared on reuse.

## Cost and ETA
Code plus unit tests, light. The full gate runs only after TE's #782 heavy slot. Local commit Fri 12:00, as agreed, or sooner.
