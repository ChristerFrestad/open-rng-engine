# Architecture

Work in progress. An early implementation exists in this repository; it is not released, and the statistical evidence is still open.

The library is intended to produce unbiased random outcomes (integers, shuffles, and weighted picks) from the platform CSPRNG.

```
Caller
        ↓
Mapping (integer ranges, shuffles, weighted picks)
        ↓
Platform CSPRNG
```

## Scope

- Outcome types in scope are integers, shuffles, and weighted picks.
- Random bits come from the platform CSPRNG.
- GLI-19 and NIST SP 800-22 are reference documents only. NIST STS results are statistical evidence, not proof.
- Not certified. Not a validated module.
- The library is not certified and cannot be.
- Any evaluation applies to an operator's or supplier's complete system, never to this library.
