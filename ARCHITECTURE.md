# Architecture

Layered design for maximum reusability and certification friendliness.

```
Game Layer (your poker, slots, roulette, etc.)
        ↓
Mapping & Utilities (Fisher-Yates, unbiased range, weighted selection)
        ↓
Provably Fair Layer (optional commit-reveal)
        ↓
DRBG Core (HMAC-DRBG SHA-256, NIST SP 800-90A)
        ↓
Entropy / Seeding (OS CSPRNG)
```

## Key decisions

- **HMAC-DRBG (SHA-256)** — NIST SP 800-90A approved, easy to audit, widely accepted by labs.
- **Unbiased mapping** — Rejection sampling for ranges, correct Fisher-Yates.
- **TypeScript** — Isomorphic (browser + Node + edge) for maximum developer adoption.
- **Provably Fair optional** — Built on top, never instead of strong cryptography.

## Certification path

Labs certify concrete builds. A well-documented, NIST-aligned core can be certified once and then reused with delta reviews.
