# open-rng-engine

Open-source TypeScript RNG and mapping library for Node.js, intended to be submitted as part of a licensee's system for independent lab evaluation. Not certified. Not a validated module.

Status: pre-alpha, work in progress. This is an early version: the library code and the verification harness are under active development, and the statistical evidence is still open. Nothing here has been released. The npm name is reserved; the published placeholder is not for use.

open-rng-engine is planned as a general-purpose Node.js library for unbiased random outcomes (bounded integers, shuffles, samples and integer-weighted picks) drawn from the platform CSPRNG (`node:crypto`). It is intended to help integrators produce evidence for their own evaluations.

## What this project is not

- Not certified. Not a validated module.
- No regulator or test laboratory has evaluated this software. Any evaluation applies to an operator's or supplier's complete system, never to this library on its own.
- It does not provide legal advice.

## Market stance

This project is not intended for, aimed at, or marketed to Norway, or any market where the integrator lacks a licence.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Security

See [SECURITY.md](SECURITY.md). Please do not report suspected vulnerabilities in public issues.

## Adapter name (provisional)

A cycling adapter package name `open-rng-engine-cycling` has been proposed. It is provisional until the G1 name freeze. It is not an official name.
