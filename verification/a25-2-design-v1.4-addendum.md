# A25-2 design v1.4 addendum: F-MI-1 (extends v1.1 §6 and the v1.3 mutant table)

F-MI-1 (found by TE, confirmed by CTO at e9c705b): `positionalConsumers` in verification/harness/stream-launcher.mjs
used `Q.positionalAccumulator(n)` directly as the fixed consumer. The launcher calls `add()` with the w=1 window `[v]`,
while the accumulator expects the permutation `v`. So every streamed shuffle/positional entry voided on its first outcome
('positional: outcome is not a permutation of n'), at any N. The adj consumer already unwrapped `win[0]`.

Fix: the consumer wraps the accumulator: `{ C: a.C, n, add: (win) => a.add(win[0]), merge: (o) => a.merge(o) }`.
`merge` and `finish` still use `a.C`, unchanged.

| Mutant | What | Test | Kill on |
|---|---|---|---|
| M55 | positional window unwrap removed | stream `F-MI-1` (runStreamCore, shuffle/positional/n-52, M=64, N=2 and N=32: counted, and x2/df/p equal one pass) | message `positional: outcome is not a permutation of 52` |

Checked before commit: with the unwrap removed, `F-MI-1` fails with exactly that void reason (log stream-fmi1-unfixed.run12.log).
