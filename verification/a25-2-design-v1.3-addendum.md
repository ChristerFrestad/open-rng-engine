# A25-2 design v1.3 addendum: extends v1.1 §4 (A25-3 / M11) and §6 (mutants)

v1.1 and v1.2 are append-only; this file adds to v1.1 §4 and §6 and supersedes nothing else.

## W1: MAJOR, found and fixed before the gate
At 2516680 a helper-mode late `registerHooks` resolve hook could short-circuit to `node:vm` and the run exited 0
(lockdown's resolve check sits below the late hook). Found by Backend's W1 wiring test before the gate; fixed in
1734059 (late hooks wrapped: resolve via schemeCheck + builtinLoadCheck, load via checkLoadResult) plus the backstop
load-side `node:` re-check. Regression test `W1:` (exit 92); mutant M54 restores the 2516680 state (wrap and load
re-check removed) and must be killed on exit 92. M41 removes only the late-resolve layer and is killed on the message.

## A25-M11 retired in both modes (HoQ/CTO 22:22), with no coverage lost
"Bare" = the bare-parent run (test/r-g64-a25-bare.mjs, no preload in the parent, child in helper mode under the
real preload and lockdown), where the A25-M* mutants run.

| Behaviour | Test | Mutant | Exit |
|---|---|---|---|
| bare eval | r-g64-a25-bare `A25-M11 replacement: eval (M50)` | M50 eval stub removed | 91 |
| bare new Function | r-g64-a25-bare `A25-M11 replacement: new Function (M51)` | M51 global Function left real | 91 |
| bare getBuiltinModule('vm') | r-g64-a25-bare `A25-M11 replacement: process.getBuiltinModule('vm') (M52)` | M52 FORBIDDEN check removed | 92 |
| helper node:vm (static + dynamic) | wiring `W1b` | M53 lockdown resolve + load re-check removed | 92 |
| W1 late hook to node:vm | wiring `W1:` | M54 (and M41, layer) | 92 |

## Late-hook rules and mutants M39–M49 (each killed on its own assertion; runner field `killOn`)
| Mutant | What | Test | Kill on |
|---|---|---|---|
| M39 | lateHookUsed never set | W-late(a) second call, W-late(e) earlier caller | 94 |
| M40 | mainIsHelper always true | W-late(b) non-helper main | 94 |
| M41 | late resolve builtin check removed | W1 | message `late resolve: forbidden builtin node:vm` |
| M42 | late load hash check removed | W1 (load side) | 90 |
| M43 | module.register unguarded | W-late(c) | 94 |
| M44 | advisory sha not compared | stream `advisory` | 90 |
| M45 | proof manifest_sha256 not compared | stream W6 | counted must be false |
| M46 | registerRefuseHook not one-shot | W2 | 87 |
| M47 | manifest file digest not compared | W4 | 90 |
| M48 | lockdown not installed | W1c | 94 |
| M49 | scheme check allows data: | W-scheme | message `scheme not allowed in helper mode: data:` |

Late-hook W-tests, all 94: earlier caller W-late(e), second call W-late(a), non-helper main W-late(b), register W-late(c), guard replacement W-late(d).

The runner reports KILLED only if the targeted test fails AND its output matches `killOn`; a failure elsewhere is KILLED-OTHER and does not count.
