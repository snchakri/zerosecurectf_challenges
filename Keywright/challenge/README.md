# Keywright

**Category:** Reverse Engineering

A vendor's offline license-key validator checks the key against a dense system of modular linear congruences (A x == t over the ring Z/2^32) baked into a per-instance image. Reverse the validator to recover the system, then SOLVE it with sympy for the one key that satisfies every constraint and unwraps the flag.

**Download the attached files** (the engine and your instance's image), reverse them offline, then present your answer to the validator.

**Connect:** `nc <challenge-host> 30056`

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
