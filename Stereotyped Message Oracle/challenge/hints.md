# Staged Hint Ladder: Stereotyped Message Oracle

### Hint Level 1 (Orientation)
The plaintext is `M = known_prefix || unknown`, with `unknown` only `secret_len`
bytes. As an integer, `M = A + x` where `A = int(known_prefix)·256^secret_len`
is known and `x = int(unknown)` is small (`x < 256^secret_len`). You have
`c = (A + x)^3 mod n`.

### Hint Level 2 (Reframe)
Define `f(x) = (A + x)^3 − c (mod n)`. The real `x` is a root of `f` modulo `n`
and it is *small* relative to `n^{1/3}`. This is exactly Coppersmith's setting:
a small root of a univariate polynomial mod `n` can be found when the root is
below roughly `n^{1/degree}`.

### Hint Level 3 (Strong Nudge)
Build the Howgrave-Graham lattice from shift polynomials
`n^{m-i}·x^j·f(x)^i` (and a few `x^i·f(x)^m`), substitute `x → xX` with
`X = 256^secret_len`, and LLL-reduce. A short vector is a polynomial with the
same small root but *integer* (not just modular) coefficients — find its integer
root (e.g. with arbitrary-precision root isolation), then read the flag off
`known_prefix || unknown`. `m = 2` with one extra shift already suffices here.

---
*Note: Crux Floor invariant — recognising the small-root structure and building
the lattice is the lesson; hints never hand over `x`.*
