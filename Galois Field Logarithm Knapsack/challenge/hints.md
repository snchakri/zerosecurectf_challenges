# Staged Hint Ladder: Galois Field Logarithm Knapsack

### Hint Level 1 (Orientation)
First build arithmetic in `GF(p^2) = GF(p)[t]/(t^2 - nr)`: an element `a + b·t`
is stored as `[a, b]`, and multiplication uses `t^2 = nr (mod p)`. The task is a
discrete log: find `x` with `g^x = y` in this field.

### Hint Level 2 (Reframe)
A direct baby-step/giant-step over the whole group is `~sqrt(p^2-1) ~ 2^49.5`
— too much. Look at the group order `p^2 - 1`. Factor it. It is smooth (only
small prime factors), which is exactly the precondition for Pohlig-Hellman.

### Hint Level 3 (Strong Nudge)
For each prime power `q^e || (p^2-1)`, project `g` and `y` into the order-`q^e`
subgroup (raise to `(p^2-1)/q^e`), solve `x mod q^e` digit by digit with a small
BSGS in the order-`q` subgroup, and CRT the residues into `x mod (p^2-1)`. Feed
`x` into the documented AES key derivation to unseal the flag.

---
*Note: Crux Floor invariant — field arithmetic plus the smooth-order
Pohlig-Hellman reduction is the lesson; hints never hand over `x`.*
