# Staged Hint Ladder: One-Time Authenticator Failure

### Hint Level 1 (Orientation)
Each tag is `tag = (c_1 r^2 + c_2 r + s) mod p` for a two-block message
`(c_1, c_2)`. Both captured messages share the same `(r, s)`. Write out the two
equations.

### Hint Level 2 (Reframe)
Subtract the two tag equations: `s` cancels, leaving
`(a_1 − b_1) r^2 + (a_2 − b_2) r − (t_1 − t_2) ≡ 0 (mod p)` — a quadratic whose
only unknown is `r`. Solve it in the field.

### Hint Level 3 (Strong Nudge)
`p = 2^130 − 5 ≡ 3 (mod 4)`, so a square root is `d^{(p+1)/4} mod p`. The
quadratic yields two candidate `r`; for each, back out `s = t_1 − (a_1 r^2 +
a_2 r)`. Forge the tag of the target message with the documented MAC, derive the
AES key from that tag, and the correct candidate is the one whose GCM tag
verifies.

---
*Note: Crux Floor invariant — the nonce-reuse linearisation (and the forgery it
enables) is the lesson; hints never hand over `(r, s)`.*
