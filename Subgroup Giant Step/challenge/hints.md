# Staged Hint Ladder: Subgroup Giant Step

### Hint Level 1 (Orientation)
Look at `subgroup_order` versus `p`. The generator's order is a small prime `q`,
not `p-1`. The discrete log you need therefore lives in a group of size `q`, no
matter how large `p` looks.

### Hint Level 2 (Reframe)
A search of all `q` exponents is over 2^40 — too slow. But in a group of order
`q` you can meet in the middle: write `x = i*m + j` with `m = ceil(sqrt(q))`.
Tabulate the "baby steps" `g^j`, then take "giant steps" of size `m` from `h`.

### Hint Level 3 (Strong Nudge)
Build `{ g^j mod p : j in [0, m) }` as a hash map, compute `g^{-m} mod p`, and
walk `h * (g^{-m})^i` for `i in [0, m)` until it lands in the map; then
`x = i*m + j`. Feed `x` into the documented AES key/nonce derivation to unseal
`sealed_flag_hex`.

---
*Note: Crux Floor invariant — the subgroup observation and the BSGS trade-off
are the lesson; hints never hand over `x`.*
