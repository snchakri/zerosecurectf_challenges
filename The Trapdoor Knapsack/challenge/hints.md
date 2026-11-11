# Staged Hint Ladder: The Trapdoor Knapsack

### Hint Level 1 (Orientation)
Each ciphertext is `C = Σ_j bit_j · b_j` for an unknown 0/1 vector (the message
bits of one block). You have the public key `b` but not the private
`(w, q, r)`. Don't try to undo the modular multiplication — attack the subset
sum directly.

### Hint Level 2 (Reframe)
Compute the density `d = n / max_j log2(b_j)`. It is well below 1, which is the
regime where lattice reduction solves subset-sum: the message bit-vector
corresponds to an unusually short vector in a lattice built from `b` and `C`.

### Hint Level 3 (Strong Nudge)
Use the Lagarias-Odlyzko lattice (or the centred CJLOSS variant, columns scaled
by 2 with an all-ones balancing row) with a large weight on the `C` coordinate,
and LLL-reduce it. A reduced vector whose first `n` entries are all `0/1` (or
`±1` for CJLOSS) and that reproduces `C` is the answer. Solve each block, then
pack the bits (MSB-first per byte) into the first `msg_len` bytes.

---
*Note: Crux Floor invariant — recognising low density and building the subset-sum
lattice is the lesson; hints never hand over the bits.*
