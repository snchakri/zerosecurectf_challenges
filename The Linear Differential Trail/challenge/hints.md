# Staged Hint Ladder: The Linear Differential Trail

### Hint Level 1 (Orientation)
The round function's S-boxes are `ROL2((a + b) mod 256)`. Addition is not linear
over XOR, but a one-bit difference of `0x80` in an addend passes through
`(a + 0x80) mod 256 = a XOR 0x80` with probability 1 — so `0x80`-type differences
propagate cleanly. That is the hook for differential cryptanalysis.

### Hint Level 2 (Reframe)
The transcript uses input difference `alpha` in the left half. Study how that
difference evolves over three rounds (it has a strongly biased pattern — around
12%). For the last round, guess the 16-bit round key `K3`, invert that round for
every ciphertext pair, and look at the resulting one-round-earlier difference:
the correct key makes a single difference value spike far above the noise.

### Hint Level 3 (Strong Nudge)
Pre-filter the "right pairs" (those whose observable round-output difference
matches the characteristic), rank `K3` by the peak count, keep the top few
candidates, peel round 4, and repeat for `K2`. Once two rounds are stripped you
have a 2-round Feistel with known plaintext: `K0` and `K1` follow directly from
`F(R0 ^ K0) = L2 ^ L0` and `F(L2 ^ K1) = R2 ^ R0`. Validate the whole key against
the transcript, then CTR-decrypt the flag. (Any key equivalent to the real one
works — it is the same permutation.)

---
*Note: Crux Floor invariant — building the differential trail and peeling rounds
is the lesson; hints never hand over the round keys.*
