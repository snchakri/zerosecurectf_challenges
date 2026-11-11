# Challenge: Galois Field Logarithm Knapsack (crypto_13_knapsack_chor_rivest)

**Category:** Cryptography
**Difficulty:** Hard
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Realistic Failure Modes

---

## Scenario & Objective
Doom's cryptographers reached back to the Chor-Rivest knapsack, whose whole
trapdoor turns on discrete logarithms in an extension field GF(p^h). They set up
their algebra over GF(p^2) and published a generator `g` and a field element
`y = g^x`, with `x` the private exponent that gates the citadel's flag vault.
What they overlooked is the shape of the group they chose: the order of
GF(p^2)* is a product of only small primes. That smoothness quietly dissolves
the "hard" logarithm.

Your objective: recover the private exponent `x` by exploiting the field's
algebra, then lift the seal.

## Provided Files
- `field_params.json` — `p`, the non-residue `nr` defining
  `GF(p^2) = GF(p)[t]/(t^2 - nr)`, the generator `g`, the target `y = g^x`, the
  AES-sealed flag, and the exact sealing recipe. Elements are written `[a, b]`
  for `a + b·t`.

## Compliance
- Universal Format asserted: `zerosecure{...}`
- Zero unreasoned guessiness. `x` is uniquely determined modulo the group order
  and fully opens the vault.
