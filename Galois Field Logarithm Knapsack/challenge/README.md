# Galois Field Logarithm Knapsack

**Category:** Cryptography

Doom's cryptographers reached back to the Chor-Rivest knapsack, whose whole
trapdoor turns on discrete logarithms in an extension field GF(p^h). They set up
their algebra over GF(p^2) and published a generator `g` and a field element
`y = g^x`, with `x` the private exponent that gates the citadel's flag vault.
What they overlooked is the shape of the group they chose: the order of
GF(p^2)* is a product of only small primes. That smoothness quietly dissolves
the "hard" logarithm.

Your objective: recover the private exponent `x` by exploiting the field's
algebra, then lift the seal.

**Download the attached file** and recover the flag.
