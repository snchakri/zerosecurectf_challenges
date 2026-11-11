# Subgroup Giant Step

**Category:** Cryptography

Doom's cipher-wrights boast that their access gate rests on the discrete
logarithm problem — "unbreakable mathematics," they engrave above the door. But
vanity chose the parameters. The public generator does not roam the whole
multiplicative group of the prime `p`; it is penned inside a small prime-order
subgroup. The gate publishes `p`, the generator `g`, and the challenge value
`h = g^x mod p`. The private exponent `x` is the session key, and the citadel's
flag is sealed under it.

Your objective: solve for `x` inside the cramped subgroup, then lift the seal.

**Download the attached file** and recover the flag.
