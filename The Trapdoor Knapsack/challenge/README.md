# The Trapdoor Knapsack

**Category:** Cryptography

Doom's quartermasters still trust the old trapdoor knapsack — a Merkle-Hellman
public key that hides a tidy superincreasing sequence behind one modular
multiplication. They mistook "once published, now broken" for "still secure,"
and shipped the citadel's manifest encrypted under it. CICADA3301 holds the
public key and the ciphertext blocks, but not the private multiplier.

The trapdoor is useless to you — but you don't need it. The knapsack's density
is low enough that the message is the shortest vector of a lattice you can build
from the public key alone. Reduce the lattice, read off the bits, and the
manifest (the flag) falls out.

**Download the attached file** and recover the flag.
