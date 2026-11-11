# Challenge: The Trapdoor Knapsack (crypto_09_knapsack_merkle_hellman)

**Category:** Cryptography
**Difficulty:** Medium
**Format:** `zerosecure{...}`
**North Star:** Authentic Tradecraft & Realistic Failure Modes

---

## Scenario & Objective
Doom's quartermasters still trust the old trapdoor knapsack — a Merkle-Hellman
public key that hides a tidy superincreasing sequence behind one modular
multiplication. They mistook "once published, now broken" for "still secure,"
and shipped the citadel's manifest encrypted under it. CICADA3301 holds the
public key and the ciphertext blocks, but not the private multiplier.

The trapdoor is useless to you — but you don't need it. The knapsack's density
is low enough that the message is the shortest vector of a lattice you can build
from the public key alone. Reduce the lattice, read off the bits, and the
manifest (the flag) falls out.

## Provided Files
- `knapsack_pubkey.json` — the 96-entry public key `public_key`, the list of
  `ciphertexts` (one per 96-bit block), `msg_len`, and a note describing the
  bit-encoding.

## Compliance
- Universal Format asserted: `zerosecure{...}`
- Zero unreasoned guessiness. Each block's bit-vector is the unique low-weight
  subset summing to its ciphertext; together they are the flag.
