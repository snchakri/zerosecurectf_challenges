# Staged Hint Ladder: Matrix Field Linear Inversion

### Hint Level 1 (Orientation)
A 3x3 Hill cipher enciphers each column of three letters `p` as `c = K·p (mod 26)`.
You know the first several plaintext letters (the header) and their ciphertext.
Letters map to 0–25 (A=0 … Z=25).

### Hint Level 2 (Reframe)
Stack three known plaintext blocks as the columns of a 3x3 matrix `P`, and the
matching ciphertext blocks as the columns of `C`. Then `C = K·P (mod 26)`, so
`K = C·P^{-1} (mod 26)` — pure linear algebra over Z_26. You only need a block
triple whose `P` is invertible mod 26 (its determinant must be coprime to 26).

### Hint Level 3 (Strong Nudge)
Compute the modular inverse of `P` via its adjugate and `det(P)^{-1} mod 26`
(skip any triple whose determinant shares a factor 2 or 13 with 26). Recover `K`,
serialise its nine entries as the documented `Kbytes`, and feed them through the
stated SHA-256 key/nonce derivation to AES-GCM-decrypt the sealed flag.

---
*Note: Crux Floor invariant — the linear-algebra inversion over Z_26 is the
lesson; hints never hand over `K`.*
