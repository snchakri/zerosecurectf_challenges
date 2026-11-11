# Matrix Field Linear Inversion — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Matrix Field Linear Inversion (Hill Cipher Known-Plaintext)


## 1. Analysis & Theoretical Foundations
The Hill cipher enciphers plaintext in blocks of `n` letters (here `n = 3`) by a
linear map over `Z_26`: a block `p` (a column of three values 0–25) becomes
`c = K·p (mod 26)`, where `K` is a secret 3x3 matrix whose determinant is
invertible mod 26. Linearity is its downfall: a handful of known
plaintext/ciphertext blocks pins `K` exactly.


## 2. The known-plaintext attack
Collect three known plaintext blocks as the columns of a matrix `P` and the
corresponding ciphertext blocks as the columns of `C`. Because encryption is
applied column-wise, `C = K·P (mod 26)`. If `P` is invertible mod 26 then
`K = C·P^{-1} (mod 26)`. Invertibility mod 26 requires `gcd(det P, 26) = 1`
(i.e. `det P` is odd and not a multiple of 13); if the first triple fails, try
another.


## 3. Step-by-Step Walkthrough
1. Read the ciphertext and the known header; map letters to 0–25.
2. Split both into 3-letter blocks and line up header blocks with their
   ciphertext blocks.
3. Search block triples for one whose `P` has `gcd(det P, 26) = 1`.
4. Invert `P` mod 26 via adjugate × `det^{-1}`; set `K = C·P^{-1} (mod 26)`.
5. Serialise `K`'s nine entries as `Kbytes` and run the documented
   `SHA256` key/nonce derivation to AES-256-GCM-decrypt `sealed_flag_hex`.


## 4. Why it resists shortcuts
- No alphabet shortcut leaks the flag: Hill output is A–Z only and the flag
  (lowercase, braces, digits) is sealed under `K` via AES-GCM, so `strings`,
  grep and every plain/hex/base64/reversed encoding find nothing.
- The matrix is recovered by exact linear algebra, not brute force (a blind
  search of 3x3 keys over Z_26 would be ~26^9 ≈ 2^42 anyway).
- The GCM tag confirms the recovered `K`.


## 5. Solver & Verification
```bash
python solve.py --dist ./dist
```
Prints the `zerosecure{...}` flag, byte-identical to `flag` (verified in a clean
room of `dist/` + `solve.py` only).


## 6. Citations & References
- Hill, L. S. (1929). *Cryptography in an Algebraic Alphabet.* American
  Mathematical Monthly 36(6).
- Stinson, D. *Cryptography: Theory and Practice* — Hill cipher and its
  known-plaintext weakness.


## 7. Defense Engineering & Remediation
Linear block ciphers are trivially broken under known plaintext. Real block
ciphers (AES) use non-linear S-boxes and many rounds precisely to defeat such
algebra. The Hill cipher is of historical interest only; never protect live
secrets with a linear map.
