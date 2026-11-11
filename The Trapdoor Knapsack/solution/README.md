# The Trapdoor Knapsack — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: The Trapdoor Knapsack (Merkle-Hellman low-density attack)


## 1. Analysis & Theoretical Foundations
Merkle-Hellman builds a public key `b_i = w_i · r mod q` from a secret
superincreasing sequence `w` and trapdoor `(q, r)`. Encryption of an `n`-bit
message `x ∈ {0,1}^n` is the subset sum `C = Σ x_i b_i`. The legitimate receiver
multiplies by `r^{-1} mod q` to fall back onto `w` and reads the bits greedily.
An attacker without `(q, r)` instead solves the **subset-sum** problem directly.

Subset-sum is easy when the *density* `d = n / log2(max_i b_i)` is low: Lagarias
and Odlyzko (and the improved Coster-Joux-LaMacchia-Odlyzko-Stern / CJLOSS
lattice) show the solution is the shortest nonzero vector of a lattice built from
`b` and `C`. Here `d ≈ 0.63`, comfortably inside the reliable regime.


## 2. The lattice
For public weights `b_1..b_n` and target `C`, the CJLOSS lattice (dimension
`n+1`) has rows `(2·e_i, b_i)` for each `i`, plus a final balancing row
`(1,1,…,1, C)`. A short vector decodes to `±1` in the first `n` coordinates with
a 0 in the last (the subset-sum constraint); mapping `+1→1, −1→0` gives the
message bits. (The plain Lagarias-Odlyzko lattice `(e_i, b_i)` with a target row
works too at this density and is used as a fallback.)


## 3. Step-by-Step Walkthrough
1. Parse `public_key = b`, `ciphertexts`, `msg_len`.
2. For each ciphertext `C`: build the lattice, LLL-reduce it (a self-contained
   integer LLL — Cohen's Algorithm 2.6.3), scan reduced rows for a `0/1`
   (or `±1`) pattern that reproduces `C`.
3. Concatenate the recovered bit-vectors, pack MSB-first into bytes, and keep
   the first `msg_len` bytes — the flag.


## 4. Why it resists shortcuts
- No trapdoor leaks: `q`, `r`, `w` are never shipped.
- No brute force: `n = 96` ⇒ a blind subset-sum search is `2^96` and even
  meet-in-the-middle / Schroeppel-Shamir is `≥ 2^48` — above the `2^40` bar.
- The flag bytes appear nowhere in the clear; `knapsack_pubkey.json` holds only
  the public key and the sums, so plain/hex/base64/reversed scans find nothing.


## 5. Solver & Verification
```bash
python solve.py --dist ./dist     # ~1 second
```
Prints the `zerosecure{...}` flag, byte-identical to `flag` (clean room of
`dist/` + `solve.py`).


## 6. Citations & References
- Merkle, R. & Hellman, M. (1978). *Hiding information and signatures in trapdoor
  knapsacks.* IEEE Trans. Inf. Theory.
- Lagarias, J. & Odlyzko, A. (1985). *Solving low-density subset sum problems.*
  J. ACM.
- Coster, Joux, LaMacchia, Odlyzko, Schnorr, Stern (1992). *Improved low-density
  subset sum algorithms.* Comput. Complexity (the CJLOSS lattice).


## 7. Defense Engineering & Remediation
Knapsack public-key schemes are broken; low-density instances fall to LLL and
most others to Shamir's trapdoor-recovery attack. Do not use them. Rely on
well-studied primitives (RSA-OAEP, ECDH/ECDSA, lattice KEMs like ML-KEM) with
standardised parameters.
