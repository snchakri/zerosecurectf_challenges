# Galois Field Logarithm Knapsack — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Galois Field Logarithm Knapsack (GF(p^2) discrete log, smooth order)


## 0. Scope note (honest framing)
The Chor-Rivest cryptosystem's trapdoor is a discrete logarithm in an extension
field GF(p^h) together with a permutation/polynomial decoding step. A full
public-key break of Chor-Rivest (Vaudenay's algebraic attack) is research-grade
and well beyond a few-hours, pure-Python solver. This challenge therefore
realises the **computational heart** of that trapdoor — a genuine discrete log
in GF(p^2) made solvable by a **smooth group order** (Pohlig-Hellman) — and gates
the flag on recovering that exponent. The field-algebra and smooth-order
discrete-log techniques are exactly the "finite-field log algebra" the title
names.


## 1. Field arithmetic
`GF(p^2) = GF(p)[t]/(t^2 - nr)`, where `nr` is a quadratic non-residue mod `p`.
Represent `a + b·t` as `[a, b]`; then
`(a+bt)(c+dt) = (ac + bd·nr) + (ad + bc)·t (mod p)`. Fast exponentiation is
square-and-multiply with this product. The inverse of any unit `z` is
`z^{(p^2-1)-1}` since `z^{p^2-1} = 1`.


## 2. Why it is solvable: smooth order + Pohlig-Hellman
`|GF(p^2)*| = p^2 - 1`. A naive discrete log costs `~sqrt(p^2-1) ≈ 2^49.5` and is
infeasible on a laptop. But `p` was chosen so that `p^2 - 1 = (p-1)(p+1)`
factors entirely into small primes (largest ≈ `2^26.5`). Factor it (trial
division + Pollard rho), then apply **Pohlig-Hellman**:
- For each prime power `q^e || (p^2-1)`: set `g_i = g^{(p^2-1)/q^e}`,
  `y_i = y^{(p^2-1)/q^e}` (order `q^e`), and solve `x ≡ x_{q^e} (mod q^e)` one
  base-`q` digit at a time, each digit via a baby-step/giant-step in the
  order-`q` subgroup (`~sqrt(q)` field ops).
- CRT-combine the residues `x_{q^e}` into `x (mod p^2-1)`.
Verify `g^x = y`.


## 3. Step-by-Step Walkthrough
1. Parse `p, nr, g, y` and the sealed flag.
2. Factor `N = p^2 - 1`.
3. Run Pohlig-Hellman as above to get `x`.
4. Derive `key = SHA256("zsctf-chorrivest|key|" + decimal(x))` (nonce
   analogously) and AES-256-GCM-decrypt the flag.


## 4. Why it resists shortcuts
- Whole-group BSGS/Pollard rho is `~2^49.5` — above the `2^40` bar; you must use
  the smooth structure.
- `x` is ~99-bit, so guessing is hopeless.
- The flag is AES-GCM sealed under `x`; no plain/hex/base64/reversed leak, and
  the GCM tag confirms the recovered exponent.


## 5. Solver & Verification
```bash
python solve.py --dist ./dist     # well under 1 second
```
Prints the `zerosecure{...}` flag, byte-identical to `flag` (clean room of
`dist/` + `solve.py`). The solver factors `N` itself and implements GF(p^2),
BSGS, Pohlig-Hellman and CRT from scratch (no gmpy2/sage).


## 6. Citations & References
- Chor, B. & Rivest, R. (1988). *A knapsack-type public key cryptosystem based
  on arithmetic in finite fields.* IEEE Trans. Inf. Theory.
- Pohlig, S. & Hellman, M. (1978). *An improved algorithm for computing
  logarithms over GF(p)...* IEEE Trans. Inf. Theory.
- Vaudenay, S. (1998). *Cryptanalysis of the Chor-Rivest cryptosystem* (context
  for why real Chor-Rivest parameters must be chosen with great care).


## 7. Defense Engineering & Remediation
Discrete-log security demands a group whose order has a large prime factor
(≥ 2^224 classically). A smooth order collapses to Pohlig-Hellman. Use
standardised groups and validate the subgroup order. Chor-Rivest itself is
deprecated — its specific parameter classes were broken by Vaudenay; prefer
modern lattice KEMs for post-quantum needs.
