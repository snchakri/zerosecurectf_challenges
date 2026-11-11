# Subgroup Giant Step — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Subgroup Giant Step (Discrete Log via Baby-Step/Giant-Step)


## 1. Analysis & Theoretical Foundations
The handout gives a prime `p`, a generator `g`, a target `h = g^x mod p`, and
the crucial leak: `subgroup_order = q`, a prime with `g^q ≡ 1 (mod p)`. So `g`
generates a subgroup of order `q`, and `x` is determined modulo `q`. The cost of
a discrete log is governed by `q`, not by the (much larger) modulus `p`. Here
`q ≈ 2^41`, so a linear scan (`> 2^40` multiplications) is impractical, but the
baby-step/giant-step (BSGS) time–memory trade-off needs only `O(sqrt(q)) ≈ 2^21`
operations and as many stored group elements — seconds on a laptop.


## 2. Baby-Step / Giant-Step
Write `x = i·m + j` with `m = ceil(sqrt(q))` and `0 ≤ i, j < m`. Then
`h = g^{i m + j}` ⇒ `h · (g^{-m})^{i} = g^{j}`. Precompute the baby steps
`{ g^j : 0 ≤ j < m }` in a hash map, then iterate the giant steps
`γ_i = h · (g^{-m})^{i}` until `γ_i` is a stored baby step `g^j`; recover
`x = i·m + j`.


## 3. Step-by-Step Walkthrough
1. Parse `p, g, h, q` from `dlog_params.json`.
2. `m = isqrt(q) + 1`; build `table = { g^j mod p : j }` for `j in [0, m)`.
3. `ginv_m = (g^m)^{-1} mod p` (Fermat inverse, `p` prime).
4. Walk `γ = h`, `γ ← γ · ginv_m` each step; when `γ` is in `table`,
   `x = i·m + table[γ]`.
5. Verify `g^x ≡ h (mod p)`. Derive `key = SHA256("zsctf-dlog|key|" + decimal(x))`
   and the matching nonce, then AES-256-GCM-decrypt `sealed_flag_hex`.


## 4. Why it resists shortcuts
- Linear search is `> 2^40`; BSGS is `~2^21`, so BSGS (or Pollard rho) is the
  intended route.
- `p` being large is a red herring — the exponent only matters modulo `q`.
- The flag is AES-GCM sealed; the authentication tag confirms the recovered `x`
  and leaves nothing to grep (no plain/hex/base64/reversed leak).


## 5. Solver & Verification
```bash
python solve.py --dist ./dist
```
Prints the recovered `zerosecure{...}` flag, byte-identical to `flag`
(verified in a clean room containing only `dist/` and `solve.py`).


## 6. Citations & References
- Shanks, D. (1971). *Class number, a theory of factorization, and genera.*
  (Origin of baby-step/giant-step.)
- Menezes, van Oorschot, Vanstone. *Handbook of Applied Cryptography*, §3.6
  (discrete logs, BSGS, Pohlig–Hellman).


## 7. Defense Engineering & Remediation
Discrete-log security requires the generator to have a *large* prime order
(≥ 2^224 for classical security). Confining `g` to a small subgroup — or using a
prime whose relevant subgroup order is small — collapses the problem to BSGS or
Pohlig–Hellman. Use standardised groups (e.g. RFC 7919, NIST P-curves) and
validate subgroup membership and order.
