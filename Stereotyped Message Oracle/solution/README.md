# Stereotyped Message Oracle — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Stereotyped Message Oracle (Coppersmith small root, e=3)


## 1. Analysis & Theoretical Foundations
With `e = 3` and no random padding, an RSA plaintext that is mostly known leaks.
Write the plaintext as `M = A + x`, where `A = int(known_prefix)·256^secret_len`
is fully known and `x = int(unknown)` satisfies `0 ≤ x < X = 256^secret_len`.
Then `f(x) = (A + x)^3 − c ≡ 0 (mod n)` has the secret as a *small* root. For
2048-bit `n`, `n^{1/3} ≈ 2^682`, while `X = 2^336` — far below the bound — so
Coppersmith's method recovers `x`.


## 2. Coppersmith / Howgrave-Graham
Coppersmith's theorem: a monic degree-`δ` polynomial `f` mod `n` has all roots
`|x| < n^{1/δ}` recoverable in polynomial time. Howgrave-Graham's lattice makes
it concrete. For integer parameters `m ≥ 1` and `t ≥ 0` build the shift
polynomials
```
g_{i,j}(x) = n^{m-i} · x^j · f(x)^i   (0 ≤ i < m, 0 ≤ j < δ)
h_i(x)     = x^i · f(x)^m             (0 ≤ i < t)
```
and form the lattice whose rows are their coefficient vectors after `x → xX`.
Any LLL-short vector is a polynomial `q` with `q(x0) = 0` **over the integers**
(not merely mod `n`), provided its norm is below `n^m/√dim`. Here `δ=3`, and
`m=2, t=1` (dimension 7) already satisfies the bound with margin.


## 3. Step-by-Step Walkthrough
1. Read `n, e, c, known_prefix, secret_len`; set `A`, `X`, `f(x)=(A+x)^3−c mod n`.
2. Build the Howgrave-Graham lattice (shift polynomials evaluated at `xX`).
3. LLL-reduce (a self-contained integer LLL — Cohen's Algorithm 2.6.3).
4. Take each short row, divide coordinate `k` by `X^k` to recover the integer
   polynomial `q(x)`, and isolate its integer root in `[0, X]` with
   arbitrary-precision root finding (mpmath), verifying `q(x0)=0` exactly.
5. Confirm `(A + x0)^3 ≡ c (mod n)`; the flag is the `zerosecure{...}` substring
   of `known_prefix || x0`.


## 4. Why it resists shortcuts
- Brute forcing `x` is `256^42 = 2^336`, utterly infeasible; the structured
  lattice attack is the only route.
- The flag body never appears in the clear — it lives inside `c`; the handout's
  `known_prefix` stops at the public `zerosecure{` marker, so no plain/hex/
  base64/reversed leak exists.


## 5. Solver & Verification
```bash
python solve.py --dist ./dist     # ~1 minute (LLL dominates)
```
Prints the `zerosecure{...}` flag, byte-identical to `flag` (clean room of
`dist/` + `solve.py`).


## 6. Citations & References
- Coppersmith, D. (1996). *Finding a Small Root of a Univariate Modular
  Equation.* EUROCRYPT.
- Howgrave-Graham, N. (1997). *Finding small roots of univariate modular
  equations revisited.* IMA Crypto & Coding.
- May, A. (2003). *New RSA Vulnerabilities Using Lattice Reduction Methods* (PhD
  thesis) — survey of the shift-polynomial construction.


## 7. Defense Engineering & Remediation
Never use textbook RSA. Use a randomised, standardised padding (RSA-OAEP) and a
large exponent (65537). OAEP destroys the stereotyped structure, so no fixed
header/short-secret relationship remains for Coppersmith to exploit.
