# One-Time Authenticator Failure — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: One-Time Authenticator Failure (Poly1305 Nonce Reuse)


## 1. Analysis & Theoretical Foundations
Poly1305 is a *one-time* authenticator: a message is split into blocks `c_i`,
accumulated as a polynomial in a secret evaluation point `r` over the prime field
GF(`2^130 − 5`), and masked by a secret `s` (the per-message nonce-derived pad):
`tag = (Σ c_i r^{k−i+1} + s) mod p`. Its security proof *requires* `(r, s)` to be
used once. Reuse turns the two tags into a solvable algebraic system.

For the two-block messages here, `tag = (c_1 r^2 + c_2 r + s) mod p`.


## 2. Key recovery via the reused nonce
Both messages were signed with the same `(r, s)`:
```
t1 = a1 r^2 + a2 r + s
t2 = b1 r^2 + b2 r + s
```
Subtracting eliminates `s`:
```
(a1 − b1) r^2 + (a2 − b2) r − (t1 − t2) ≡ 0  (mod p)
```
a quadratic in `r`. Its discriminant is a quadratic residue (the true `r` is a
root), and since `p ≡ 3 (mod 4)` the square root is `disc^{(p+1)/4} mod p`. The
two roots give two candidate `r`; each yields `s = t1 − (a1 r^2 + a2 r)`.


## 3. Forgery and flag recovery
With `(r, s)` in hand the MAC is fully forgeable. Compute the authenticator of
the target admin message `RELEASE-VAULT-KEYS-TO-BEARER;AUTH=DOOM` (padded to a
multiple of 16 bytes) under each candidate. That forged tag `T` keys the seal:
`key = SHA256("zsctf-poly1305|key|" + decimal(T))`, nonce analogously. The
wrong candidate fails the AES-GCM authentication tag; the right one decrypts the
flag — so the GCM tag doubles as the disambiguator.


## 4. Why it resists shortcuts
- `r, s ∈ [1, p)` are ~130-bit; guessing is `~2^130`. The attack is pure field
  algebra, instantaneous.
- Nothing in the artifact encodes the flag directly — it is sealed under a value
  (the forged tag) that itself requires the key recovery; no plain/hex/base64/
  reversed leak exists.


## 5. Solver & Verification
```bash
python solve.py --dist ./dist
```
Prints the `zerosecure{...}` flag, byte-identical to `flag` (clean room of
`dist/` + `solve.py`).


## 6. Citations & References
- Bernstein, D. J. (2005). *The Poly1305-AES message-authentication code.* FSE.
- Joux, A. (2006). *Authentication failures in NIST version of GCM* — the general
  "forbidden attack" from one-time-key/nonce reuse in polynomial MACs.


## 7. Defense Engineering & Remediation
Never reuse a one-time MAC/AEAD key-nonce pair. Derive `(r, s)` (or the GCM `H`,
`J0`) freshly per message with a strict nonce discipline (counter or random
96-bit nonce with rekeying limits). Consider misuse-resistant AEADs (AES-GCM-SIV)
where a nonce slip degrades gracefully instead of leaking the authentication key.
