# Unison — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Unison — official writeup

**Flag:** `zerosecurectf{h4st4d_br0adcast_cube_r00t_1n_un1s0n}` (static demo seed; per-instance in production)


## The flaw

RSA with a small public exponent is not broken by itself. It becomes broken when
the **same plaintext** is sent to **several recipients** under that small
exponent. Unison ships exactly that mistake: one activation record `m`, exponent
`e = 3`, encrypted to `k` devices with distinct moduli:

```
c_0 = m^3 mod N_0
c_1 = m^3 mod N_1
...
c_{k-1} = m^3 mod N_{k-1}
```

This is the textbook setting for **Håstad's broadcast attack** (J. Håstad,
*Solving simultaneous modular equations of low degree*, SIAM J. Computing 17(2),
1988; summarised in D. Boneh, *Twenty Years of Attacks on the RSA Cryptosystem*,
Notices of the AMS 46(2), 1999, §4 "Low private/public exponent").


## Why it breaks

Because the activation record is a valid RSA plaintext for every device, `m < N_i`
for all `i`. Take any **three** devices (three, because `e = 3`). Then

```
m^3  <  N_0 · N_1 · N_2            (each factor m is below the matching N_i)
```

The three congruences `m^3 ≡ c_i (mod N_i)` have pairwise-coprime moduli (distinct
RSA primes), so the **Chinese Remainder Theorem** gives a unique residue modulo
the product:

```
C ≡ m^3   (mod N_0 · N_1 · N_2),      0 ≤ C < N_0 · N_1 · N_2
```

Since `0 ≤ m^3 < N_0·N_1·N_2` as well, the residue *is* the integer: `C = m^3`
exactly, with no modular wraparound left. A plain **integer cube root** of `C`
returns `m`. The flag is ASCII inside `m`.

```
d = CRT((N_0,N_1,N_2), (c_0,c_1,c_2))   # == m^3 over the integers
m = icbrt(d)                            # exact cube root
flag = regex zerosecurectf{...} in m.to_bytes(...)
```


## The decoy — why one ciphertext is not enough

The obvious first thing to try against "small `e`" is a cube root of a *single*
ciphertext. That is the classic small-message attack, and it works only when
`m^3 < N` (no reduction happened). Unison pads the activation record so that

```
m^3 > N_i    for every device.
```

So each `c_i` has genuinely wrapped around, `icbrt(c_i)` is not `m`, and the lone
cube root fails. The acceptance test asserts this directly
(`no single-ciphertext cube root wins`). The broadcast / CRT step is therefore
**mandatory**, not optional — that is the reasoning handle that separates this
from a one-liner.


## Steps

1. `CAPTURE` → `k` records `(i, e=3, N_i, c_i)`.
2. Pick any three (pairwise-coprime) moduli; `C = CRT((N_a,N_b,N_c),(c_a,c_b,c_c))`.
3. `m = icbrt(C)`; assert the cube root is exact (`sympy.integer_nthroot(C,3)`).
4. Decode `m` to bytes and read the embedded `zerosecurectf{...}`.
5. Optional: `VERIFY <m_hex>` → the service echoes `FLAG …` to confirm.

Reference implementation: [`solution/solve.py`](solution/solve.py). It uses sympy for
CRT and the cube root (`gmpy2`/`sage` are not in the target environment) and
carries a pure-stdlib Newton-cube-root + pairwise-CRT fallback.


## Why the intended path is the only cheap one

- **No factoring shortcut:** the moduli are 1024-bit (two 512-bit primes). RSA-1024
  factoring is infeasible for a CTF, so recovering any single private key and
  decrypting is off the table — the broadcast is cheaper by astronomical margins.
- **No single-ciphertext cube root:** `m^3 > N_i`, so a lone cube root returns
  garbage (see the decoy above).
- **No shared-factor GCD trick:** the moduli are pairwise coprime (distinct
  primes), so `gcd(N_i, N_j) = 1` and there is no common-factor factorisation.
- **No guessing:** the whole scheme is in the source; the route is reachable
  purely by reasoning (one plaintext + `e = 3` + many moduli ⇒ Håstad).


## Design notes (for the ZSCTF team)

- **Lineage (corpus-genome.yaml, system.html §17):**
  - `crypto-004 pacap` — "a large-modulus composite scheme still falls to a
    small-root/lattice attack" → operator **GROUND**: re-ground the abstract
    low-exponent/small-root idea as a concrete firmware-activation broadcast the
    attacker *intercepts*. (Authenticity ↑↑.)
  - `crypto-009 Sus` — "RSA keys / weak keygen (public keys given)" → borrow the
    **RSA public-key, data-given** target shape and the `GROUND → PARAMETERISE`
    affordance (per-instance keys).
  - operator **CONSTRAIN** (§17.3): the solver interacts with a live service
    (`CAPTURE`/`DEVICE`/`VERIFY`) rather than a static dump — an online, intercept
    access model, matching the crypto-oracle pattern of the sibling challenges.
  - operator **PARAMETERISE**: `ZSCTF_SEED` → unique fleet + unique padded
    plaintext, defeating writeup transfer (Evolve-CTF semantics-preserving
    variation, system.html §9).
- **Guard = a real mitigation boundary, not an artificial rule:** the three facts
  above (big moduli, `m^3 > N`, coprime moduli) are exactly the conditions that
  make the *real* Håstad attack the intended and only cheap route.

