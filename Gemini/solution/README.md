# Gemini — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Gemini — official writeup

**Flag (demo seed):** `zerosecurectf{c0mm0n_m0dulus_br34ks_b0th_exp0nents}` (per-instance in production)


## The flaw

The same token `m` is encrypted to **one shared modulus** `N` under two public
exponents: `c1 = m^e1 mod N` and `c2 = m^e2 mod N`, with `gcd(e1, e2) = 1`. Reusing
a modulus across exponents is a real RSA misconfiguration (CWE-327).


## The attack (common-modulus)

Because `gcd(e1, e2) = 1`, the extended Euclidean algorithm gives integers `a, b`
with `a*e1 + b*e2 = 1`. Then:

```
c1^a * c2^b = m^(a*e1) * m^(b*e2) = m^(a*e1 + b*e2) = m^1 = m   (mod N)
```

One of `a, b` is negative; replace that ciphertext with its modular inverse and use
the absolute exponent. Three lines, no factoring, no brute force.


## Why the intended path is the only cheap one

- **Single ciphertext is secure:** `e1 = 65537` is large and `m` is near `N`, so
  there is no small-`e` / broadcast cube-root shortcut from `c1` alone.
- **No factoring:** `N` is 1024-bit; factoring is infeasible.
- **No brute force:** the token is ~256-bit of entropy.
- The attack *requires* both ciphertexts and `gcd(e1, e2) = 1`, which is exactly the
  given misconfiguration — reasoning-reachable, guess-exposure 0.

