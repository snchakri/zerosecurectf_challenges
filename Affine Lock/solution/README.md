# Affine Lock — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Affine Lock — official writeup

**Flag (demo seed):** `zerosecurectf{aff1ne_h4s_t00_few_k3ys}` (per-instance in production)


## Flaw & attack
E(x)=a*x+b mod m over a 36-char alphabet; there are only phi(36)*36 = 12*36 keys. Try each a coprime to m with its inverse and each b; the key whose decrypt begins with the known 'TKN' prefix is correct.


## Rabbit-holes 
Three escapable traps; the fair solve path (affine brute + known prefix + gate)
is unchanged. Each is rejectable by reasoning from published information.

- **R1/R5/R6 — `relay` decoy flag (first banner line).** `relay` is a single
  shift (degenerate affine, a=1) of a seed-varied, flag-shaped UPPERCASE taunt
  over the 36-char alphabet. A lazy ROT/affine brute recovers
  `ZER0SECURECTFAFF1NE<tag>`, surfaced first. **Tell:** it fails the strict
  validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$` (uppercase, `zer0`, no braces)
  and is not a `TKN` token. Inert — the server never reads `relay`. Varies per
  `ZSCTF_SEED`.
- **R3/R6 — textbook modulus (26 vs 36).** Affine is almost always taught mod 26
  over `A-Z`. **Tell:** the published alphabet has 36 symbols and the ciphertext
  (and the recovered token) contain DIGITS (index ≥ 26), so a 26-symbol `A-Z`
  affine cannot even represent them; the modulus must be 36. A solver who
  pattern-matches "affine ⇒ mod 26" gets stuck or wrong.
- **R2/R3 — short-prefix key collision (first-match footgun).** The known prefix
  `TKN` is only 3 characters, so it is NOT unique: for every seed, exactly three
  affine keys reproduce a `TKN`-prefixed full-length decode (e.g. seed
  `affine-test-0001` → `TKNSQPH6IBVRG` (real), `TKNGQDHIUBJ34`, `TKN4Q1HU6B7FS`).
  A solver who stops at the **first** `TKN` match submits a near-miss and is
  `DENIED` with no other feedback. **Tell / escape:** the verifiable
  discriminator is the SUBMIT gate — enumerate *all* `TKN`-matching keys (a tiny
  set of 3) and submit each; exactly one is accepted. This is reasoning over a
  parse differential, not blind guessing.
  > Note: the original single-seed test happened to place the real key first, so
  > the old reference solver passed by luck. The hardened solver now enumerates
  > all `TKN` candidates and gate-checks each, which is required for correctness
  > on arbitrary per-instance seeds as well as to document this escape.

The reference solver `solution/solve.py` demonstrates all three escapes: it notes
the digit-bearing ciphertext (modulus 36), runs the naive shift pass on `relay`
and discards it via the strict validator, enumerates every `TKN` key and submits
each until the gate accepts, and asserts the final `FLAG` matches the strict
validator.
