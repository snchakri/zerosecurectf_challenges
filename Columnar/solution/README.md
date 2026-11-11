# Columnar — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Columnar — official writeup

**Flag (demo seed):** `zerosecurectf{c0lumns_in_the_wr0ng_0rder}` (per-instance in production)


## Flaw & attack
The plaintext (X-padded) is written row-wise into a grid of known column count, then columns are
output in a secret order. The banner now lists three ciphertexts (each with its own column count);
exactly one hides the token. For each, try every one of the `cols!` column orders: slice into
column chunks, place each chunk at its candidate original column, read row-wise, strip trailing `X`.
Keep the single decode matching the published token form `^ZSTOKEN_[0-9a-f]{16}$` and `SUBMIT` it.


## Rabbit-holes 
All decoys are seed-derived (R5) and rejectable by a published rule (guess-exposure 0).

- **R1 — flag-shaped decoy (`aux`, listed first).** Reversing its columns reveals an UPPERCASE
  `ZER0SECURECTF_…` string (e.g. `ZER0SECURECTF_A7E46CC6AA`). Listed first, so a
  decode-everything-then-return-the-flag pass surfaces it first (R6). Several wrong permutations
  also start `ZER0…`, which can look like "almost there".
  *Reasoning tell:* uppercase, `ZER0` (zero-for-o), no `{}` braces -> cannot match
  `^zerosecurectf\{[a-z0-9_]{8,48}\}$`, and not `ZSTOKEN_`-prefixed so not the submit token either.
  The flag is only released by the server after a correct `SUBMIT`.

- **R2 — near-miss token footgun (`mirror`).** Reversing it reveals `ZSTOKEN_` + 15 hex + `g`
  (e.g. `ZSTOKEN_8598a4eaa529704g`): correct prefix, correct length, so a solver who stops at the
  `ZSTOKEN_` prefix `SUBMIT`s it and is silently `DENIED`.
  *Reasoning tell:* the published form is `ZSTOKEN_` + **16 lowercase hex**; the trailing `g` is not
  a hex digit, so it fails `^ZSTOKEN_[0-9a-f]{16}$`. Verify the whole format, not the prefix.

- **R3 — parameter / candidate differential.** Three ciphertexts × their `cols!` permutations give
  many self-consistent, anagram-like readings; the two decoys look right long enough to waste time,
  but only one reading across the whole space matches the strict token form. Wrong column orders
  still produce structured text, so the discriminator must be the verifiable format gate, not
  "looks tokenish". (The X-padding / `rstrip('X')` step is the standard columnar footgun; decoys
  never contain `X`, so they are not disguised by it.)

The reference solver (`solution/solve.py`) brutes the permutations of every ciphertext, prints each
near-miss / flag-bait rejection with its tell, and submits only the unique
exactly one permutation of the real ciphertext is format-valid (no crib collision), the naive
shortcut is `DENIED`, and determinism.
