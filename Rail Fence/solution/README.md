# Rail Fence — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Rail Fence — official writeup

**Flag (demo seed):** `zerosecurectf{transp0sition_is_just_reorder1ng}` (per-instance in production)


## Flaw & attack
A rail-fence cipher writes the token in a zigzag across R rails then reads row by row. The banner
now lists three ciphertexts; exactly one hides the token. For each ciphertext try every R in 2..8:
rebuild the zigzag index pattern, refill the rails from the ciphertext, and read along the zigzag.
Keep the single decode matching the published token form `^ZSTOKEN_[0-9a-f]{16}$` and `SUBMIT` it.


## Rabbit-holes 
All decoys are seed-derived (R5) and rejectable by a published rule (guess-exposure 0).

- **R1 — flag-shaped decoy (`aux`, listed first).** Brute-forcing it over R=2..8 reveals an
  UPPERCASE `ZER0SECURECTF_…` string (e.g. `ZER0SECURECTF_78B9C20063`). Listed first, so a
  decode-everything-then-return-the-flag pass surfaces it first (R6).
  *Reasoning tell:* it is uppercase, uses `ZER0` (zero-for-o) and has no `{}` braces, so it cannot
  match `^zerosecurectf\{[a-z0-9_]{8,48}\}$`. It is also not `ZSTOKEN_`-prefixed, so it is not the
  submit token either. The flag is only released by the server after a correct `SUBMIT`.

- **R2 — near-miss token footgun (`mirror`).** Brute-forcing it reveals
  `ZSTOKEN_` + 15 hex + `g` (e.g. `ZSTOKEN_aab61ff2237f796g`): correct prefix, correct length (24),
  so a solver who stops at the `ZSTOKEN_` prefix (the weaker hint) `SUBMIT`s it and is silently
  `DENIED`. *Reasoning tell:* the published form is `ZSTOKEN_` + **16 lowercase hex**; the trailing
  `g` is not a hex digit, so it fails `^ZSTOKEN_[0-9a-f]{16}$`. Verify the whole format, not the prefix.

- **R3 — parameter / candidate differential.** Three ciphertexts × seven rail counts give many
  self-consistent decodes; several (the two decoys above) look right long enough to waste time, but
  only one decode across the whole grid matches the strict token form. This is the natural
  transposition trap: wrong parameters still yield structured, anagram-like text, so the
  discriminator must be the verifiable format gate, not "looks tokenish".

The reference solver (`solution/solve.py`) brutes R on every ciphertext, prints each near-miss /
flag-bait rejection with its tell, and submits only the unique `^ZSTOKEN_[0-9a-f]{16}$` match.
ciphertext is format-valid (no crib collision), the naive shortcut is `DENIED`, and determinism.
