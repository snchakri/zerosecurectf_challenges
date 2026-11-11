# Vigenere — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Vigenere — official writeup

**Flag (demo seed):** `zerosecurectf{a_kn0wn_crib_breaks_v1genere}` (per-instance in production)


## Flaw & attack
For a Vigenere cipher with key length L over an m-letter alphabet, the known prefix 'ZSTOKEN' (>= L letters) gives key[i] = (idx(ct[i]) - idx(crib[i])) mod m for i<L; applying that key decrypts the whole token.


## Rabbit-holes 
Two escapable traps were added; the fair solve path (crib + published keylen) is
unchanged. Both cost the *careless* time only.

- **R1/R5/R6 — `relay` decoy flag (first banner line).** `relay` is a single
  Caesar shift (seed-varied) of a flag-shaped UPPERCASE taunt over the cipher
  alphabet. A lazy "try the one obvious classical cipher" pass (ROT/Caesar brute)
  recovers `ZER0SECURECTFCR4CKED<tag>`, which looks like the answer and is the
  *first* thing surfaced. **Reasoning tell to reject it:** it fails the published
  strict validator `^zerosecurectf\{[a-z0-9_]{8,48}\}$` on three counts —
  uppercase body, `zer0` (zero→'0') instead of `zero`, and no braces. It is also
  not a `ZSTOKEN`-prefixed token, so it is not the value you SUBMIT. Inert:
  the server never reads `relay`. The shift and 6-char tail vary per
  `ZSCTF_SEED`, so a leaked walkthrough does not transfer.
- **R2/R3 — near-miss key period (crib length vs published keylen).** The crib
  `ZSTOKEN` is 7 chars but the true period is the published `keylen 5`. Using the
  7-char crib *as* the repeating key (a common confusion between a known-plaintext
  crib and a running key) reproduces the crib exactly for the first 7 positions,
  so the decode still **starts with `ZSTOKEN`** and looks right — but diverges
  after position 7 into a wrong token (e.g. `ZSTOKENPIU5QVJ6MHUH8` vs real
  `ZSTOKEN90F62F1B5EFBD`). There is no feedback until the `SUBMIT` gate returns
  `DENIED`. **Reasoning tell to reject it:** the banner *publishes* `keylen 5`;
  a careful solver uses the published period, not the crib length. (Two
  self-consistent interpretations of the period both reproduce the crib; only the
  published one yields the real token — a parse differential.)

The reference solver `solution/solve.py` demonstrates both escapes explicitly: it
runs the naive Caesar pass on `relay` and discards the result via the strict
validator, computes the crib-as-key token and discards it in favour of the
published keylen, and asserts the final `FLAG` matches the strict validator.
