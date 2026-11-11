# Morse — solution

Run commands from this challenge's title directory. Python dependencies, when needed, are in `solution/requirements.txt`.

```bash
python solution/solve.py --local solution/runtime/server.py
```

`accepted_flags.txt` records the accepted event answers. Locally reproduced services use their source defaults unless a flag is supplied through the documented environment variable; those demo answers can differ from the event answer.

# Morse — official writeup

**Flag (demo seed):** `zerosecurectf{dih_dah_is_n0t_encrypt10n}` (per-instance in production)


## Flaw & attack
The banner logs several space-separated Morse transmissions. Invert the standard A-Z/0-9 Morse
table on each group (one space-separated group = one letter). Exactly one transmission is the
station **token**, published to have the form `ZSTOKEN` + 13 uppercase hex digits
(`^ZSTOKEN[0-9A-F]{13}$`). Decode each channel, keep the one that matches that form, and
`SUBMIT` it to receive the flag.


## Rabbit-holes 
All decoys are seed-derived (R5), so they differ per instance; none is information-free (every one
is rejectable by a published rule, so guess-exposure is 0).

- **R1 — flag-shaped decoy (`beacon`, listed first).** Decodes to an UPPERCASE
  `ZER0SECURECTF…` string (e.g. `ZER0SECURECTF2FE2755`). It is the first channel printed, so a
  lazy "decode everything, return the thing that looks like the flag" pass surfaces it first (R6).
  *Reasoning tell:* the Morse alphabet only emits `A–Z` / `0–9` — it cannot produce the lowercase
  letters or the `{`/`}` braces that `^zerosecurectf\{[a-z0-9_]{8,48}\}$` requires, so **no decoded
  Morse string can ever be the flag**. The flag is only released by the server after a correct
  `SUBMIT`. The decoy additionally announces itself with `ZER0` (zero-for-o) and uppercase.

- **R2 — near-miss token footgun (`alt`).** Decodes to `ZSTOKEN` + 12 hex + `P`
  (e.g. `ZSTOKENFB6C2E9B3B43P`): correct prefix, correct length (20), so a solver who tests only
  the `ZSTOKEN` prefix accepts it and `SUBMIT`s it — and is silently `DENIED`.
  *Reasoning tell:* the published form is `ZSTOKEN` + **13 hex** digits `[0-9A-F]`; the trailing
  `P` is not a hex digit, so it fails `^ZSTOKEN[0-9A-F]{13}$`. Verify the full format, not the prefix.

- **R3 — grouping / representation differential (`raw`).** The continuous keystream `raw` is the
  real `code` with inter-symbol spaces removed. Greedily (max-munch) re-chunking an un-spaced Morse
  stream is ambiguous and yields a different string (e.g. `72QLU6RC48477ZCV4OE`).
  *Reasoning tell:* the published convention is **space-separated groups, one per letter**; `raw` is
  a non-canonical representation. Its greedy decode neither starts with `ZSTOKEN` nor matches the
  token form, so it is rejectable without ever touching the server.

The reference solver (`solution/solve.py`) decodes every channel, prints each rejection with its tell,
and submits only the unique `^ZSTOKEN[0-9A-F]{13}$` match — documenting the escape a careful human
first-channel/flag-looking shortcut is `DENIED`, and determinism (same seed identical, different
seed different).
