# Format String Illusion - Reimplemented

**Category:** Cryptography

# Format String Illusion - Reimplemented

## Story
A second incident export from the same backend stack looks like routine numeric log lines.
The visible values are mostly noise, but the case pattern in letter sequences carries hidden data.

## Your Task
Inspect `challenge.txt` and recover the hidden flag.
Extract only alphabetic characters in order, convert case into a two-state stream, and decode using Baconian groups.

## Rules
- Keep only alphabetic characters (`A-Z` and `a-z`) in original order.
- Use case as the signal:
  - uppercase -> `A`
  - lowercase -> `B`
- Split into groups of 5 and decode with Baconian mapping.
- In decoded plaintext, `X` acts as a separator and should be converted to `_` in the final flag.
- Submit only the final flag.
- Flag format is: `ZeroSecure_CTF{...}`
- Keep exact characters (case-sensitive).

Good luck.

[2026-04-17 09:14:12] 500 :: NEAtMMKIFQpAPfESYvPDaEqe :: 3901/0
[2026-04-17 09:14:13] 502 :: fKDFwHWSvuhOBIKAKfqKvLtm :: 3902/1
[2026-04-17 09:14:14] 503 :: MkXJzFLTrPiocZxpiFTFJpIC :: 3903/2
[2026-04-17 09:14:15] 429 :: DXMNVOpHPhdtONrnHh :: 3904/0
