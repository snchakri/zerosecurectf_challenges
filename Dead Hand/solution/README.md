# Dead Hand — solution

# DEAD HAND

**Category:** Crypto · **Difficulty:** ★★☆ (30–45m)

> Two encrypted transmissions pulled off the silo's landline the same night.
> The station's "single-use" key tape may not have been used only once.


## Files
- `dist/briefing.txt` — mission briefing
- `dist/transmission_alpha.txt` — intercept C1 (hex)
- `dist/transmission_bravo.txt` — intercept C2 (hex)

Both messages were encrypted with the **same** one-time pad. XOR the two
ciphertexts and the pad cancels (`C1 ⊕ C2 = P1 ⊕ P2`). Crib-drag the known flag
prefix `ZeroSecure{` across the result to align the plaintexts, then extend your
cribs until the messages — and the flag — fall out.

Flag format: `ZeroSecure{...}`


## Build
```
python build.py
```
Regenerates `dist/` with a fresh random pad and self-verifies that the pad
reuse holds, the flag is absent from the ciphertexts, and the crib-drag lines up.

## Archive layout

The original README above uses its original development paths. In this archive player files live under `challenge/`, source and local service code under `solution/runtime/`, and author scripts under `solution/`. The event accepted values are recorded in `accepted_flags.txt`; some original exercises were deliberate decoys.
