# Matryoshka — Bunker — solution

# MATRYOSHKA

**Category:** Crypto · **Difficulty:** ★☆☆ (20–40m)

> A doll inside a doll inside a doll. Keep peeling.


## Files
- `dist/cipher.txt` — the outermost shell

Peel the encodings until you hit the bottom. Don't throw away the pieces you
pass through on the way down — one of them isn't just encoded text.

Flag format: `DOOM{...}`


## Build
```
python build.py
```
Regenerates `dist/cipher.txt` and self-verifies the full peel (base64 → hex →
base85 → ZIP → reverse → base32).

## Archive layout

The original README above uses its original development paths. In this archive player files live under `challenge/`, source and local service code under `solution/runtime/`, and author scripts under `solution/`. The event accepted values are recorded in `accepted_flags.txt`; some original exercises were deliberate decoys.
