<a id="c103"></a>
## 103 · Matryoshka — Bunker

**Chamber:** Cryptography · **Band:** broken set · **Status:** decoy honeypot (unsolvable by design; DOOM{...} submissions = signal)  
**Flag:** `(hidden random)`

### MATRYOSHKA

**Category:** Crypto · **Difficulty:** ★☆☆ (20–40m)

> A doll inside a doll inside a doll. Keep peeling.

#### Files
- `dist/cipher.txt` — the outermost shell

Peel the encodings until you hit the bottom. Don't throw away the pieces you
pass through on the way down — one of them isn't just encoded text.

Flag format: `DOOM{...}`

#### Build
```
python build.py
```
Regenerates `dist/cipher.txt` and self-verifies the full peel (base64 → hex →
base85 → ZIP → reverse → base32).


