# Multi-Stage Dynamic Runtime Code Decryption — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Multi-Stage Dynamic Runtime Code Decryption (Staged Loader)


## 1. Analysis & Theoretical Foundations
`dist/stager` is a static x86-64 ELF that performs three chained decryption
stages at runtime, each stage keyed by the *plaintext of the previous stage*
(a code/data checksum), so no stage key is stored directly. The decrypted
payload is materialised into an `mmap` RWX page — the tell of a polymorphic
loader. The final verification value (`TARGET`) exists only in memory, after the
whole chain has run.


## 2. Embedded image format
Bracketed by magic markers `Z5STG_v1` ... `Z5STGEND` (little-endian):
```
u16 n                 # key length
u8  key1              # stage-1 XOR key
32 bytes STAGE2_ENC   # encrypted stage-2 payload
n  bytes STAGE3_ENC   # encrypted stage-3 target
```


## 3. The key chain (recovered from the loader)
1. **Stage 1:** `T2[i] = STAGE2_ENC[i] XOR key1` (32-byte payload into RWX page).
2. **Stage 2:** `seed2 = FNV1a32(T2)` — a checksum of the decrypted stage-2
   bytes. Drive an LCG: `s = s*1664525 + 1013904223 (mod 2^32)`,
   output byte `(s>>24)&0xff`. Take `2n` bytes: `streamA = first n`,
   `streamB = next n`.
3. **Stage 3:** `TARGET[i] = STAGE3_ENC[i] XOR streamB[i]`.
4. **Verify:** accept iff `len(input)==n` and
   `input[i] ^ T2[i%32] ^ streamA[i] == TARGET[i]` for all `i`.


## 4. Recovery
Invert the final equation:
```
flag[i] = TARGET[i] ^ T2[i%32] ^ streamA[i]
```
All inputs to the right-hand side are reconstructible from the stored image by
replaying stages 1–3. No brute force; O(n).


## 5. Step-by-Step Walkthrough
1. Scan the ELF for the `Z5STG_v1` region; read `n`, `key1`, `STAGE2_ENC`,
   `STAGE3_ENC`.
2. `T2 = STAGE2_ENC ^ key1`.
3. `seed2 = FNV1a32(T2)`; generate `streamA`, `streamB` via the LCG.
4. `TARGET = STAGE3_ENC ^ streamB`.
5. `flag[i] = TARGET[i] ^ T2[i%32] ^ streamA[i]`.


## 6. Why it resists shortcuts
- `strings` finds nothing: both stored blobs are opaque XOR ciphertext, the flag
  never appears (confirmed by the leak check).
- A single-step guess fails: you must identify and reproduce the *chained* key
  derivation (XOR → FNV checksum of decrypted payload → LCG keystream → XOR) to
  get `TARGET` at all. Breaking the chain at any stage yields garbage.
- Deterministic and fast once understood.


## 7. Exploit Script & Verification
`solve.py` reads only the ELF in `dist/`:
```bash
python solve.py --dist ./dist
```
Prints the recovered `zerosecure{...}` key, byte-identical to `flag`. Independent
check: `./dist/stager "<key>"` prints "ACCESS GRANTED".


## 8. Citations & References
- Eilam, E. (2005). *Reversing: Secrets of Reverse Engineering.* Wiley.
- Sikorski, M., & Honig, A. (2012). *Practical Malware Analysis.* No Starch Press
  (self-decrypting / staged loaders).
- Fowler–Noll–Vo (FNV-1a) hash specification.
- Knuth, D. E. *TAOCP Vol. 2* (linear congruential generators; the constants
  1664525 / 1013904223 are the Numerical Recipes LCG).


## 9. Defense Engineering & Remediation
Enforce W^X: never map pages writable and executable at once. More importantly,
runtime unpacking only delays a reverser — it is not confidentiality. Keep key
verification server-side behind a slow, salted hash.
