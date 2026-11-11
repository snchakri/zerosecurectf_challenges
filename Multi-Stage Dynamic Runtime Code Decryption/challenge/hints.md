# Staged Hint Ladder: Multi-Stage Dynamic Runtime Code Decryption

### Hint Level 1 (Orientation)
The binary carries one opaque image, bracketed by an ASCII magic marker
(`Z5STG_v1` ... `Z5STGEND`). It holds: a length `n`, a one-byte `key1`, a
32-byte `STAGE2_ENC`, and an `n`-byte `STAGE3_ENC`. Watch the loader
decrypt these in sequence into an RWX page — or just reproduce its arithmetic
statically.

### Hint Level 2 (Reframe)
The chain is: `T2 = STAGE2_ENC XOR key1` (stage-2 payload). The stage-3 key is a
**checksum of that decrypted payload** — an FNV-1a 32-bit hash of `T2` — which
seeds a linear-congruential keystream. No stage key is stored directly; each is
computed from the previous stage's plaintext.

### Hint Level 3 (Strong Nudge)
Generate `2n` LCG bytes from `seed2 = FNV1a32(T2)` using
`s = s*1664525 + 1013904223 (mod 2^32)`, byte `= (s>>24)&0xff`; the first `n` are
`streamA`, the next `n` are `streamB`. Then `TARGET = STAGE3_ENC XOR streamB`, and
the verifier checks `in[i] ^ T2[i%32] ^ streamA[i] == TARGET[i]`. Solve for the
input: `flag[i] = TARGET[i] ^ T2[i%32] ^ streamA[i]`.

---
*Note: Crux Floor invariant: The core reverse engineering insight is never handed out completely; each hint restores a reasoning handle.*
