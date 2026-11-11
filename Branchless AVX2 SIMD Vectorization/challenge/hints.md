# Staged Hint Ladder: Vectorized Gate of Latveria

### Hint Level 1 (orientation)
Disassemble `dist/rev09_checker`. The check is one straight-line AVX2 routine
with no data-dependent branches: `VPSHUFB`, `VPADDB`, `VPXOR`, `VPBLENDVB`,
then `VPCMPEQB` + `VPMOVMSKB` against an embedded 64-byte block. It processes
the input 32 bytes per 256-bit vector. Nothing in the binary is the key -- only
the block it compares against, plus the tables that build the comparison.

### Hint Level 2 (reframe)
`VPSHUFB` with a 16-byte table is a per-nibble substitution. The routine runs
*two* full pipelines (two S-box pairs, two add vectors, two xor vectors) and
`VPBLENDVB` selects between them per byte using a constant mask. The key fact:
the operation applied to a byte depends only on its **lane** (its position mod
32), never on the byte's value. Find the parameter blob in `.rodata` (it is
tagged with an 8-byte magic); read out the two S-box pairs, the two add/xor
vectors, the blend mask, the length, and the target.

### Hint Level 3 (strong nudge)
Each pipeline is a bijection on a byte: substitute low nibble `SL[lo]` and high
nibble `SH[hi]`, recombine, add `A[lane]` (mod 256), xor `X[lane]`. Invert in
reverse: `y = out XOR X[lane]`; `y = (y - A[lane]) & 0xff`; split `y` into
nibbles and apply the *inverse* permutations `SL^-1`, `SH^-1`. For each position
pick the pipeline the mask selects (high bit set -> pipeline 1, else pipeline 0),
invert the corresponding target byte, and you get the key byte. No search; it is
a direct per-position inversion.

---
*Note: Crux Floor invariant -- the core reverse-engineering insight is never
handed out completely; each hint restores a reasoning handle, not the answer.*
