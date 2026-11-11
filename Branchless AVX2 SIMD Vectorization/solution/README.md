# Branchless AVX2 SIMD Vectorization — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Vectorized Gate of Latveria (rev_09)


## Flag
`zerosecure{simd_avx2_vectorized_mask_comparison_66aa}`


## Design summary
`dist/rev09_checker` is a static, stripped x86-64 ELF (built with
`musl-gcc -mavx2 -O2 -static -s`). It validates a candidate with a single
branchless AVX2 routine that processes the input 32 bytes per 256-bit vector.
For each byte, with `lane = position mod 32`, it applies a **position-wise byte
bijection** -- the transform depends only on the lane, never on the byte value,
which is what makes the check constant-time *and* fully invertible.

Two independent pipelines are computed on every vector and blended per lane:

```
pipeline p (SLp, SHp, Ap, Xp):
    lo  = v & 0x0F                      # VPAND
    hi  = (v >> 4) & 0x0F               # VPSRLW + VPAND
    sub = (SHp[hi] << 4) | SLp[lo]      # two VPSHUFB + VPSLLW/VPAND/VPOR
    sub = sub + Ap[lane]                # VPADDB  (mod 256)
    sub = sub ^ Xp[lane]                # VPXOR

out  = VPBLENDVB(pipeline0, pipeline1, MASK)   # lane picks p1 if MASK&0x80 else p0
```

It then compares `out` to an embedded `TARGET` with `VPCMPEQB` + `VPMOVMSKB`
and accepts iff every lane matches (all mask bits set) across both blocks.

All parameters live in one `const` blob in `.rodata`, tagged by the 8-byte magic
`AVX2SBX\x01`:

```
off 0   magic[8]   "AVX2SBX\x01"
off 8   N          u32 little-endian (53)
off 12  S0L[16] S0H[16] S1L[16] S1H[16]   nibble permutations (two pipelines)
off 76  A0[32] X0[32] A1[32] X1[32]        per-lane add / xor vectors
off 204 MASK[32]                           per-lane blend selector (0x00/0xFF)
off 236 TARGET[64]                         ceil(N/32)*32 bytes
```

The flag (the input) is never stored; `TARGET` is the flag's image under the
transform (the flag is zero-padded to a multiple of 32 before transforming).


## Why the naive readings fail
- `strings`/grep show nothing: only `TARGET` and the tables are present, never
  the flag in any plain/hex/base64/reversed form.
- An oracle/brute approach is dead: the gate only answers accept/reject on the
  whole input (a single AND of all lane masks), so you cannot isolate one byte;
  guessing all 53 is `256^53`.
- The transform is branchless and byte-parallel, so there is nothing to
  single-step -- you must read the vector math and the tables.


## Intended solution
Each pipeline is a composition of bijections (two nibble permutations, a modular
add, an xor), hence a bijection on bytes; the per-lane blend just picks one of
two bijections, and the mask that picks it is a constant you can read. So invert
position by position:

1. Find the blob by its magic; read `N`, the two S-box pairs, `A0/X0/A1/X1`,
   `MASK`, and `TARGET[0:ceil(N/32)*32]`.
2. For each position `i` (`lane = i % 32`): if `MASK[lane] & 0x80` use
   pipeline 1's parameters else pipeline 0's. Compute
   `y = TARGET[i] XOR X[lane]`; `y = (y - A[lane]) & 0xff`; then
   `byte = (SH^-1[(y>>4)&0xF] << 4) | SL^-1[y & 0xF]`.
3. The first `N` recovered bytes are the flag.

Cost is O(N); no brute force.


## Solver
```
python solve.py --dist ./dist
# -> zerosecure{simd_avx2_vectorized_mask_comparison_66aa}
```
`solve.py` reads only the ELF in `dist/`, parses the blob by magic, and inverts.
It contains no flag string and never reads the `flag` file.


## Rebuild (reproducible from ./flag)
```
wsl -d Ubuntu -- bash src/build.sh
# src/gen.py derives the fixed tables (seeded constant, not the flag), computes
# TARGET from ../flag, self-tests the inverse, emits src/params.h; then
# musl-gcc -mavx2 -O2 -static -s, strip.
```


## References
- Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 2:
  `VPSHUFB`, `VPBLENDVB`, `VPCMPEQB`, `VPMOVMSKB`, `VPADDB`.
- Intel Intrinsics Guide: `_mm256_shuffle_epi8`, `_mm256_blendv_epi8`,
  `_mm256_cmpeq_epi8`, `_mm256_movemask_epi8`.


## Defense note
Constant-time comparison protects against timing side-channels; it does nothing
to hide the secret when the secret's invertible image is shipped in the binary.
Store only a salted KDF/hash of a secret, or verify server-side.
