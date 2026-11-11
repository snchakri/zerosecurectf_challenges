# Mixed Boolean-Arithmetic — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Mixed Boolean-Arithmetic (MBA) Deobfuscation (rev_05)


## Flag
`zerosecure{mba_linear_boolean_simplification_19af}`


## Design summary
`dist/rev05_mba` validates each byte with an affine map, but every arithmetic
operation is written via MBA identities so the disassembly looks like a tangle of
`&`, `|`, `^`, `~`, shifts and adds. Blob magic `MBALIN05`:

```
off 0  MAGIC  8  "MBALIN05"
off 8  N      u16   flag length (50)
off 10 A  B  A2  B2  IV   (5 x u8) = 0x4D 0x1F 0x6B 0x2D 0x57
off 15 TARGET[N]
```

The binary computes, with `a + b` realised as `(a ^ b) + 2*(a & b)` and
multiply-by-constant unrolled into MBA additions of shifted terms:
```
m   = (A*x + B) & 0xFF        # affine layer 1 (A odd -> bijection)
c   = (m + prev) & 0xFF       # linear diffusion chain, prev starts at IV
prev= m
out = (A2*c + B2) & 0xFF      # affine layer 2 (A2 odd -> bijection)
```
Accept iff `out == TARGET`.


## Why it is not trivially broken
`strings` reveals nothing (confirmed). The MBA rewriting hides the affine
structure from pattern-matchers, and the diffusion chain couples each byte to its
predecessor so bytes are not independent. The solver must recognise and collapse
the MBA identities (`(a^b)+2*(a&b) = a+b`; shift-add = constant multiply), then
invert a two-layer affine map around a chain.


## Intended solution
Both multipliers are odd, hence invertible mod 256 (`77^-1=133`, `107^-1=67`).
Compute the inverses (extended Euclid), then unwind per byte left to right:
```
c = (A2inv * ((out - B2) & 0xFF)) & 0xFF
m = (c - prev) & 0xFF ; prev = m
x = (Ainv  * ((m  - B ) & 0xFF)) & 0xFF
```
Pure linear algebra mod 256, O(N), no brute force and no SMT needed (Z3 also
solves it). `solve.py` parses the ELF, reads the constants + target, and prints
the flag.


## Solver
```
python solve.py --dist ./dist
# -> zerosecure{mba_linear_boolean_simplification_19af}
```


## Rebuild
```
wsl -d Ubuntu -- bash src/build.sh     # musl-gcc -static, stripped
```
`src/gen.py` derives the target from the `flag` file into `src/blob.h`; the flag
is never stored.
