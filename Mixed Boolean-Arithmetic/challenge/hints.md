# Staged Hints: Mixed Boolean-Arithmetic (MBA) Deobfuscation

### Hint Level 1 (orientation)
The per-character check is drowned in bitwise/arithmetic noise, but the noise is
built from standard MBA identities and collapses to something small. The useful
identity: `(a ^ b) + 2*(a & b) == a + b`. Wherever you see that shape, it is just
an addition. The transformed bytes are compared to a fixed target block in the
binary.

### Hint Level 2 (reframe)
After collapsing the identities, each byte goes through: an affine map `m = (A*x +
B) mod 256`; a diffusion step that adds the previous `m` (`c = (m + prev) & 0xFF`,
`prev = m`); and a second affine map `out = (A2*c + B2) mod 256`. The
multiply-by-constant you see unrolled as a sum of shifted terms is exactly that --
a constant multiply. `A` and `A2` are odd, so both affine maps are bijections mod
256. The small constants `A, B, A2, B2` and the chain IV are present in the binary.

### Hint Level 3 (strong nudge)
An odd multiplier `A` mod 256 has an inverse (e.g. `77^-1 = 133`); compute each
inverse with the extended Euclidean algorithm. Then invert per byte, left to
right, carrying `prev`:
```
c = (A2^-1 * (out - B2)) & 0xFF
m = (c - prev) & 0xFF ; prev = m
x = (A^-1 * (m - B)) & 0xFF
```
No Z3 is required (though it would also work); the system is linear. No brute force.
