# Staged Hint Ladder: WASM Gate of the Citadel

### Hint Level 1 (orientation)
`dist/validator.wasm` is a real WebAssembly module. Parse it (write a tiny
section walker, or use any wasm disassembler / `wasm2wat` if you have one). You
will find one exported function, `validate(len)`, a single page of linear
memory, and a **data segment** loaded higher in memory. The candidate is read
from offset 0; the data segment holds an 8-byte magic, a few 32-bit words, and
a block of target bytes. There is no stored key.

### Hint Level 2 (reframe)
Read the `validate` body as a stack machine. It keeps a 32-bit `state` (seeded
from the data segment) and loops over the input. For each byte it: xors in the
low byte of `state`, adds the next byte of `state` (mod 256), and rotates the
result left by a few bits taken from `state`, then compares to `TARGET[i]`.
After each byte it updates `state`. Pull `N`, `SEED`, `MULT`, `ADD` and the
`TARGET[]` bytes straight out of the data segment.

### Hint Level 3 (strong nudge)
The state update is `state = (state*MULT + produced_byte + ADD) mod 2**32`,
where `produced_byte` is the compared byte -- i.e. exactly `TARGET[i]`, which
you already have. So replay `state` forward from `SEED` using the `TARGET`
values and invert each step: `t = rotr8(TARGET[i], (state>>16)&7)`;
`t = (t - ((state>>8)&0xff)) & 0xff`; `in[i] = t XOR (state & 0xff)`. One
left-to-right pass recovers the key; no search, no brute force.

---
*Note: Crux Floor invariant -- the core reverse-engineering insight is never
handed out completely; each hint restores a reasoning handle, not the answer.*
