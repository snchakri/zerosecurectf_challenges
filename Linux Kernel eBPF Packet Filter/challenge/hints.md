# Staged Hint Ladder: Doombot Border Filter

### Hint Level 1 (orientation)
`dist/filter.bpf` is a flat array of 8-byte eBPF instructions (see
`dist/README` for the encoding and the harness ABI). Write a disassembler, or
extend the shipped `ebpf_vm.py`, and print the program. It is fully unrolled:
a short prologue that rejects wrong lengths, then one repeating block per
packet byte, then a PASS/DROP tail. There is no stored key -- each byte is
transformed and compared against an immediate welded into a `JNE` instruction.

### Hint Level 2 (reframe)
Look at the per-byte block. A 32-bit register (call it the *state*) is kept
across bytes. For byte `i` the program takes the low byte of the state as an
xor key, the next byte of the state as an additive key, applies both to the
packet byte, masks to 8 bits, and compares to the welded immediate `TARGET[i]`.
Then it updates the state. Find the three constants that drive the state: the
initial `MOV32` into that register (SEED), the `*=` immediate (MULT), and the
`+=` immediate (ADD).

### Hint Level 3 (strong nudge)
The crucial detail is *what* the state update consumes: after the compare, the
state becomes `state = (state*MULT + produced_byte + ADD) mod 2**32`, where
`produced_byte` is the transformed byte -- i.e. exactly `TARGET[i]`, which you
can read straight out of the bytecode. So replay the state forward from SEED
using the `TARGET` values, and at each step invert the per-byte op:
`in[i] = ((TARGET[i] - ka) & 0xff) XOR kx`, with `kx = state & 0xff`,
`ka = (state>>8) & 0xff`. No search; one left-to-right pass yields the packet.

---
*Note: Crux Floor invariant -- the core reverse-engineering insight is never
handed out completely; each hint restores a reasoning handle, not the answer.*
