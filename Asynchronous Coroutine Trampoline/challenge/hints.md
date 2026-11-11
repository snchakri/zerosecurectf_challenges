# Staged Hint Ladder: Asynchronous Coroutine Trampoline

### Hint Level 1 (Orientation)
Decompile or disassemble `dist/checker.pyc` (e.g. with `dis`/`marshal`, or a
decompiler). The module primes three generator workers and drives them from a
single `trampoline` loop that calls `.send(...)` once per input byte. The loop
compares the result against an embedded `TARGET` byte-blob — there is no stored
plaintext key to read.

### Hint Level 2 (Reframe)
Each worker applies one small, *reversible* byte operation (think: XOR, modular
add, bit-rotate) that depends on a shared `state` word. The worker chosen for
byte *i* is decided by the schedule (`i % 3`). Work out exactly what each worker
does and how `state` is updated after every byte — the update consumes the
*output* byte, not the input byte.

### Hint Level 3 (Strong Nudge)
Because `state` advances from the produced (output) bytes, and those bytes are
exactly what `TARGET` stores, you can replay the state evolution forward while
inverting each worker's operation in place. No search is needed: recover the key
one byte at a time, left to right, using the same seed and feedback constants the
bytecode uses.

---
*Note: Crux Floor invariant: The core reverse engineering insight is never handed out completely; each hint restores a reasoning handle.*
