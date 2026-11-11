# Staged Hints: Golang Concurrent Channel Pipeline

### Hint Level 1 (orientation)
The binary is a Go-style pipeline rendered with POSIX threads: a producer plus
four stage workers, linked by bounded FIFO "channels" (mutex + condition
variable). The concurrency is a smokescreen -- each byte still visits the four
stages in a fixed order, so the net result is deterministic. Identify the four
stage functions and the single fixed key table.

### Hint Level 2 (reframe)
The stages, in order, are: (1) add a position ramp `(i*37 + 11) & 0xFF`; (2) XOR
with a 16-byte key table indexed by position; (3) rotate left by 3 then XOR 0x3C;
(4) a running-difference accumulator `out = (x - run) & 0xFF; run = (run + x) &
0xFF`. The pipeline output is compared to a fixed target block in the binary.

### Hint Level 3 (strong nudge)
Invert the stages in reverse. Stage 4 unwinds left to right: `x = (out + run) &
0xFF` then `run = (run + x) & 0xFF`, because `run` only ever depends on bytes you
have already recovered. Stage 3 inverse is `rotr8(y ^ 0x3C, 3)`; stage 2 is the
same keyed XOR; stage 1 subtracts the position ramp. No brute force -- it is a
clean four-step unwind.
