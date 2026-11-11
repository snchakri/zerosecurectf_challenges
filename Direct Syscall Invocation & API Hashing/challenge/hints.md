# Staged Hints: Direct Syscall Invocation & API Hashing

### Hint Level 1 (orientation)
Output is written with a raw `syscall` instruction, not the libc `write` wrapper
-- so don't expect tidy imports to hook or trace; set a breakpoint on the compare
instead. The validator transforms your input and checks the result against a fixed
block in the binary. Nearby you will find a small table of 32-bit constants.

### Hint Level 2 (reframe)
Those 32-bit constants are DJB2 hashes (`h = h*33 + c`) of API names -- the names
themselves are not present, exactly as in hash-based import resolution. They are
not the answer; they *seed* a per-position keystream. Each position mixes one seed
with an evolving 32-bit state (a rotate), runs DJB2 over the four bytes, folds the
result to one byte, and then either XORs it with the plaintext (odd positions) or
adds it (even positions). The state then advances as `state = state*33 + produced`.

### Hint Level 3 (strong nudge)
The state update uses the *produced* byte, which is exactly the target byte you
already have -- so the entire keystream is deterministic and replayable from the
embedded data alone. Walk left to right: recompute the key byte from the current
state and the right seed, invert the op (XOR is self-inverse on odd positions,
subtract the key on even positions), then fold the target byte into the state and
continue. No brute force.
