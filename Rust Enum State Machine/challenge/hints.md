# Staged Hints: Rust Enum State Machine

### Hint Level 1 (orientation)
The validator never compares your input to a stored string. It transforms the
input and compares the *result* to a fixed block of bytes baked into the binary.
Find that block and the loop that produces it. Note there are two passes, not
one: an inner per-character transform and an outer chaining pass over the whole
buffer.

### Hint Level 2 (reframe)
The per-character transform is not fixed -- it depends on a small state variable
that takes one of five values, and each value selects a different reversible
operation (add, xor, rotate-then-add, xor-then-subtract, rotate-then-xor). After
each character the state jumps to a new value chosen by a 5x5 table, indexed by
the byte just produced. A rolling key also evolves each step. Every one of these
updates depends only on values you can already see (the produced bytes and the
seed), not on the unknown plaintext -- so the whole key/state schedule can be
replayed forward from the target.

### Hint Level 3 (strong nudge)
First undo the outer chain: it is a byte-wise CBC-style XOR (`out[i] = mid[i] ^
out[i-1]`, with a fixed IV), so recovering `mid[]` from the embedded target is a
one-line sweep. Then walk left to right: at each position recompute the rolling
key from the seed, invert the operation picked by the current state, advance the
state via the table using `mid[i] % 5`, and move on. No search or brute force is
needed -- it is a deterministic unwind.
