# Rust Enum State Machine — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Rust Enum State Machine (rev_01)


## Flag
`zerosecure{rust_enum_pattern_match_transitions_91da}`


## Design summary
The handout `dist/rev01_statemachine` is a faithful C re-implementation of a Rust
tagged-union state machine (the Rust toolchain was unavailable in the build
sandbox; the control structure -- a 5-variant enum with pattern-matched
transitions -- is preserved exactly). It embeds an opaque parameter+target blob,
located by the 8-byte magic `R1STMVM\x01`:

```
off 0  MAGIC      8  "R1STMVM\x01"
off 8  N          u16   flag length (52)
off 10 SEED       u32   rolling-key seed (0x1B873CA9)
off 14 IV8        u8    chain IV (0x3C)
off 15 TRANS[25]  u8    5x5 next-state table (pattern match on produced_byte % 5)
off 40 TARGET[N]  u8    expected final output
```

The forward validation is two passes over the input `in[0..N)`:

**Pass 1 - enum FSM.** With `state=0` (Init) and `acc=SEED`:
```
key   = (acc ^ (acc>>11) ^ (acc<<7)) & 0xFF
t = match state {
  0 => (b + key) & 0xFF
  1 =>  b ^ key
  2 => (rotl8(b,3) + key) & 0xFF
  3 => ((b ^ 0x5A) - key) & 0xFF
  4 => (rotr8(b,2) ^ key)
}
mid[i] = t
acc    = acc*1664525 + 1013904223 + t        (mod 2^32)
state  = TRANS[state*5 + (t % 5)]
```

**Pass 2 - integrity chain.** `out[i] = mid[i] ^ prev`, `prev = out[i]`, starting
from `prev = IV8`. The binary accepts iff `out == TARGET`.


## Why it is not trivially broken
`strings` shows nothing (confirmed): only the transformed target lives in the
binary, never the flag, nor any plain/hex/base64/reversed encoding of it. A
single angr/one-shot pass is frustrated by the data-dependent state transitions
(control flow chosen by a produced byte via a table) layered under the CBC-style
diffusion, so the solver must actually model the automaton and its key schedule.


## Intended solution
Because every key/state update depends only on the *produced* bytes (which the
target reveals once the chain is undone) and the seed -- never on the unknown
plaintext -- the whole schedule can be replayed forward and each byte inverted:

1. Undo pass 2: `mid[i] = TARGET[i] ^ (i ? TARGET[i-1] : IV8)`.
2. Replay pass 1 forward, inverting each variant:
   - 0: `b = (t - key) & 0xFF`
   - 1: `b = t ^ key`
   - 2: `b = rotr8((t - key) & 0xFF, 3)`
   - 3: `b = ((t + key) & 0xFF) ^ 0x5A`
   - 4: `b = rotl8(t ^ key, 2)`
   then update `acc` from `t` and `state` from `TRANS`.

No brute force (cost O(N)). See `solve.py`, which parses the ELF, reads the blob
by magic and prints the flag.


## Solver
```
python solve.py --dist ./dist
# -> zerosecure{rust_enum_pattern_match_transitions_91da}
```


## Rebuild
```
wsl -d Ubuntu -- bash src/build.sh     # musl-gcc -static, stripped
```
Reproducible from the `flag` file: `src/gen.py` reads it and regenerates
`src/blob.h` (only the transformed target, never the flag).
