# WebAssembly Linear Memory Validation — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: WASM Gate of the Citadel (rev_06)


## Flag
`zerosecure{wasm_linear_memory_stack_validator_31cb}`


## Design summary
`dist/validator.wasm` is a hand-assembled WebAssembly module (built without
wat2wasm). It exports one page of `memory` and `validate(len: i32) -> i32`. The
Node harness `dist/run.js` writes the candidate bytes to linear memory at
offset 0 and calls `validate(length)`; a return of 1 accepts, 0 rejects.

A data segment is loaded at linear-memory offset 256 and holds, tagged by the
8-byte magic `W6VMBLOB`:

```
+0   magic[8]  "W6VMBLOB"
+8   N         u32  flag length (51)
+12  SEED      u32  0x6D1E7F3B
+16  MULT      u32  1664525
+20  ADD       u32  1013904223
+24  TARGET[N] u8   expected per-byte results
```

`validate` is a stack-machine loop. With a 32-bit `state = SEED`, for each input
byte `in[i]`:

```
t = in[i] XOR (state & 0xff)
t = (t + ((state>>8) & 0xff)) & 0xff
t = rotl8(t, (state>>16) & 7)                 ; 8-bit rotate left
if t != TARGET[i] -> return 0
state = (state*MULT + t + ADD) & 0xffffffff    ; wraps as i32
```

It returns 1 only if every byte matches. The flag itself is never stored; only
its transformed image `TARGET` lives in the module.


## Why the naive readings fail
- `strings`/grep find nothing: only `TARGET` and the scalar parameters are in
  the module, never the flag in any plain/hex/base64/reversed form.
- `validate` returns one boolean over the whole input (first mismatch returns 0),
  so a byte cannot be brute-forced in isolation; the space is `256^51`.
- The key is produced by a stateful transform, not stored, so you must model the
  wasm stack machine to recover it.


## Intended solution
The state update consumes the **produced** byte, which equals the stored
`TARGET[i]`. So replay the schedule forward and invert each byte:

1. Parse the wasm (or just locate the magic in the module bytes) and read `N`,
   `SEED`, `MULT`, `ADD`, `TARGET[]` from the data segment.
2. `state = SEED`; for each `TARGET[i]`:
   `t = rotr8(TARGET[i], (state>>16)&7)`;
   `t = (t - ((state>>8)&0xff)) & 0xff`;
   `in[i] = t XOR (state & 0xff)`;
   then `state = (state*MULT + TARGET[i] + ADD) & 0xffffffff`.
3. `in[]` is the flag. O(N), no brute force.


## Solver
```
python solve.py --dist ./dist
# -> zerosecure{wasm_linear_memory_stack_validator_31cb}
```
`solve.py` reads only `dist/validator.wasm`, extracts the blob by magic, and
inverts. It contains no flag string and never reads `flag`.


## Rebuild (reproducible from ./flag)
```
python src/gen.py
# forward-transforms ../flag, self-tests the inverse, hand-assembles the wasm
# (type/function/memory/export/code/data sections), writes dist/validator.wasm
# and dist/run.js, and self-checks with Node (accept flag, reject wrong/short).
```


## References
- WebAssembly Core Specification 1.0 -- binary format (sections, LEB128,
  memarg) and the instruction set used (`i32.load`/`i32.load8_u`, `i32.and`,
  `i32.shl`/`i32.shr_u`, `block`/`loop`/`if`/`br_if`).
- MDN, `WebAssembly.instantiate` / `WebAssembly.Memory`.


## Defense note
A client-side validator -- even one compiled to WebAssembly in a sandbox -- can
always be read and inverted when it ships the secret's reversible image. Verify
secrets server-side against a salted KDF/MAC.
