# Linux Kernel eBPF Packet Filter — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Doombot Border Filter (rev_08)


## Flag
`zerosecure{ebpf_xdp_packet_inspector_bpf_filter_49de}`


## Design summary
`dist/filter.bpf` is a hand-assembled eBPF XDP filter in the classic 8-byte
instruction encoding (`u8 code; u8 regs=(src<<4|dst); s16 off; s32 imm`, little
endian). `dist/ebpf_vm.py` is a faithful emulator for the subset it uses and
defines the harness ABI: on entry `R1 -> ctx` (a 16-byte struct, `u64 data` at
+0 and `u64 data_end` at +8); the bytes between `data` and `data_end` are the
packet; the program returns `1 = XDP_DROP` (reject) or `2 = XDP_PASS` (accept).

The program is fully unrolled:

```
R2 = ctx->data ; R3 = ctx->data_end ; R4 = R3 - R2        ; len
if R4 != N goto DROP                                       ; length guard
R6 = SEED                                                  ; 32-bit rolling key
repeat for i in 0..N-1:
    R0 = packet[i]
    R0 ^= (R6 & 0xff)                 ; kx = low byte of state
    R0  = (R0 + ((R6>>8) & 0xff)) & 0xff   ; ka = 2nd byte of state
    if R0 != TARGET[i] goto DROP      ; TARGET[i] welded as a JNE immediate
    R6 = (R6*MULT + R0 + ADD) & 0xffffffff ; state advances from produced byte
R0 = XDP_PASS ; exit
DROP: R0 = XDP_DROP ; exit
```

The constants are `SEED = 0x1A2B3C4D`, `MULT = 1664525`, `ADD = 1013904223`
(the Numerical Recipes LCG pair). The accept condition *is* the encoded flag:
the `TARGET[i]` immediates are the flag's image under the rolling-key transform.
The plaintext flag is never stored.


## Why the naive readings fail
- `strings`/grep reveal nothing: only the transformed `TARGET` bytes live in the
  program (spread across the `imm` fields of 53 `JNE` instructions), never the
  flag in any plain/hex/base64/reversed form.
- The filter answers only PASS/DROP on the whole packet (the first wrong byte
  jumps to DROP), so you cannot brute-force a single byte in isolation; the full
  space is `256^53`.
- You cannot just read a stored string -- the key is defined by a stateful
  computation you must model.


## Intended solution
The state update consumes the **produced** byte, which equals `TARGET[i]` --
and `TARGET[i]` is sitting in the bytecode. So the entire key schedule can be
replayed forward while inverting each byte:

1. Decode the 8-byte instructions. Read `SEED` (the `MOV32` into the state reg),
   `MULT` (the `*=` immediate), `ADD` (the `+=` immediate), `N` (the length-guard
   `JNE` immediate), and `TARGET[]` (the per-byte `JNE` immediates, in order).
2. `state = SEED`; for each `TARGET[i]`:
   `kx = state & 0xff`, `ka = (state>>8) & 0xff`,
   `in[i] = ((TARGET[i] - ka) & 0xff) XOR kx`,
   then `state = (state*MULT + TARGET[i] + ADD) & 0xffffffff`.
3. The recovered `in[]` is the flag. O(N), no brute force.


## Solver
```
python solve.py --dist ./dist
# -> zerosecure{ebpf_xdp_packet_inspector_bpf_filter_49de}
```
`solve.py` reads only `dist/filter.bpf`, extracts the constants and the TARGET
immediates, and inverts. It contains no flag string and never reads `flag`.


## Rebuild (reproducible from ./flag)
```
python src/gen.py
# forward-transforms ../flag, self-tests the inverse, assembles the eBPF
# program (src/ebpf_asm.py), writes dist/filter.bpf, and self-checks it against
# dist/ebpf_vm.py (accepts the flag, drops a wrong key / wrong length).
```


## References
- Linux kernel, `Documentation/bpf/` and `include/uapi/linux/bpf.h` -- eBPF
  instruction set and encoding.
- Fabian Yamaguchi et al.; iovisor/bpf docs -- classic 8-byte `bpf_insn` format.
- XDP action codes `XDP_DROP` / `XDP_PASS` (`include/uapi/linux/bpf.h`).


## Defense note
Comparing a transformed input against embedded targets is obfuscation, not
authentication: a reversible per-byte transform ships its own inverse. Verify
secrets with a keyed MAC/KDF server-side, never in a filter the client can read.
