# Hardware Trap & Signal Redirection — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Hardware Trap & Signal Redirection (rev_04)


## Flag
`zerosecure{signal_handler_trap_redirection_55ef}`


## Design summary
`dist/rev04_sigtrap` moves the real computation off the straight-line path and
into CPU-fault handlers. Each loop iteration executes a deliberately faulting
2-byte instruction; the handler performs one transform step, mutates a shared
accumulator, and advances `RIP` by 2 (the fault instructions are all 2 bytes:
`ud2`=0F 0B, `div %ecx`=F7 F1, `mov (%rax),%eax`=8B 00). Blob magic `SIGTRAP4`:

```
off 0  MAGIC  8  "SIGTRAP4"
off 8  N      u16   flag length (48)
off 10 SEED   u32   accumulator seed (0x5EED4A17)
off 14 TARGET[N]
```

Trap chosen by `i % 3`; `k = (acc ^ (acc>>7)) & 0xFF`:
```
i%3==0  SIGILL  : o = ((b ^ k) + (acc & 7)) & 0xFF
i%3==1  SIGFPE  : o = rotl8(b,3) ^ k
i%3==2  SIGSEGV : o = ((b - k) & 0xFF) ^ 0x6D
acc = acc*1103515245 + 12345 + o        (mod 2^32)
```
Accept iff the produced stream equals `TARGET`.


## Why it is not trivially broken
`strings` reveals nothing (confirmed). A linear disassembly of `main` shows only a
loop of trapping instructions; the transform lives in three separate handlers, and
the operation applied to each byte depends on its position (`i % 3`). Recovering
the logic requires either dynamic analysis (letting the faults fire and observing
the handlers) or careful static reading of the `sigaction` wiring -- more than a
one-shot decompile.


## Intended solution
`acc` advances from the produced byte (= target byte), so the schedule is
deterministic. Read `SEED` and `TARGET`, then per position recompute `k`, pick the
handler by `i % 3`, invert it (see hints level 3), and advance `acc`. O(N).
`solve.py` parses the ELF and prints the flag.


## Solver
```
python solve.py --dist ./dist
# -> zerosecure{signal_handler_trap_redirection_55ef}
```


## Rebuild
```
wsl -d Ubuntu -- bash src/build.sh     # musl-gcc -static, stripped
```
`src/gen.py` derives the target from the `flag` file into `src/blob.h`; the flag
is never stored.
