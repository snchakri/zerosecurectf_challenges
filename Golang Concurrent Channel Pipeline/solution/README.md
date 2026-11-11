# Golang Concurrent Channel Pipeline — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Golang Concurrent Channel Pipeline (rev_03)


## Flag
`zerosecure{golang_concurrent_channel_pipeline_82cd}`


## Design summary
`dist/rev03_pipeline` faithfully reproduces a Go goroutine/channel pipeline using
POSIX threads (the Go toolchain was unavailable in the build sandbox; the
structure -- independent workers linked by FIFO channels -- is preserved). A
producer thread feeds the source channel; four stage threads each read from one
channel and write to the next; `main` collects the final channel and compares to
the embedded target. Blob magic `GOCHANv1`:

```
off 0  MAGIC   8  "GOCHANv1"
off 8  N       u16   flag length (51)
off 10 KLEN    u8    16
off 11 K[16]         stage-2 XOR key
off 27 TARGET[N]
```

Stages (applied in order to the stream):
```
stage1: y = (x + ((i*37 + 11) & 0xFF)) & 0xFF      # additive position ramp
stage2: y = x ^ K[i % 16]                          # keyed xor
stage3: y = rotl8(x,3) ^ 0x3C                      # rotate + brand
stage4: y = (x - run) & 0xFF; run = (run + x)&0xFF # running-difference accumulator
```
Accept iff the stage-4 output equals `TARGET`.


## Why it is not trivially broken
`strings` reveals nothing (confirmed). The threaded channel plumbing obscures the
data path for static tools, and stage 4 introduces a cross-byte dependency (a
running sum) so the bytes cannot be solved fully independently -- you must model
the accumulator. Still fully deterministic and solvable by hand in minutes once
the four transforms are identified.


## Intended solution
Invert the four stages in reverse order; the running accumulator in stage 4 is
causal (depends only on already-recovered bytes), so it unwinds cleanly:
```
# stage4^-1 (left to right): x = (y + run)&0xFF; run = (run + x)&0xFF
# stage3^-1: x = rotr8(y ^ 0x3C, 3)
# stage2^-1: x = y ^ K[i % 16]
# stage1^-1: x = (y - ((i*37+11)&0xFF)) & 0xFF
```
O(N), no brute force. `solve.py` parses the ELF and prints the flag.


## Solver
```
python solve.py --dist ./dist
# -> zerosecure{golang_concurrent_channel_pipeline_82cd}
```


## Rebuild
```
wsl -d Ubuntu -- bash src/build.sh     # musl-gcc -static -pthread, stripped
```
`src/gen.py` derives the target from the `flag` file into `src/blob.h`; the flag
is never stored.
