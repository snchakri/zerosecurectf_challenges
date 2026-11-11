# Seccomp BPF Sandbox Policy Audit — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Seccomp BPF Policy Audit


## 1. Artifact
`dist/seccomp_policy.bpf` is a classic-BPF (cBPF) seccomp filter in the raw
on-disk form the kernel loads: a flat array of 8-byte `struct sock_filter`
records `{ u16 code; u8 jt; u8 jf; u32 k; }` in little-endian. 1896 bytes =
237 instructions.


## 2. What the program computes
Disassembling (seccomp-tools, or a hand-rolled parser) reveals the structure:

```
LD  [0]              ; A = seccomp_data.nr
TAX                  ; X = nr                      (save it)
A = A * 1103515245   ; MUL  (glibc LCG multiplier)
A = A + 12345        ; ADD  (glibc LCG increment)
A = A >> 8           ; RSH
A = A & 0xFF         ; AND  ->  ks = keystream(nr)
ST  M[1]             ; stash ks
TXA                  ; A = nr again
; dispatch table:
for i in 0..L-1:  JEQ #i -> JA blk_i
RET #0               ; default: SECCOMP_RET_KILL
blk_i:  LD #enc_i ; JA tail      ; enc_i = flag[i] ^ ks(i)
tail:   LDX M[1] ; A ^= X ; A |= 0x00050000 ; RET A   ; SECCOMP_RET_ERRNO | byte
```

So the filter is a **per-syscall oracle**: probed with `nr = i`, it returns
`SECCOMP_RET_ERRNO` whose low byte is `enc_i XOR ks(i) = flag[i]`. The stored
constants `enc_i` are the flag masked by the LCG keystream, so nothing readable
appears in the blob (confirmed by the leak check).


## 3. Intended solution
Write a classic-BPF virtual machine and run it for `nr = 0, 1, 2, ...`,
collecting `ret & 0xFF` while `(ret & 0xFFFF0000) == SECCOMP_RET_ERRNO`; stop at
the first non-ERRNO return (the default `SECCOMP_RET_KILL = 0`). The collected
bytes are the flag. Because the VM performs the XOR with the keystream itself,
no manual demasking is needed -- faithfully executing the bytecode is enough.

Key cBPF semantics to implement: accumulator `A`, index `X`, scratch `M[0..15]`;
`LD`/`LDX` (ABS/IMM/MEM), `ST`, `ALU` (ADD/SUB/MUL/OR/AND/LSH/RSH/XOR with K or
X, mod 2**32), `JMP` (`JA` adds `k`, conditional adds `jt`/`jf` to `pc+1`),
`RET` (A or K), and `MISC` (TAX/TXA).


## 4. Solver
`solve.py --dist ./dist` implements the VM independently, parses the struct
array, probes `nr = 0..`, and prints the recovered flag. It contains no flag
string and never reads `./flag`.

```
python solve.py --dist ./dist
zerosecure{seccomp_bpf_syscall_architecture_bypass_91fe}
```


## 5. Why it is hard but fair
The whole difficulty is writing a correct cBPF interpreter and realising the
policy is an executable oracle, not a static allow-list. No brute force is
involved; the sequence length is self-delimiting via the default KILL branch.


## 6. Defensive note
A seccomp policy that returns data-bearing `SECCOMP_RET_ERRNO`/`TRACE` values
per syscall can become a side channel. Return a single, constant action
(`KILL`/`ERRNO(EPERM)`) and never encode state in the data field.
