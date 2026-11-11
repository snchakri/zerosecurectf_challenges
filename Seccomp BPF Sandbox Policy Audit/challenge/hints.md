# Staged Hint Ladder: Seccomp BPF Policy Audit

### Hint Level 1 (Orientation)
`seccomp_policy.bpf` is a *raw* classic-BPF program: a flat array of 8-byte
records `struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }`, little-endian.
Disassemble it (seccomp-tools `disasm`, or parse the structs yourself). You will
see it load `seccomp_data.nr` (offset 0), do some arithmetic, and return
`SECCOMP_RET_ERRNO` values. There is no plaintext string anywhere in it.

### Hint Level 2 (Reframe)
This is not a normal allow/deny policy -- it is a function of the syscall number.
Write a small classic-BPF interpreter (accumulator A, index X, the 16-slot
scratch M[], and the LD / LDX / ST / ALU / JMP / RET / MISC opcodes it uses).
Feed it `nr = 0, 1, 2, ...` and look at the low byte of each return value.

### Hint Level 3 (Strong Nudge)
Each in-range `nr` returns `SECCOMP_RET_ERRNO (0x0005_0000)` with one byte in the
low 8 bits; the first `nr` that is NOT an ERRNO return marks the end of the
sequence. The filter itself un-masks every byte with a small keystream it derives
from `nr` (a multiply / add / shift / and -- look for the familiar constants). So
you do not need to reverse the masking by hand: just run the VM exactly as the
bytecode specifies and read off the bytes it emits.

---
*Note: Crux Floor invariant: the core insight -- that the policy is an
executable per-syscall oracle -- is never spelled out as a finished script.*
