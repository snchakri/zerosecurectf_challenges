#!/usr/bin/env python3
"""
Real solver for misc_01_bpf_seccomp_policy_auditing.

Reads ONLY dist/seccomp_policy.bpf : a raw classic-BPF seccomp filter (an array
of 8-byte `struct sock_filter`, little-endian). The solver:

  1. Parses the blob into instructions.
  2. Implements a classic-BPF virtual machine (accumulator A, index X, 16-slot
     scratch M[], the LD/LDX/ST/ALU/JMP/RET/MISC subset the filter uses).
  3. Probes the filter with seccomp_data.nr = 0,1,2,... Each in-range probe
     returns SECCOMP_RET_ERRNO (0x0005_0000) whose low byte is one flag byte;
     the first probe that is NOT an ERRNO return (the default KILL) marks the
     end. The filter internally un-masks each byte with its own LCG keystream,
     so simply running the VM yields the plaintext.

Does not contain the flag and never reads the ./flag file.
"""
import argparse
import os
import struct

# opcode bits
LD, LDX, ST, STX, ALU, JMP, RET, MISC = 0, 1, 2, 3, 4, 5, 6, 7
ABS, IMM, MEM = 0x20, 0x00, 0x60
SRC_X = 0x08
J_A, J_EQ, J_GT, J_GE, J_SET = 0x00, 0x10, 0x20, 0x30, 0x40
A_ADD, A_SUB, A_MUL, A_DIV, A_OR, A_AND, A_LSH, A_RSH, A_NEG, A_MOD, A_XOR = \
    0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0

SECCOMP_RET_ACTION = 0xFFFF0000
SECCOMP_RET_ERRNO = 0x00050000


def parse(blob):
    prog = []
    for off in range(0, len(blob), 8):
        code, jt, jf, k = struct.unpack_from("<HBBI", blob, off)
        prog.append((code, jt, jf, k))
    return prog


def run(prog, nr):
    buf = bytearray(64)
    struct.pack_into("<i", buf, 0, nr)            # seccomp_data.nr
    struct.pack_into("<I", buf, 4, 0xC000003E)    # arch (not used by the filter)
    A = X = 0
    M = [0] * 16
    pc = 0
    for _ in range(1_000_000):
        code, jt, jf, k = prog[pc]
        cls = code & 7
        if cls == LD:
            mode = code & 0xE0
            if mode == ABS:
                A = struct.unpack_from("<I", buf, k)[0]
            elif mode == IMM:
                A = k
            elif mode == MEM:
                A = M[k]
            else:
                raise ValueError(f"LD mode {mode:#x}")
            pc += 1
        elif cls == LDX:
            mode = code & 0xE0
            X = M[k] if mode == MEM else k
            pc += 1
        elif cls == ST:
            M[k] = A; pc += 1
        elif cls == STX:
            M[k] = X; pc += 1
        elif cls == ALU:
            op = code & 0xF0
            s = (X if code & SRC_X else k) & 0xFFFFFFFF
            if op == A_ADD: A = (A + s) & 0xFFFFFFFF
            elif op == A_SUB: A = (A - s) & 0xFFFFFFFF
            elif op == A_MUL: A = (A * s) & 0xFFFFFFFF
            elif op == A_DIV: A = (A // s) & 0xFFFFFFFF if s else 0
            elif op == A_OR:  A = (A | s) & 0xFFFFFFFF
            elif op == A_AND: A = (A & s) & 0xFFFFFFFF
            elif op == A_LSH: A = (A << (s & 31)) & 0xFFFFFFFF
            elif op == A_RSH: A = (A >> (s & 31)) & 0xFFFFFFFF
            elif op == A_XOR: A = (A ^ s) & 0xFFFFFFFF
            elif op == A_MOD: A = (A % s) & 0xFFFFFFFF if s else 0
            else: raise ValueError(f"ALU op {op:#x}")
            pc += 1
        elif cls == JMP:
            op = code & 0xF0
            if op == J_A:
                pc += 1 + k
            else:
                c = (X if code & SRC_X else k) & 0xFFFFFFFF
                if op == J_EQ: cond = A == c
                elif op == J_GT: cond = A > c
                elif op == J_GE: cond = A >= c
                elif op == J_SET: cond = bool(A & c)
                else: raise ValueError(f"JMP op {op:#x}")
                pc += 1 + (jt if cond else jf)
        elif cls == RET:
            return A if (code & 0x18) == 0x10 else k
        elif cls == MISC:
            if code & 0x80:
                A = X          # TXA
            else:
                X = A          # TAX
            pc += 1
        else:
            raise ValueError(f"class {cls:#x}")
    raise RuntimeError("VM did not terminate")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    blob = open(os.path.join(args.dist, "seccomp_policy.bpf"), "rb").read()
    prog = parse(blob)

    out = bytearray()
    nr = 0
    while True:
        ret = run(prog, nr)
        if (ret & SECCOMP_RET_ACTION) != SECCOMP_RET_ERRNO:
            break                      # default path -> end of the sequence
        out.append(ret & 0xFF)
        nr += 1
        if nr > 4096:
            break
    print(out.decode())


if __name__ == "__main__":
    main()
