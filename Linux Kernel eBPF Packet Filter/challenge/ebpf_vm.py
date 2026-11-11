#!/usr/bin/env python3
"""
Minimal eBPF interpreter for rev_08_ebpf_packet_filter_bytecode.

There is no bpftool in the challenge sandbox, so this is a small, faithful
emulator for the subset of the eBPF ISA used by dist/filter.bpf.  Instructions
are the standard 8-byte encoding:

    struct bpf_insn { u8 code; u8 regs(=src<<4|dst); s16 off; s32 imm; }   (LE)

Calling convention (harness ABI):
    R1 -> ctx, a 16-byte struct:  u64 data at +0, u64 data_end at +8
    data .. data_end is the packet (the candidate key bytes).
    Program returns an XDP action in R0:  1 = XDP_DROP (reject),
    2 = XDP_PASS (accept).

Run:  python ebpf_vm.py '<candidate-key>'    # or pipe the candidate on stdin
"""
import os
import struct
import sys

# opcode classes / ops actually used by filter.bpf
LDX_DW, LDX_B = 0x79, 0x71
MOV64_R, MOV64_I, SUB64_R = 0xbf, 0xb7, 0x1f
MOV32_R, MOV32_I = 0xbc, 0xb4
AND32_I, XOR32_R, RSH32_I = 0x54, 0xac, 0x74
ADD32_R, ADD32_I, MUL32_I = 0x0c, 0x04, 0x24
JNE_I, EXIT = 0x55, 0x95

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


def decode(code):
    n = len(code) // 8
    return [struct.unpack_from("<BBhi", code, 8 * k) for k in range(n)]


def _imm64(imm):
    return imm & M64  # struct already returned signed; mask to 64-bit two's complement


def run(code, packet, max_steps=50_000_000):
    ins = decode(code)
    mem = {}

    def w8(a, v):
        mem[a & M64] = v & 0xFF

    def r8(a):
        return mem.get(a & M64, 0)

    def w64(a, v):
        for i in range(8):
            mem[(a + i) & M64] = (v >> (8 * i)) & 0xFF

    def r64(a):
        v = 0
        for i in range(8):
            v |= mem.get((a + i) & M64, 0) << (8 * i)
        return v

    DATA, CTX, STACK = 0x100000, 0x200000, 0x300000
    for i, b in enumerate(packet):
        w8(DATA + i, b)
    w64(CTX + 0, DATA)
    w64(CTX + 8, DATA + len(packet))

    R = [0] * 11
    R[1] = CTX
    R[10] = STACK
    pc = 0
    steps = 0
    while True:
        steps += 1
        if steps > max_steps:
            raise RuntimeError("runaway program")
        c, regs, off, imm = ins[pc]
        dst, src = regs & 0xF, (regs >> 4) & 0xF
        npc = pc + 1
        if c == LDX_DW:
            R[dst] = r64((R[src] + off) & M64)
        elif c == LDX_B:
            R[dst] = r8((R[src] + off) & M64)
        elif c == MOV64_R:
            R[dst] = R[src] & M64
        elif c == MOV64_I:
            R[dst] = _imm64(imm)
        elif c == SUB64_R:
            R[dst] = (R[dst] - R[src]) & M64
        elif c == MOV32_R:
            R[dst] = R[src] & M32
        elif c == MOV32_I:
            R[dst] = imm & M32
        elif c == AND32_I:
            R[dst] = (R[dst] & (imm & M32)) & M32
        elif c == XOR32_R:
            R[dst] = (R[dst] ^ R[src]) & M32
        elif c == RSH32_I:
            R[dst] = (R[dst] & M32) >> (imm & 31)
        elif c == ADD32_R:
            R[dst] = (R[dst] + R[src]) & M32
        elif c == ADD32_I:
            R[dst] = (R[dst] + (imm & M32)) & M32
        elif c == MUL32_I:
            R[dst] = (R[dst] * (imm & M32)) & M32
        elif c == JNE_I:
            if (R[dst] & M64) != _imm64(imm):
                npc = pc + 1 + off
        elif c == EXIT:
            return R[0]
        else:
            raise RuntimeError("unsupported opcode 0x%02x at insn %d" % (c, pc))
        pc = npc


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    code = open(os.path.join(here, "filter.bpf"), "rb").read()
    if len(sys.argv) > 1:
        pkt = sys.argv[1].encode("latin-1", "ignore")
    else:
        pkt = sys.stdin.buffer.read()
    while pkt and pkt[-1:] in (b"\n", b"\r"):
        pkt = pkt[:-1]
    rc = run(code, pkt)
    if rc == 2:
        print("ACCEPTED: packet passes the filter (XDP_PASS).")
        return 0
    print("REJECTED (XDP_DROP).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
