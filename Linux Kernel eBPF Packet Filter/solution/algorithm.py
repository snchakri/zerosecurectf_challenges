#!/usr/bin/env python3
"""
Real solver for rev_08_ebpf_packet_filter_bytecode.

Reads ONLY dist/filter.bpf.  It decodes the 8-byte eBPF instructions, reads out
the feedback constants (SEED, MULT, ADD), the required length N, and the
per-byte comparison immediates (the TARGET the filter checks each transformed
byte against), then inverts the rolling-key transform in one pass.

The per-byte transform the filter computes is:
    kx    = state & 0xff
    ka    = (state >> 8) & 0xff
    out   = ((in ^ kx) + ka) & 0xff           # compared to TARGET[i]
    state = (state * MULT + out + ADD) & 2**32 # advances from the OUTPUT byte
Because `state` advances from the produced byte (== TARGET[i], which we hold),
the schedule can be replayed forward while inverting each byte:
    in = ((TARGET[i] - ka) & 0xff) ^ kx

Contains no flag string and never reads the ./flag file.

Usage: python solve.py [--dist ./dist]
"""
import argparse
import os
import struct

LDX_B = 0x71
MOV32_I = 0xb4
ADD32_I = 0x04
MUL32_I = 0x24
JNE_I = 0x55
R0, R4, R6 = 0, 4, 6


def decode(code):
    return [struct.unpack_from("<BBhi", code, 8 * k) for k in range(len(code) // 8)]


def extract(code):
    ins = decode(code)
    seed = mult = add = N = None
    target = []
    for c, regs, off, imm in ins:
        dst = regs & 0xF
        u32 = imm & 0xFFFFFFFF
        if c == MOV32_I and dst == R6 and seed is None:
            seed = u32                      # initial state load
        elif c == MUL32_I and dst == R6:
            mult = u32                      # state *= MULT
        elif c == ADD32_I and dst == R6:
            add = u32                       # state += ADD
        elif c == JNE_I and dst == R4 and N is None:
            N = u32                         # length guard
        elif c == JNE_I and dst == R0:
            target.append(imm & 0xFF)       # per-byte compare immediate
    if None in (seed, mult, add):
        raise SystemExit("could not recover feedback constants from bytecode")
    if N is not None:
        target = target[:N]
    return seed, mult, add, bytes(target)


def invert(target, seed, mult, add):
    state = seed & 0xFFFFFFFF
    out = bytearray()
    for tv in target:
        kx = state & 0xFF
        ka = (state >> 8) & 0xFF
        out.append(((tv - ka) & 0xFF) ^ kx)
        state = (state * mult + tv + add) & 0xFFFFFFFF
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    code = open(os.path.join(args.dist, "filter.bpf"), "rb").read()
    seed, mult, add, target = extract(code)
    flag = invert(target, seed, mult, add)
    print(flag.decode("latin-1"))


if __name__ == "__main__":
    main()
