#!/usr/bin/env python3
"""
Real solver for rev_06_wasm_bytecode_parser.

Reads ONLY dist/validator.wasm.  It locates the parameter+target blob stored in
the module's data segment (tagged by an 8-byte magic), reads N, SEED, MULT, ADD
and the TARGET bytes, then inverts the stack-machine transform the `validate`
function applies.

The per-byte transform (recovered from the wasm code) is, with a rolling 32-bit
`state` starting at SEED:
    t = in[i] XOR (state & 0xff)
    t = (t + ((state>>8) & 0xff)) & 0xff
    t = rotl8(t, (state>>16) & 7)             # compared to TARGET[i]
    state = (state*MULT + t + ADD) & 2**32    # advances from the OUTPUT byte t
Since `state` advances from the produced byte (== TARGET[i], which is stored),
the schedule replays forward while each byte is inverted:
    t = rotr8(TARGET[i], (state>>16)&7)
    t = (t - ((state>>8)&0xff)) & 0xff
    in[i] = t XOR (state & 0xff)

Contains no flag string and never reads the ./flag file.

Usage: python solve.py [--dist ./dist]
"""
import argparse
import glob
import os
import struct
import sys

MAGIC = b"W6VMBLOB"


def rotr8(v, r):
    r &= 7
    return v & 0xFF if r == 0 else ((v >> r) | (v << (8 - r))) & 0xFF


def parse_blob(data):
    idx = data.find(MAGIC)
    if idx < 0:
        raise SystemExit("MAGIC not found in module")
    b = data[idx:]
    N, SEED, MULT, ADD = struct.unpack_from("<IIII", b, 8)
    if not (0 < N < 4096):
        raise SystemExit("implausible N=%d" % N)
    target = b[24:24 + N]
    return N, SEED, MULT, ADD, target


def invert(target, SEED, MULT, ADD):
    state = SEED & 0xFFFFFFFF
    out = bytearray()
    for tv in target:
        t = rotr8(tv, (state >> 16) & 7)
        t = (t - ((state >> 8) & 0xFF)) & 0xFF
        out.append(t ^ (state & 0xFF))
        state = (state * MULT + tv + ADD) & 0xFFFFFFFF
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    cands = [p for p in glob.glob(os.path.join(args.dist, "*")) if os.path.isfile(p)]
    for p in cands:
        data = open(p, "rb").read()
        if MAGIC in data:
            N, SEED, MULT, ADD, target = parse_blob(data)
            flag = invert(target, SEED, MULT, ADD)
            sys.stdout.write(flag.decode("latin-1") + "\n")
            return
    raise SystemExit("no wasm module containing the blob found in %s" % args.dist)


if __name__ == "__main__":
    main()
