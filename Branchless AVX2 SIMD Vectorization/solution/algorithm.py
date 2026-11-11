#!/usr/bin/env python3
"""
Real solver for rev_09_branchless_avx2_simd_checker.

Reads ONLY the stripped ELF in dist/.  It finds the embedded parameter blob by
its 8-byte MAGIC, extracts the two pairs of nibble S-boxes, the per-lane
add/xor vectors, the blend mask and the TARGET, then inverts the position-wise
AVX2 byte bijection lane by lane (the transform never depends on the input
value, only on the lane = position mod 32, so it is directly invertible).

Contains no flag string and never reads the ./flag file.

Usage: python solve.py [--dist ./dist]
"""
import argparse
import glob
import os
import struct
import sys

MAGIC = b"AVX2SBX\x01"

OFF_N = 8
OFF_S0L = 12
OFF_S0H = 28
OFF_S1L = 44
OFF_S1H = 60
OFF_A0 = 76
OFF_X0 = 108
OFF_A1 = 140
OFF_X1 = 172
OFF_MASK = 204
OFF_TARGET = 236


def inv_perm(p):
    q = [0] * 16
    for i, v in enumerate(p):
        q[v] = i
    return q


def parse_blob(data):
    idx = data.find(MAGIC)
    if idx < 0:
        raise SystemExit("MAGIC not found in binary")
    b = data[idx:]
    N = struct.unpack_from("<I", b, OFF_N)[0]
    if not (0 < N < 4096):
        raise SystemExit("implausible N=%d" % N)
    blocks = (N + 31) // 32
    P = {}
    for name, off in (("S0L", OFF_S0L), ("S0H", OFF_S0H),
                      ("S1L", OFF_S1L), ("S1H", OFF_S1H)):
        P[name] = list(b[off:off + 16])
    for name, off in (("A0", OFF_A0), ("X0", OFF_X0),
                      ("A1", OFF_A1), ("X1", OFF_X1), ("MASK", OFF_MASK)):
        P[name] = list(b[off:off + 32])
    target = b[OFF_TARGET:OFF_TARGET + blocks * 32]
    return N, P, target


def invert_byte(o, j, P):
    if P["MASK"][j] & 0x80:
        SL, SH, A, X = P["S1L"], P["S1H"], P["A1"], P["X1"]
    else:
        SL, SH, A, X = P["S0L"], P["S0H"], P["A0"], P["X0"]
    iSL, iSH = inv_perm(SL), inv_perm(SH)
    y = o ^ X[j]
    y = (y - A[j]) & 0xFF
    return ((iSH[(y >> 4) & 0xF] << 4) | iSL[y & 0xF]) & 0xFF


def solve(data):
    N, P, target = parse_blob(data)
    out = bytes(invert_byte(target[i], i % 32, P) for i in range(N))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    cands = [p for p in glob.glob(os.path.join(args.dist, "*")) if os.path.isfile(p)]
    for p in cands:
        data = open(p, "rb").read()
        if MAGIC in data:
            flag = solve(data)
            sys.stdout.write(flag.decode("latin-1") + "\n")
            return
    raise SystemExit("no artifact containing the blob found in %s" % args.dist)


if __name__ == "__main__":
    main()
