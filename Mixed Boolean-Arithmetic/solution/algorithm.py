#!/usr/bin/env python3
"""
rev_05 real solver.

Reads ONLY the ELF in dist/, finds the blob by MAGIC. The MBA mess simplifies to
two affine byte maps around a linear diffusion chain; the solver inverts them
(modular inverse of the odd multipliers + chain unwind) to recover the flag.
No flag string, does not read the flag file.

Usage: python solve.py [--dist ./dist]
"""
import argparse
import glob
import os
import sys


MAGIC = b"MBALIN05"


def inv_mod256(a):
    # a must be odd; extended Euclid
    for t in range(256):
        if (a * t) & 0xFF == 1:
            return t
    raise ValueError("no inverse for %d mod 256" % a)


def solve(b):
    N = b[8] | (b[9] << 8)
    A, B, A2, B2, IV = b[10], b[11], b[12], b[13], b[14]
    target = b[15:15 + N]
    Ai = inv_mod256(A)
    A2i = inv_mod256(A2)
    prev = IV
    flag = bytearray(N)
    for i in range(N):
        o = target[i]
        c = (A2i * ((o - B2) & 0xFF)) & 0xFF   # invert affine layer 2
        m = (c - prev) & 0xFF                   # invert diffusion chain
        prev = m
        x = (Ai * ((m - B) & 0xFF)) & 0xFF      # invert affine layer 1
        flag[i] = x
    return bytes(flag)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    for p in glob.glob(os.path.join(args.dist, "*")):
        if not os.path.isfile(p):
            continue
        data = open(p, "rb").read()
        idx = data.find(MAGIC)
        if idx >= 0:
            sys.stdout.write(solve(data[idx:]).decode("latin-1") + "\n")
            return
    raise SystemExit("blob not found in %s" % args.dist)


if __name__ == "__main__":
    main()
