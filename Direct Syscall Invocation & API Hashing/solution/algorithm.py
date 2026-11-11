#!/usr/bin/env python3
"""
rev_02 real solver.

Reads ONLY the ELF in dist/, finds the embedded blob by MAGIC, rebuilds the
DJB2 API-hash keystream and inverts the transform to recover the flag.
No flag string, does not read the flag file.

Usage: python solve.py [--dist ./dist]
"""
import argparse
import glob
import os
import sys

MAGIC = b"D2SYSAPI"


def rd32(b, o):
    return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)


def rotl32(x, r):
    x &= 0xFFFFFFFF
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF


def ks_byte(i, state, seeds):
    s = seeds[i % 8]
    r = (i & 7) + 1
    m = (s ^ rotl32(state, r)) & 0xFFFFFFFF
    h = 5381
    for k in range(4):
        h = ((h << 5) + h + ((m >> (8 * k)) & 0xFF)) & 0xFFFFFFFF
    return (h ^ (h >> 16) ^ (h >> 24)) & 0xFF


def solve(b):
    N = b[8] | (b[9] << 8)
    STATE0 = rd32(b, 10)
    seeds = [rd32(b, 14 + 4 * j) for j in range(8)]
    target = b[46:46 + N]
    state = STATE0
    flag = bytearray(N)
    for i in range(N):
        k = ks_byte(i, state, seeds)
        o = target[i]
        flag[i] = (o ^ k) if (i & 1) else ((o - k) & 0xFF)
        state = (state * 33 + o) & 0xFFFFFFFF
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
