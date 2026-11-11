#!/usr/bin/env python3
"""
rev_04 real solver.

Reads ONLY the ELF in dist/, finds the blob by MAGIC, and replays the
signal-handler state machine (trap op cycles SIGILL/SIGFPE/SIGSEGV by i%3),
inverting each handler's transform to recover the flag. No flag string, does
not read the flag file.

Usage: python solve.py [--dist ./dist]
"""
import argparse
import glob
import os
import sys

MAGIC = b"SIGTRAP4"


def rotl8(b, n):
    b &= 0xFF
    return ((b << n) | (b >> (8 - n))) & 0xFF


def rotr8(b, n):
    b &= 0xFF
    return ((b >> n) | (b << (8 - n))) & 0xFF


def solve(b):
    N = b[8] | (b[9] << 8)
    acc = b[10] | (b[11] << 8) | (b[12] << 16) | (b[13] << 24)
    target = b[14:14 + N]
    flag = bytearray(N)
    for i in range(N):
        k = (acc ^ (acc >> 7)) & 0xFF
        o = target[i]
        op = i % 3
        if op == 0:
            x = (((o - (acc & 7)) & 0xFF) ^ k) & 0xFF
        elif op == 1:
            x = rotr8(o ^ k, 3)
        else:
            x = (((o ^ 0x6D) + k) & 0xFF)
        flag[i] = x
        acc = (acc * 1103515245 + 12345 + o) & 0xFFFFFFFF
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
