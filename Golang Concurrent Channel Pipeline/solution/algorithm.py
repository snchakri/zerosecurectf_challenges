#!/usr/bin/env python3
"""
rev_03 real solver.

Reads ONLY the ELF in dist/, finds the blob by MAGIC, and inverts the 4-stage
channel pipeline in reverse order to recover the flag. No flag string, does not
read the flag file.

Usage: python solve.py [--dist ./dist]
"""
import argparse
import glob
import os
import sys

MAGIC = b"GOCHANv1"


def rotl8(b, n):
    b &= 0xFF
    return ((b << n) | (b >> (8 - n))) & 0xFF


def rotr8(b, n):
    b &= 0xFF
    return ((b >> n) | (b << (8 - n))) & 0xFF


def solve(b):
    N = b[8] | (b[9] << 8)
    KLEN = b[10]
    K = b[11:11 + KLEN]
    target = list(b[11 + KLEN:11 + KLEN + N])

    # inv stage4: running-difference accumulator
    s3 = []
    run = 0
    for y in target:
        x = (y + run) & 0xFF
        s3.append(x)
        run = (run + x) & 0xFF
    # inv stage3: rotl8(x,3) ^ 0x3C
    s2 = [rotr8(y ^ 0x3C, 3) for y in s3]
    # inv stage2: keyed xor
    s1 = [y ^ K[i % KLEN] for i, y in enumerate(s2)]
    # inv stage1: additive position ramp
    flag = bytes([(y - ((i * 37 + 11) & 0xFF)) & 0xFF for i, y in enumerate(s1)])
    return flag


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
