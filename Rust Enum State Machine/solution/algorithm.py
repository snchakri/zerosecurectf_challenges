#!/usr/bin/env python3
"""
rev_01 real solver.

Reads ONLY the stripped ELF in dist/, locates the embedded parameter+target
blob by its MAGIC, and inverts the two-pass Rust-enum state machine to recover
the flag. Does not read the flag file and contains no flag string.

Usage: python solve.py [--dist ./dist]
"""
import argparse
import glob
import os
import sys

MAGIC = b"R1STMVM\x01"


def rotl8(b, n):
    b &= 0xFF
    return ((b << n) | (b >> (8 - n))) & 0xFF


def rotr8(b, n):
    b &= 0xFF
    return ((b >> n) | (b << (8 - n))) & 0xFF


def find_blob(data):
    idx = data.find(MAGIC)
    if idx < 0:
        raise SystemExit("MAGIC not found in binary")
    return idx


def solve(blob_bytes):
    b = blob_bytes
    N = b[8] | (b[9] << 8)
    SEED = b[10] | (b[11] << 8) | (b[12] << 16) | (b[13] << 24)
    IV8 = b[14]
    TRANS = b[15:15 + 25]
    TARGET = b[40:40 + N]

    # invert pass 2 (CBC-style chain): out[i] = mid[i] ^ prev ; prev = out[i]
    mid = [0] * N
    prev = IV8
    for i in range(N):
        mid[i] = TARGET[i] ^ prev
        prev = TARGET[i]

    # invert pass 1 (enum FSM). State + key evolve from mid[] (known), so we
    # replay them forward and invert each variant's transform.
    state = 0
    acc = SEED & 0xFFFFFFFF
    flag = bytearray(N)
    for i in range(N):
        key = (acc ^ (acc >> 11) ^ ((acc << 7) & 0xFFFFFFFF)) & 0xFF
        t = mid[i]
        if state == 0:
            x = (t - key) & 0xFF
        elif state == 1:
            x = t ^ key
        elif state == 2:
            x = rotr8((t - key) & 0xFF, 3)
        elif state == 3:
            x = ((t + key) & 0xFF) ^ 0x5A
        else:
            x = rotl8(t ^ key, 2)
        flag[i] = x
        acc = (acc * 1664525 + 1013904223 + t) & 0xFFFFFFFF
        state = TRANS[state * 5 + (t % 5)]
    return bytes(flag)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    cands = [p for p in glob.glob(os.path.join(args.dist, "*")) if os.path.isfile(p)]
    for p in cands:
        data = open(p, "rb").read()
        if MAGIC in data:
            idx = find_blob(data)
            flag = solve(data[idx:])
            sys.stdout.write(flag.decode("latin-1") + "\n")
            return
    raise SystemExit("no binary containing the blob found in %s" % args.dist)


if __name__ == "__main__":
    main()
