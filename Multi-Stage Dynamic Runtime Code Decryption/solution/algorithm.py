#!/usr/bin/env python3
"""
Real solver for rev_13_dynamic_code_decryption_stages.

Reads ONLY the ELF in dist/ (default --dist ./dist). It locates the
magic-delimited staged image (Z5STG_v1 .. Z5STGEND), then reproduces the
runtime key chain that the loader performs across its three stages:

  stage1: T2 = STAGE2_ENC XOR key1
  stage2: seed2 = FNV-1a32(T2);  LCG keystream -> streamA, streamB
  stage3: TARGET = STAGE3_ENC XOR streamB
  recover: flag[i] = TARGET[i] XOR T2[i%32] XOR streamA[i]

Does not contain the flag and never reads the `flag` file.
"""
import argparse
import glob
import os
import struct

MAGIC = b"Z5STG_v1"
MAGICEND = b"Z5STGEND"


def fnv1a32(data):
    h = 2166136261
    for b in data:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def lcg_stream(seed, count):
    s = seed & 0xFFFFFFFF
    out = bytearray()
    for _ in range(count):
        s = (s * 1664525 + 1013904223) & 0xFFFFFFFF
        out.append((s >> 24) & 0xFF)
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()

    data = None
    for p in glob.glob(os.path.join(args.dist, "*")):
        if os.path.isfile(p):
            d = open(p, "rb").read()
            if MAGIC in d:
                data = d
                break
    assert data is not None, "staged image not found in dist/"

    i = data.index(MAGIC)
    off = i + 8
    (n,) = struct.unpack_from("<H", data, off); off += 2
    key1 = data[off]; off += 1
    stage2_enc = data[off:off + 32]; off += 32
    stage3_enc = data[off:off + n]; off += n
    assert data[off:off + 8] == MAGICEND, "image end marker mismatch"

    t2 = bytes((b ^ key1) & 0xFF for b in stage2_enc)
    seed2 = fnv1a32(t2)
    stream = lcg_stream(seed2, 2 * n)
    streamA, streamB = stream[:n], stream[n:]
    target = bytes((stage3_enc[i] ^ streamB[i]) & 0xFF for i in range(n))
    flag = bytes((target[i] ^ t2[i % 32] ^ streamA[i]) & 0xFF for i in range(n))
    print(flag.decode())


if __name__ == "__main__":
    main()
