#!/usr/bin/env python3
"""
Real solver for rev_07_cellular_automata_rule30.

Reads ONLY dist/checker.pyc.  It pulls the embedded FINAL row and the
RIGHT-EDGE integrity column out of the marshalled bytecode, then runs Wolfram
Rule 30 *backwards*: because Rule 30 (new[i] = left XOR (center OR right))
moves information strictly leftward, the full next row plus the single
rightmost cell of a row uniquely determine that row.  Iterating the reversal
G times walks the lattice back to its seed row, whose bits are the flag.

This script contains no flag string and never reads the ./flag file.

Usage: python solve.py [--dist ./dist]
"""
import argparse
import marshal
import os


def load_consts(pyc_path):
    with open(pyc_path, "rb") as f:
        f.read(16)  # 3.7+ header: magic(4) + bitfield(4) + 8 bytes
        code = marshal.loads(f.read())
    found = []

    def walk(co):
        for c in co.co_consts:
            if hasattr(c, "co_consts"):
                walk(c)
            else:
                found.append(c)

    walk(code)
    return found


def recover_blobs(pyc_path):
    consts = load_consts(pyc_path)
    byte_consts = sorted(
        {bytes(c) for c in consts if isinstance(c, (bytes, bytearray))},
        key=len,
        reverse=True,
    )
    if len(byte_consts) < 2:
        raise SystemExit("expected two packed blobs in the bytecode")
    final_b = byte_consts[0]          # longest  -> final row (N bits)
    redge_b = byte_consts[1]          # 2nd      -> right-edge column (G bits)
    return final_b, redge_b


def unpack(bs, nbits):
    bits = []
    for b in bs:
        for k in range(7, -1, -1):
            bits.append((b >> k) & 1)
    return bits[:nbits]


def pack(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for k in range(8):
            v = (v << 1) | (bits[i + k] if i + k < len(bits) else 0)
        out.append(v)
    return bytes(out)


def unstep(nxt, rightmost):
    n = len(nxt)
    cur = [0] * n
    cur[n - 1] = rightmost
    for j in range(n - 2, -1, -1):
        cur[j] = nxt[j + 1] ^ (cur[j + 1] | (cur[j + 2] if j + 2 < n else 0))
    return cur


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    pyc = os.path.join(args.dist, "checker.pyc")
    final_b, redge_b = recover_blobs(pyc)

    N = 8 * len(final_b)              # cells = flag bits (flag is whole bytes)
    G = 8 * len(redge_b)             # generations (G chosen a multiple of 8)
    final = unpack(final_b, N)
    redge = unpack(redge_b, G)

    row = final
    for t in range(G - 1, -1, -1):
        row = unstep(row, redge[t])

    flag = pack(row)
    print(flag.decode("latin-1"))


if __name__ == "__main__":
    main()
