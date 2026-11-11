#!/usr/bin/env python3
"""
Real solver for crypto_09_knapsack_merkle_hellman.

Reads ONLY dist/knapsack_pubkey.json (default ./dist): the Merkle-Hellman public
key `b` (96 entries), the ciphertext list, and `msg_len`. For each ciphertext it
solves the low-density subset-sum with a lattice attack (CJLOSS, with a
Lagarias-Odlyzko fallback), using a self-contained integer LLL. The recovered
0/1 vectors are the message bits; reassembled, the first msg_len bytes are the
flag.

This script does not contain the flag and never reads the ./flag file.
"""
import argparse
import json
import os
from fractions import Fraction


def lll_int(mat, delta=Fraction(3, 4)):
    n = len(mat); m = len(mat[0])
    b = [None] + [list(map(int, row)) for row in mat]
    lam = [[0] * (n + 1) for _ in range(n + 1)]
    d = [0] * (n + 1); d[0] = 1

    def dot(i, j):
        return sum(b[i][t] * b[j][t] for t in range(m))

    def RED(k, l):
        if 2 * abs(lam[k][l]) <= d[l]:
            return
        q = int(round(Fraction(lam[k][l], d[l])))
        bk = b[k]; bl = b[l]
        for t in range(m):
            bk[t] -= q * bl[t]
        lam[k][l] -= q * d[l]
        for i in range(1, l):
            lam[k][i] -= q * lam[l][i]

    d[1] = dot(1, 1); k = 2; kmax = 1
    dn, dd = delta.numerator, delta.denominator
    while k <= n:
        if k > kmax:
            kmax = k
            for j in range(1, k + 1):
                u = dot(k, j)
                for i in range(1, j):
                    u = (d[i] * u - lam[k][i] * lam[j][i]) // d[i - 1]
                if j < k:
                    lam[k][j] = u
                else:
                    d[k] = u
        while True:
            RED(k, k - 1)
            if d[k] * d[k - 2] * dd < dn * d[k - 1] * d[k - 1] - dd * lam[k][k - 1] * lam[k][k - 1]:
                lv = lam[k][k - 1]
                b[k], b[k - 1] = b[k - 1], b[k]
                if k > 2:
                    for j in range(1, k - 1):
                        lam[k][j], lam[k - 1][j] = lam[k - 1][j], lam[k][j]
                B = (d[k - 2] * d[k] + lv * lv) // d[k - 1]
                for i in range(k + 1, kmax + 1):
                    t = lam[i][k]
                    lam[i][k] = (d[k] * lam[i][k - 1] - lv * t) // d[k - 1]
                    lam[i][k - 1] = (B * t + lv * lam[i][k]) // d[k]
                d[k - 1] = B
                if k > 2:
                    k -= 1
                if k == 2:
                    continue
            else:
                for l in range(k - 2, 0, -1):
                    RED(k, l)
                k += 1
                break
    return [b[i] for i in range(1, n + 1)]


def attack(pub, C):
    n = len(pub)
    # CJLOSS centred lattice (handles density up to ~0.94)
    basis = [[0] * (n + 1) for _ in range(n + 1)]
    for i in range(n):
        basis[i][i] = 2
        basis[i][n] = pub[i]
    for i in range(n):
        basis[n][i] = 1
    basis[n][n] = C
    for row in lll_int(basis):
        for sgn in (1, -1):
            cand = []
            ok = True
            for i in range(n):
                e = sgn * row[i]
                if e == 1:
                    cand.append(1)
                elif e == -1:
                    cand.append(0)
                else:
                    ok = False
                    break
            if ok and sum(cand[i] * pub[i] for i in range(n)) == C:
                return cand
    # Lagarias-Odlyzko fallback
    basis = [[0] * (n + 1) for _ in range(n + 1)]
    for i in range(n):
        basis[i][i] = 1
        basis[i][n] = pub[i]
    basis[n][n] = C
    for row in lll_int(basis):
        for sgn in (1, -1):
            cand = [sgn * v for v in row[:n]]
            if all(v in (0, 1) for v in cand) and sum(cand[i] * pub[i] for i in range(n)) == C:
                return cand
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()

    with open(os.path.join(args.dist, "knapsack_pubkey.json"), "r", encoding="utf-8") as f:
        D = json.load(f)
    b = [int(x) for x in D["public_key"]]
    cts = [int(x) for x in D["ciphertexts"]]
    msg_len = int(D["msg_len"])

    bits = []
    for c in cts:
        rec = attack(b, c)
        if rec is None:
            raise SystemExit("lattice attack failed on a block")
        bits.extend(rec)

    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for t in range(8):
            byte = (byte << 1) | bits[i + t]
        out.append(byte)
    print(bytes(out[:msg_len]).decode())


if __name__ == "__main__":
    main()
