#!/usr/bin/env python3
"""
Real solver for crypto_07_hill_cipher_known_plaintext.

Reads ONLY dist/ (default ./dist):
  - intercepted_hill.txt  : the 3x3 Hill ciphertext (A-Z)
  - intelligence_note.txt : the known plaintext header
  - flag_vault.json       : AES-GCM sealed flag + sealing recipe

Attack (Hill known-plaintext): align known plaintext/ciphertext blocks, find
three blocks whose plaintext matrix P is invertible mod 26, compute the key
K = C * P^{-1} (mod 26), then derive the AES key from K and decrypt the flag.

This script does not contain the flag and never reads the ./flag file.
"""
import argparse
import hashlib
import itertools
import json
import os
from math import gcd

from Crypto.Cipher import AES

M = 26
TAG = b"zsctf-hill"


def det3(a):
    return (a[0][0] * (a[1][1] * a[2][2] - a[1][2] * a[2][1])
            - a[0][1] * (a[1][0] * a[2][2] - a[1][2] * a[2][0])
            + a[0][2] * (a[1][0] * a[2][1] - a[1][1] * a[2][0])) % M


def inv3(a):
    di = pow(det3(a), -1, M)
    cof = [
        [(a[1][1] * a[2][2] - a[1][2] * a[2][1]), -(a[0][1] * a[2][2] - a[0][2] * a[2][1]), (a[0][1] * a[1][2] - a[0][2] * a[1][1])],
        [-(a[1][0] * a[2][2] - a[1][2] * a[2][0]), (a[0][0] * a[2][2] - a[0][2] * a[2][0]), -(a[0][0] * a[1][2] - a[0][2] * a[1][0])],
        [(a[1][0] * a[2][1] - a[1][1] * a[2][0]), -(a[0][0] * a[2][1] - a[0][1] * a[2][0]), (a[0][0] * a[1][1] - a[0][1] * a[1][0])],
    ]
    return [[(cof[i][j] * di) % M for j in range(3)] for i in range(3)]


def matmul(a, b):
    return [[sum(a[i][k] * b[k][j] for k in range(3)) % M for j in range(len(b[0]))] for i in range(len(a))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()

    with open(os.path.join(args.dist, "intercepted_hill.txt"), "r", encoding="utf-8") as f:
        ct = f.read().strip()
    with open(os.path.join(args.dist, "intelligence_note.txt"), "r", encoding="utf-8") as f:
        note = f.read()
    with open(os.path.join(args.dist, "flag_vault.json"), "r", encoding="utf-8") as f:
        blob = bytes.fromhex(json.load(f)["sealed_flag_hex"])

    header = note.split("'")[1]  # text between the single quotes
    hnums = [ord(c) - 65 for c in header]
    cnums = [ord(c) - 65 for c in ct[:len(header)]]
    nblk = len(header) // 3
    pblk = [[hnums[3 * b + r] for r in range(3)] for b in range(nblk)]
    cblk = [[cnums[3 * b + r] for r in range(3)] for b in range(nblk)]

    K = None
    for a, b, c in itertools.combinations(range(nblk), 3):
        P = [[pblk[a][r], pblk[b][r], pblk[c][r]] for r in range(3)]
        if gcd(det3(P), M) != 1:
            continue
        C = [[cblk[a][r], cblk[b][r], cblk[c][r]] for r in range(3)]
        K = matmul(C, inv3(P))
        break
    assert K is not None, "no invertible plaintext block triple found"

    kbytes = bytes(K[i][j] % M for i in range(3) for j in range(3))
    key = hashlib.sha256(TAG + b"|key|" + kbytes).digest()
    nonce, c2, tag = blob[:12], blob[12:-16], blob[-16:]
    flag = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(c2, tag)
    print(flag.decode())


if __name__ == "__main__":
    main()
