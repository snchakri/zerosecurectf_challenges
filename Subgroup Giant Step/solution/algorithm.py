#!/usr/bin/env python3
"""
Real solver for crypto_08_discrete_log_baby_step_giant_step.

Reads ONLY dist/dlog_params.json (default ./dist): p, g, h, subgroup_order q,
and the AES-GCM sealed flag. Recovers x = log_g(h) in the order-q subgroup via
baby-step/giant-step, then derives the AES key from x and decrypts the flag.

This script does not contain the flag and never reads the ./flag file.
"""
import argparse
import hashlib
import json
import math
import os

from Crypto.Cipher import AES

TAG = b"zsctf-dlog"


def bsgs(g, h, p, order):
    m = math.isqrt(order) + 1
    table = {}
    cur = 1
    for j in range(m):
        if cur not in table:
            table[cur] = j
        cur = (cur * g) % p
    ginv_m = pow(pow(g, m, p), p - 2, p)  # (g^m)^(-1) mod p, p prime
    gamma = h
    for i in range(m):
        j = table.get(gamma)
        if j is not None:
            return i * m + j
        gamma = (gamma * ginv_m) % p
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()

    with open(os.path.join(args.dist, "dlog_params.json"), "r", encoding="utf-8") as f:
        P = json.load(f)
    p, g, h, q = int(P["p"]), int(P["g"]), int(P["h"]), int(P["subgroup_order"])
    blob = bytes.fromhex(P["sealed_flag_hex"])

    x = bsgs(g, h, p, q)
    assert x is not None and pow(g, x, p) == h, "discrete log not found"

    key = hashlib.sha256(TAG + b"|key|" + str(x).encode()).digest()
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    flag = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    print(flag.decode())


if __name__ == "__main__":
    main()
