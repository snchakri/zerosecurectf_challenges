#!/usr/bin/env python3
"""
Real solver for crypto_06_poly1305_nonce_reuse.

Reads ONLY dist/mac_transmissions.json (default ./dist). Exploits the reused
one-time key (r, s) across two two-block messages: the tag difference is a
quadratic in r, so solve it mod p, recover (r, s), forge the tag of the target
admin message, and use that forged tag to key the AES-GCM seal over the flag.

This script does not contain the flag and never reads the ./flag file.
"""
import argparse
import hashlib
import json
import os

from Crypto.Cipher import AES

TAG = b"zsctf-poly1305"


def blocks(m):
    return [int.from_bytes(m[i:i + 16], "big") for i in range(0, len(m), 16)]


def mac(m, r, s, p):
    acc = 0
    for c in blocks(m):
        acc = (acc + c) * r % p
    return (acc + s) % p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()

    with open(os.path.join(args.dist, "mac_transmissions.json"), "r", encoding="utf-8") as f:
        D = json.load(f)
    p = int(D["p"])
    m1, m2 = bytes.fromhex(D["m1_hex"]), bytes.fromhex(D["m2_hex"])
    t1, t2 = int(D["tag1"]), int(D["tag2"])
    target = bytes.fromhex(D["target_hex"])
    blob = bytes.fromhex(D["sealed_flag_hex"])

    a, b = blocks(m1), blocks(m2)
    # (a0-b0) r^2 + (a1-b1) r - (t1-t2) = 0  (mod p)
    A = (a[0] - b[0]) % p
    B = (a[1] - b[1]) % p
    C = (-(t1 - t2)) % p
    disc = (B * B - 4 * A * C) % p
    sd = pow(disc, (p + 1) // 4, p)   # p = 2^130-5 is 3 mod 4
    assert sd * sd % p == disc, "discriminant is not a quadratic residue"
    inv2A = pow(2 * A % p, -1, p)

    for rc in (((-B + sd) * inv2A) % p, ((-B - sd) * inv2A) % p):
        sc = (t1 - (a[0] * rc * rc + a[1] * rc)) % p
        forged = mac(target, rc, sc, p)
        key = hashlib.sha256(TAG + b"|key|" + str(forged).encode()).digest()
        nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
        try:
            flag = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
        except Exception:
            continue
        print(flag.decode())
        return
    raise SystemExit("failed to recover key")


if __name__ == "__main__":
    main()
