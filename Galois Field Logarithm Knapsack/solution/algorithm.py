#!/usr/bin/env python3
"""
Real solver for crypto_13_knapsack_chor_rivest.

Reads ONLY dist/field_params.json (default ./dist): p, nr (so GF(p^2) =
GF(p)[t]/(t^2 - nr)), generator g, and y = g^x. The group order p^2-1 is smooth;
the solver factors it (trial division + Pollard rho), runs Pohlig-Hellman
(per-prime-power BSGS + CRT) over GF(p^2) to recover x, then AES-GCM-decrypts the
flag with a key derived from x.

This script does not contain the flag and never reads the ./flag file.
"""
import argparse
import hashlib
import json
import math
import os
import random

from Crypto.Cipher import AES

TAG = b"zsctf-chorrivest"


def is_prime(m):
    if m < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if m % sp == 0:
            return m == sp
    d = m - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, m)
        if x in (1, m - 1):
            continue
        for _ in range(s - 1):
            x = x * x % m
            if x == m - 1:
                break
        else:
            return False
    return True


def factor(n):
    f = {}
    d = 2
    while d * d <= n and d < (1 << 20):
        while n % d == 0:
            f[d] = f.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2

    def rho(m):
        if m % 2 == 0:
            return 2
        while True:
            c = random.randrange(1, m)
            x = random.randrange(2, m)
            y = x
            g = 1
            while g == 1:
                x = (x * x + c) % m
                y = (y * y + c) % m
                y = (y * y + c) % m
                g = math.gcd(abs(x - y), m)
            if g != m:
                return g

    stack = [n] if n > 1 else []
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if is_prime(m):
            f[m] = f.get(m, 0) + 1
            continue
        dd = rho(m)
        stack.append(dd)
        stack.append(m // dd)
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()

    with open(os.path.join(args.dist, "field_params.json"), "r", encoding="utf-8") as f:
        D = json.load(f)
    p = int(D["p"])
    nr = int(D["nr"])
    g = (int(D["g"][0]), int(D["g"][1]))
    y = (int(D["y"][0]), int(D["y"][1]))
    blob = bytes.fromhex(D["sealed_flag_hex"])
    N = p * p - 1

    def mul(a, b):
        a0, a1 = a
        b0, b1 = b
        return ((a0 * b0 + a1 * b1 * nr) % p, (a0 * b1 + a1 * b0) % p)

    ONE = (1, 0)

    def powg(x, e):
        r = ONE
        while e:
            if e & 1:
                r = mul(r, x)
            x = mul(x, x)
            e >>= 1
        return r

    def inv_elt(z):
        return powg(z, N - 1)

    def bsgs_sub(base, target, order):
        m = math.isqrt(order) + 1
        table = {}
        cur = ONE
        for j in range(m):
            table.setdefault(cur, j)
            cur = mul(cur, base)
        binv_m = powg(powg(base, order - 1), m)
        gamma = target
        for i in range(m):
            j = table.get(gamma)
            if j is not None:
                return i * m + j
            gamma = mul(gamma, binv_m)
        return None

    FACT = factor(N)
    res, mod = [], []
    for q, e in FACT.items():
        qe = q ** e
        gi = powg(g, N // qe)
        hi = powg(y, N // qe)
        xk = 0
        base_q = powg(gi, qe // q)
        for k in range(e):
            tmp = mul(hi, inv_elt(powg(gi, xk)))
            hk = powg(tmp, qe // (q ** (k + 1)))
            dk = bsgs_sub(base_q, hk, q)
            if dk is None:
                raise SystemExit("BSGS failed in a subgroup")
            xk += dk * (q ** k)
        res.append(xk)
        mod.append(qe)

    M = 1
    for m_ in mod:
        M *= m_
    x = 0
    for r, m_ in zip(res, mod):
        Mi = M // m_
        x += r * Mi * pow(Mi, -1, m_)
    x %= M
    assert powg(g, x) == y, "recovered x does not satisfy g^x = y"

    key = hashlib.sha256(TAG + b"|key|" + str(x).encode()).digest()
    flag = AES.new(key, AES.MODE_GCM, nonce=blob[:12]).decrypt_and_verify(blob[12:-16], blob[-16:])
    print(flag.decode())


if __name__ == "__main__":
    main()
