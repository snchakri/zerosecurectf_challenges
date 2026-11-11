#!/usr/bin/env python3
"""
Real solver for crypto_11_coppersmith_short_pad.

Reads ONLY dist/stereotyped_rsa.json (default ./dist): n, e, c, known_prefix,
secret_len. The RSA plaintext is M = known_prefix || unknown (secret_len bytes),
with c = M^e mod n and e=3. Recovers `unknown` as the small root of
    f(x) = (A + x)^e - c  (mod n),  A = int(known_prefix) << (8*secret_len)
using Coppersmith's method (Howgrave-Graham shift polynomials + a self-contained
LLL), then prints the zerosecure{...} substring of known_prefix||unknown.

This script does not contain the flag and never reads the ./flag file.
"""
import argparse
import json
import os
from fractions import Fraction

import mpmath


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


def pmul(a, b):
    r = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                r[i + j] += x * y
    return r


def ppow(a, e):
    r = [1]
    for _ in range(e):
        r = pmul(r, a)
    return r


def int_roots(q, X):
    while q and q[-1] == 0:
        q.pop()
    if len(q) <= 1:
        return []

    def ev(x):
        s = 0
        for c in reversed(q):
            s = s * x + c
        return s
    maxbits = max(abs(c).bit_length() for c in q)
    mpmath.mp.prec = maxbits + 200
    coeffs = [mpmath.mpf(c) for c in reversed(q)]
    try:
        rts = mpmath.polyroots(coeffs, maxsteps=300, extraprec=maxbits + 200)
    except Exception:
        return []
    out = []
    for rt in rts:
        if abs(mpmath.im(rt)) < mpmath.mpf(10) ** (-20):
            xr = int(mpmath.nint(mpmath.re(rt)))
            for cand in (xr - 1, xr, xr + 1):
                if 0 <= cand <= X and ev(cand) == 0:
                    out.append(cand)
    return out


def coppersmith(fpoly, N, X, m, t):
    d = len(fpoly) - 1
    dim = d * m + t
    polys = []
    for i in range(m):
        fi = ppow(fpoly, i)
        for j in range(d):
            polys.append([0] * j + [c * (N ** (m - i)) for c in fi])
    fm = ppow(fpoly, m)
    for i in range(t):
        polys.append([0] * i + fm[:])
    B = [[0] * dim for _ in range(dim)]
    for r, g in enumerate(polys):
        for k, c in enumerate(g):
            if k < dim:
                B[r][k] = c * (X ** k)
    for row in lll_int(B):
        q = []
        ok = True
        for k in range(dim):
            if row[k] % (X ** k) != 0:
                ok = False
                break
            q.append(row[k] // (X ** k))
        if not ok:
            continue
        rs = int_roots(q[:], X)
        if rs:
            return rs[0]
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()

    with open(os.path.join(args.dist, "stereotyped_rsa.json"), "r", encoding="utf-8") as f:
        D = json.load(f)
    n, e, c = int(D["n"]), int(D["e"]), int(D["c"])
    prefix = D["known_prefix"].encode()
    secret_len = int(D["secret_len"])

    A = int.from_bytes(prefix, "big") << (8 * secret_len)
    X = 1 << (8 * secret_len)
    fpoly = ppow([A, 1], e)
    fpoly[0] -= c
    fpoly = [cc % n for cc in fpoly]

    for (m, t) in [(2, 1), (2, 2), (2, 3), (3, 1), (3, 2)]:
        root = coppersmith(fpoly, n, X, m, t)
        if root is not None and pow(A + root, e, n) == c:
            full = prefix + root.to_bytes(secret_len, "big")
            marker = b"zerosecure{"
            print(full[full.index(marker):].decode())
            return
    raise SystemExit("Coppersmith failed to recover the root")


if __name__ == "__main__":
    main()
