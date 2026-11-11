#!/usr/bin/env python3
"""
ZSCTF :: Noisefloor -- reference solver (standalone).

Intended path (pure maths; no brute force, no quantum):
  1. The public key is an LWE instance  b = A.s + e (mod q),  with s,e ternary and
     q ~ 2^20 enormously larger than |e|. That is Bounded-Distance Decoding with a
     *huge* gap, so the unique short solution is visible to lattice reduction.
  2. Build the primal / Kannan embedding lattice of dimension m+n+1 whose unique
     shortest nonzero vector is (+-e, -+s, +-K). Reduce it with LLL (implemented
     here in pure Python -- no fpylll / sage needed, because LLL alone suffices at
     this gap; BKZ is not required).
  3. Read the ternary secret s out of the short vector; verify b - A.s is ternary.
  4. SPLIT-KDF: the sealing key is NOT HKDF(s) alone. It is
        key = HKDF( SHA256( label | canon(s) | '|s2|' | canon(s2) ) )
     where s2 is the private key of a SECOND, independent LWE lockbox (A2, b2)
     published alongside. So repeat the SAME lattice attack on (A2, b2) to recover
     s2 (a smaller, faster instance). s alone CANNOT open the box -- GCM auth fails.
  5. Derive the split key from (s, s2) and AES-256-GCM-decrypt the real flag.
     The published format ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$ is the discriminator:
     the sign-flipped second secret (-s2) opens only the DECOY box to a
     format-invalid near-flag, which this solver rejects by the consistency check.

Run:
    python solve.py path/to/params.json
    python lockbox.py --stdout | python solve.py -          # read artifact from stdin
"""
from __future__ import annotations

import hashlib
import json
import re
import sys

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

# --- sealing contract (must match challenge/lockbox.py) --------------------
KDF_LABEL = b"NOISEFLOOR-KEM-v1"              # legacy s-only label (dead path)
SPLIT_LABEL = b"NOISEFLOOR-SPLITKDF-v2"       # split-KDF domain separator
SPLIT_SEP = b"|s2|"
KDF_INFO = b"noisefloor/aes256gcm"
AAD = b"zsctf:noisefloor:lockbox:v1"
# The STRICT validator is the DECOY discriminator (organizer/grader side): the
# sign-flipped decoy near-flag is built to fail it. We do NOT gate the REAL flag
# on it -- deployed flags may legitimately contain uppercase (e.g. the default
# zerosecurectf{REPLACE_ME_AT_DEPLOY}). GCM auth under the consistency-fixed +s2
# is the authoritative proof; LOOSE_FLAG is only a defensive shape check.
STRICT_FLAG = re.compile(rb"^zerosecurectf\{[a-z0-9_]{8,48}\}$")
LOOSE_FLAG = re.compile(rb"^zerosecurectf\{[\x20-\x7e]{1,80}\}$")


# ---------------------------------------------------------------------------
# Pure-Python LLL (float Gram-Schmidt, incremental swap updates).
# Reference: A. K. Lenstra, H. W. Lenstra, L. Lovasz, "Factoring polynomials
# with rational coefficients", Math. Ann. 261 (1982); Cohen, "A Course in
# Computational Algebraic Number Theory", Alg. 2.6.3 (incremental GS update).
# ---------------------------------------------------------------------------
def lll(basis, delta=0.99):
    b = [list(map(int, row)) for row in basis]
    n = len(b)
    dim = len(b[0])
    mu = [[0.0] * n for _ in range(n)]
    Bn = [0.0] * n
    bstar = [[0.0] * dim for _ in range(n)]

    for i in range(n):
        vi = [float(x) for x in b[i]]
        for j in range(i):
            s = 0.0
            bij = b[i]
            bsj = bstar[j]
            for t in range(dim):
                s += bij[t] * bsj[t]
            mu[i][j] = s / Bn[j] if Bn[j] > 0 else 0.0
            m_ij = mu[i][j]
            for t in range(dim):
                vi[t] -= m_ij * bsj[t]
        bstar[i] = vi
        Bn[i] = sum(x * x for x in vi)

    def red(k, l):
        if abs(mu[k][l]) > 0.5:
            q = int(round(mu[k][l]))
            bk, bl = b[k], b[l]
            for t in range(dim):
                bk[t] -= q * bl[t]
            mu[k][l] -= q
            mul = mu[l]
            mk = mu[k]
            for i in range(l):
                mk[i] -= q * mul[i]

    k = 1
    while k < n:
        red(k, k - 1)
        if Bn[k] >= (delta - mu[k][k - 1] ** 2) * Bn[k - 1]:
            for l in range(k - 2, -1, -1):
                red(k, l)
            k += 1
        else:
            b[k], b[k - 1] = b[k - 1], b[k]
            for j in range(k - 1):
                mu[k][j], mu[k - 1][j] = mu[k - 1][j], mu[k][j]
            mu_ = mu[k][k - 1]
            Bcap = Bn[k] + mu_ * mu_ * Bn[k - 1]
            if Bcap > 0:
                mu[k][k - 1] = mu_ * Bn[k - 1] / Bcap
                Bn[k] = Bn[k - 1] * Bn[k] / Bcap
                Bn[k - 1] = Bcap
            for i in range(k + 1, n):
                t = mu[i][k]
                mu[i][k] = mu[i][k - 1] - mu_ * t
                mu[i][k - 1] = t + mu[k][k - 1] * mu[i][k]
            k = max(k - 1, 1)
    return b


# ---------------------------------------------------------------------------
# Primal / Kannan embedding attack on small-secret LWE.
# ---------------------------------------------------------------------------
def recover_secret(A, b, q, ebound, K=1):
    m = len(A)
    n = len(A[0])
    d = m + n + 1
    M = [[0] * d for _ in range(d)]
    # block 1 (m rows):  [ q I_m | 0 | 0 ]
    for i in range(m):
        M[i][i] = q
    # block 2 (n rows):  row j = [ col_j(A) | e_j | 0 ]
    for j in range(n):
        for i in range(m):
            M[m + j][i] = A[i][j]
        M[m + j][m + j] = 1
    # block 3 (1 row):   [ b | 0 | K ]
    for i in range(m):
        M[m + n][i] = b[i]
    M[m + n][m + n] = K

    R = lll(M)
    for row in R:
        if abs(row[m + n]) == K:
            # short vector is +-(..., s-block, K); if last == +K the s-block is -s
            sign = -1 if row[m + n] > 0 else 1
            s_rec = [sign * row[m + j] for j in range(n)]
            if _consistent(A, b, s_rec, q, ebound):
                return s_rec
    return None


def _consistent(A, b, s, q, ebound):
    m = len(A)
    n = len(A[0])
    for i in range(m):
        r = (b[i] - sum(A[i][j] * s[j] for j in range(n))) % q
        if r > q // 2:
            r -= q
        if abs(r) > ebound:
            return False
    return True


# ---------------------------------------------------------------------------
# Key derivation + unseal (matches challenge/lockbox.py).
# ---------------------------------------------------------------------------
def canon_ternary(vec):
    return bytes((x % 3) for x in vec)


# legacy s-only derivation -- kept only to demonstrate the DEAD one-shot path
def derive_key(s, salt):
    material = hashlib.sha256(KDF_LABEL + b"|" + canon_ternary(s)).digest()
    return HKDF(material, 32, salt, SHA256, context=KDF_INFO)


def derive_split_key(s, s2, salt):
    material = hashlib.sha256(
        SPLIT_LABEL + b"|" + canon_ternary(s) + SPLIT_SEP + canon_ternary(s2)
    ).digest()
    return HKDF(material, 32, salt, SHA256, context=KDF_INFO)


def _open(inst, key, ct_key, tag_key, nonce_key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(inst[nonce_key]))
    cipher.update(inst.get("aad", AAD.decode()).encode())
    return cipher.decrypt_and_verify(
        bytes.fromhex(inst[ct_key]), bytes.fromhex(inst[tag_key])
    )


def unseal(inst, s, s2):
    """Open the REAL lockbox with the split key binding both recovered secrets."""
    key = derive_split_key(s, s2, bytes.fromhex(inst["salt"]))
    return _open(inst, key, "ciphertext", "tag", "nonce")


def solve(inst):
    # --- channel 1: the primary lattice crux (UNCHANGED) -------------------
    s = recover_secret(inst["A"], inst["b"], inst["q"], inst.get("error_bound", 1))
    if s is None:
        raise RuntimeError("primary lattice reduction did not recover a consistent secret")

    # --- channel 2: the independent second lockbox (A2, b2) ----------------
    # recover_secret applies the SAME b2 - A2.s2 ternary-consistency gate, which
    # also fixes the +-sign: the sign-flipped -s2 is rejected here, so we never
    # drift into the decoy box.
    s2 = recover_secret(inst["A2"], inst["b2"], inst["q2"], inst.get("error_bound2", 1))
    if s2 is None:
        raise RuntimeError("second-channel lattice reduction did not recover s2")

    flag = unseal(inst, s, s2)
    if not LOOSE_FLAG.match(flag):
        # defensive: a correct two-channel solve GCM-authenticates to the real
        # flag; anything not flag-shaped means a mis-solve -- reject rather than
        # report junk. (The decoy near-flag is never reached: recover_secret's
        # ternary-consistency gate fixes the sign to +s2, not the decoy's -s2.)
        raise RuntimeError("recovered plaintext is not flag-shaped (mis-solve)")
    return s, s2, flag


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        sys.stderr.write("usage: solve.py <params.json | ->\n")
        return 2
    src = argv[0]
    if src == "-":
        inst = json.load(sys.stdin)
    else:
        with open(src, "r", encoding="ascii") as fh:
            inst = json.load(fh)
    s, s2, flag = solve(inst)
    print("[+] recovered ternary private key s (dim %d)" % len(s))
    print("[+] s =", s)
    print("[+] recovered second-channel secret s2 (dim %d)" % len(s2))
    print("[+] s2 =", s2)
    try:
        print("[+] FLAG =", flag.decode())
    except UnicodeDecodeError:
        print("[+] FLAG (bytes) =", flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
