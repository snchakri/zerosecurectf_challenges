#!/usr/bin/env python3
"""
ZSCTF :: Windage -- reference solver (standalone, pure Python).

Intended path (no exploit of anything but the maths):

  1. The beacon signs report i with a *biased* nonce k_i drawn in [1, 2^L),
     L = NONCE_BITS -- so the top (bitlen(N) - L) bits of every nonce are zero.
     Each signature is individually valid; no single one leaks the key.

  2. ECDSA gives, for each signature (r_i, s_i) over hash h_i:
         s_i = k_i^{-1} (h_i + r_i d)   (mod n)
     Rearranged, the nonce is an AFFINE function of the secret key d:
         k_i = a_i d + c_i   (mod n),   a_i = r_i/s_i,  c_i = h_i/s_i   (mod n)
     with the extra, exploitable fact that  0 <= k_i < 2^L  (the windage).

  3. That is exactly the Hidden Number Problem (Boneh-Venkatesan 1996;
     Nguyen-Shparlinski 2003 for (EC)DSA). Build the HNP lattice whose unique
     short vector encodes the (small, centred) nonces and the key d, and recover
     it by LATTICE REDUCTION. LLL alone suffices at these parameters -- BKZ is
     not needed -- but a lattice reduction genuinely IS needed: no amount of
     linear algebra over Z_n recovers d from the congruences alone, and the
     nonces/key are far too large to brute force.

  4. FLAG EXTRACTION (CRT reconstruction). The flag is not handed over whole. It
     is the decommission code C, split across K pairwise-coprime moduli m_j
     published in the banner. For each j we forge a valid signature over the
     modulus-bound attestation token j (which needs d) and the beacon releases
     the residue C mod m_j. We collect all K residues and CRT-reconstruct C
     offline, then decode it to the flag bytes. A wrong signature would return a
     decoy residue that reconstructs to a format-invalid near-flag, so we verify
     the result against the published flag format.

LLL is implemented here in pure Python with EXACT rational Gram-Schmidt
(fractions.Fraction), so there is no floating-point blow-up at 160-bit entries
-- fpylll / sage are not required and are not used.

Run locally against the source:   python solve.py --local ../challenge/beacon.py
Run against a deployed instance:   python solve.py --remote HOST PORT

References:
  * D. Boneh, R. Venkatesan, "Hardness of Computing the Most Significant Bits of
    Secret Keys in Diffie-Hellman and Related Schemes", CRYPTO 1996.
  * P. Q. Nguyen, I. E. Shparlinski, "The Insecurity of the Elliptic Curve
    Digital Signature Algorithm with Partially Known Nonces", Designs, Codes and
    Cryptography 30 (2003), 201-217.
  * A. K. Lenstra, H. W. Lenstra, L. Lovasz, "Factoring Polynomials with Rational
    Coefficients", Math. Ann. 261 (1982) -- the LLL algorithm.
"""
import sys, subprocess, socket, argparse, hashlib, re
from fractions import Fraction as Fr

# ----------------------------------------------------------------------------
# secp160k1 domain parameters (must match the service).
# ----------------------------------------------------------------------------
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73
A  = 0
B  = 7
Gx = 0x3B4C382CE37AA192A4019E763036F4F5DD4D7EBB
Gy = 0x938CF935318FDCED6BC28286531733C3F03C4FEE
N  = 0x0100000000000000000001B8FA16DFAB9ACA16B6B3
G  = (Gx, Gy)

def inv(a, m): return pow(a % m, -1, m)
def add(Pt, Q):
    if Pt is None: return Q
    if Q is None: return Pt
    x1, y1 = Pt; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % P == 0: return None
    lam = (3*x1*x1)*inv(2*y1, P) % P if Pt == Q else (y2-y1)*inv(x2-x1, P) % P
    x3 = (lam*lam - x1 - x2) % P
    return (x3, (lam*(x1-x3) - y1) % P)
def mul(k, Pt):
    R = None; k %= N
    while k:
        if k & 1: R = add(R, Pt)
        Pt = add(Pt, Pt); k >>= 1
    return R
def Hn(msg): return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N

# ----------------------------------------------------------------------------
# Pure-Python LLL with EXACT rational Gram-Schmidt (no floats -> no overflow /
# precision loss at 160-bit lattice entries). Float Gram-Schmidt would silently
# fail here because a single dot product exceeds 2^300 and loses all precision
# in a 53-bit double. The structure (incremental swap update) follows Cohen,
# "A Course in Computational Algebraic Number Theory", Alg. 2.6.3, with Fraction
# arithmetic standing in for the exact integer book-keeping.
# ----------------------------------------------------------------------------
def lll(basis, delta=Fr(99, 100)):
    b = [list(map(int, row)) for row in basis]
    n = len(b)
    dim = len(b[0])
    mu = [[Fr(0)] * n for _ in range(n)]
    Bn = [Fr(0)] * n
    bstar = [[Fr(0)] * dim for _ in range(n)]

    for i in range(n):
        vi = [Fr(x) for x in b[i]]
        for j in range(i):
            s = Fr(0)
            bij = b[i]; bsj = bstar[j]
            for t in range(dim):
                s += bij[t] * bsj[t]
            mu[i][j] = s / Bn[j] if Bn[j] != 0 else Fr(0)
            m_ij = mu[i][j]
            for t in range(dim):
                vi[t] -= m_ij * bsj[t]
        bstar[i] = vi
        Bn[i] = sum(x * x for x in vi)

    def red(k, l):
        if abs(mu[k][l]) > Fr(1, 2):
            q = round(mu[k][l])
            bk, bl = b[k], b[l]
            for t in range(dim):
                bk[t] -= q * bl[t]
            mu[k][l] -= q
            mk, mul_ = mu[k], mu[l]
            for i in range(l):
                mk[i] -= q * mul_[i]

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
            if Bcap != 0:
                mu[k][k - 1] = mu_ * (Bn[k - 1] / Bcap)
                Bn[k] = (Bn[k - 1] / Bcap) * Bn[k]
                Bn[k - 1] = Bcap
            for i in range(k + 1, n):
                t = mu[i][k]
                mu[i][k] = mu[i][k - 1] - mu_ * t
                mu[i][k - 1] = t + mu[k][k - 1] * mu[i][k]
            k = max(k - 1, 1)
    return b

# ----------------------------------------------------------------------------
# Build the HNP lattice and recover d by lattice reduction.
#
# From k_i = a_i d + c_i (mod n) with 0 <= k_i < 2^L, centre the nonces:
#   C = 2^(L-1),  k_i' = k_i - C  in [-C, C),   a_i d + (c_i - C) = k_i' (mod n)
#
# Lattice (dimension m+2), with column weight W = n // C chosen so every
# coordinate of the target short vector is ~ n:
#
#   rows 0..m-1 :  [ n*W on diagonal, 0, 0 ]
#   row  m      :  [ a_i*W (i<m),      1, 0 ]     # d-tracking column
#   row  m+1    :  [ c_i'*W (i<m),     0, K ]     # embedding column, K = n
#
# The integer combination (y_0..y_{m-1}, d, 1) yields
#   coord i (i<m) = W*k_i'   (|.| < W*C ~ n)
#   coord m       = d        (< n)
#   coord m+1     = K = n
# i.e. a vector of norm ~ n*sqrt(m+2), far shorter than anything else in the
# lattice when (bitlen(n) - L) * m > bitlen(n). LLL surfaces it; we read d out of
# the d-tracking column (fixing the overall sign by the +/-K coordinate) and
# confirm it against the public key Q.
# ----------------------------------------------------------------------------
def build_lattice(sigs, L):
    m = len(sigs)
    C = 1 << (L - 1)
    W = N // C
    K = N
    a = []; c = []
    for (r, s, h) in sigs:
        si = inv(s, N)
        a.append(r * si % N)
        c.append((h * si - C) % N)
    D = m + 2
    M = [[0] * D for _ in range(D)]
    for i in range(m):
        M[i][i] = N * W
    for i in range(m):
        M[m][i] = a[i] * W
    M[m][m] = 1
    for i in range(m):
        M[m + 1][i] = c[i] * W
    M[m + 1][m + 1] = K
    return M, W, K

def recover_key(sigs, Q, L):
    m = len(sigs)
    M, W, K = build_lattice(sigs, L)
    R = lll(M)
    # Primary: read d directly from the d-tracking column of any row whose
    # embedding coordinate is +/-K (that row is +/- the planted target vector).
    for row in R:
        last = row[m + 1]
        if abs(last) == K:
            sign = 1 if last > 0 else -1
            d = (sign * row[m]) % N
            if mul(d, G) == Q:
                return d
    # Fallback: recover the centred nonce k_0' from a short row and solve for d
    # algebraically (handles sign/representation quirks of the short vector).
    C = 1 << (L - 1)
    r0, s0, h0 = sigs[0]
    a0 = r0 * inv(s0, N) % N
    c0 = (h0 * inv(s0, N) - C) % N
    for row in R:
        if W == 0:
            break
        for sign in (1, -1):
            kp0 = sign * row[0] // W
            d = ((kp0 - c0) % N) * inv(a0, N) % N
            if mul(d, G) == Q:
                return d
    return None

def forge(d, msg, k=0x5eed1337):
    m = Hn(msg)
    R = mul(k, G); r = R[0] % N
    s = inv(k, N) * (m + r * d) % N
    return r, s

# ----------------------------------------------------------------------------
# Flag-extraction layer: CRT reconstruction.
# ----------------------------------------------------------------------------
FLAG_RE = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")

def attest_token(j, m):
    """Exact bytes of the modulus-bound DECOMMISSION attestation token (mirrors
    the service). Forging a signature over it requires the recovered key d."""
    return (b"BEACON WINDAGE-7 :: command=DECOMMISSION; segment=%d; modulus=%x; "
            b"authority=FLEET-ACTUAL; effective=IMMEDIATE" % (j, m))

def crt(residues, moduli):
    """Garner/CRT over pairwise-coprime moduli; unique because prod(moduli) > C."""
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for a, m in zip(residues, moduli):
        Mi = M // m
        x += a * Mi * inv(Mi, m)
    return x % M

def int_to_text(x):
    b = x.to_bytes((x.bit_length() + 7) // 8, "big")
    try:
        return b.decode()
    except UnicodeDecodeError:
        return b.decode("latin-1")

# ----------------------------------------------------------------------------
# Transport abstractions (identical interface for --local subprocess and
# --remote socket).
# ----------------------------------------------------------------------------
class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([sys.executable, path], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True, bufsize=1)
    def readline(self): return self.p.stdout.readline()
    def send(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        try: self.p.wait(timeout=5)
        except Exception: self.p.kill()

class Sock:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=15)
        self.f = self.s.makefile("rw", newline="\n")
    def readline(self): return self.f.readline()
    def send(self, line): self.f.write(line + "\n"); self.f.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        self.s.close()

def read_banner(io):
    """Read banner lines until the 'commands:' marker; return
    (Q, L, num_reports, moduli)."""
    Qx = Qy = None; L = None; num = None
    moduli = {}
    while True:
        line = io.readline()
        if not line:
            raise RuntimeError("service closed during banner")
        line = line.rstrip("\n")
        if line.startswith("pubkey Qx"): Qx = int(line.split()[-1], 16)
        elif line.startswith("pubkey Qy"): Qy = int(line.split()[-1], 16)
        elif "every nonce k satisfies" in line:
            # "... 1 <= k < 2^153"
            L = int(line.rsplit("2^", 1)[1])
        elif line.startswith("routine reports available"):
            num = int(line.rsplit("0..", 1)[1]) + 1
        elif line.startswith("modulus "):
            # "modulus <j> <hex>"  (the CRT segment moduli)
            parts = line.split()
            moduli[int(parts[1])] = int(parts[2], 16)
        elif line.startswith("commands:"):
            break
    if None in (Qx, Qy, L, num) or not moduli:
        raise RuntimeError("failed to parse banner")
    mods = [moduli[j] for j in sorted(moduli)]
    return (Qx, Qy), L, num, mods

def get_sig(io, i):
    io.send("SIGN %d" % i)
    line = io.readline().rstrip("\n")
    assert line.startswith("SIG "), "unexpected: %r" % line
    _, r_hex, s_hex, man_hex = line.split()
    man = bytes.fromhex(man_hex)
    return (int(r_hex, 16), int(s_hex, 16), Hn(man))

def solve(io, max_sigs=None):
    Q, L, num, moduli = read_banner(io)
    use = num if max_sigs is None else min(num, max_sigs)
    sigs = [get_sig(io, i) for i in range(use)]
    d = recover_key(sigs, Q, L)
    if d is None:
        raise RuntimeError("lattice reduction did not recover the key")
    assert mul(d, G) == Q, "recovered key does not match the public key"
    # --- CRT flag extraction: one valid attestation signature per modulus ------
    residues = []
    for j, m in enumerate(moduli):
        r, s = forge(d, attest_token(j, m), k=0x5eed1337 + j)
        io.send("SUBMIT %d %x %x" % (j, r, s))
        line = io.readline().rstrip("\n")
        assert line.startswith("RESIDUE %d " % j), "unexpected: %r" % line
        residues.append(int(line.split()[2], 16))
    code = crt(residues, moduli)
    flag = int_to_text(code)
    return d, flag, (FLAG_RE.match(flag) is not None)

def main():
    ap = argparse.ArgumentParser(description="Windage HNP/LLL reference solver.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="BEACON_PY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    ap.add_argument("--max-sigs", type=int, default=None,
                    help="cap the number of signatures used (default: all offered)")
    args = ap.parse_args()
    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        d, flag, ok = solve(io, args.max_sigs)
        print("[+] recovered private key d = %x" % d)
        print("[+] CRT-reconstructed the decommission authorization code from residues")
        print("[+] FLAG = %s" % flag)
        if ok:
            return 0
        print("[-] reconstruction does NOT match ^zerosecurectf{[a-z0-9_]{8,48}}$ -- "
              "decoy residues? re-check that every attestation signature was valid")
        return 1
    finally:
        io.close()

if __name__ == "__main__":
    sys.exit(main())
