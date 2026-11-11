#!/usr/bin/env python3
"""
ZSCTF :: Signet -- reference solver (full extraction).

The intended path has two layers:

  CRUX (unchanged) -- recover the vendor signing key d:
    1. The service signs manifest i with nonce k_i = k0 + b*i  (k0, b secret,
       but the *schedule is linear* -- consecutive nonces differ by step b).
    2. From any signature, k_i is affine in d:
          k_i = alpha_i + beta_i * d   (mod N),  alpha_i = m_i/s_i, beta_i = r_i/s_i
    3. Linearity means (k_1 - k_0) == (k_2 - k_1): one linear equation in d, so
       three signatures recover d outright -- no lattice, no brute force.

  EXTRACTION -- the flag is NOT handed over; it is Shamir-shared k-of-n over
  GF(2^521-1). Recovering d earns the ability to forge the vendor signature on
  arbitrary messages; each share j is released only against a VALID vendor
  signature over the distinct attestation token CHAL[j]:
    4. Sign k distinct tokens with d, ATTEST each, collect k genuine shares.
    5. Lagrange-interpolate the shares at x=0 OFFLINE to recover the secret =
       SHA-independent integer encoding of the flag bytes; decode and validate
       against the strict format ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$.

  A forged / invalid signature returns a DECOY share instead (no error), which
  reconstructs to a format-invalid near-flag -- so this solver signs each exact
  token with the verified key (d*G == Q) and never redeems a decoy.

Run locally against the source:   python solve.py --local ../challenge/server.py
Run against a deployed instance:   python solve.py --remote HOST PORT
"""
import sys, subprocess, socket, argparse, re, hashlib

P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)
FLAG_RE = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")

def Hn(msg): return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N
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

# -- transport abstractions --------------------------------------------------
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
        self.s = socket.create_connection((host, port), timeout=10)
        self.f = self.s.makefile("rw", newline="\n")
    def readline(self): return self.f.readline()
    def send(self, line): self.f.write(line + "\n"); self.f.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        self.s.close()

def read_banner(io):
    """Read the banner; return (Q, prime, k, n, tokens[list of bytes])."""
    Qx = Qy = prime = None; k = n = None
    tokens = {}
    while True:
        line = io.readline()
        if not line:
            raise RuntimeError("service closed during banner")
        line = line.rstrip("\n")
        if line.startswith("pubkey Qx"): Qx = int(line.split()[-1], 16)
        elif line.startswith("pubkey Qy"): Qy = int(line.split()[-1], 16)
        elif "prime 2^521-1 =" in line: prime = int(line.split("=")[-1].strip(), 16)
        elif "threshold k =" in line:
            k = int(line.split("threshold k =")[1].split(";")[0].strip())
            n = int(line.split("slots n =")[1].split(";")[0].strip())
        elif line.startswith("attest token slot"):
            j = int(line.split("slot")[1].split(":")[0].strip())
            tokens[j] = line.split(":", 1)[1].strip().encode()
        elif line.startswith("commands:"):
            break
    toks = [tokens[j] for j in sorted(tokens)]
    return (Qx, Qy), prime, k, n, toks

def get_sig(io, i):
    io.send("SIGN %d" % i)
    line = io.readline().rstrip("\n")
    assert line.startswith("SIG "), "unexpected: %r" % line
    _, r_hex, s_hex, man_hex = line.split()
    return int(r_hex, 16), int(s_hex, 16), bytes.fromhex(man_hex)

def recover_d(sigs):
    # sigs: list of (r, s, manifest) for indices 0,1,2 (contiguous)
    alpha, beta = [], []
    for r, s, man in sigs:
        si = inv(s, N)
        alpha.append(Hn(man) * si % N)
        beta.append(r * si % N)
    # (k1-k0) == (k2-k1):
    # (a1-a0)+(b1-b0)d == (a2-a1)+(b2-b1)d
    coef = ((beta[1]-beta[0]) - (beta[2]-beta[1])) % N
    rhs  = ((alpha[2]-alpha[1]) - (alpha[1]-alpha[0])) % N
    return rhs * inv(coef, N) % N

def sign_msg(d, msg, k):
    """Forge the vendor's ECDSA signature over `msg` using recovered d."""
    m = Hn(msg)
    R = mul(k, G); r = R[0] % N
    s = inv(k, N) * (m + r*d) % N
    assert r != 0 and s != 0
    return r, s

def redeem_share(io, j, r, s):
    io.send("ATTEST %d %x %x" % (j, r, s))
    line = io.readline().rstrip("\n")
    assert line.startswith("SHARE "), "unexpected: %r" % line
    _, jj, x_hex, y_hex = line.split()
    assert int(jj) == j
    return int(x_hex, 16), int(y_hex, 16)

def lagrange_at_zero(points, prime):
    """Recover f(0) from >=k points via Lagrange interpolation over GF(prime)."""
    secret = 0
    for i, (xi, yi) in enumerate(points):
        num = 1; den = 1
        for jx, (xj, _) in enumerate(points):
            if jx == i: continue
            num = num * ((-xj) % prime) % prime
            den = den * ((xi - xj) % prime) % prime
        secret = (secret + yi * num % prime * inv(den, prime)) % prime
    return secret

def int_to_flag(secret):
    blen = (secret.bit_length() + 7) // 8
    raw = secret.to_bytes(blen, "big")
    try:
        return raw.decode()
    except UnicodeDecodeError:
        return raw.decode("latin-1")

def solve(io):
    Q, prime, k, n, tokens = read_banner(io)
    # --- CRUX: recover the vendor signing key d from three signatures ---
    sigs = [get_sig(io, i) for i in (0, 1, 2)]
    d = recover_d(sigs)
    assert mul(d, G) == Q, "recovered key does not match the public key"

    # --- EXTRACTION: redeem k genuine shares by signing k distinct tokens ---
    points = []
    for j in range(k):                         # slots 0..k-1 suffice (k-of-n)
        r, s = sign_msg(d, tokens[j], k=0x1337c0de + 0x9e3779b9 * (j + 1))
        x, y = redeem_share(io, j, r, s)
        points.append((x, y))

    secret = lagrange_at_zero(points, prime)
    flag = int_to_flag(secret)
    return d, flag, points

def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="SERVER_PY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    args = ap.parse_args()
    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        d, flag, points = solve(io)
        print("[+] recovered private key d = %x" % d)
        print("[+] redeemed %d genuine Shamir shares: %s" %
              (len(points), [(x, hex(y)) for x, y in points]))
        if FLAG_RE.match(flag):
            print("[+] reconstructed flag passes strict format")
            print("[+] FLAG =", flag)
            return 0
        print("[-] reconstructed string FAILS strict flag format (decoy?): %r" % flag)
        return 1
    finally:
        io.close()

if __name__ == "__main__":
    sys.exit(main())
