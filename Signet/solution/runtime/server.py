#!/usr/bin/env python3
"""
ZSCTF :: Signet  (crypto, Hard)

A firmware-update *signing service*. It will sign the vendor's benign update
manifests on request. The cryptographic crux is UNCHANGED: the per-request
nonces follow a secret-but-LINEAR schedule, so three signatures recover the
vendor signing key `d` outright (related-nonce ECDSA key recovery).

What recovering `d` *earns* you is not the flag directly -- it earns you the
ability to forge the vendor's signature on arbitrary messages. The flag itself
is never handed over whole. It is split with Shamir secret sharing (k-of-n over
the Mersenne-prime field GF(2^521-1)); each share is locked behind a DISTINCT
server-issued "attestation token", released only when you present a valid vendor
signature over that exact token. So you must exercise the recovered key n times,
over n different messages, to redeem the shares -- then reconstruct the flag
OFFLINE by Lagrange interpolation.

Footgun (documented for organizers in writeup.md): an invalid / forged signature
does NOT bounce with an error. It silently returns a *decoy* share lying on a
different polynomial, which reconstructs to a near-flag that fails the strict
flag format. A careless solver who never actually recovered `d` collects decoy
shares and reconstructs garbage; a careful solver verifies d*G == Q and signs
each exact token, so every share they redeem is genuine.

Players are given this exact source file. The flaw is in plain sight, in the
per-request nonce derivation -- that is the point.

Self-contained: pure-Python secp256k1 + ECDSA + Shamir (no external crypto
libraries), so there is nothing to trust but the maths in front of you.
"""
import os, sys, hashlib, socketserver

# ----------------------------------------------------------------------------
# secp256k1 domain parameters (public constants)
# ----------------------------------------------------------------------------
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)

def inv(a, m):
    return pow(a % m, -1, m)

def ec_add(Pt, Q):
    if Pt is None: return Q
    if Q is None: return Pt
    x1, y1 = Pt; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if Pt == Q:
        lam = (3 * x1 * x1) * inv(2 * y1, P) % P      # a = 0 for secp256k1
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def ec_mul(k, Pt):
    R = None
    k %= N
    while k:
        if k & 1:
            R = ec_add(R, Pt)
        Pt = ec_add(Pt, Pt)
        k >>= 1
    return R

# ----------------------------------------------------------------------------
# Per-instance secrets, derived deterministically from a seed (team id).
# This gives every team a unique key + unique nonce schedule + unique flag
# position + unique attestation tokens + unique decoy, so a leaked solution for
# one instance does not transfer.
# ----------------------------------------------------------------------------
def _derive(seed, label):
    return int.from_bytes(hashlib.sha256(seed + b"|" + label).digest(), "big") % (N - 1) + 1

SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG")
if FLAG is None:
    FLAG = "zerosecurectf{local_review_flag}"
    sys.stderr.write("WARNING: ZSCTF_FLAG unset; using insecure default "
                     "zerosecurectf{local_review_flag}\n")
    sys.stderr.flush()

d  = _derive(SEED, b"signing-key")          # secret signing key
k0 = _derive(SEED, b"nonce-start")          # secret nonce base
b  = _derive(SEED, b"nonce-step")           # secret nonce step
Q  = ec_mul(d, G)                           # public key (published below)

# ----------------------------------------------------------------------------
# Benign manifests are signable on request (the oracle that leaks d).
# ----------------------------------------------------------------------------
BENIGN = [b"firmware:stable;ver:1.0.%d;url:https://vendor.example/fw/%d" % (i, i)
          for i in range(8)]

def H(msg):
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N

# ---- per-request nonce derivation (THE FLAW -- unchanged) ------------------
# For reproducible, "stateless" signing the service derives the per-request
# nonce from the request index with a fixed arithmetic schedule:
#
#       k_i = (k0 + b * i) mod N          # k0, b secret; the schedule is linear
#
# i.e. consecutive nonces differ by the same secret step b. Classic.
def nonce(i):
    return (k0 + b * i) % N

def sign_index(i):
    m = H(BENIGN[i])
    k = nonce(i)
    R = ec_mul(k, G)
    r = R[0] % N
    s = inv(k, N) * (m + r * d) % N
    if r == 0 or s == 0:
        raise ValueError("degenerate signature")   # never happens for these params
    return r, s

def verify(msg, r, s):
    if not (1 <= r < N and 1 <= s < N):
        return False
    m = H(msg)
    w = inv(s, N)
    u1 = m * w % N
    u2 = r * w % N
    X = ec_add(ec_mul(u1, G), ec_mul(u2, Q))
    if X is None:
        return False
    return X[0] % N == r

# ----------------------------------------------------------------------------
# FLAG-EXTRACTION LAYER  (Shamir k-of-n over GF(2^521-1), gated by attestations)
# ----------------------------------------------------------------------------
# The flag is NEVER returned whole. It is the secret f(0) of a degree-(k-1)
# polynomial over the Mersenne-prime field GF(2^521-1). Share j = (x_j, f(x_j))
# with x_j = j+1. Share j is released only when you present a VALID vendor
# signature over attestation token CHAL[j]. The service will NOT sign those
# tokens for you (SIGN serves only benign indices), so the only way to produce
# the signature is to have recovered d -- the ECDSA crux stays the gate.
#
# A signature that does NOT verify yields a DECOY share (a point on a different
# polynomial whose secret is a deliberately format-INVALID near-flag). No error
# is raised; the mistake only surfaces when offline reconstruction fails the
# strict flag format. Guess-exposure stays 0: decoy reconstructions are
# rejectable by the published format rule, and a careful solver who checks
# d*G == Q and signs the exact token never redeems a decoy.
PRIME_SHARE = (1 << 521) - 1            # M_521, a Mersenne prime
SHARE_N = 5                             # number of share slots
SHARE_K = 3                             # threshold

# Per-instance public fingerprint (binds the tokens/decoy to this seed).
FP = hashlib.sha256(SEED + b"|attest-fingerprint").hexdigest()[:16]
CHAL = [("attest:flag-share;slot:%d;fp:%s" % (j, FP)).encode() for j in range(SHARE_N)]

def _derive_field(label):
    """Deterministic field element in [0, PRIME_SHARE) with > 521 bits of input."""
    buf = b""
    ctr = 0
    while len(buf) < 80:   # 640 bits of SHA-256 output, reduced mod the prime
        buf += hashlib.sha256(SEED + b"|" + label + b"|" + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return int.from_bytes(buf[:80], "big") % PRIME_SHARE

_secret_int = int.from_bytes(FLAG.encode(), "big")
if _secret_int >= PRIME_SHARE:
    raise SystemExit("ZSCTF_FLAG too long for GF(2^521-1) share field")

# Decoy secret: a near-flag that FAILS ^zerosecurectf\{[a-z0-9_]{8,48}\}$ because
# the body is UPPERCASE. Varies per instance via the fingerprint (no transfer).
_NEARFLAG = ("zerosecurectf{ATTESTATION_FORGED_%s}" % FP).encode()
_decoy_int = int.from_bytes(_NEARFLAG, "big")

_REAL_COEFFS  = [_secret_int] + [_derive_field(b"share-coeff-%d" % t)  for t in range(1, SHARE_K)]
_DECOY_COEFFS = [_decoy_int]  + [_derive_field(b"decoy-coeff-%d" % t)  for t in range(1, SHARE_K)]

def _poly_eval(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % PRIME_SHARE
    return acc

def real_share(j):
    x = j + 1
    return x, _poly_eval(_REAL_COEFFS, x)

def decoy_share(j):
    x = j + 1
    return x, _poly_eval(_DECOY_COEFFS, x)

# ----------------------------------------------------------------------------
# Line protocol
# ----------------------------------------------------------------------------
def banner():
    out = []
    out.append("=== ZSCTF Firmware Attestation Service ===")
    out.append("pubkey Qx %x" % Q[0])
    out.append("pubkey Qy %x" % Q[1])
    out.append("benign manifests available for signing: index 0..%d" % (len(BENIGN) - 1))
    out.append("flag attestation: Shamir k-of-n secret sharing over GF(2^521-1)")
    out.append("  prime 2^521-1 = %x" % PRIME_SHARE)
    out.append("  threshold k = %d ; slots n = %d ; share x-coordinate of slot j is (j+1)" % (SHARE_K, SHARE_N))
    out.append("  redeem slot j by signing its attestation token with the vendor key:")
    for j in range(SHARE_N):
        out.append("attest token slot %d: %s" % (j, CHAL[j].decode()))
    out.append("note: the service will NOT sign these attestation tokens (SIGN serves only benign indices)")
    out.append("commands: SIGN <i> | ATTEST <j> <r_hex> <s_hex> | QUIT")
    return "\n".join(out)

def handle_line(line):
    parts = line.strip().split()
    if not parts:
        return ""
    cmd = parts[0].upper()
    try:
        if cmd == "SIGN":
            i = int(parts[1])
            if not (0 <= i < len(BENIGN)):
                return "ERR index out of range"
            r, s = sign_index(i)
            return "SIG %x %x %s" % (r, s, BENIGN[i].hex())
        if cmd == "ATTEST":
            j = int(parts[1]); r = int(parts[2], 16); s = int(parts[3], 16)
            if not (0 <= j < SHARE_N):
                return "ERR slot out of range"
            # Valid vendor signature over THIS exact token -> genuine share.
            # Anything else -> a decoy share (no error; same shape).
            if verify(CHAL[j], r, s):
                x, y = real_share(j)
            else:
                x, y = decoy_share(j)
            return "SHARE %d %x %x" % (j, x, y)
        if cmd == "QUIT":
            return "__QUIT__"
        return "ERR unknown command"
    except (IndexError, ValueError):
        return "ERR malformed command"

def serve_stdio():
    print(banner(), flush=True)
    for line in sys.stdin:
        resp = handle_line(line)
        if resp == "__QUIT__":
            break
        if resp:
            print(resp, flush=True)

class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write((banner() + "\n").encode())
        for raw in self.rfile:
            resp = handle_line(raw.decode(errors="ignore"))
            if resp == "__QUIT__":
                break
            if resp:
                self.wfile.write((resp + "\n").encode())

def serve_tcp(host, port):
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, port), _Handler) as srv:
        sys.stderr.write("listening on %s:%d\n" % (host, port)); sys.stderr.flush()
        srv.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--tcp":
        host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 1337
        serve_tcp(host, port)
    else:
        serve_stdio()
