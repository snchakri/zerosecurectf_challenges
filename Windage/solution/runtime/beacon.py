#!/usr/bin/env python3
"""
ZSCTF :: Windage  (crypto, Extreme)

A maritime navigation beacon that ECDSA-signs its status reports. The beacon
will sign its routine position reports on request. The beacon's decommission
authorization code (the flag) is NOT handed over whole: it is split by the
Chinese Remainder Theorem across several pairwise-coprime moduli, and the beacon
releases exactly one residue (code mod m_j) for each VALID signature you file
over a distinct, modulus-bound DECOMMISSION attestation token -- a message the
beacon will not sign for you. Collect every residue and CRT-reconstruct the code
offline. Forging even one token requires the private key d, so the HNP lattice
attack below is UNCHANGED as the gate; the CRT reconstruction is a graded
extraction layered on top of it. A wrong/forged signature yields a DECOY residue,
so a careless reconstruction produces a rejectable near-flag -- verify the
reconstruction against the published flag format before trusting it.

Players are given this exact source file. The cryptographic flaw is therefore
not hidden by obscurity: it is in plain sight, in how per-request nonces are
produced. The beacon's hardware RNG has a documented *windage* -- a fixed bias
that forces the top few bits of every ECDSA nonce to zero. Each individual
signature is still a perfectly valid signature; no single one leaks the key.
But the bias turns the set of signatures into a Hidden Number Problem (HNP),
and the private key falls out of a lattice built from MANY of them.

Curve: secp160k1 -- a real, standardized Koblitz curve of the secp256k1 family
(same short-Weierstrass shape y^2 = x^3 + 7, a = 0), scaled to a 160-bit field.
It is used here instead of full secp256k1 for one honest, documented reason: the
reference attack hand-rolls LLL in pure Python (no fpylll / no sage), and a
160-bit modulus keeps that reduction reliably inside the solver's time budget.
The ECDLP on secp160k1 is still ~2^80 work (Pollard rho), so you cannot shortcut
the key by computing a discrete log -- the lattice attack is the intended path.

Self-contained: pure-Python secp160k1 + ECDSA (no external crypto libraries),
so there is nothing to trust but the maths in front of you.
"""
import os, sys, hashlib, socketserver

# ----------------------------------------------------------------------------
# secp160k1 domain parameters (SEC 2, v2 -- public constants).
# Verified self-consistent in test/test.py: G lies on the curve and N*G = O.
# ----------------------------------------------------------------------------
P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73
A  = 0
B  = 7
Gx = 0x3B4C382CE37AA192A4019E763036F4F5DD4D7EBB
Gy = 0x938CF935318FDCED6BC28286531733C3F03C4FEE
N  = 0x0100000000000000000001B8FA16DFAB9ACA16B6B3
G  = (Gx, Gy)

# ----------------------------------------------------------------------------
# The planted weakness, in plain sight: the beacon's nonce RNG has "windage".
# Every per-request nonce is drawn in [1, 2**NONCE_BITS), i.e. the top
# (N.bit_length() - NONCE_BITS) bits are forced to zero. That per-nonce leak is
# tiny, but NUM_REPORTS signatures together over-determine the key via the HNP.
# ----------------------------------------------------------------------------
NONCE_BITS  = 153           # nonce in [1, 2**153): top 8 bits of the ~161-bit order are zero
NUM_REPORTS = 45            # how many routine reports the beacon will sign

def inv(a, m):
    return pow(a % m, -1, m)

def ec_add(Pt, Q):
    if Pt is None: return Q
    if Q is None: return Pt
    x1, y1 = Pt; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if Pt == Q:
        lam = (3 * x1 * x1) * inv(2 * y1, P) % P      # a = 0 for this curve
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
# Deterministic, portable DRBG: a SHA-256 counter stream keyed by (seed,label).
# Version-independent (unlike random.Random), so an instance is reproducible on
# any platform -- required for determinism and per-instance generation.
# ----------------------------------------------------------------------------
class DRBG:
    def __init__(self, seed_bytes, label):
        self._key = hashlib.sha256(label + b"|" + seed_bytes).digest()
        self._ctr = 0
        self._buf = b""

    def _refill(self):
        self._buf += hashlib.sha256(self._key + self._ctr.to_bytes(8, "big")).digest()
        self._ctr += 1

    def take(self, k):
        while len(self._buf) < k:
            self._refill()
        out, self._buf = self._buf[:k], self._buf[k:]
        return out

    def randbelow(self, bound):
        # unbiased rejection sampling in [0, bound)
        nbytes = (bound.bit_length() + 7) // 8 + 1
        limit = (256 ** nbytes) - ((256 ** nbytes) % bound)
        while True:
            v = int.from_bytes(self.take(nbytes), "big")
            if v < limit:
                return v % bound

# ----------------------------------------------------------------------------
# Deterministic primality + CRT-moduli generation (pure stdlib -- no sympy, so
# the service stays dependency-free). These feed the flag-EXTRACTION layer: the
# flag is Chinese-Remainder-split across the moduli produced here.
# ----------------------------------------------------------------------------
def _is_prime(n, wrng=None):
    # Miller-Rabin: the first 12 primes as fixed witnesses make this a very
    # strong probable-prime test; optional random witnesses from a DRBG harden
    # it further. More than adequate for 128-bit CTF moduli.
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    witnesses = list(small)
    if wrng is not None:
        for _ in range(8):
            witnesses.append(2 + wrng.randbelow(n - 3))
    for a in witnesses:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True

def _gen_moduli(seed_bytes, need, target):
    """Deterministic, pairwise-coprime (distinct prime) moduli. Per-modulus size
    is chosen so that about `target` of them are needed, and generation stops the
    instant the product first exceeds `need`. Two consequences the extraction
    relies on:
      * product > need  -> the CRT reconstruction of the flag is UNIQUE;
      * product WITHOUT the last (critical) modulus is <= need -> you genuinely
        need every residue; no proper subset reconstructs the flag.
    Distinct primes are trivially pairwise coprime."""
    rng = DRBG(seed_bytes, b"windage-crt-moduli")
    mbits = max(28, need.bit_length() // target + 2)
    top = 1 << (mbits - 1)
    mods = []
    prod = 1
    while prod <= need:
        while True:
            cand = rng.randbelow(1 << mbits) | top | 1   # full-width, odd
            if cand not in mods and _is_prime(cand, rng):
                break
        mods.append(cand)
        prod *= cand
    return mods

def _decoy_flag(flag_str):
    r"""A format-invalid near-flag. The classic 'zer0' (digit-zero) prefix defect
    makes it fail the published validator ^zerosecurectf\{[a-z0-9_]{8,48}\}$ on
    sight, so any all-decoy reconstruction is rejectable by reasoning."""
    marker = "zerosecurectf{"
    if flag_str.startswith(marker):
        return "zer0securectf{" + flag_str[len(marker):]
    return "zer0_" + flag_str

# ----------------------------------------------------------------------------
# Per-instance secrets, derived deterministically from a seed (team id).
# Every team gets a unique signing key, a unique nonce stream and a unique flag,
# so a leaked solution for one instance does not transfer to another.
# ----------------------------------------------------------------------------
SEED = os.environ.get("ZSCTF_SEED")
FLAG = os.environ.get("ZSCTF_FLAG")
if SEED is None:
    sys.stderr.write("WARNING: ZSCTF_SEED unset -- using INSECURE default placeholder seed.\n")
    SEED = "windage-default-seed"
if FLAG is None:
    sys.stderr.write("WARNING: ZSCTF_FLAG unset -- using DEFAULT placeholder flag.\n")
    FLAG = "zerosecurectf{local_review_flag}"
SEED = SEED.encode()

_key_rng   = DRBG(SEED, b"windage-signing-key")
_nonce_rng = DRBG(SEED, b"windage-nonce-stream")

d = _key_rng.randbelow(N - 1) + 1          # secret signing key in [1, N-1]
Q = ec_mul(d, G)                           # public key (published in the banner)

# ----------------------------------------------------------------------------
# Flag-EXTRACTION layer: CRT reconstruction (ASSIGNED MECHANISM).
# The flag is the beacon's decommission authorization code C. It is NOT revealed
# whole. C is split across K pairwise-coprime 128-bit prime moduli; the residue
# C mod m_j is released ONLY for a valid signature over modulus-bound attestation
# token j. A wrong/forged signature releases the DECOY residue (decoy flag
# "zer0securectf{...}", which fails the published format on sight). The product
# of the moduli exceeds C, so CRT reconstruction from the real residues is
# unique; from the decoys it is the rejectable near-flag. No single response
# contains C; C is never transmitted whole.
# ----------------------------------------------------------------------------
TARGET_SEGMENTS = 6          # moduli are sized so ~this many are needed

_flag_int  = int.from_bytes(FLAG.encode(), "big")
_decoy_str = _decoy_flag(FLAG)
_decoy_int = int.from_bytes(_decoy_str.encode(), "big")
MODULI     = _gen_moduli(SEED, max(_flag_int, _decoy_int), TARGET_SEGMENTS)
K          = len(MODULI)
REAL_RES   = [_flag_int % m for m in MODULI]
DECOY_RES  = [_decoy_int % m for m in MODULI]

def attest_token(j):
    # Distinct, modulus-bound token: a signature over token j does not transfer
    # to any other segment (verify() binds the message hash to this exact byte
    # string). The beacon never signs this itself -- forging it requires d.
    return (b"BEACON WINDAGE-7 :: command=DECOMMISSION; segment=%d; modulus=%x; "
            b"authority=FLEET-ACTUAL; effective=IMMEDIATE" % (j, MODULI[j]))

# ----------------------------------------------------------------------------
# Messages. Routine reports are signable on request; the DECOMMISSION attestation
# tokens (built from the CRT moduli, below) are NOT -- forging them requires d.
# ----------------------------------------------------------------------------
REPORTS = [
    b"BEACON WINDAGE-7 :: status=ONLINE; pos=%02d.%03dN,%03d.%03dW; seq=%d"
    % (40 + (i * 3) % 9, (i * 137) % 1000, 70 + (i * 5) % 20, (i * 311) % 1000, i)
    for i in range(NUM_REPORTS)
]

def H(msg):
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N

# ---- per-request nonce derivation (the planted weakness) -------------------
# The beacon derives each nonce from its biased RNG: the value is uniform in
# [1, 2**NONCE_BITS), so the top (bitlen(N) - NONCE_BITS) bits are always zero.
# That is the "windage". The derivation is deterministic per report index so the
# service is stateless and reproducible.
def nonce(i):
    rng = DRBG(SEED, b"windage-nonce|%d" % i)
    return rng.randbelow((1 << NONCE_BITS) - 1) + 1

def sign_index(i):
    m = H(REPORTS[i])
    k = nonce(i)
    R = ec_mul(k, G)
    r = R[0] % N
    s = inv(k, N) * (m + r * d) % N
    if r == 0 or s == 0:
        raise ValueError("degenerate signature")
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
# Line protocol
# ----------------------------------------------------------------------------
def banner():
    out = []
    out.append("=== ZSCTF Beacon WINDAGE-7 :: ECDSA status signer (secp160k1) ===")
    out.append("curve secp160k1  p %x" % P)
    out.append("curve secp160k1  n %x" % N)
    out.append("curve secp160k1  Gx %x" % Gx)
    out.append("curve secp160k1  Gy %x" % Gy)
    out.append("pubkey Qx %x" % Q[0])
    out.append("pubkey Qy %x" % Q[1])
    out.append("advisory: RNG windage -- every nonce k satisfies 1 <= k < 2^%d" % NONCE_BITS)
    out.append("routine reports available for signing: index 0..%d" % (NUM_REPORTS - 1))
    out.append("decommission: authorization code C (the flag bytes as a big-endian int)")
    out.append("  is CRT-split across %d pairwise-coprime moduli; residue (C mod m_j) is" % K)
    out.append("  released ONLY for a VALID signature over attestation token j, a")
    out.append("  DECOMMISSION order the beacon will not sign for you. Reconstruct C by CRT.")
    for j, m in enumerate(MODULI):
        out.append("modulus %d %x" % (j, m))
    out.append("attestation token j (exact bytes to sign): BEACON WINDAGE-7 :: "
               "command=DECOMMISSION; segment=<j>; modulus=<m_j as lowercase hex>; "
               "authority=FLEET-ACTUAL; effective=IMMEDIATE")
    out.append("a WRONG/forged signature returns a DECOY residue -- it reconstructs to a")
    out.append("  near-flag that FAILS ^zerosecurectf{[a-z0-9_]{8,48}}$; verify before trusting")
    out.append("commands: SIGN <i> | SUBMIT <j> <r_hex> <s_hex> | QUIT")
    return "\n".join(out)

def handle_line(line):
    parts = line.strip().split()
    if not parts:
        return ""
    cmd = parts[0].upper()
    try:
        if cmd == "SIGN":
            i = int(parts[1])
            if not (0 <= i < NUM_REPORTS):
                return "ERR index out of range"
            r, s = sign_index(i)
            return "SIG %x %x %s" % (r, s, REPORTS[i].hex())
        if cmd == "SUBMIT":
            j = int(parts[1]); r = int(parts[2], 16); s = int(parts[3], 16)
            if not (0 <= j < K):
                return "ERR segment index out of range (0..%d)" % (K - 1)
            if verify(attest_token(j), r, s):
                return "RESIDUE %d %x" % (j, REAL_RES[j])
            # Wrong/forged signature -> DECOY residue (never an error): a careless
            # solver who skips the key recovery reconstructs a rejectable near-flag.
            return "RESIDUE %d %x" % (j, DECOY_RES[j])
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
