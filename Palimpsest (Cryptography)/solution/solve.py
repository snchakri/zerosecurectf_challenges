#!/usr/bin/env python3
"""
ZSCTF :: Palimpsest -- reference solver.

Intended path (the AES-GCM "forbidden attack" -- nonce reuse / authentication-key
recovery; Joux, "Authentication Failures in NIST Version of GCM", 2006). No key
is ever recovered and AES is never broken; only the maths of GHASH is used.

  1. The collector seals every record with the SAME (key, nonce). In GCM the tag
     is  T = GHASH_H(AAD, C) (+) E ,  where (+) is XOR, E = AES_K(J0) depends only
     on the nonce, and H = AES_K(0^128) is the GHASH authentication key. Because
     the nonce is reused, E is identical for every record.

  2. GHASH is a polynomial in H over GF(2^128):
        GHASH_H(AAD, C) = sum_k  block_k * H^(m-k+1)
     So for two records of equal shape, T_1 (+) T_2 cancels E and leaves a known
     polynomial in H that evaluates to zero:
        f_12(H) = GHASH_H(AAD,C_1) (+) GHASH_H(AAD,C_2) (+) (T_1 (+) T_2) = 0
     We only need the public (C_i, T_i) -- never the plaintexts -- to build it.

  3. Solve f_12 over GF(2^128) (root-finding: split off the linear part with
     gcd(f, x^(2^128)+x), then Berlekamp's trace algorithm). f_12 has a few
     candidate roots; the true H is pinned down with a third record
     (E = T_1 (+) GHASH_H(AAD,C_1) must also reproduce T_3).

  4. Forge. With H and E known, the valid tag for ANY (AAD, C*) is
        T* = GHASH_H(AAD, C*) (+) E .
     To make C* decrypt to the admin directive we also need the keystream, which
     nonce reuse hands us for free: for a record we logged with known plaintext
     P, keystream = P (+) C, so  C* = ADMIN (+) keystream . Submit (C*, T*).

Implements GF(2^128) from scratch (stdlib only); the collector's own crypto is a
real library, so the forged tag is checked by real AES-GCM.

EXTRACTION LAYER (what H actually buys you): recovering H does NOT yield the flag.
The collector holds a secret disclosure polynomial P(x) over the SAME GF(2^128),
with the flag packed (length-prefixed) into its coefficients. A valid forged tag
for the point-bound directive "disclose:flag:<i>" releases ONE evaluation P(x_i)
-- a single field element, never the flag. We forge k such directives (k is the
banner's `shares`), collect P(x_1)..P(x_k), and Lagrange-interpolate P offline
(hand-rolled, below) to read the flag off its coefficients. A careless solver who
chases the "disclose:audit:<i>" stream interpolates a DIFFERENT polynomial to a
flag-shaped near-miss; we reject it by the published strict validator.

Run locally against the source:   python3 solve.py --local ../challenge/server.py
Run against a deployed instance:  python3 solve.py --remote HOST PORT
"""
import sys, subprocess, socket, argparse, random, re

FLAG_RE = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")  # published strict validator

# ============================================================================
# GF(2^128) as used by GCM: reduction poly x^128 + x^7 + x^2 + x + 1, with GCM's
# bit convention (the most-significant bit of byte 0 is the lowest-degree term).
# A field element is a 128-bit Python int = int.from_bytes(block, "big").
# ============================================================================
R   = 0xE1 << 120           # the GCM reduction constant
ONE = 1 << 127              # the multiplicative identity in this bit convention

def gf_mul(x, y):
    """Carry-less multiply-and-reduce in GF(2^128), GCM convention (SP 800-38D)."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:        # consume bits of x from the MSB downward
            z ^= v
        v = (v >> 1) ^ R if (v & 1) else (v >> 1)
    return z

def gf_pow(a, e):
    r = ONE
    while e:
        if e & 1:
            r = gf_mul(r, a)
        a = gf_mul(a, a)
        e >>= 1
    return r

def gf_inv(a):
    return gf_pow(a, (1 << 128) - 2)    # Fermat: a^(2^128 - 2)

# ============================================================================
# Polynomials over GF(2^128), coefficient lists low-degree -> high-degree.
# ============================================================================
def p_trim(p):
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p

def p_deg(a):
    a = p_trim(a[:]); return len(a) - 1

def p_add(a, b):                        # addition == XOR in characteristic 2
    n = max(len(a), len(b)); r = [0] * n
    for i in range(len(a)): r[i] ^= a[i]
    for i in range(len(b)): r[i] ^= b[i]
    return p_trim(r)

def p_mul(a, b):
    if a == [0] or b == [0]: return [0]
    r = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if not ai: continue
        for j, bj in enumerate(b):
            if bj: r[i + j] ^= gf_mul(ai, bj)
    return p_trim(r)

def p_scale(a, s):
    return p_trim([gf_mul(c, s) for c in a])

def p_divmod(a, b):
    b = p_trim(b[:])
    if b == [0]: raise ZeroDivisionError("polynomial division by zero")
    db = p_deg(b); lead_inv = gf_inv(b[-1])
    q = [0] * (max(0, p_deg(a) - db) + 1)
    rem = p_trim(a[:])
    while rem != [0] and p_deg(rem) >= db:
        shift = p_deg(rem) - db
        coef = gf_mul(rem[-1], lead_inv)
        q[shift] ^= coef
        for i, bc in enumerate(b):
            rem[i + shift] ^= gf_mul(coef, bc)
        rem = p_trim(rem)
    return p_trim(q), rem

def p_mod(a, b):
    return p_divmod(a, b)[1]

def p_gcd(a, b):
    a = p_trim(a[:]); b = p_trim(b[:])
    while b != [0]:
        a, b = b, p_mod(a, b)
    return a

def p_monic(a):
    a = p_trim(a[:])
    return a if a == [0] else p_scale(a, gf_inv(a[-1]))

# ---- root finding over GF(2^128) -------------------------------------------
def _x_to_2_128_mod(f):
    """Return x^(2^128) mod f, by squaring x a hundred-and-twenty-eight times."""
    h = p_mod([0, ONE], f)              # x  mod f
    for _ in range(128):
        h = p_mod(p_mul(h, h), f)       # repeatedly square -> x^(2^128)
    return h

def roots(f):
    """All roots of f in GF(2^128)."""
    f = p_monic(f)
    if p_deg(f) <= 0:
        return []
    # g = gcd(f, x^(2^128) - x) collects exactly the distinct linear factors.
    g = p_monic(p_gcd(f, p_add(_x_to_2_128_mod(f), [0, ONE])))
    if p_deg(g) <= 0:
        return []
    out = []
    _bta(g, out)
    return out

def _bta(g, out):
    """Berlekamp trace algorithm: split g (a product of distinct linear factors)
    into its roots over GF(2^128)."""
    g = p_monic(g); d = p_deg(g)
    if d <= 0:
        return
    if d == 1:                          # monic (x + c) -> root c
        out.append(g[0]); return
    while True:
        beta = random.getrandbits(128)
        if beta == 0:
            continue
        # trace polynomial of beta*x modulo g: sum_{i=0}^{127} (beta*x)^(2^i)
        acc = [0]
        cur = p_mod([0, beta], g)       # beta * x
        for _ in range(128):
            acc = p_add(acc, cur)
            cur = p_mod(p_mul(cur, cur), g)
        factor = p_gcd(g, p_mod(acc, g))
        if 0 < p_deg(factor) < d:
            break
    _bta(factor, out)
    _bta(p_divmod(g, factor)[0], out)

# ============================================================================
# GHASH (verified bit-for-bit against pycryptodome's GCM tag).
# ============================================================================
def _blocks(data):
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        if len(chunk) < 16:
            chunk += b"\x00" * (16 - len(chunk))
        out.append(int.from_bytes(chunk, "big"))
    return out

def ghash(H, aad, ct):
    y = 0
    for b in _blocks(aad): y = gf_mul(y ^ b, H)
    for b in _blocks(ct):  y = gf_mul(y ^ b, H)
    lenblock = ((len(aad) * 8) << 64) | (len(ct) * 8)
    return gf_mul(y ^ lenblock, H)

def ghash_poly(aad, ct):
    """GHASH_H(aad, ct) as a polynomial in the unknown H (coeffs low->high)."""
    blks = _blocks(aad) + _blocks(ct) + [((len(aad) * 8) << 64) | (len(ct) * 8)]
    m = len(blks)
    p = [0] * (m + 1)
    for k, b in enumerate(blks):        # block k+1 is multiplied by H^(m-k)
        p[m - k] ^= b
    return p_trim(p)

def xor(a, b):
    return bytes(i ^ j for i, j in zip(a, b))

# ============================================================================
# Disclosure-polynomial extraction: Lagrange interpolation over GF(2^128) and
# the flag packing (MUST match challenge/server.py byte-for-byte). The abscissa
# for share i is the field element whose integer value is i.
# ============================================================================
def point(i):
    return i

def interpolate(points):
    """Lagrange-interpolate a polynomial (coeffs low->high) through the field
    points [(x_i, y_i), ...] over GF(2^128). Subtraction == XOR (characteristic 2)."""
    result = [0]
    for j, (xj, yj) in enumerate(points):
        num = [ONE]                       # the constant polynomial "1"
        denom = ONE
        for m, (xm, _) in enumerate(points):
            if m == j:
                continue
            num = p_mul(num, [xm, ONE])   # (x + xm): constant term xm, linear coeff 1
            denom = gf_mul(denom, xj ^ xm)
        result = p_add(result, p_scale(num, gf_mul(yj, gf_inv(denom))))
    return result

def unpack_flag(coeffs, k):
    """Invert server's pack_coeffs: concatenate k 16-byte big-endian coefficients,
    read the 2-byte big-endian length prefix, slice out the flag bytes."""
    coeffs = (coeffs + [0] * k)[:k]
    raw = b"".join(c.to_bytes(16, "big") for c in coeffs)
    n = int.from_bytes(raw[:2], "big")
    return raw[2:2 + n]

# ============================================================================
# Transport (identical shape to the other ZSCTF crypto solvers).
# ============================================================================
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
    """Read lines until 'commands:'; return (nonce, aad, admin, shares)."""
    nonce = aad = admin = shares = None
    while True:
        line = io.readline()
        if not line:
            raise RuntimeError("service closed during banner")
        line = line.rstrip("\n")
        if line.startswith("nonce "):    nonce  = bytes.fromhex(line.split()[1])
        elif line.startswith("aad "):    aad    = bytes.fromhex(line.split()[1])
        elif line.startswith("admin "):  admin  = bytes.fromhex(line.split()[1])
        elif line.startswith("shares "): shares = int(line.split()[1])
        elif line.startswith("commands:"):
            break
    if None in (nonce, aad, admin, shares):
        raise RuntimeError("banner missing nonce/aad/admin/shares")
    return nonce, aad, admin, shares

def log_record(io, pt):
    """LOG a known plaintext; return (plaintext, ct, tag)."""
    io.send("LOG " + pt.hex())
    resp = io.readline().rstrip("\n")
    assert resp.startswith("REC "), "unexpected LOG response: %r" % resp
    _, ct_hex, tag_hex = resp.split()
    return pt, bytes.fromhex(ct_hex), bytes.fromhex(tag_hex)

# ============================================================================
# The attack.
# ============================================================================
def recover_H(aad, records):
    """records: list of (pt, ct, tag). Recover the GHASH key H via the forbidden
    attack. Uses records[0],[1] to build the polynomial and records[2] to pin the
    unique root."""
    (_, c0, t0), (_, c1, t1), (_, c2, t2) = records[0], records[1], records[2]
    # f_12(H) = GHASH(C0) + GHASH(C1) + (T0 + T1) = 0
    f = p_add(ghash_poly(aad, c0), ghash_poly(aad, c1))
    f = p_add(f, [int.from_bytes(t0, "big") ^ int.from_bytes(t1, "big")])
    candidates = roots(f)

    def consistent(H):
        E = int.from_bytes(t0, "big") ^ ghash(H, aad, c0)
        return (ghash(H, aad, c2) ^ E).to_bytes(16, "big") == t2

    survivors = [H for H in candidates if consistent(H)]
    if len(survivors) != 1:
        raise RuntimeError("expected a unique H, got %d candidate(s): %r"
                           % (len(survivors), [hex(s) for s in survivors]))
    return survivors[0]

def request_eval(io, H, E, aad, known_pt, known_ct, stream, i):
    """Forge the directive 'disclose:<stream>:<i>' and submit it; return (x_i, y_i)
    where y_i = P_<stream>(x_i), or raise if the service did not return an EVAL."""
    msg = b"disclose:%s:%d" % (stream, i)
    keystream = xor(known_pt, known_ct)
    assert len(keystream) >= len(msg), "known record too short for directive keystream"
    ct_star = xor(msg, keystream[:len(msg)])
    tag_star = (ghash(H, aad, ct_star) ^ E).to_bytes(16, "big")
    io.send("EXEC %s %s" % (ct_star.hex(), tag_star.hex()))
    resp = io.readline().rstrip("\n")
    parts = resp.split()
    if len(parts) != 3 or parts[0] != "EVAL" or int(parts[1]) != i:
        raise RuntimeError("unexpected EXEC response for %r: %r" % (msg, resp))
    return point(i), int(parts[2], 16)

def extract(io, H, aad, known, k, stream=b"flag"):
    """Forge k point-bound directives, collect k evaluations P_<stream>(x_i), and
    Lagrange-interpolate to recover the packed flag bytes (offline)."""
    known_pt, known_ct, known_tag = known
    E = int.from_bytes(known_tag, "big") ^ ghash(H, aad, known_ct)
    pts = [request_eval(io, H, E, aad, known_pt, known_ct, stream, i)
           for i in range(1, k + 1)]
    coeffs = interpolate(pts)
    return unpack_flag(coeffs, k)

def solve(io):
    nonce, aad, admin, shares = read_banner(io)
    # Three DISTINCT, EQUAL-LENGTH known records under the reused nonce. Equal
    # length makes the GHASH length-block cancel, keeping the polynomial small;
    # the length gives us enough keystream to forge the disclosure directives.
    plaintexts = [b"audit: user=alice action=login ok#1",
                  b"audit: user=bob   action=logout ok#2",
                  b"audit: user=carol action=export ok#3"]
    L = 40
    plaintexts = [p[:L].ljust(L, b".") for p in plaintexts]
    records = [log_record(io, p) for p in plaintexts]

    H = recover_H(aad, records)

    # local cross-check: our own GHASH must reproduce the known tags from H
    E = int.from_bytes(records[0][2], "big") ^ ghash(H, aad, records[0][1])
    assert (ghash(H, aad, records[1][1]) ^ E).to_bytes(16, "big") == records[1][2]

    # H is the MEANS to extract, not the flag. The banner advertises two disclosure
    # streams, "flag" and "audit"; only one reconstructs to a string matching the
    # published strict validator ^zerosecurectf{[a-z0-9_]{8,48}}$ -- that is the
    # discriminator, so we try BOTH and keep the one that validates (this is exactly
    # how a careful solver rejects the decoy without guessing).
    candidates = {}
    for stream in (b"flag", b"audit"):
        recon = extract(io, H, aad, records[0], shares, stream=stream).decode("latin-1")
        candidates[stream.decode()] = recon

    valid = [v for v in candidates.values() if FLAG_RE.match(v)]
    if len(valid) == 1:
        return H, valid[0]
    # Fallback (only the unreplaced default placeholder fails the validator in a
    # real deployment the organizer's flag always validates and is unique).
    return H, candidates["flag"]

def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="SERVER_PY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    args = ap.parse_args()
    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        H, flag = solve(io)
        print("[+] recovered GHASH key H = %032x" % H)
        print("[+] interpolated disclosure polynomial and reconstructed the flag")
        print("[+] FLAG =", flag)
        return 0
    finally:
        io.close()

if __name__ == "__main__":
    sys.exit(main())
