#!/usr/bin/env python3
"""
ZSCTF :: Palimpsest  (crypto, Extreme)

A central *audit-log collector*. It encrypts every log record it accepts with
AES-256-GCM and will act on authenticated control records. Through a
configuration bug it reuses the *same (key, nonce)* for every record it writes.
In AES-GCM that is forbidden, and the earlier record bleeds through the later
one -- not just the keystream (a two-time pad) but the GHASH authentication key
itself, which an attacker can solve for and then use to forge tags at will.

CRUX (unchanged): recover the GHASH authentication subkey H from the reused-nonce
forbidden attack (Joux 2006). What recovering H buys you has changed, though --
it does NOT hand over the flag. Instead H is the *means to extract*:

  The collector holds a secret disclosure polynomial  P(x)  over GF(2^128). The
  flag is packed into P's coefficients (constant term first). The collector will
  release a single evaluation  P(x_i)  -- one field element, never the flag --
  but ONLY in response to a record whose authenticated plaintext is a valid,
  point-bound disclosure directive  "disclose:flag:<i>".  Forging the tag for
  that directive needs H (the collector refuses to self-seal any directive). One
  evaluation reveals nothing; you must forge k distinct directives, collect k
  evaluations P(x_1)..P(x_k), and Lagrange-interpolate P offline to read the
  flag off its coefficients. k is published in the banner as `shares`.

  A second, decoy stream "disclose:audit:<i>" evaluates a DIFFERENT polynomial Q
  whose coefficients interpolate to a flag-shaped near-miss that fails the
  published strict validator ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$ . Both streams
  need a valid forged tag; the discriminator between the real flag and the decoy
  is the strict format rule, published in the banner.

Players are given this exact source file. The flaw (one fixed nonce) is in plain
sight; the field math is the work.
"""
import os, sys, re, hashlib, socketserver
from Crypto.Cipher import AES

TAG_LEN   = 16          # 128-bit GCM tag
NONCE_LEN = 12          # 96-bit GCM nonce (the standard, single-block-counter case)
MAX_LOG   = 64          # bytes; keep records small (and the attacker's algebra small)

# Published strict flag validator. The real disclosure polynomial interpolates to
# a string matching this; the decoy polynomial does not. This IS the discriminator.
FLAG_RE = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")

# ----------------------------------------------------------------------------
# Per-instance secrets, derived deterministically from a seed (team id).
# ----------------------------------------------------------------------------
def _derive(seed, label, length):
    """Deterministic byte string of `length` bytes from (seed, label)."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + b"|" + label + b"|" + str(counter).encode()).digest()
        counter += 1
    return out[:length]

SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("WARNING: ZSCTF_FLAG unset; using default placeholder flag\n")
    sys.stderr.flush()

KEY   = _derive(SEED, b"gcm-key", 32)        # secret AES-256 key
NONCE = _derive(SEED, b"gcm-nonce", 12)      # the nonce -- fixed, and (the bug) REUSED for every record

# A constant record tag the collector stamps on every record (authenticated,
# not encrypted). Being constant, it is the same for every instance; the secret
# that actually varies per instance is the key (hence H) and the nonce.
AAD = b"zerosecure-audit-collector/v3"

# The legacy privileged directive. Historically a record decrypting to exactly
# these 32 bytes released the flag; it is SUPERSEDED by the share-gated
# disclosure protocol below and now only acknowledges (it never releases the
# flag). Kept public (and refused by LOG) so the old footgun is still visible.
ADMIN = b"action=disclose;scope=audit-flag"   # exactly 32 bytes == 2 AES blocks
assert len(ADMIN) == 32

# ============================================================================
# GF(2^128) exactly as GCM uses it (SP 800-38D): reduction poly x^128+x^7+x^2+x+1,
# constant R = 0xE1<<120, GCM bit convention (MSB of byte 0 is the lowest-degree
# term). A field element is a 128-bit int. This is the SAME field the GHASH
# authenticator lives in -- the disclosure polynomial reuses it on purpose.
# ============================================================================
R   = 0xE1 << 120
ONE = 1 << 127                       # the multiplicative identity in this convention

def gf_mul(x, y):
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ R if (v & 1) else (v >> 1)
    return z

# ----------------------------------------------------------------------------
# The disclosure polynomial. The flag is packed, length-prefixed, into 16-byte
# field elements which become the coefficients c_0, c_1, ... (constant term
# first). P(x) = c_0 (+) c_1*x (+) c_2*x^2 (+) ...   (all ops in GF(2^128)).
# A single evaluation P(x_i) is a GF(2^128) combination of ALL coefficients, so
# it leaks no individual coefficient; k evaluations are required to interpolate.
# ----------------------------------------------------------------------------
def pack_coeffs(flag_str):
    body = len(flag_str).to_bytes(2, "big") + flag_str.encode()
    if len(body) % 16:
        body += b"\x00" * (16 - len(body) % 16)
    return [int.from_bytes(body[i:i + 16], "big") for i in range(0, len(body), 16)]

def _decoy_flag(real):
    """A per-instance, flag-shaped NEAR-MISS, same length as the real flag, with
    an UPPERCASE marker so it provably fails ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$."""
    inner_len = max(8, len(real) - len("zerosecurectf{}"))
    filler = "DECOY" + _derive(SEED, b"decoy-stream", 64).hex()
    return "zerosecurectf{" + filler[:inner_len] + "}"

FLAG_COEFFS  = pack_coeffs(FLAG)                 # real polynomial (constant term first)
SHARES       = len(FLAG_COEFFS)                  # k: evaluations needed to interpolate
_decoy       = _decoy_flag(FLAG)
DECOY_COEFFS = pack_coeffs(_decoy)
while len(DECOY_COEFFS) < SHARES:                # same degree as the real polynomial
    DECOY_COEFFS.append(0)
DECOY_COEFFS = DECOY_COEFFS[:SHARES]
assert not FLAG_RE.match(_decoy), "decoy near-flag must fail the strict validator"

def point(i):
    """Evaluation abscissa for share i (i = 1..k): the field element whose integer
    value is i. Distinct and nonzero -> the Vandermonde system is invertible."""
    return i

def poly_eval(coeffs, x):
    acc = 0
    xp = ONE                                     # x^0 == field identity
    for c in coeffs:
        acc ^= gf_mul(c, xp)
        xp = gf_mul(xp, x)
    return acc

# ----------------------------------------------------------------------------
# The collector's crypto. A real library (pycryptodome) does the AES-GCM; the
# ONLY thing wrong is that NONCE is a fixed constant reused on every call.
# ----------------------------------------------------------------------------
def gcm_seal(plaintext):
    c = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)   # <-- same key+nonce every time: forbidden
    c.update(AAD)
    ct, tag = c.encrypt_and_digest(plaintext)
    return ct, tag

def gcm_open(ct, tag):
    """Return the plaintext iff the GCM tag is valid under the fixed key+nonce+AAD,
    else None. (Standard AEAD: an invalid tag reveals nothing but its invalidity.)"""
    c = AES.new(KEY, AES.MODE_GCM, nonce=NONCE)
    c.update(AAD)
    try:
        return c.decrypt_and_verify(ct, tag)
    except ValueError:
        return None

# A directive is "disclose:<stream>:<i>" with stream in {flag, audit}, i decimal.
_DIRECTIVE = re.compile(rb"^disclose:(flag|audit):([0-9]{1,3})$")

def is_directive(pt):
    """True for any disclosure directive or the legacy ADMIN -- the plaintexts the
    collector must never self-seal (else a forged tag would not need H)."""
    return pt == ADMIN or _DIRECTIVE.match(pt) is not None or pt.startswith(b"disclose:")

# ----------------------------------------------------------------------------
# Line protocol
# ----------------------------------------------------------------------------
def banner():
    out = []
    out.append("=== ZSCTF Audit-Log Collector v3 ===")
    out.append("scheme: AES-256-GCM, %d-byte tag; every record is sealed under a FIXED nonce" % TAG_LEN)
    out.append("nonce %s" % NONCE.hex())
    out.append("aad %s" % AAD.hex())
    out.append("admin %s  (legacy directive; superseded, no longer releases the flag)" % ADMIN.hex())
    out.append("shares %d" % SHARES)
    out.append("disclosure: present a VALID record (ct,tag) decrypting to \"disclose:<stream>:<i>\"")
    out.append("  to receive  EVAL <i> <hex>  == P_<stream>(x_i),  x_i = i in GF(2^128)")
    out.append("  (reduction x^128+x^7+x^2+x+1, GCM bit order); collect i=1..%d and interpolate." % SHARES)
    out.append("  the audit flag is the stream whose reconstruction matches ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$")
    out.append("commands: LOG <plaintext_hex> | EXEC <ct_hex> <tag_hex> | QUIT")
    return "\n".join(out)

def handle_line(line):
    parts = line.strip().split()
    if not parts:
        return ""
    cmd = parts[0].upper()
    try:
        if cmd == "LOG":
            pt = bytes.fromhex(parts[1])
            if not (1 <= len(pt) <= MAX_LOG):
                return "ERR plaintext must be 1..%d bytes" % MAX_LOG
            if is_directive(pt):
                return "DENIED the collector will not self-seal a disclosure directive"
            ct, tag = gcm_seal(pt)
            return "REC %s %s" % (ct.hex(), tag.hex())
        if cmd == "EXEC":
            ct = bytes.fromhex(parts[1]); tag = bytes.fromhex(parts[2])
            if len(tag) != TAG_LEN:
                return "ERR tag must be %d bytes" % TAG_LEN
            pt = gcm_open(ct, tag)
            if pt is None:
                return "DENIED tag invalid"          # AEAD integrity: forging needs H
            if pt == ADMIN:
                return "OK legacy directive acknowledged; disclosure is share-gated now"
            m = _DIRECTIVE.match(pt)
            if m:
                stream = m.group(1)
                i = int(m.group(2))
                if not (1 <= i <= SHARES):
                    return "ERR share index must be 1..%d" % SHARES
                coeffs = FLAG_COEFFS if stream == b"flag" else DECOY_COEFFS
                y = poly_eval(coeffs, point(i))
                return "EVAL %d %032x" % (i, y)
            return "OK record accepted (%d bytes)" % len(pt)
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
