#!/usr/bin/env python3
"""ZSCTF :: Wren  (crypto, Hard)

An IoT device uses a deliberately SMALL RSA private exponent d for fast
decryption/signing (a real performance shortcut). A small d is catastrophic:
Wiener's attack recovers it from the public (N, e) alone.

Recovering d is only the GATE. It earns you the device's private key operation
(RSA decryption, c^d mod N) -- the *means*, not the flag. The activation token
is delivered as a staged "activation chain": the device hands out one encrypted
activation record at a time. Each record you decrypt carries (a) one fragment of
the activation token and (b) an 8-byte *link* nonce. You must present that link
(LINK <hex>) to make the device release the NEXT stage's ciphertext. Only by
walking every stage and concatenating the CRC-authenticated fragments do you
assemble the full token. The token never crosses the wire in cleartext and no
single response contains it.

Players are given this source.
"""
import os, sys, hashlib, zlib, socketserver

def _stream(seed, label):
    ctr = 0
    while True:
        for b in hashlib.sha256(seed + b"|" + label + b"|" + ctr.to_bytes(8, "big")).digest():
            yield b
        ctr += 1

def _take(gen, nbytes):
    return bytes(next(gen) for _ in range(nbytes))

def _rand_odd(gen, nbits):
    v = int.from_bytes(_take(gen, (nbits + 7) // 8), "big")
    return (v | (1 << (nbits - 1)) | 1)

def _is_prime(n, gen):
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(20):
        a = 2 + int.from_bytes(_take(gen, 16), "big") % (n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        ok = False
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                ok = True
                break
        if not ok:
            return False
    return True

def _prime(gen, nbits):
    while True:
        c = _rand_odd(gen, nbits)
        if _is_prime(c, gen):
            return c

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

SEED = os.environ.get("ZSCTF_SEED", "wren-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_SEED" not in os.environ or "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("[warn] ZSCTF_SEED/ZSCTF_FLAG unset; demo defaults in use -- do NOT deploy unconfigured\n")

# ---- The deliberate flaw: 1024-bit N with a ~200-bit private exponent d ----
_g = _stream(SEED, b"primes")
P = _prime(_g, 512)
Q = _prime(_g, 512)
N = P * Q
PHI = (P - 1) * (Q - 1)
# small private exponent (~200-bit, well under the Wiener bound N^0.25/3 ~ 2^252)
_dg = _stream(SEED, b"d")
while True:
    D = _rand_odd(_dg, 200)
    g, _, _ = egcd(D, PHI)
    if g == 1:
        break
E = pow(D, -1, PHI)

# ---------------------------------------------------------------------------
# Activation chain (S2/S2a extraction layer).
#
# The flag is split into N_STAGES fragments.  For stage i we build a fixed
# BLK-byte record:
#     b"WREN" | idx(1) | nstages(1) | link(8) | declen(1) | decoy_frag |
#               reallen(1) | real_frag | crc32(real_frag)(4)   ... zero padded
# then encrypt it under the PUBLIC key:  ct_i = record^E mod N.
# Recovering d (Wiener) lets the solver compute record = ct_i^d mod N, read the
# real fragment (authenticated by its CRC32) and the 8-byte link, then present
# the link to release ct_{i+1}.  Fragments are decrypted client-side and never
# appear in any server response; the token is assembled only by walking all
# stages.  The `decoy_frag` fields concatenate to an uppercase near-flag -- a
# rabbit-hole that FAILS the strict validator ^zerosecurectf\{[a-z0-9_]{8,48}\}$.
# ---------------------------------------------------------------------------
BLK = 64
MAGIC = b"WREN"

def _split(data, n):
    """Split bytes into exactly n near-even chunks (last absorbs remainder)."""
    size = (len(data) + n - 1) // n if len(data) else 0
    out = [data[i * size:(i + 1) * size] for i in range(n)]
    # guarantee reassembly == data regardless of rounding
    joined = b"".join(out)
    if joined != data:
        out[-1] += data[len(joined):]
    return out

def _decoy_token(flag_str):
    """A plausible-but-invalid near-flag: same wrapper, UPPERCASED body.
    Guaranteed to differ from the real flag and to fail the strict validator."""
    pre = "zerosecurectf{"
    if flag_str.startswith(pre) and flag_str.endswith("}"):
        body = flag_str[len(pre):-1]
    else:
        body = flag_str
    up = body.upper()
    if up == body:                       # body had no letters to uppercase
        up = "X" + body                  # force a format defect anyway
    return pre + up + "}"

def build_chain(flag_str):
    fb = flag_str.encode()
    CHUNK = 5
    n = max(2, (len(fb) + CHUNK - 1) // CHUNK)
    real_chunks = _split(fb, n)
    decoy_chunks = _split(_decoy_token(flag_str).encode(), n)
    cts, links = [], []
    for i in range(n):
        link = hashlib.sha256(SEED + b"|link|" + i.to_bytes(4, "big")).digest()[:8]
        real = real_chunks[i]
        dec = decoy_chunks[i]
        rec = (MAGIC + bytes([i, n]) + link +
               bytes([len(dec)]) + dec +
               bytes([len(real)]) + real +
               zlib.crc32(real).to_bytes(4, "big"))
        if len(rec) > BLK:
            raise ValueError("activation record overflow (flag too long for BLK)")
        r_int = int.from_bytes(rec.ljust(BLK, b"\x00"), "big")
        cts.append(pow(r_int, E, N))
        links.append(link)
    return n, cts, links

N_STAGES, CTS, LINKS = build_chain(FLAG)
FPR = "%08x" % zlib.crc32(FLAG.encode())      # integrity tag of the assembled token

def banner():
    return "\n".join([
        "=== ZSCTF Device Activation (staged) ===",
        "N %x" % N, "e %x" % E, "c %x" % CTS[0],
        "stages %d" % N_STAGES,
        "blk %d" % BLK,
        "fpr %s" % FPR,
        "; firmware note: factory test key activation=zerosecurectf{FACTORY_TEST_KEY}",
        "the device decrypts fast (small d). recover d, then WALK the activation chain:",
        "each stage decrypt the current ciphertext (record = c^d mod N), read its",
        "8-byte link, send LINK <link_hex> to release the next stage's ciphertext.",
        "concatenate every stage's CRC-authenticated fragment to assemble the token.",
        "commands: LINK <link_hex> | SUBMIT <token_hex> | QUIT",
    ])

class Session:
    """Per-connection activation state. stage = highest released ciphertext index."""
    def __init__(self):
        self.stage = 0

    def handle(self, line):
        p = line.strip().split()
        if not p:
            return ""
        cmd = p[0].upper()
        if cmd == "QUIT":
            return "__QUIT__"
        if cmd == "SUBMIT":
            # Footgun: the textbook "decrypt the ciphertext and submit it" path.
            # It never yields the flag -- staged activation is mandatory.
            return "DENIED staged activation in effect; prove each stage with LINK <link_hex>"
        if cmd == "LINK":
            if self.stage >= N_STAGES:
                return "DONE activation sequence already complete"
            try:
                got = bytes.fromhex(p[1])
            except (IndexError, ValueError):
                return "ERR malformed link"
            if got != LINKS[self.stage]:
                return "DENIED bad activation proof for stage %d" % self.stage
            self.stage += 1
            if self.stage < N_STAGES:
                return "NEXT %x" % CTS[self.stage]
            return "DONE activation sequence complete"
        return "ERR unknown command"

def serve_stdio():
    sess = Session()
    print(banner(), flush=True)
    for line in sys.stdin:
        r = sess.handle(line)
        if r == "__QUIT__":
            break
        if r:
            print(r, flush=True)

class H(socketserver.StreamRequestHandler):
    def handle(self):
        sess = Session()
        self.wfile.write((banner() + "\n").encode())
        for raw in self.rfile:
            r = sess.handle(raw.decode(errors="ignore"))
            if r == "__QUIT__":
                break
            if r:
                self.wfile.write((r + "\n").encode())

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--tcp":
        host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 1337
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        with socketserver.ThreadingTCPServer((host, port), H) as s:
            sys.stderr.write("listening %s:%d\n" % (host, port))
            sys.stderr.flush()
            s.serve_forever()
    else:
        serve_stdio()
