#!/usr/bin/env python3
"""
ZSCTF :: Matryoshka  (crypto, Easy)

An intercepted message was wrapped in several nested layers of *encoding* and a
light classical cipher. Nothing here is a real secret algorithm -- every layer
is a standard, reversible transform whose output advertises itself (by its
alphabet). The puzzle is to recognise each layer and peel them, one at a time,
until the flag falls out.

The wrapping (outermost last), applied to the intercepted message:

    message
      -> Caesar shift by K           (letters only; K is per-instance, 1..25)
      -> Atbash                      (letters only; a<->z, b<->y, ...)
      -> Base32 encode               (RFC 4648; alphabet A-Z 2-7, '=' padding)
      -> Base64 encode               (alphabet A-Za-z0-9+/, '=' padding)
      -> Hex encode                  (lowercase 0-9a-f)

The service just hands you the final hex blob. Everything needed to reverse it
is standard and self-evident from each layer's character set -- see solve.py.

Self-contained: Python standard library only.
"""
import os
import sys
import base64
import hashlib
import binascii
import socketserver

SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG")
if FLAG is None:
    sys.stderr.write("WARNING: ZSCTF_FLAG is not set; wrapping the placeholder "
                     "token.\n")
    sys.stderr.flush()
    FLAG = "zerosecurectf{local_review_flag}"


# ---------------------------------------------------------------------------
# Per-instance parameters, derived deterministically from the seed.
#   - K    : the Caesar shift (1..25), so the same flag looks different per team.
#   - tag  : a 32-bit session id folded into the message envelope, so even two
#            instances that happen to share K produce different ciphertexts.
# ---------------------------------------------------------------------------
def _derive_int(label, mod):
    h = hashlib.sha256(SEED + b"|" + label).digest()
    return int.from_bytes(h[:8], "big") % mod

K = 1 + _derive_int(b"caesar-shift", 25)            # 1..25
TAG = _derive_int(b"session-tag", 1 << 32)          # 0 .. 2^32-1


# ---------------------------------------------------------------------------
# Layer primitives (all standard, all reversible).
# ---------------------------------------------------------------------------
def caesar(text, k):
    out = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + k) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + k) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def atbash(text):
    out = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(90 - (o - 65)))
        elif 97 <= o <= 122:
            out.append(chr(122 - (o - 97)))
        else:
            out.append(ch)
    return "".join(out)


def wrap(flag):
    # The intercepted message: a readable envelope around the flag. The session
    # tag guarantees per-instance uniqueness; the solver simply locates the flag
    # by its known format once the layers are peeled.
    message = "ZSCTF intercept session=%08x :: %s" % (TAG, flag)
    t1 = caesar(message, K)                               # classical shift
    t2 = atbash(t1)                                       # classical reflect
    t3 = base64.b32encode(t2.encode()).decode()           # base32
    t4 = base64.b64encode(t3.encode()).decode()           # base64
    t5 = binascii.hexlify(t4.encode()).decode()           # hex
    return t5


CIPHERTEXT = wrap(FLAG)


# ---------------------------------------------------------------------------
# Presentation: hand the client the final blob.
# ---------------------------------------------------------------------------
def banner():
    return "\n".join([
        "=== ZSCTF :: Matryoshka ===",
        "An intercepted message, wrapped in several nested encoding layers.",
        "Recognise each layer by its alphabet and peel them until the flag appears.",
        "ciphertext: " + CIPHERTEXT,
    ])


def serve_stdio():
    print(banner(), flush=True)


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write((banner() + "\n").encode())


def serve_tcp(host, port):
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, port), _Handler) as srv:
        sys.stderr.write("matryoshka listening on %s:%d\n" % (host, port))
        sys.stderr.flush()
        srv.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--tcp":
        host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 1337
        serve_tcp(host, port)
    else:
        serve_stdio()
