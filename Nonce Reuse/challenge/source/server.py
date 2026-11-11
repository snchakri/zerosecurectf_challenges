#!/usr/bin/env python3
import os, sys, hashlib

SEED = os.environ.get("ZSCTF_SEED", "zsctf-demo").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_SEED" not in os.environ or "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("[warn] ZSCTF_SEED/ZSCTF_FLAG unset; demo defaults in use -- do NOT deploy unconfigured\n")

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
def _inv(a, m): return pow(a % m, -1, m)
def _add(Pt, Q):
    if Pt is None: return Q
    if Q is None: return Pt
    x1, y1 = Pt; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % _P == 0: return None
    lam = (3 * x1 * x1) * _inv(2 * y1, _P) % _P if Pt == Q else (y2 - y1) * _inv(x2 - x1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return (x3, (lam * (x1 - x3) - y1) % _P)
def _mul(k, Pt):
    R = None; k %= _N
    while k:
        if k & 1: R = _add(R, Pt)
        Pt = _add(Pt, Pt); k >>= 1
    return R
def _u(label, n): return int.from_bytes(hashlib.sha256(SEED + b"|" + label).digest(), "big") % n
D_ = _u(b"d", _N - 1) + 1
K_ = _u(b"k", _N - 1) + 1
R_ = _mul(K_, (_Gx, _Gy))[0] % _N
M1 = _u(b"m1", _N); M2 = _u(b"m2", _N)
S1 = (_inv(K_, _N) * (M1 + R_ * D_)) % _N
S2 = (_inv(K_, _N) * (M2 + R_ * D_)) % _N
TITLE = "ZSCTF Nonce Reuse"
PARAMS = ["n %x" % _N, "r %x" % R_, "s1 %x" % S1, "m1 %x" % M1, "s2 %x" % S2, "m2 %x" % M2]
PROMPT = "two ECDSA signatures reused the nonce (note the identical r); recover d."
SECRET = "%x" % D_

def banner():
    return "\n".join(["=== " + TITLE + " ==="] + PARAMS + [PROMPT, "commands: SUBMIT <value> | QUIT"])

def handle(line):
    p = line.strip().split()
    if not p:
        return ""
    c = p[0].upper()
    if c == "QUIT":
        return "__QUIT__"
    if c == "SUBMIT":
        if len(p) < 2:
            return "ERR malformed"
        return ("FLAG " + FLAG) if p[1].strip() == SECRET else "DENIED wrong value"
    return "ERR unknown command"

def serve_stdio():
    print(banner(), flush=True)
    for line in sys.stdin:
        r = handle(line)
        if r == "__QUIT__":
            break
        if r:
            print(r, flush=True)

import socketserver
class _H(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write((banner() + "\n").encode())
        for raw in self.rfile:
            r = handle(raw.decode(errors="ignore"))
            if r == "__QUIT__":
                break
            if r:
                self.wfile.write((r + "\n").encode())

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--tcp":
        host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 1337
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        with socketserver.ThreadingTCPServer((host, port), _H) as s:
            print("listening %s:%d" % (host, port), file=sys.stderr, flush=True)
            s.serve_forever()
    else:
        serve_stdio()
