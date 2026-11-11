#!/usr/bin/env python3
import os, sys, hashlib

SEED = os.environ.get("ZSCTF_SEED", "zsctf-demo").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_SEED" not in os.environ or "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("[warn] ZSCTF_SEED/ZSCTF_FLAG unset; demo defaults in use -- do NOT deploy unconfigured\n")

def _st(seed, label):
    ctr = 0
    while True:
        for b in hashlib.sha256(seed + b"|" + label + b"|" + ctr.to_bytes(8, "big")).digest():
            yield b
        ctr += 1
def _tk(g, n): return bytes(next(g) for _ in range(n))
def _odd(g, nb):
    v = int.from_bytes(_tk(g, (nb + 7) // 8), "big"); return v | (1 << (nb - 1)) | 1
def _isp(n, g):
    for p in (2,3,5,7,11,13,17,19,23,29,31,37,41,43,47):
        if n % p == 0: return n == p
    d, r = n - 1, 0
    while d % 2 == 0: d //= 2; r += 1
    for _ in range(14):
        a = 2 + int.from_bytes(_tk(g, 16), "big") % (n - 3); x = pow(a, d, n)
        if x in (1, n - 1): continue
        ok = False
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1: ok = True; break
        if not ok: return False
    return True
E = 65537
def _prime(g, nb):
    while True:
        c = _odd(g, nb)
        if _isp(c, g) and (c - 1) % E != 0: return c
_g = _st(SEED, b"n")
N = _prime(_g, 1024)
D = pow(E, -1, N - 1)
M = int.from_bytes(_tk(_st(SEED, b"tok"), 100), "big") % N
C = pow(M, E, N)
TITLE = "ZSCTF Keygen Slip"
PARAMS = ["N %x" % N, "e %x" % E, "c %x" % C]
PROMPT = "the modulus was produced by a keygen that skipped a step."
SECRET = "%x" % M

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
