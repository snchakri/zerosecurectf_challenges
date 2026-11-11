#!/usr/bin/env python3
"""ZSCTF :: Gemini  (crypto, Hard)

A firmware activation broadcast. The SAME secret activation token is encrypted to
ONE shared RSA modulus under TWO different public exponents (a real-world
misconfiguration when several services reuse a key). Recover the token from the
two ciphertexts and submit it to release the flag. Players are given this source.
"""
import os, sys, hashlib, socketserver

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

def _prime(gen, nbits, es):
    while True:
        c = _rand_odd(gen, nbits)
        if _is_prime(c, gen) and all((c - 1) % e != 0 for e in es):
            return c

SEED = os.environ.get("ZSCTF_SEED", "gemini-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_SEED" not in os.environ or "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("[warn] ZSCTF_SEED/ZSCTF_FLAG unset; demo defaults in use -- do NOT deploy unconfigured\n")

E1, E2 = 65537, 257
_g = _stream(SEED, b"primes")
P = _prime(_g, 512, (E1, E2))
Q = _prime(_g, 512, (E1, E2))
N = P * Q
M = int.from_bytes(_take(_stream(SEED, b"token"), 120), "big") % N
C1, C2 = pow(M, E1, N), pow(M, E2, N)

def banner():
    return "\n".join([
        "=== ZSCTF Activation Broadcast ===",
        "N  %x" % N, "e1 %x" % E1, "e2 %x" % E2, "c1 %x" % C1, "c2 %x" % C2,
        "one activation token was encrypted under e1 and e2 to this shared modulus.",
        "commands: SUBMIT <token_hex> | QUIT",
    ])

def handle(line):
    p = line.strip().split()
    if not p:
        return ""
    c = p[0].upper()
    if c == "QUIT":
        return "__QUIT__"
    if c == "SUBMIT":
        try:
            m = int(p[1], 16)
        except (IndexError, ValueError):
            return "ERR malformed"
        return ("FLAG " + FLAG) if m == M else "DENIED wrong token"
    return "ERR unknown command"

def serve_stdio():
    print(banner(), flush=True)
    for line in sys.stdin:
        r = handle(line)
        if r == "__QUIT__":
            break
        if r:
            print(r, flush=True)

class H(socketserver.StreamRequestHandler):
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
        with socketserver.ThreadingTCPServer((host, port), H) as s:
            sys.stderr.write("listening %s:%d\n" % (host, port))
            sys.stderr.flush()
            s.serve_forever()
    else:
        serve_stdio()
