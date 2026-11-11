#!/usr/bin/env python3
"""Gemini reference solver -- RSA common-modulus attack.

With a*e1 + b*e2 = 1 (extended Euclid), m = c1^a * c2^b (mod N); a negative
exponent means invert that ciphertext mod N first.
  python solve.py --local ../challenge/server.py
  python solve.py --remote HOST PORT
"""
import sys, subprocess, socket, argparse

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([sys.executable, path], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True, bufsize=1)
    def rl(self):
        return self.p.stdout.readline()
    def send(self, l):
        self.p.stdin.write(l + "\n")
        self.p.stdin.flush()
    def close(self):
        try:
            self.send("QUIT")
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()

class Sock:
    def __init__(self, h, p):
        self.s = socket.create_connection((h, p), timeout=10)
        self.f = self.s.makefile("rw", newline="\n")
    def rl(self):
        return self.f.readline()
    def send(self, l):
        self.f.write(l + "\n")
        self.f.flush()
    def close(self):
        try:
            self.send("QUIT")
        except Exception:
            pass
        self.s.close()

def read_params(io):
    d = {}
    while True:
        line = io.rl()
        if not line:
            raise RuntimeError("service closed")
        line = line.rstrip("\n")
        for k in ("N", "e1", "e2", "c1", "c2"):
            if line.startswith(k + " "):
                d[k] = int(line.split()[1], 16)
        if line.startswith("commands:"):
            break
    return d

def solve(io):
    d = read_params(io)
    N, e1, e2, c1, c2 = d["N"], d["e1"], d["e2"], d["c1"], d["c2"]
    g, a, b = egcd(e1, e2)
    assert g == 1, "exponents are not coprime"
    t1 = pow(c1 if a >= 0 else pow(c1, -1, N), abs(a), N)
    t2 = pow(c2 if b >= 0 else pow(c2, -1, N), abs(b), N)
    m = (t1 * t2) % N
    io.send("SUBMIT %x" % m)
    return m, io.rl().rstrip("\n")

def main():
    ap = argparse.ArgumentParser()
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--local")
    grp.add_argument("--remote", nargs=2)
    a = ap.parse_args()
    io = Proc(a.local) if a.local else Sock(a.remote[0], int(a.remote[1]))
    try:
        m, resp = solve(io)
        print("[+] recovered token m = %x" % m)
        print("[+] response:", resp)
        if resp.startswith("FLAG "):
            print("[+] FLAG =", resp[5:])
            return 0
        return 1
    finally:
        io.close()

if __name__ == "__main__":
    sys.exit(main())
