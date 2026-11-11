#!/usr/bin/env python3
"""Reference solver (standalone).

The banner now lists three rail-fence ciphertexts. Brute the rail count (2..8) on each, but accept
ONLY the decode matching the published token form ^ZSTOKEN_[0-9a-f]{16}$. The decoys are rejectable
by that gate without any server round-trip, so the trap costs only the careless.
"""
import sys, subprocess, socket, argparse, re

TOKEN_RE = re.compile(r"^ZSTOKEN_[0-9a-f]{16}$")        # published token form (verifiable gate)
FLAG_RE = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")

class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([sys.executable, path], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True, bufsize=1)
    def rl(self): return self.p.stdout.readline()
    def send(self, l): self.p.stdin.write(l + "\n"); self.p.stdin.flush()
    def close(self):
        try: self.send("QUIT"); self.p.wait(timeout=5)
        except Exception: self.p.kill()

class Sock:
    def __init__(self, h, p):
        self.s = socket.create_connection((h, p), timeout=10)
        self.f = self.s.makefile("rw", newline="\n")
    def rl(self): return self.f.readline()
    def send(self, l): self.f.write(l + "\n"); self.f.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        self.s.close()

def read_banner(io):
    d = {}
    while True:
        line = io.rl()
        if not line: raise RuntimeError("service closed")
        line = line.rstrip("\n")
        if line.startswith("commands:"): break
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[0] in ("aux", "ct", "mirror"):
            d[parts[0]] = parts[1]
    return d

def rail_decode(ct, rails):
    n = len(ct); pat = []; r = 0; dr = 1
    for i in range(n):
        pat.append(r)
        if r == 0: dr = 1
        elif r == rails - 1: dr = -1
        r += dr
    res = [None] * n; pos = 0
    for rail in range(rails):
        for i in range(n):
            if pat[i] == rail:
                res[i] = ct[pos]; pos += 1
    return "".join(res)

def solve(io):
    d = read_banner(io)
    accepted = []
    for field in ("aux", "ct", "mirror"):
        if field not in d: continue
        ct = d[field]
        for rails in range(2, 9):
            dec = rail_decode(ct, rails)
            if TOKEN_RE.match(dec):
                accepted.append((field, rails, dec))
            elif dec.startswith("ZSTOKEN_"):
                print("[-] reject %-6s R=%d -> %s : right prefix but fails ^ZSTOKEN_[0-9a-f]{16}$ (non-hex body)" % (field, rails, dec))
            elif dec.startswith("ZER0") or (dec[:13].isupper() and "SECURECTF" in dec.upper()):
                print("[-] reject %-6s R=%d -> %s : flag-shaped bait (uppercase/zer0, no braces -> not the flag)" % (field, rails, dec))
    if len(accepted) != 1:
        raise RuntimeError("expected exactly one format-valid token, got %r" % accepted)
    field, rails, tok = accepted[0]
    print("[+] accept  %-6s R=%d -> %s" % (field, rails, tok))
    io.send("SUBMIT %s" % tok)
    return tok, io.rl().rstrip("\n")

def main():
    ap = argparse.ArgumentParser()
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--local"); grp.add_argument("--remote", nargs=2)
    a = ap.parse_args()
    io = Proc(a.local) if a.local else Sock(a.remote[0], int(a.remote[1]))
    try:
        val, resp = solve(io)
        print("[+] recovered:", val)
        print("[+] response:", resp)
        if resp.startswith("FLAG "):
            flag = resp[5:]
            if not FLAG_RE.match(flag):
                print("[!] server flag fails strict format:", flag); return 1
            print("[+] FLAG =", flag); return 0
        return 1
    finally:
        io.close()

if __name__ == "__main__":
    sys.exit(main())
