#!/usr/bin/env python3
"""Reference solver (standalone).

Also documents the escape from the two rabbit-holes (see writeup.md):
  * R1/R6 `relay`: a flag-shaped decoy ciphertext. Rejected because its naive
    decode (`zer0securectf{...}`) fails the strict flag validator.
  * R2 frequency heuristic: 'most common byte == space' picks the WRONG key here
    (the token has no spaces). Rejected by using the known-prefix crib instead.
"""
import sys, subprocess, socket, argparse, math, re
from collections import Counter

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
        if len(parts) == 2: d[parts[0]] = parts[1]
    return d

def solve(io):
    d = read_banner(io); ct = bytes.fromhex(d["ct"])

    # Reject R1/R6: the `relay` archive, if present, is a decoy. Run the naive
    # 256-key brute a lazy tool would run on it and confirm the flag-shaped
    # result is NOT a valid flag, so we do not submit/report it.
    if "relay" in d:
        relay = bytes.fromhex(d["relay"])
        hit = None
        for k in range(256):
            try: s = bytes(b ^ k for b in relay).decode()
            except Exception: continue
            if s.startswith("zer0securectf{"):   # canonical decoy decode
                hit = s; break
            if hit is None and "securectf" in s.lower():
                hit = s                           # fallback case-variant
        if hit is not None:
            assert not FLAG_RE.match(hit), "relay unexpectedly valid"
            print("[-] relay decoy (rejected, fails strict validator):", hit)

    # Reject R2: the 'most frequent byte -> space' heuristic is the wrong tool
    # here (the token has no spaces). Show the key it would pick and that its
    # decode does NOT match the known prefix, then discard it.
    mc = Counter(ct).most_common(1)[0][0]
    hk = mc ^ 0x20
    try:
        hdec = bytes(b ^ hk for b in ct).decode("latin-1")
        if not hdec.startswith("ZSTOKEN_"):
            print("[-] frequency heuristic key 0x%02x -> %r (ignored; wrong prefix)" % (hk, hdec))
    except Exception:
        pass

    # Intended path: the key whose plaintext starts with the known prefix.
    for k in range(256):
        try: s = bytes(b ^ k for b in ct).decode()
        except Exception: continue
        if s.startswith("ZSTOKEN_"):
            io.send("SUBMIT %s" % s); return s, io.rl().rstrip("\n")
    raise RuntimeError("key byte not found")

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
            assert FLAG_RE.match(flag), "server flag failed strict validator: %r" % flag
            print("[+] FLAG =", flag); return 0
        return 1
    finally:
        io.close()

if __name__ == "__main__":
    sys.exit(main())
