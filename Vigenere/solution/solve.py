#!/usr/bin/env python3
"""Reference solver (standalone).

Also documents the escape from the two rabbit-holes (see writeup.md):
  * R1/R6 `relay`: a Caesar-shifted flag-shaped taunt. Rejected because its
    naive decode fails the strict flag validator (uppercase, `zer0`, no braces).
  * R2/R3 near-miss key length: using the 7-char crib AS the key period (a
    common known-plaintext confusion) reproduces the crib but yields a WRONG
    token. Rejected by using the PUBLISHED `keylen`, not the crib length.
"""
import sys, subprocess, socket, argparse, math, re

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
    d = read_banner(io); ct = d["ct"]; AB = d["alphabet"]; kl = int(d["keylen"]); m = len(AB)
    idx = {c: i for i, c in enumerate(AB)}; crib = "ZSTOKEN"

    # --- Reject R1/R6: the `relay` archive, if present, is a decoy. Run the naive
    # single-shift (Caesar) pass a lazy tool would run and confirm the recovered
    # string is NOT a valid flag, so we do not submit/report it. -----------------
    if "relay" in d:
        relay = d["relay"]
        for s in range(m):
            cand = "".join(AB[(idx[c] - s) % m] for c in relay)
            if "SECURECTF" in cand or cand.lower().startswith("zer0"):
                assert not FLAG_RE.match(cand), "relay unexpectedly valid"
                print("[-] relay decoy (rejected, fails strict validator):", cand)
                break

    # --- Reject R2/R3: do NOT use the 7-char crib as the key period. Show it
    # reproduces the crib yet yields a different (wrong) token, then discard it. --
    kcrib = [(idx[ct[i]] - idx[crib[i]]) % m for i in range(len(crib))]
    dec_crib = "".join(AB[(idx[ct[i]] - kcrib[i % len(crib)]) % m] for i in range(len(ct)))
    if dec_crib != None:
        print("[-] crib-as-key (period %d) decoy -> %s (ignored; keylen is %d)"
              % (len(crib), dec_crib, kl))

    # --- Intended path: recover the key using the PUBLISHED key length. ----------
    key = [(idx[ct[i]] - idx[crib[i]]) % m for i in range(kl)]
    dec = "".join(AB[(idx[ct[i]] - key[i % kl]) % m] for i in range(len(ct)))
    io.send("SUBMIT %s" % dec); return dec, io.rl().rstrip("\n")

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
