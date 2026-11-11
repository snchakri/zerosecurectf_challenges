#!/usr/bin/env python3
"""Reference solver (standalone).

The banner now lists three columnar ciphertexts (each with its own column count). Brute the column
permutation for each, but accept ONLY the decode matching the published token form
^ZSTOKEN_[0-9a-f]{16}$. The decoys are rejectable by that gate without a server round-trip.
"""
import sys, subprocess, socket, argparse, re, itertools

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
        if len(parts) == 2 and parts[0] in ("aux", "aux_cols", "ct", "cols", "mirror", "mirror_cols"):
            d[parts[0]] = parts[1]
    return d

def col_decodes(ct, cols):
    rows = len(ct) // cols
    chunks = [ct[i * rows:(i + 1) * rows] for i in range(cols)]
    for perm in itertools.permutations(range(cols)):
        gc = [None] * cols
        for j, oc in enumerate(perm):
            gc[oc] = chunks[j]
        yield "".join(gc[c][r] for r in range(rows) for c in range(cols)).rstrip("X")

def solve(io):
    d = read_banner(io)
    fields = [("aux", int(d["aux_cols"])), ("ct", int(d["cols"])), ("mirror", int(d["mirror_cols"]))]
    accepted = []
    seen_reject = set()
    for field, cols in fields:
        if field not in d: continue
        for pt in col_decodes(d[field], cols):
            if TOKEN_RE.match(pt):
                accepted.append((field, pt))
            elif pt.startswith("ZSTOKEN_") and pt not in seen_reject:
                seen_reject.add(pt)
                print("[-] reject %-6s -> %s : right prefix but fails ^ZSTOKEN_[0-9a-f]{16}$ (non-hex body)" % (field, pt))
            elif pt.startswith("ZER0") and pt not in seen_reject:
                seen_reject.add(pt)
                print("[-] reject %-6s -> %s : flag-shaped bait (uppercase/zer0, no braces -> not the flag)" % (field, pt))
    # de-dup accepted (a token only has one correct reading per field)
    uniq = sorted(set(accepted))
    if len(uniq) != 1:
        raise RuntimeError("expected exactly one format-valid token, got %r" % uniq)
    field, tok = uniq[0]
    print("[+] accept  %-6s -> %s" % (field, tok))
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
