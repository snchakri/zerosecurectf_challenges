#!/usr/bin/env python3
"""Reference solver (standalone).

The banner now logs several Morse transmissions. A careless "decode everything and grab the
flag-looking string" pass is trapped; the methodical path decodes each space-separated channel
and keeps only the one matching the published token form  ^ZSTOKEN[0-9A-F]{13}$.
"""
import sys, subprocess, socket, argparse, re

MORSE = {"A":".-","B":"-...","C":"-.-.","D":"-..","E":".","F":"..-.","G":"--.","H":"....","I":"..","J":".---","K":"-.-","L":".-..","M":"--","N":"-.","O":"---","P":".--.","Q":"--.-","R":".-.","S":"...","T":"-","U":"..-","V":"...-","W":".--","X":"-..-","Y":"-.--","Z":"--..","0":"-----","1":".----","2":"..---","3":"...--","4":"....-","5":".....","6":"-....","7":"--...","8":"---..","9":"----."}
REV = {v: k for k, v in MORSE.items()}
TOKEN_RE = re.compile(r"^ZSTOKEN[0-9A-F]{13}$")   # published token form (the verifiable gate)
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
        if len(parts) == 2 and parts[0] in ("beacon", "code", "alt", "raw"):
            d[parts[0]] = parts[1]
    return d

def decode_spaced(code):
    """Canonical decode: one space-separated group per letter (the published convention)."""
    try:
        return "".join(REV[sym] for sym in code.split(" ") if sym)
    except KeyError:
        return None

def decode_greedy(stream):
    """Non-canonical: greedily re-chunk a space-less stream (max-munch). Ambiguous on purpose."""
    out = []; i = 0; n = len(stream)
    while i < n:
        for ln in (5, 4, 3, 2, 1):
            sym = stream[i:i + ln]
            if sym in REV:
                out.append(REV[sym]); i += ln; break
        else:
            return None
    return "".join(out)

def solve(io):
    d = read_banner(io)
    # Decode every logged transmission under the published (space-separated) convention,
    # plus the greedy reading of the continuous 'raw' keystream.
    cands = {}
    for name in ("beacon", "code", "alt"):
        if name in d: cands[name] = decode_spaced(d[name])
    if "raw" in d: cands["raw/greedy"] = decode_greedy(d["raw"])

    accepted, rejected = [], []
    for name, txt in cands.items():
        if txt is not None and TOKEN_RE.match(txt):
            accepted.append((name, txt))
        else:
            rejected.append((name, txt))
    for name, txt in rejected:
        why = "flag-shaped bait (not a token)" if (txt and txt.startswith("ZER0")) else \
              "fails ^ZSTOKEN[0-9A-F]{13}$ (non-hex body / non-canonical grouping)"
        print("[-] reject %-10s -> %r : %s" % (name, txt, why))
    if len(accepted) != 1:
        raise RuntimeError("expected exactly one format-valid token, got %r" % accepted)
    chan, tok = accepted[0]
    print("[+] accept  %-10s -> %s" % (chan, tok))
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
