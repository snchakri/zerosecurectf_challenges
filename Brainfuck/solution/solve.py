#!/usr/bin/env python3
"""Reference solver (standalone)."""
import sys, subprocess, socket, argparse, math

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
    d = read_banner(io); code = d["program"]
    tape = [0] * 4096; p = 0; out = []; i = 0; match = {}; st = []
    for j, ch in enumerate(code):
        if ch == "[": st.append(j)
        elif ch == "]": k = st.pop(); match[k] = j; match[j] = k
    while i < len(code):
        ch = code[i]
        if ch == ">": p += 1
        elif ch == "<": p -= 1
        elif ch == "+": tape[p] = (tape[p] + 1) & 0xff
        elif ch == "-": tape[p] = (tape[p] - 1) & 0xff
        elif ch == ".": out.append(chr(tape[p]))
        elif ch == "[" and tape[p] == 0: i = match[i]
        elif ch == "]" and tape[p] != 0: i = match[i]
        i += 1
    tok = "".join(out)
    io.send("SUBMIT %s" % tok); return tok, io.rl().rstrip("\n")

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
            print("[+] FLAG =", resp[5:]); return 0
        return 1
    finally:
        io.close()

if __name__ == "__main__":
    sys.exit(main())
