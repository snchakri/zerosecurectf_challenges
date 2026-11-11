#!/usr/bin/env python3
import os, sys, hashlib

SEED = os.environ.get("ZSCTF_SEED", "zsctf-demo").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_SEED" not in os.environ or "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("[warn] ZSCTF_SEED/ZSCTF_FLAG unset; demo defaults in use -- do NOT deploy unconfigured\n")

def _ks(seed, n):
    out = b""; ctr = 0
    while len(out) < n:
        out += hashlib.sha256(seed + b"ks" + ctr.to_bytes(8, "big")).digest(); ctr += 1
    return out[:n]
_tok = "ZS-" + hashlib.sha256(SEED + b"tok").hexdigest()[:24]
_m1 = b"PUBLIC BROADCAST: system nominal, all stations report ready and standing by."
_m2 = b"TOKEN:" + _tok.encode()
_k = _ks(SEED, max(len(_m1), len(_m2)))
_c1 = bytes(_m1[i] ^ _k[i] for i in range(len(_m1)))
_c2 = bytes(_m2[i] ^ _k[i] for i in range(len(_m2)))
TITLE = "ZSCTF Two-Time Pad"
PARAMS = ["m1 %s" % _m1.hex(), "c1 %s" % _c1.hex(), "c2 %s" % _c2.hex()]
PROMPT = "two messages XORed with the SAME keystream; m1 (hex) is public."
SECRET = _tok

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
