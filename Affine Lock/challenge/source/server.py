#!/usr/bin/env python3
import os, sys, hashlib

SEED = os.environ.get("ZSCTF_SEED", "zsctf-demo").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_SEED" not in os.environ or "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("[warn] ZSCTF_SEED/ZSCTF_FLAG unset; demo defaults in use -- do NOT deploy unconfigured\n")

import math as _m
AB = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_mod = len(AB)
def _u(label): return int.from_bytes(hashlib.sha256(SEED + b"|" + label).digest(), "big")
_units = [x for x in range(1, _mod) if _m.gcd(x, _mod) == 1]
_a = _units[_u(b"a") % len(_units)]
_b = _u(b"b") % _mod
_tok = "TKN" + "".join(AB[_u(b"t%d" % i) % _mod] for i in range(10))
_ct = "".join(AB[(_a * AB.index(ch) + _b) % _mod] for ch in _tok)

# --- Rabbit-hole R1/R5/R6 (organizer-only; see writeup) -----------------------
# `relay` is a DECOY: a single shift (degenerate affine, a=1) of a seed-varied,
# flag-shaped UPPERCASE taunt over this same 36-char alphabet. A naive "try the
# one obvious classical cipher" pass (Caesar/affine brute) recovers
# ZER0SECURECTFAFF1NE... which looks like the answer but FAILS the published
# strict validator ^zerosecurectf\{[a-z0-9_]{8,48}\}$ (uppercase, `zer0`, no
# braces). It is inert: the real secret is still the affine token from `ct`. The
# shift and tail vary per ZSCTF_SEED so a leaked walkthrough does not transfer.
_taunt = "ZER0SECURECTFAFF1NE" + "".join(AB[_u(b"d%d" % i) % _mod] for i in range(6))
_rshift = _u(b"relay") % _mod
_relay = "".join(AB[(AB.index(ch) + _rshift) % _mod] for ch in _taunt)

TITLE = "ZSCTF Affine Lock"
# `relay` is surfaced FIRST on purpose: it is the first thing a lazy tool grabs.
PARAMS = ["relay %s" % _relay, "ct %s" % _ct, "alphabet %s" % AB]
PROMPT = "affine cipher over the alphabet; the token starts with 'TKN'. ignore the 'relay' archive."
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
