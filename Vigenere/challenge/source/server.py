#!/usr/bin/env python3
import os, sys, hashlib

SEED = os.environ.get("ZSCTF_SEED", "zsctf-demo").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_SEED" not in os.environ or "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("[warn] ZSCTF_SEED/ZSCTF_FLAG unset; demo defaults in use -- do NOT deploy unconfigured\n")

AB = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"; _m = len(AB)
def _u(label, n): return int.from_bytes(hashlib.sha256(SEED + b"|" + label).digest(), "big") % n
_kl = 5
_key = [_u(b"k%d" % i, _m) for i in range(_kl)]
_tok = "ZSTOKEN" + hashlib.sha256(SEED + b"tok").hexdigest()[:13].upper()
_idx = {c: i for i, c in enumerate(AB)}
_ct = "".join(AB[(_idx[ch] + _key[i % _kl]) % _m] for i, ch in enumerate(_tok))

# --- Rabbit-hole R1/R5/R6 (organizer-only; see writeup) -----------------------
# `relay` is a DECOY. It is a single Caesar shift of a seed-varied, flag-shaped
# taunt over this same alphabet. A naive "try the one obvious classical cipher"
# pass (ROT/Caesar brute) recovers an UPPERCASE string that looks like a flag
# (ZER0SECURECTF...) but FAILS the published strict validator
#   ^zerosecurectf\{[a-z0-9_]{8,48}\}$
# (uppercase body, `zer0` not `zero`, no braces). It is inert: the real secret
# is still the Vigenere token recovered from `ct` and submitted below. The shift
# and tail vary per ZSCTF_SEED so a leaked walkthrough does not transfer.
_taunt = "ZER0SECURECTFCR4CKED" + "".join(AB[_u(b"d%d" % i, _m)] for i in range(6))
_rshift = _u(b"relay", _m)
_relay = "".join(AB[(_idx[ch] + _rshift) % _m] for ch in _taunt)

TITLE = "ZSCTF Vigenere"
# `relay` is surfaced FIRST on purpose: it is the first thing a lazy tool grabs.
PARAMS = ["relay %s" % _relay, "ct %s" % _ct, "alphabet %s" % AB, "keylen %d" % _kl]
PROMPT = "vigenere over the alphabet; the token starts with 'ZSTOKEN'. ignore the 'relay' archive."
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
