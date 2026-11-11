#!/usr/bin/env python3
import os, sys, hashlib

SEED = os.environ.get("ZSCTF_SEED", "zsctf-demo").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_SEED" not in os.environ or "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("[warn] ZSCTF_SEED/ZSCTF_FLAG unset; demo defaults in use -- do NOT deploy unconfigured\n")

_tok = "ZSTOKEN_" + hashlib.sha256(SEED + b"tok").hexdigest()[:16]
_k = hashlib.sha256(SEED + b"k").digest()[0] or 0x42
_ct = bytes(b ^ _k for b in _tok.encode())

# --- Rabbit-hole R1/R5/R6 (organizer-only; see writeup) -----------------------
# `relay` is a DECOY ciphertext: a flag-shaped, seed-varied taunt XORed with a
# different single byte. A naive "brute all 256 keys and grep for the flag" pass
# recovers `zer0securectf{...}`, which FAILS the published strict validator
#   ^zerosecurectf\{[a-z0-9_]{8,48}\}$
# because the prefix is `zer0` (zero -> '0'), not `zerosecurectf`. It is inert:
# the real secret is still the token recovered from `ct` and submitted below.
# Because `ct` decrypts to `ZSTOKEN_<hex>` (NOT flag-shaped), a lazy flag-grep
# lands on the decoy, not the answer. Tag and decoy key vary per ZSCTF_SEED.
_tag = hashlib.sha256(SEED + b"decoy").hexdigest()[:12]
_taunt = ("zer0securectf{" + _tag + "}").encode()
_kd = hashlib.sha256(SEED + b"kd").digest()[0] or 0x37
if _kd == _k:
    _kd ^= 0x5a  # keep the decoy key distinct from the real key
_relay = bytes(b ^ _kd for b in _taunt)

TITLE = "ZSCTF One Byte"
# `relay` is surfaced FIRST on purpose: it is the first thing a lazy tool grabs.
PARAMS = ["relay %s" % _relay.hex(), "ct %s" % _ct.hex()]
PROMPT = "single-byte XOR; the token starts with 'ZSTOKEN_'. ignore the 'relay' archive."
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
