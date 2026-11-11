#!/usr/bin/env python3
import os, sys, hashlib

SEED = os.environ.get("ZSCTF_SEED", "zsctf-demo").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_SEED" not in os.environ or "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("[warn] ZSCTF_SEED/ZSCTF_FLAG unset; demo defaults in use -- do NOT deploy unconfigured\n")

MORSE = {"A":".-","B":"-...","C":"-.-.","D":"-..","E":".","F":"..-.","G":"--.","H":"....","I":"..","J":".---","K":"-.-","L":".-..","M":"--","N":"-.","O":"---","P":".--.","Q":"--.-","R":".-.","S":"...","T":"-","U":"..-","V":"...-","W":".--","X":"-..-","Y":"-.--","Z":"--..","0":"-----","1":".----","2":"..---","3":"...--","4":"....-","5":".....","6":"-....","7":"--...","8":"---..","9":"----."}

def _mcode(s):
    return " ".join(MORSE[ch] for ch in s)

# --- real station token (crux UNCHANGED): ZSTOKEN + 13 uppercase hex ---
_tok = "ZSTOKEN" + hashlib.sha256(SEED + b"tok").hexdigest()[:13].upper()
_code = _mcode(_tok)
SECRET = _tok

# --- added misdirection (all seed-derived; vary per instance) ---
# R1: flag-shaped decoy. Decodes to an UPPERCASE "zer0securectf"-looking string with
#     no braces -> cannot satisfy the strict flag format ^zerosecurectf\{[a-z0-9_]{8,48}\}$.
_beacon_txt = "ZER0SECURECTF" + hashlib.sha256(SEED + b"beacon").hexdigest()[:7].upper()
_beacon = _mcode(_beacon_txt)
# R2: near-miss token decoy. Right prefix + right length, but one body char ('P') is not a
#     hex digit -> fails the published token form ^ZSTOKEN[0-9A-F]{13}$ (prefix match alone is a trap).
_alt_txt = "ZSTOKEN" + hashlib.sha256(SEED + b"alt").hexdigest()[:12].upper() + "P"
_alt = _mcode(_alt_txt)
# R3: non-canonical "continuous keystream" (no inter-symbol spaces). The published convention is
#     space-separated groups; greedily re-chunking this ambiguous stream yields a different string.
_raw = _code.replace(" ", "")

TITLE = "ZSCTF Morse"
# R1/R6: decoy transmission listed first, so a decode-everything-then-grab-the-flag pass lands on it.
PARAMS = [
    "beacon %s" % _beacon,
    "code %s" % _code,
    "alt %s" % _alt,
    "raw %s" % _raw,
]
PROMPT = ("several Morse transmissions are logged above; exactly one carries the station token. "
          "the token has the form ZSTOKEN followed by 13 uppercase hex digits [0-9A-F]; "
          "groups are space-separated (one symbol group = one letter). SUBMIT that exact token.")

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
