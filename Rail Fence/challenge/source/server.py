#!/usr/bin/env python3
import os, sys, hashlib

SEED = os.environ.get("ZSCTF_SEED", "zsctf-demo").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_SEED" not in os.environ or "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("[warn] ZSCTF_SEED/ZSCTF_FLAG unset; demo defaults in use -- do NOT deploy unconfigured\n")

def _rail_encode(s, rails):
    rows = [[] for _ in range(rails)]; r = 0; dr = 1
    for ch in s:
        rows[r].append(ch)
        if r == 0: dr = 1
        elif r == rails - 1: dr = -1
        r += dr
    return "".join("".join(x) for x in rows)

def _u(label, n):
    return int.from_bytes(hashlib.sha256(SEED + b"|" + label).digest(), "big") % n

# --- real token (crux UNCHANGED): ZSTOKEN_ + 16 lowercase hex, rail-fenced over an unknown R in 2..8 ---
_tok = "ZSTOKEN_" + hashlib.sha256(SEED + b"tok").hexdigest()[:16]
_rails = 2 + int.from_bytes(hashlib.sha256(SEED + b"r").digest(), "big") % 7
_ct = _rail_encode(_tok, _rails)
SECRET = _tok

# --- added misdirection (seed-derived; vary per instance) ---
# R1: flag-shaped decoy, rail-fenced at its own rail. Brute-forcing it reveals an UPPERCASE
#     "zer0securectf"-looking string with no braces -> can never satisfy the strict flag format.
_aux_pt = "ZER0SECURECTF_" + hashlib.sha256(SEED + b"aux").hexdigest()[:10].upper()
_aux = _rail_encode(_aux_pt, 2 + _u(b"ar", 7))
# R2: near-miss token decoy. Right prefix + right length, but one body char ('g') is not a
#     lowercase hex digit -> fails the published token form ^ZSTOKEN_[0-9a-f]{16}$.
_mir_pt = "ZSTOKEN_" + hashlib.sha256(SEED + b"mir").hexdigest()[:15] + "g"
_mir = _rail_encode(_mir_pt, 2 + _u(b"mr", 7))

TITLE = "ZSCTF Rail Fence"
# R1/R6: decoy ciphertext listed first so a decode-and-grab-the-flag pass lands on it.
PARAMS = ["aux %s" % _aux, "ct %s" % _ct, "mirror %s" % _mir]
PROMPT = ("three rail-fence ciphertexts above; exactly one hides the token. rails unknown (2-8). "
          "the token has the form ZSTOKEN_ followed by 16 lowercase hex digits "
          "(^ZSTOKEN_[0-9a-f]{16}$). SUBMIT that exact token.")

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
