#!/usr/bin/env python3
import os, sys, hashlib

SEED = os.environ.get("ZSCTF_SEED", "zsctf-demo").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")
if "ZSCTF_SEED" not in os.environ or "ZSCTF_FLAG" not in os.environ:
    sys.stderr.write("[warn] ZSCTF_SEED/ZSCTF_FLAG unset; demo defaults in use -- do NOT deploy unconfigured\n")

def _u(label, n): return int.from_bytes(hashlib.sha256(SEED + b"|" + label).digest(), "big") % n

def _perm_for(cols, tag):
    perm = list(range(cols))
    for i in range(cols - 1, 0, -1):
        j = _u(tag + b"p%d" % i, i + 1); perm[i], perm[j] = perm[j], perm[i]
    return perm

def _col_encode(text, cols, perm):
    pt = text + "X" * ((-len(text)) % cols)
    rows = len(pt) // cols
    grid = [pt[r * cols:(r + 1) * cols] for r in range(rows)]
    return "".join("".join(grid[r][c] for r in range(rows)) for c in perm)

# --- real token (crux UNCHANGED): ZSTOKEN_ + 16 lowercase hex, X-padded, columns permuted ---
_tok = "ZSTOKEN_" + hashlib.sha256(SEED + b"tok").hexdigest()[:16]
_cols = 4 + _u(b"c", 3)
_ct = _col_encode(_tok, _cols, _perm_for(_cols, b""))
SECRET = _tok

# --- added misdirection (seed-derived; vary per instance) ---
# R1: flag-shaped decoy. Reversing the columns reveals an UPPERCASE "zer0securectf"-looking string
#     with no braces -> can never satisfy the strict flag format.
_aux_txt = "ZER0SECURECTF_" + hashlib.sha256(SEED + b"aux").hexdigest()[:10].upper()
_aux_cols = 4 + _u(b"ac", 3)
_aux = _col_encode(_aux_txt, _aux_cols, _perm_for(_aux_cols, b"aux"))
# R2: near-miss token decoy. Right prefix + right length, but one body char ('g') is not a
#     lowercase hex digit -> fails the published token form ^ZSTOKEN_[0-9a-f]{16}$.
_mir_txt = "ZSTOKEN_" + hashlib.sha256(SEED + b"mir").hexdigest()[:15] + "g"
_mir_cols = 4 + _u(b"mc", 3)
_mir = _col_encode(_mir_txt, _mir_cols, _perm_for(_mir_cols, b"mir"))

TITLE = "ZSCTF Columnar"
# R1/R6: decoy ciphertext listed first so a decode-and-grab-the-flag pass lands on it.
PARAMS = ["aux %s" % _aux, "aux_cols %d" % _aux_cols,
          "ct %s" % _ct, "cols %d" % _cols,
          "mirror %s" % _mir, "mirror_cols %d" % _mir_cols]
PROMPT = ("three columnar ciphertexts above (each with its own column count); exactly one hides "
          "the token; column order unknown and X-padded. the token has the form ZSTOKEN_ followed "
          "by 16 lowercase hex digits (^ZSTOKEN_[0-9a-f]{16}$). SUBMIT that exact token.")

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
