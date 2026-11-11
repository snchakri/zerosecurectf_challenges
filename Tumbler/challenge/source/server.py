#!/usr/bin/env python3
"""
ZSCTF :: Tumbler  (crypto, Hard)

A sealed-token *vault*. On connect it hands you a sealed blob -- a secret unlock
token encrypted with AES-128-CBC -- and then behaves as a lock you may rattle:
you may submit any blob and it will tell you only whether the padding came out
valid. Recover the token and present it to open the vault and claim the flag.

Players are given this exact source file. The cryptographic flaw is therefore
not hidden behind obscurity: it is in plain sight, in the fact that the vault
distinguishes "padding valid" from "padding invalid" on arbitrary input. That
single leaked bit is the whole challenge -- a classic CBC padding oracle
(Vaudenay 2002). Just like the tumblers of a lock, the plaintext falls into
place one byte at a time.

Self-contained: one standard primitive (AES-CBC + PKCS#7) via pycryptodome,
with the per-request logic in plain Python in front of you, so there is nothing
to trust but the construction you can read.
"""
import os, sys, hashlib, socketserver
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK = 16  # AES block size in bytes

# ----------------------------------------------------------------------------
# Per-instance secrets, derived deterministically from a seed (team id).
# This gives every team a unique key, a unique IV, and a unique unlock token
# (hence a unique sealed blob and a unique flag), so a leaked solution for one
# instance does not transfer: the attack must be re-run against each instance.
# ----------------------------------------------------------------------------
def _derive(seed, label, length):
    """Deterministic byte string of `length` bytes from (seed, label)."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + b"|" + label + b"|" + str(counter).encode()).digest()
        counter += 1
    return out[:length]

SEED = os.environ.get("ZSCTF_SEED", "static-demo-seed").encode()
FLAG = os.environ.get("ZSCTF_FLAG", "zerosecurectf{local_review_flag}")

KEY   = _derive(SEED, b"aes-key", 16)                     # secret AES-128 key
IV    = _derive(SEED, b"aes-iv", 16)                      # secret per-instance IV
# The secret the player must recover. High entropy (128 bits) so it cannot be
# guessed or brute-forced; it can only be obtained by decrypting the blob, and
# the only decryption handle offered is the padding oracle.
TOKEN = b"ZSCTF-VAULT-" + _derive(SEED, b"token", 16).hex().encode()   # 12 + 32 = 44 bytes

# ----------------------------------------------------------------------------
# The sealed blob: AES-128-CBC( PKCS#7(TOKEN) ), published as IV || ciphertext.
# Encryption of a fixed plaintext under a fixed key+IV is deterministic, so the
# published blob is identical for identical seeds (per-instance reproducibility).
# ----------------------------------------------------------------------------
def _seal():
    ct = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(TOKEN, BLOCK))
    return IV + ct

SEALED = _seal()

# ---- THE PADDING ORACLE (this is the whole challenge) ----------------------
# Given a blob = IV' || C, decrypt under the secret key and report ONLY whether
# the resulting plaintext carries valid PKCS#7 padding. One bit per query.
# Nothing else about the plaintext is ever revealed. That one bit is enough.
def padding_ok(blob):
    if len(blob) < 2 * BLOCK or len(blob) % BLOCK != 0:
        return None                      # structurally malformed -> not a yes/no answer
    iv, ct = blob[:BLOCK], blob[BLOCK:]
    pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(ct)
    try:
        unpad(pt, BLOCK)                 # strict PKCS#7; raises on bad padding
        return True
    except ValueError:
        return False

# ----------------------------------------------------------------------------
# Line protocol
# ----------------------------------------------------------------------------
def banner():
    out = []
    out.append("=== ZSCTF Vault :: Tumbler ===")
    out.append("sealed %s" % SEALED.hex())
    out.append("scheme: AES-128-CBC with PKCS#7 padding; 'sealed' is IV || ciphertext (%d-byte blocks)" % BLOCK)
    out.append("the plaintext is a secret unlock token; recover it to open the vault")
    out.append("commands: CHECK <blob_hex> | UNLOCK <token_hex> | QUIT")
    return "\n".join(out)

def handle_line(line):
    parts = line.strip().split()
    if not parts:
        return ""
    cmd = parts[0].upper()
    try:
        if cmd == "CHECK":
            blob = bytes.fromhex(parts[1])
            ok = padding_ok(blob)
            if ok is None:
                return "ERR blob must be at least 2 blocks and a multiple of %d bytes" % BLOCK
            return "PAD OK" if ok else "PAD FAIL"
        if cmd == "UNLOCK":
            tok = bytes.fromhex(parts[1])
            if tok == TOKEN:
                return "FLAG " + FLAG
            return "DENIED that is not the unlock token"
        if cmd == "QUIT":
            return "__QUIT__"
        return "ERR unknown command"
    except (IndexError, ValueError):
        return "ERR malformed command"

def serve_stdio():
    print(banner(), flush=True)
    for line in sys.stdin:
        resp = handle_line(line)
        if resp == "__QUIT__":
            break
        if resp:
            print(resp, flush=True)

class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write((banner() + "\n").encode())
        for raw in self.rfile:
            resp = handle_line(raw.decode(errors="ignore"))
            if resp == "__QUIT__":
                break
            if resp:
                self.wfile.write((resp + "\n").encode())

def serve_tcp(host, port):
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, port), _Handler) as srv:
        sys.stderr.write("listening on %s:%d\n" % (host, port)); sys.stderr.flush()
        srv.serve_forever()

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--tcp":
        host = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 1337
        serve_tcp(host, port)
    else:
        serve_stdio()
