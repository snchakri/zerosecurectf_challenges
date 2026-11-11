#!/usr/bin/env python3
"""
ZSCTF :: Matryoshka -- reference solver.

The intended path is pure recognition: each layer announces itself by the set
of characters it uses, so you peel from the outside in.

  1. lowercase 0-9a-f, even length      -> hex, decode it
  2. A-Z 2-7 with '=' padding, len % 8   -> Base32, decode it
  3. A-Za-z0-9+/ with '=', len % 4       -> Base64, decode it
  (repeat until the text is no longer a recognised encoding)
  4. what remains is letters under a classical cipher: undo Atbash (its own
     inverse), then try all 25 Caesar shifts and keep the one that reveals the
     flag format "zerosecurectf{...}".

This solver auto-detects each layer rather than hard-coding the order, so it
peels any nesting of hex/base32/base64 it is handed and then resolves the
classical layer by brute-forcing the 25 shifts (trivial). Standard library only
-- no sage/pwntools/gmpy2.

Usage:
  python3 solve.py --file ciphertext.txt
  python3 solve.py --local challenge/server.py
  python3 solve.py --remote HOST PORT
"""
import sys
import base64
import socket
import argparse
import binascii
import subprocess

HEX = set("0123456789abcdef")
B32 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
B64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
CRIB = "zerosecurectf{"


def is_hex(s):
    return len(s) > 0 and len(s) % 2 == 0 and all(c in HEX for c in s)


def is_b32(s):
    body = s.rstrip("=")
    return len(s) > 0 and len(s) % 8 == 0 and len(body) > 0 and all(c in B32 for c in body)


def is_b64(s):
    body = s.rstrip("=")
    return len(s) > 0 and len(s) % 4 == 0 and len(body) > 0 and all(c in B64 for c in body)


def caesar(text, k):
    k %= 26
    out = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + k) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + k) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def atbash(text):
    out = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(90 - (o - 65)))
        elif 97 <= o <= 122:
            out.append(chr(122 - (o - 97)))
        else:
            out.append(ch)
    return "".join(out)


def peel_encodings(blob):
    """Peel hex/base32/base64 layers (outer to inner) until none is recognised."""
    cur = blob.strip()
    trace = []
    while True:
        if is_hex(cur):
            cur = binascii.unhexlify(cur).decode("ascii")
            trace.append("hex")
        elif is_b32(cur):
            cur = base64.b32decode(cur).decode("ascii")
            trace.append("base32")
        elif is_b64(cur):
            cur = base64.b64decode(cur).decode("ascii")
            trace.append("base64")
        else:
            break
    return cur, trace


def resolve_classical(text):
    """Undo Atbash, then brute-force the Caesar shift that reveals the flag."""
    reflected = atbash(text)
    for shift in range(26):
        cand = caesar(reflected, -shift)   # undo the +shift applied at wrap time
        i = cand.find(CRIB)
        if i >= 0:
            j = cand.find("}", i)
            if j >= 0:
                return cand[i:j + 1], shift, cand
    return None, None, None


def solve(blob):
    inner, trace = peel_encodings(blob)
    flag, shift, message = resolve_classical(inner)
    return flag, trace, shift, message


# --- transports -------------------------------------------------------------
def read_ciphertext_from_text(text):
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("ciphertext:"):
            return line.split(":", 1)[1].strip()
    # fall back: a bare blob file
    return text.strip()


def from_local(server_py):
    out = subprocess.run([sys.executable, server_py],
                         capture_output=True, text=True, timeout=60)
    return read_ciphertext_from_text(out.stdout)


def from_remote(host, port):
    with socket.create_connection((host, port), timeout=10) as s:
        s.settimeout(10)
        chunks = []
        while True:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
    return read_ciphertext_from_text(b"".join(chunks).decode("latin-1", "replace"))


def main():
    ap = argparse.ArgumentParser(description="Matryoshka onion peeler")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--file", metavar="CIPHERTEXT")
    g.add_argument("--local", metavar="SERVER_PY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    args = ap.parse_args()

    if args.file:
        with open(args.file, "r") as f:
            blob = read_ciphertext_from_text(f.read())
    elif args.local:
        blob = from_local(args.local)
    else:
        blob = from_remote(args.remote[0], int(args.remote[1]))

    flag, trace, shift, message = solve(blob)
    print("[*] peeled encoding layers (outer->inner): " + " -> ".join(trace))
    if flag:
        print("[*] Caesar shift was K = %d; recovered envelope: %r" % (shift, message))
        print("[+] FLAG = " + flag)
        return 0
    print("[-] no flag recovered")
    return 1


if __name__ == "__main__":
    sys.exit(main())
