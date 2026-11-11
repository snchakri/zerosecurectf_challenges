#!/usr/bin/env python3
"""
ZSCTF :: Ferrule -- reference solver (classic known-plaintext repeating-key XOR).

Intended path (nothing exotic -- this is a beginner on-ramp):
  1. Static analysis of the binary shows the decode loop:
         out[i] = SECRET[i] ^ key[i % keylen]
     i.e. the sealed payload is the flag under a short repeating-key XOR, and a
     correct key is confirmed by an FNV-1a checksum. Neither the key nor the
     flag appears in plaintext, so `strings` yields nothing useful.
  2. The decoded payload must be the CTF flag, so it must begin with the known
     format prefix "zerosecurectf{". XORing the sealed bytes against that crib
     recovers the first bytes of the repeating key:
         key[i % keylen] = SECRET[i] ^ "zerosecurectf{"[i]
  3. The repeat exposes the key's length (its period), so the whole key -- and
     then the whole flag -- fall out. No running of the binary is even required.

This solver locates the sealed SECRET array inside the binary purely by that
known-plaintext crib (so it works whether or not the binary keeps its symbol
table), recovers the key + flag offline, and then -- as a cross-check -- feeds
the recovered key to a live instance (the local binary, or a remote socket) and
confirms it unlocks the same flag.

Usage:
  python3 solve.py --local  ../build/ferrule
  python3 solve.py --remote HOST PORT [--bin ../build/ferrule]
"""
import sys
import socket
import argparse
import subprocess

CRIB = b"zerosecurectf{"


def find_period(ks: bytes):
    """Smallest period p such that ks is a whole repetition of its first p bytes."""
    n = len(ks)
    for p in range(1, n + 1):
        if all(ks[i] == ks[i % p] for i in range(n)):
            return p
    return n


def recover_from_blob(data: bytes):
    """
    Scan the binary for the sealed SECRET array by the flag-format crib.
    Returns (key_bytes, flag_bytes) or None.
    """
    n = len(data)
    clen = len(CRIB)
    for o in range(0, n - clen):
        # Candidate keystream from the crib at this offset.
        ks = bytes(data[o + i] ^ CRIB[i] for i in range(clen))
        p = find_period(ks)
        # Require a genuine short repeat: the crib window (14 bytes) must show at
        # least two full periods of the key. A random offset yields period == clen
        # (no repeat), so this rejects the overwhelming majority of false hits;
        # the true SECRET offset yields ks == key repeated (period == key length).
        if 2 * p > clen:
            continue
        key = ks[:p]
        # Decode forward until the closing brace; the flag is printable ASCII.
        flag = bytearray()
        j = 0
        ok = False
        while o + j < n and j < 256:
            c = data[o + j] ^ key[j % p]
            if not (32 <= c < 127):
                break
            flag.append(c)
            if c == ord("}"):
                ok = True
                break
            j += 1
        if ok and bytes(flag).startswith(CRIB):
            return key, bytes(flag)
    return None


# --- transports -------------------------------------------------------------
def unlock_local(binary, key, timeout=20):
    p = subprocess.run([binary], input=key + b"\n",
                       capture_output=True, timeout=timeout)
    return p.stdout + p.stderr


def unlock_remote(host, port, key, timeout=20):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(key + b"\n")
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        chunks = []
        while True:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks)


def extract_flag(blob: bytes):
    text = blob.decode("latin-1", "replace")
    i = text.find("zerosecurectf{")
    if i < 0:
        return None
    j = text.find("}", i)
    if j < 0:
        return None
    return text[i:j + 1]


def main():
    ap = argparse.ArgumentParser(description="Ferrule known-plaintext XOR solver")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="BINARY",
                   help="path to the ferrule binary to analyse and unlock")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"),
                   help="host and port of a deployed instance")
    ap.add_argument("--bin", metavar="BINARY",
                    help="binary to recover the key from (required with --remote)")
    args = ap.parse_args()

    bin_path = args.local or args.bin
    if not bin_path:
        print("[-] --remote needs --bin pointing at the downloaded binary")
        return 2

    with open(bin_path, "rb") as f:
        data = f.read()

    res = recover_from_blob(data)
    if not res:
        print("[-] could not locate the sealed payload by the flag crib")
        return 1
    key, flag_offline = res
    print("[*] recovered activation key = %r (len %d)" % (key.decode("latin-1"), len(key)))
    print("[*] decoded flag offline     = " + flag_offline.decode("latin-1"))

    # Cross-check against a live instance.
    if args.local:
        out = unlock_local(args.local, key)
    else:
        out = unlock_remote(args.remote[0], int(args.remote[1]), key)

    flag_live = extract_flag(out)
    if flag_live:
        print("[+] FLAG = " + flag_live)
        if flag_live.encode() != flag_offline:
            print("[!] note: live flag differs from the offline decode")
        return 0
    print("[-] live instance did not unlock")
    sys.stdout.buffer.write(b"--- service output ---\n" + out + b"\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
