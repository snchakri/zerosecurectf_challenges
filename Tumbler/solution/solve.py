#!/usr/bin/env python3
"""
ZSCTF :: Tumbler -- reference solver.

Intended path (pure cryptanalysis of THIS oracle -- no key, no brute force):

  1. The vault publishes `sealed = IV || C_1 || C_2 || ...` and answers CHECK
     with exactly one bit: does the decryption carry valid PKCS#7 padding?
  2. For any ciphertext block C_t, submit a crafted two-block blob  B' || C_t .
     The oracle decrypts the second block to   I_t XOR B'   where I_t = Dec(C_t)
     is the (secret) intermediate state. By choosing B' so that this equals a
     valid padding string and watching the one bit, we recover I_t one byte at a
     time, from the last byte to the first -- the tumblers of the lock falling
     into place. (Vaudenay, 2002.)
  3. The real plaintext block is  P_t = I_t XOR (real preceding block) , so once
     every I_t is known we reconstruct the whole plaintext, strip PKCS#7, and
     obtain the unlock token.
  4. UNLOCK with the recovered token -> the vault opens and prints the flag.

Only the CHECK bit is ever used; nothing here depends on the key or on this
particular instance's parameters, and it works against any seed.

Run locally against the source:   python solve.py --local ../challenge/server.py
Run against a deployed instance:   python solve.py --remote HOST PORT
"""
import sys, subprocess, socket, argparse

BLOCK = 16

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def blocks(data):
    return [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]

# -- transport abstractions --------------------------------------------------
class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([sys.executable, path], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True, bufsize=1)
    def readline(self): return self.p.stdout.readline()
    def send(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        try: self.p.wait(timeout=5)
        except Exception: self.p.kill()

class Sock:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=10)
        self.f = self.s.makefile("rw", newline="\n")
    def readline(self): return self.f.readline()
    def send(self, line): self.f.write(line + "\n"); self.f.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        self.s.close()

def read_banner(io):
    """Read lines until the 'commands:' marker; return the sealed blob bytes."""
    sealed = None
    while True:
        line = io.readline()
        if not line:
            raise RuntimeError("service closed during banner")
        line = line.rstrip("\n")
        if line.startswith("sealed "):
            sealed = bytes.fromhex(line.split()[1])
        elif line.startswith("commands:"):
            break
    if sealed is None:
        raise RuntimeError("no sealed blob in banner")
    return sealed

def oracle(io, blob):
    """One padding-oracle query: True iff the decryption has valid padding."""
    io.send("CHECK " + blob.hex())
    resp = io.readline().rstrip("\n")
    if resp == "PAD OK":
        return True
    if resp == "PAD FAIL":
        return False
    raise RuntimeError("unexpected oracle response: %r" % resp)

def recover_intermediate(io, c_t):
    """Recover I_t = Dec(c_t): the AES decryption of one block, before the CBC
    XOR. Uses only the padding bit. Bytes are peeled off from position 15 down
    to 0, each forced to the padding value pad = BLOCK - j."""
    inter = bytearray(BLOCK)
    for j in range(BLOCK - 1, -1, -1):
        pad_val = BLOCK - j
        prefix = bytes(j)                 # positions 0..j-1: don't care (zeros)
        # positions j+1..15 forced so their plaintext byte equals pad_val
        tail = bytes(inter[k] ^ pad_val for k in range(j + 1, BLOCK))
        found = None
        for guess in range(256):
            forged = prefix + bytes([guess]) + tail
            if not oracle(io, forged + c_t):
                continue
            if j == BLOCK - 1:
                # Disambiguate the pad_val == 1 case from a coincidental longer
                # valid padding: perturb the byte at position 14 and re-test.
                probe = bytearray(forged)
                probe[j - 1] ^= 0xFF
                if not oracle(io, bytes(probe) + c_t):
                    continue              # was a longer-padding coincidence; keep looking
            found = guess
            break
        if found is None:
            raise RuntimeError("padding oracle stalled at byte %d" % j)
        inter[j] = found ^ pad_val
    return bytes(inter)

def decrypt(io, sealed):
    """Full plaintext of `sealed` (IV || C_1 || ... || C_n) via the oracle."""
    bs = blocks(sealed)                   # bs[0] = IV, bs[1..] = ciphertext blocks
    plaintext = b""
    for t in range(1, len(bs)):
        inter = recover_intermediate(io, bs[t])
        plaintext += xor(inter, bs[t - 1])   # P_t = Dec(C_t) XOR previous block
    return plaintext

def strip_pkcs7(pt):
    n = pt[-1]
    if not (1 <= n <= BLOCK) or pt[-n:] != bytes([n]) * n:
        raise ValueError("recovered plaintext has invalid PKCS#7 padding")
    return pt[:-n]

def solve(io):
    sealed = read_banner(io)
    token = strip_pkcs7(decrypt(io, sealed))
    io.send("UNLOCK " + token.hex())
    resp = io.readline().rstrip("\n")
    return token, resp

def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="SERVER_PY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    args = ap.parse_args()
    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        token, resp = solve(io)
        print("[+] recovered unlock token = %r" % token)
        print("[+] service response: %s" % resp)
        if resp.startswith("FLAG "):
            print("[+] FLAG =", resp[5:]); return 0
        print("[-] did not get a flag"); return 1
    finally:
        io.close()

if __name__ == "__main__":
    sys.exit(main())
