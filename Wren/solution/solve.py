#!/usr/bin/env python3
"""Wren reference solver -- Wiener's attack + staged activation-chain extraction.

Stage 1 (the gate): Wiener's attack recovers the small private exponent d from
the public (N, e).  The convergents k/d of the continued fraction of e/N include
the true 1/d when d is small; each candidate is confirmed by checking that the
implied phi makes N factor cleanly.

Stage 2 (the means -> the flag): d earns you the RSA private operation.  The
device publishes only the FIRST activation ciphertext.  We decrypt it
(record = c^d mod N), read its real fragment (authenticated by an embedded
CRC32) and its 8-byte link nonce, then present the link (LINK <hex>) to release
the next ciphertext.  Walk every stage and concatenate the CRC-authenticated
fragments to assemble the token.  The token never crosses the wire and no single
response contains it.

Rabbit-holes rejected here by reasoning (guess-exposure 0):
  * banner "factory test key" decoy flag -- UPPERCASE body, fails the strict
    validator ^zerosecurectf\\{[a-z0-9_]{8,48}\\}$.
  * SUBMIT footgun -- the textbook "decrypt and submit" never returns the flag.
  * decoy_frag fields -- they assemble to an uppercase near-flag; we select the
    CRC-authenticated real fragment at each stage and confirm the full assembly
    against the published fpr integrity tag.

  python solve.py --local ../challenge/server.py
  python solve.py --remote HOST PORT
"""
import sys, re, math, zlib, subprocess, socket, argparse

STRICT = re.compile(r"^zerosecurectf\{[a-z0-9_]{8,48}\}$")
BLK = 64
MAGIC = b"WREN"

def cont_frac(a, b):
    while b:
        q = a // b
        yield q
        a, b = b, a - q * b

def convergents(a, b):
    n0, n1 = 0, 1
    d0, d1 = 1, 0
    for q in cont_frac(a, b):
        n = q * n1 + n0
        d = q * d1 + d0
        yield (n, d)
        n0, n1 = n1, n
        d0, d1 = d1, d

def wiener(e, N):
    for k, d in convergents(e, N):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = N - phi + 1          # p + q
        disc = s * s - 4 * N
        if disc < 0:
            continue
        r = math.isqrt(disc)
        if r * r == disc and (s + r) % 2 == 0:
            return d
    return None

class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([sys.executable, path], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True, bufsize=1)
    def rl(self): return self.p.stdout.readline()
    def send(self, l): self.p.stdin.write(l + "\n"); self.p.stdin.flush()
    def close(self):
        try: self.send("QUIT"); self.p.wait(timeout=5)
        except Exception: self.p.kill()

class Sock:
    def __init__(self, h, p):
        self.s = socket.create_connection((h, p), timeout=10); self.f = self.s.makefile("rw", newline="\n")
    def rl(self): return self.f.readline()
    def send(self, l): self.f.write(l + "\n"); self.f.flush()
    def close(self):
        try: self.send("QUIT")
        except Exception: pass
        self.s.close()

def read_params(io):
    d = {}
    while True:
        line = io.rl()
        if not line:
            raise RuntimeError("service closed")
        line = line.rstrip("\n")
        for k in ("N", "e", "c", "stages", "fpr"):
            if line.startswith(k + " "):
                v = line.split()[1]
                d[k] = v if k == "fpr" else int(v, 16 if k in ("N", "e", "c") else 10)
        if line.startswith("commands:"):
            break
    return d

def parse_record(r_int):
    """Parse one BLK-byte activation record. Returns (idx, n, link, real, decoy).
    The CRC32 authenticates the REAL fragment -- this is how we reject the decoy
    field without guessing."""
    rb = r_int.to_bytes(BLK, "big")
    if rb[:4] != MAGIC:
        raise ValueError("record magic mismatch -- wrong d or wrong ciphertext")
    idx, n = rb[4], rb[5]
    link = rb[6:14]
    p = 14
    declen = rb[p]; p += 1
    decoy = rb[p:p + declen]; p += declen
    reallen = rb[p]; p += 1
    real = rb[p:p + reallen]; p += reallen
    crc = int.from_bytes(rb[p:p + 4], "big")
    if zlib.crc32(real) != crc:
        raise ValueError("fragment CRC mismatch (stage %d)" % idx)
    return idx, n, link, real, decoy

def solve(io):
    prm = read_params(io)
    N, e, c0 = prm["N"], prm["e"], prm["c"]
    n = prm["stages"]
    fpr = prm["fpr"]

    d = wiener(e, N)
    assert d is not None, "Wiener attack failed (d not small enough?)"
    print("[+] Wiener recovered d (%d bits)" % d.bit_length())

    cts = [c0]
    real_frags, decoy_frags = [], []
    for i in range(n):
        r = pow(cts[i], d, N)
        idx, ntot, link, real, decoy = parse_record(r)
        assert idx == i and ntot == n, "stage/index inconsistency"
        real_frags.append(real)
        decoy_frags.append(decoy)
        io.send("LINK " + link.hex())
        resp = io.rl().rstrip("\n")
        if i < n - 1:
            assert resp.startswith("NEXT "), "stage %d not released: %r" % (i + 1, resp)
            cts.append(int(resp.split()[1], 16))
        else:
            assert resp.startswith("DONE"), "final stage not acknowledged: %r" % resp

    token = b"".join(real_frags)
    decoy = b"".join(decoy_frags).decode(errors="replace")
    flag = token.decode(errors="replace")

    # verify-before-commit: the published fpr authenticates the WHOLE assembly
    ok_fpr = ("%08x" % zlib.crc32(token)) == fpr
    ok_fmt = bool(STRICT.match(flag))
    print("[decoy] assembled decoy field = %r  (strict-valid=%s -> REJECTED)"
          % (decoy, bool(STRICT.match(decoy))))
    print("[+] assembled token across %d stages" % n)
    print("[+] fpr integrity match = %s ; strict-format = %s" % (ok_fpr, ok_fmt))
    return flag, ok_fpr and ok_fmt

def main():
    ap = argparse.ArgumentParser()
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--local")
    grp.add_argument("--remote", nargs=2)
    a = ap.parse_args()
    io = Proc(a.local) if a.local else Sock(a.remote[0], int(a.remote[1]))
    try:
        flag, ok = solve(io)
        print("[+] FLAG =", flag)
        return 0 if ok else 1
    finally:
        io.close()

if __name__ == "__main__":
    sys.exit(main())
