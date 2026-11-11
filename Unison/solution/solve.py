#!/usr/bin/env python3
"""
ZSCTF :: Unison -- reference solver.

Intended path (Hastad's broadcast attack; no exploit of anything but the maths):
  1. The vendor sends the SAME activation record m to every device, encrypting
     it with exponent e = 3 under each device's modulus N_i:
            c_i = m^3 mod N_i
  2. Because m < N_i for every device, m^3 is smaller than the product of ANY
     three distinct moduli:  m^3 < N_0 * N_1 * N_2. The Chinese Remainder
     Theorem combines three ciphertexts into
            C === m^3   (mod N_0 * N_1 * N_2)
     and since 0 <= m^3 < that product, C equals m^3 as an integer -- no modular
     wraparound survives.
  3. A plain integer cube root of C returns m exactly. The flag is ASCII inside m.

  (Note: a single ciphertext does NOT fall to a cube root here -- the record is
   padded so that m^3 > N_i, i.e. every c_i has genuinely wrapped around. The
   broadcast / CRT step is therefore mandatory.)

Primitive libraries: sympy for CRT and the integer cube root (gmpy2/sage are not
available in the target environment); a pure-stdlib fallback is included so the
solver runs even where sympy is absent.

Run locally against the source:   python solve.py --local ../challenge/server.py
Run against a deployed instance:   python solve.py --remote HOST PORT
"""
import sys, re, subprocess, socket, argparse

# ---- CRT + integer cube root: sympy primary, stdlib fallback ---------------
try:
    from sympy import integer_nthroot as _sym_nthroot
    from sympy.ntheory.modular import crt as _sym_crt

    def icbrt(x):
        r, exact = _sym_nthroot(int(x), 3)
        return int(r), bool(exact)

    def crt3(moduli, residues):
        res, mod = _sym_crt([int(m) for m in moduli], [int(r) for r in residues])
        return int(res), int(mod)

    BACKEND = "sympy"
except Exception:                                   # pragma: no cover - fallback
    def icbrt(x):
        x = int(x)
        if x < 0:
            raise ValueError("negative")
        if x == 0:
            return 0, True
        r = 1 << ((x.bit_length() + 2) // 3 + 1)    # over-estimate, then Newton
        while True:
            nxt = (2 * r + x // (r * r)) // 3
            if nxt >= r:
                break
            r = nxt
        while r ** 3 > x:
            r -= 1
        while (r + 1) ** 3 <= x:
            r += 1
        return r, r ** 3 == x

    def crt3(moduli, residues):
        res, mod = 0, 1
        for n, a in zip(moduli, residues):
            n, a = int(n), int(a)
            g = pow(mod % n, -1, n)                  # moduli are pairwise coprime
            res += mod * (((a - res) * g) % n)
            mod *= n
        return res % mod, mod

    BACKEND = "stdlib"


# ---- transport abstractions (identical shape to the other ZSCTF solvers) ---
class Proc:
    def __init__(self, path):
        self.p = subprocess.Popen([sys.executable, path], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True, bufsize=1)

    def readline(self):
        return self.p.stdout.readline()

    def send(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def close(self):
        try:
            self.send("QUIT")
        except Exception:
            pass
        try:
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


class Sock:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=10)
        self.f = self.s.makefile("rw", newline="\n")

    def readline(self):
        return self.f.readline()

    def send(self, line):
        self.f.write(line + "\n")
        self.f.flush()

    def close(self):
        try:
            self.send("QUIT")
        except Exception:
            pass
        self.s.close()


def read_banner(io):
    """Read lines until the 'commands:' marker; return the advertised count."""
    count = None
    while True:
        line = io.readline()
        if not line:
            raise RuntimeError("service closed during banner")
        line = line.rstrip("\n")
        if line.startswith("devices:"):
            count = int(line.split(":", 1)[1])
        elif line.startswith("commands:"):
            break
    if count is None:
        raise RuntimeError("banner did not advertise a device count")
    return count


def parse_device(line):
    """'device <i> e <e> n <n_hex> ct <c_hex>' -> (i, e, n, c)."""
    t = line.split()
    kv = {t[j]: t[j + 1] for j in range(2, len(t) - 1, 2)}   # pairs after 'device <i>'
    return int(t[1]), int(kv["e"]), int(kv["n"], 16), int(kv["ct"], 16)


def capture(io, count):
    io.send("CAPTURE")
    devices = []
    for _ in range(count):
        line = io.readline().rstrip("\n")
        assert line.startswith("device "), "unexpected CAPTURE line: %r" % line
        i, e, n, c = parse_device(line)
        devices.append((i, e, n, c))
    return devices


def hastad(devices):
    """Combine >= e ciphertexts (e = 3) via CRT, cube-root the result."""
    es = {e for _, e, _, _ in devices}
    assert es == {3}, "this solver is the e = 3 broadcast; saw exponents %r" % es
    # any 3 distinct (pairwise-coprime) moduli suffice for e = 3
    chosen = devices[:3]
    moduli = [n for _, _, n, _ in chosen]
    cts = [c for _, _, _, c in chosen]
    C, _ = crt3(moduli, cts)
    m, exact = icbrt(C)
    assert exact, "cube root not exact -- need >= 3 ciphertexts with a common m"
    return m


def extract_flag(m):
    blob = m.to_bytes((m.bit_length() + 7) // 8, "big")
    match = re.search(rb"zerosecurectf\{[^}]*\}", blob)
    return (match.group().decode() if match else None), blob


def solve(io):
    count = read_banner(io)
    devices = capture(io, count)
    m = hastad(devices)
    flag, blob = extract_flag(m)
    # Confirm with the service (leaks nothing: VERIFY needs the exact m we found).
    io.send("VERIFY %x" % m)
    resp = io.readline().rstrip("\n")
    return count, m, blob, flag, resp


def main():
    ap = argparse.ArgumentParser(description="Unison -- Hastad broadcast solver")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--local", metavar="SERVER_PY")
    g.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    args = ap.parse_args()
    io = Proc(args.local) if args.local else Sock(args.remote[0], int(args.remote[1]))
    try:
        count, m, blob, flag, resp = solve(io)
        print("[+] crypto backend: %s" % BACKEND)
        print("[+] captured %d device records (e = 3, distinct moduli)" % count)
        print("[+] recovered the activation record via CRT + integer cube root")
        print("[+] plaintext m (hex) = %x" % m)
        print("[+] activation record = %r" % blob[:48])
        if flag:
            print("[+] FLAG = %s" % flag)
        print("[+] server VERIFY response: %s" % resp)
        if flag and flag.startswith("zerosecurectf{"):
            return 0
        print("[-] did not recover a flag")
        return 1
    finally:
        io.close()


if __name__ == "__main__":
    sys.exit(main())
