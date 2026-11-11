#!/usr/bin/env python3
"""
ZSCTF :: Keywright -- reference solver (pure algebra, no brute force).

Intended path:
  1. Recover the validator's behaviour by reversing the `keywright` engine
     (done once; the image format, the base-32 key parse, and the fact that
     the check is  A @ x == t  over the ring Z/2^32 are encoded below exactly
     as the engine implements them).
  2. Parse the per-instance `.kwl` image: dimension n, group size g, the dense
     constraint matrix A, and the target vector t.
  3. SOLVE the system of modular linear congruences  A x == t  (mod 2^32) for
     the unknown word vector x. A is invertible over Z/2^32 (its determinant
     is odd), so x = A^{-1} t is unique. We use sympy's modular matrix inverse
     -- not field-style Gaussian elimination, which breaks on even pivots
     because even numbers have no inverse mod 2^32.
  4. Re-encode x as the canonical license key, then (optionally) feed it to the
     real `keywright` binary and watch it print the flag.

No search, no guessing: recovering the matrix and one modular linear solve
produce the one key that satisfies every constraint.

  python3 solve.py --image license.kwl                 # recover + print key
  python3 solve.py --image license.kwl --bin ./keywright  # ...and win the flag
"""
import os, sys, struct, argparse, subprocess
from sympy import Matrix

# --- constants recovered from the engine -----------------------------------
MOD = 1 << 32                                   # uint32 arithmetic == mod 2^32
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"   # base-32, no I L O U


def parse_image(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"KWL1":
        raise ValueError("not a KWL1 image")
    n, g = data[4], data[5]
    (flag_len,) = struct.unpack_from("<H", data, 6)
    off = 8
    A = list(struct.unpack_from("<%dI" % (n * n), data, off)); off += 4 * n * n
    t = list(struct.unpack_from("<%dI" % n, data, off));       off += 4 * n
    flag_ct = data[off:off + flag_len];                        off += flag_len
    return dict(n=n, g=g, A=A, t=t, flag_ct=flag_ct)


def encode_key(x, g):
    """Word vector -> canonical license key (mirrors the engine's encoder)."""
    groups = []
    for v in x:
        s = "".join(ALPHABET[(v >> (5 * (g - 1 - p))) & 31] for p in range(g))
        groups.append(s)
    return "-".join(groups)


def matmul_vec(A, x, n):
    """y = A @ x (mod 2^32); used only to verify the recovered key."""
    return [sum(A[i * n + j] * x[j] for j in range(n)) % MOD for i in range(n)]


def solve_system(A_flat, t, n):
    """Solve A x == t (mod 2^32) for x, using sympy's modular matrix inverse."""
    A = Matrix(n, n, A_flat)
    tv = Matrix(n, 1, t)
    # det(A) is odd => gcd(det, 2^32) = 1 => A is a unit over Z/2^32.
    Ainv = A.inv_mod(MOD)
    x = (Ainv * tv).applyfunc(lambda e: int(e) % MOD)
    return [int(v) for v in x]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True, help="path to the .kwl image")
    ap.add_argument("--bin", help="path to the compiled keywright engine (to win the flag)")
    args = ap.parse_args()

    im = parse_image(args.image)
    n, g = im["n"], im["g"]

    x = solve_system(im["A"], im["t"], n)

    # sanity: the recovered vector must satisfy every constraint
    if matmul_vec(im["A"], x, n) != im["t"]:
        print("[-] solve failed: A @ x != t (mod 2^32)", file=sys.stderr)
        return 1

    key = encode_key(x, g)
    print("[+] constraint system: %d x %d over Z/2^32 (A x == t)" % (n, n))
    print("[+] recovered word vector x = %s" % x)
    print("[+] recovered license key: %s" % key)

    if not args.bin:
        print("[+] (no --bin given; key recovered by analysis only)")
        return 0

    engine = os.path.abspath(args.bin)
    image = os.path.abspath(args.image)
    proc = subprocess.run([engine, image], input=key.encode() + b"\n",
                          capture_output=True, timeout=30)
    out = proc.stdout.decode("latin-1", "replace").strip()
    print("[+] engine response: %s" % out)
    if out.startswith("zerosecurectf{"):
        print("[+] FLAG =", out)
        return 0
    print("[-] did not get a flag")
    return 1


if __name__ == "__main__":
    sys.exit(main())
