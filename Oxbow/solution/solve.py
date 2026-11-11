#!/usr/bin/env python3
"""
ZSCTF :: Oxbow -- reference solver (pure analysis, no brute force).

Intended path:
  1. Recover the engine: the dispatcher loop, the 6-byte block format, the
     per-byte transforms, and the edge selector pred(pk, c). (Done once; the
     semantics are encoded below exactly as the handlers implement them.)
  2. Parse the per-instance `.oxb` image: S-box, position permutation, the
     block table, entry block, and the comparison target `expected`.
  3. Reconstruct the REAL pipeline: start at `entry`; at each block resolve
     pred(pk, c) to pick the LIVE successor; collect the block's transform;
     stop at END. The decoy blocks reached only by the dead edge are ignored.
  4. Every transform is a bijection on the register file, so the recovered
     pipeline is invertible. Run it BACKWARDS from `expected` -- apply each
     op's inverse in reverse order -- to obtain the unique correct key X.
  5. (Optional) feed X to the real `oxbow` binary and watch it print the flag.

No search, no guessing: resolving the opaque predicates linearises the
flattened graph to a single pipeline, which then inverts deterministically.

  python3 solve.py --image challenge.oxb                 # recover + print key
  python3 solve.py --image challenge.oxb --bin ./oxbow    # ...and win the flag
"""
import os, sys, struct, argparse, subprocess, hashlib

# --- Oxbow ISA (recovered from the engine) ---
END, XORK, ADDK, MULK, ROLK, ADDP, XORP, SBOX, PERM, CHN = \
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
HAS_ARG = {XORK, ADDK, MULK, ROLK, ADDP, XORP, CHN}
BLK_SZ = 6


def rol8(v, r):
    r &= 7
    return ((v << r) | (v >> (8 - r))) & 0xFF


def pred(pk, c):
    """Edge selector recovered from the engine; a function of c only."""
    x = c
    pk &= 3
    if pk == 0:   return (x * x - x) & 1
    if pk == 1:   return (x * x + x) & 1
    if pk == 2:   return ((x * x - x) & 1) ^ 1
    return (x * x + x + 1) & 1


def parse_image(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"OXBW":
        raise ValueError("not an OXBW image")
    ver, L = data[4], data[5]
    flag_len, nblk = struct.unpack_from("<HH", data, 6)
    entry = data[10]
    off = 12
    sbox = data[off:off + 256]; off += 256
    perm = data[off:off + L]; off += L
    blocks = []
    for _ in range(nblk):
        op, k, sA, sB, pk, c = data[off:off + BLK_SZ]
        blocks.append((op, k, sA, sB, pk, c))
        off += BLK_SZ
    expected = data[off:off + L]; off += L
    flag_ct = data[off:off + flag_len]; off += flag_len
    return dict(L=L, entry=entry, nblk=nblk, sbox=sbox, perm=perm,
                blocks=blocks, expected=expected, flag_ct=flag_ct)


def recover_pipeline(im):
    """Walk the flattened dispatcher statically: follow the live edge out of
    each block from `entry` to END, collecting (op, k). Ignores decoys."""
    ops, seen = [], set()
    st = im["entry"]
    while True:
        if st in seen:
            raise ValueError("cycle in live path (not expected for a valid image)")
        seen.add(st)
        op, k, sA, sB, pk, c = im["blocks"][st]
        if op == END:
            break
        ops.append((op, k))
        st = sA if pred(pk, c) else sB
        if st >= im["nblk"]:
            raise ValueError("live edge out of range")
    return ops


def run_pipeline(ops, sbox, perm, b):
    """Forward run of the recovered pipeline (used to verify the key)."""
    b = list(b); L = len(b)
    for op, k in ops:
        if op == XORK:   b = [x ^ k for x in b]
        elif op == ADDK: b = [(x + k) & 0xFF for x in b]
        elif op == MULK: b = [(x * k) & 0xFF for x in b]
        elif op == ROLK: b = [rol8(x, k) for x in b]
        elif op == ADDP: b = [(b[i] + k * (i + 1)) & 0xFF for i in range(L)]
        elif op == XORP: b = [b[i] ^ ((k + i) & 0xFF) for i in range(L)]
        elif op == SBOX: b = [sbox[x] for x in b]
        elif op == PERM: b = [b[perm[i]] for i in range(L)]
        elif op == CHN:
            for i in range(1, L):
                b[i] ^= rol8(b[i - 1], k)
    return bytes(b)


def invert(ops, sbox, perm, expected):
    """Run the pipeline backwards: inverse of each op, in reverse order."""
    L = len(expected)
    sinv = [0] * 256
    for x, y in enumerate(sbox):
        sinv[y] = x

    b = list(expected)
    for op, k in reversed(ops):
        if op == XORK:                       # self-inverse
            b = [x ^ k for x in b]
        elif op == ADDK:                     # subtract
            b = [(x - k) & 0xFF for x in b]
        elif op == MULK:                     # multiply by modular inverse (k odd)
            kinv = pow(k, -1, 256)
            b = [(x * kinv) & 0xFF for x in b]
        elif op == ROLK:                     # rotate the other way
            b = [rol8(x, (8 - (k & 7)) & 7) for x in b]
        elif op == ADDP:                     # subtract position term
            b = [(b[i] - k * (i + 1)) & 0xFF for i in range(L)]
        elif op == XORP:                     # self-inverse per position
            b = [b[i] ^ ((k + i) & 0xFF) for i in range(L)]
        elif op == SBOX:                     # inverse S-box
            b = [sinv[x] for x in b]
        elif op == PERM:                     # scatter back
            nb = [0] * L
            for i in range(L):
                nb[perm[i]] = b[i]
            b = nb
        elif op == CHN:                      # undo running chain, high->low
            for i in range(L - 1, 0, -1):
                b[i] ^= rol8(b[i - 1], k)
    return bytes(b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True, help="path to the .oxb image")
    ap.add_argument("--bin", help="path to the compiled oxbow engine (to win the flag)")
    args = ap.parse_args()

    im = parse_image(args.image)
    ops = recover_pipeline(im)
    key = invert(ops, im["sbox"], im["perm"], im["expected"])

    # sanity: forward(key) must reproduce the embedded target
    check = run_pipeline(ops, im["sbox"], im["perm"], key)
    if check != im["expected"]:
        print("[-] inversion failed: forward(key) != expected", file=sys.stderr)
        return 1

    printable = all(32 <= c < 127 for c in key)
    print("[+] real pipeline length: %d ops (%d blocks total in image, %d decoys)"
          % (len(ops), im["nblk"], im["nblk"] - (len(ops) + 1)))
    print("[+] recovered license key: %s%s"
          % (key.decode("latin-1"), "" if printable else "  (non-printable)"))

    # The archived event image is v1, while the included engine was upgraded to
    # v2. Decode the documented v1 wrap directly after recovering the real key.
    if len(open(args.image, "rb").read()) == 12 + 256 + im["L"] * 2 + im["nblk"] * 6 + len(im["flag_ct"]):
        stream = b"".join(hashlib.sha256(key + bytes([i])).digest()
                          for i in range((len(im["flag_ct"]) + 31) // 32))
        flag = bytes(a ^ b for a, b in zip(im["flag_ct"], stream))
        if not flag.startswith(b"zerosecurectf{"):
            raise RuntimeError("v1 image did not decode to a flag")
        print("[+] FLAG =", flag.decode())
        return 0

    if not args.bin:
        print("[+] (no --bin given; key recovered by analysis only)")
        return 0

    engine = os.path.abspath(args.bin)
    image = os.path.abspath(args.image)
    proc = subprocess.run([engine, image], input=key + b"\n",
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
