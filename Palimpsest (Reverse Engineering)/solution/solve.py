#!/usr/bin/env python3
"""
ZSCTF :: Palimpsest -- reference solver (pure analysis, no brute force).

The player receives only `palimpsest.pyc`: a marshalled CPython 3.13 code
object with the readable source scraped away. There is no working decompiler
for 3.13 bytecode, so the activation logic has to be recovered by *reading the
disassembly*. Once read, it is an invertible transform with a unique preimage.

Intended path:
  1. Strip the 16-byte .pyc header and `marshal.loads` the module code object.
  2. Walk it with `dis`: the activation gate is a composition of five layers --
        affine (per-position add then xor)          [_affine]
        modular multiply by an odd constant MUL      [_mix]
        S-box substitution                           [_sub]
        rotate-xor diffusion chain (low -> high)     [_diffuse]
        position permutation out[i] = b[perm[i]]     [_permute]
     then  transform(key) == EXPECTED.  The rotate amount is derived at run
     time as ROT = (SBOX[7] % 7) + 1 -- it is computed, not a literal.
  3. Pull the per-instance constants (L, SBOX, PERM, ADD, XOR, MUL, EXPECTED)
     straight out of the marshalled code object's module-level assignments.
  4. Every layer is a bijection, so the whole gate is invertible. Start from
     EXPECTED and apply each layer's inverse in reverse order -> the unique
     correct license key X. (No search: the structure collapses it to one pass.)
  5. (Optional) feed X to the real interpreter on the .pyc and watch the flag.

The flag itself is never in the image in the clear: it is stored as
FLAG XOR keystream(X) with keystream(X) = SHA256(X||0)||SHA256(X||1)||...,
so `strings` finds nothing and patching the comparison only unwraps garbage
(a wrong key hashes to a wrong keystream). The only path to the flag is X.

  python3 solve.py --image palimpsest.pyc               # recover + print key
  python3 solve.py --image palimpsest.pyc --run          # ...and win the flag
  python3 solve.py --image palimpsest.pyc --disasm       # show the disassembly
"""
import sys
import dis
import marshal
import hashlib
import argparse
import subprocess


# --- .pyc / marshal front-end ----------------------------------------------
def load_module_code(path):
    """Strip the 16-byte header and return the module-level code object."""
    with open(path, "rb") as f:
        blob = f.read()
    # .pyc layout (3.7+): u32 magic | u32 bitfield | u32+u32 (mtime+size OR hash)
    return marshal.loads(blob[16:])


def iter_code_objects(code, depth=0):
    """Yield (depth, code) for the module code and every nested code object."""
    yield depth, code
    for const in code.co_consts:
        if hasattr(const, "co_code"):
            yield from iter_code_objects(const, depth + 1)


def module_assignments(code):
    """Recover module-level `NAME = <const>` by tracking LOAD_CONST/STORE_NAME.

    This is the whole point of the challenge done mechanically: the per-instance
    tables are module globals, so each is a single LOAD_CONST immediately stored
    into a name. We read them straight from the disassembly rather than by
    importing (never execute an untrusted artifact to analyse it)."""
    g = {}
    last_const = None
    for ins in dis.get_instructions(code):
        if ins.opname == "LOAD_CONST":
            last_const = ins.argval
        elif ins.opname == "STORE_NAME":
            g[ins.argval] = last_const
    return g


# --- the recovered transform (read once from the bytecode) ------------------
def rol8(v, r):
    r &= 7
    return ((v << r) | (v >> (8 - r))) & 0xFF


def forward(key, p):
    """Forward activation transform -- mirrors _transform in the bytecode.
    Used only to self-check the recovered key against EXPECTED."""
    L = p["L"]
    b = bytearray(key)
    for i in range(L):
        b[i] = (b[i] + p["ADD"][i]) & 0xFF
    for i in range(L):
        b[i] ^= p["XOR"][i]
    for i in range(L):
        b[i] = (b[i] * p["MUL"]) & 0xFF
    for i in range(L):
        b[i] = p["SBOX"][b[i]]
    for i in range(1, L):
        b[i] ^= rol8(b[i - 1], p["ROT"])
    out = bytearray(L)
    for i in range(L):
        out[i] = b[p["PERM"][i]]
    return bytes(out)


def invert(p):
    """Run the gate backwards: inverse of each layer, in reverse order."""
    L = p["L"]
    SBOX, PERM, ADD, XOR, MUL, EXPECTED, ROT = (
        p["SBOX"], p["PERM"], p["ADD"], p["XOR"], p["MUL"], p["EXPECTED"], p["ROT"])

    sinv = [0] * 256
    for x, y in enumerate(SBOX):
        sinv[y] = x
    minv = pow(MUL, -1, 256)            # MUL is odd -> a unit mod 256 (NOT a divide)

    b = bytearray(L)
    for i in range(L):                  # undo _permute: scatter back (not re-apply)
        b[PERM[i]] = EXPECTED[i]
    for i in range(L - 1, 0, -1):       # undo _diffuse: unwind the chain high -> low
        b[i] ^= rol8(b[i - 1], ROT)
    for i in range(L):                  # undo _sub: inverse S-box
        b[i] = sinv[b[i]]
    for i in range(L):                  # undo _mix: multiply by MUL^-1 mod 256
        b[i] = (b[i] * minv) & 0xFF
    for i in range(L):                  # undo _affine: xor first, then subtract
        b[i] ^= XOR[i]
    for i in range(L):
        b[i] = (b[i] - ADD[i]) & 0xFF
    return bytes(b)


def recover_params(code):
    """Pull the per-instance parameters out of the marshalled module."""
    g = module_assignments(code)
    need = ["L", "SBOX", "PERM", "ADD", "XOR", "MUL", "EXPECTED", "FLAG_CT"]
    missing = [n for n in need if n not in g]
    if missing:
        raise ValueError("could not locate module constants: %s" % missing)
    p = {n: g[n] for n in need}
    # ROT is computed in the bytecode, not stored -- reproduce the derivation.
    p["ROT"] = (p["SBOX"][7] % 7) + 1
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True, help="path to palimpsest.pyc")
    ap.add_argument("--run", action="store_true",
                    help="feed the recovered key to the real interpreter and show the flag")
    ap.add_argument("--disasm", action="store_true",
                    help="print the recovered disassembly (module + nested code objects)")
    args = ap.parse_args()

    code = load_module_code(args.image)

    if args.disasm:
        for depth, c in iter_code_objects(code):
            print("%s--- code object: %s ---" % ("  " * depth, c.co_name))
            dis.dis(c)
            print()

    p = recover_params(code)
    key = invert(p)

    # self-check: the recovered key must reproduce the embedded target
    if forward(key, p) != p["EXPECTED"]:
        print("[-] inversion failed: forward(key) != EXPECTED", file=sys.stderr)
        return 1

    printable = all(32 <= c < 127 for c in key)
    print("[+] recovered license key: %s%s"
          % (key.decode("latin-1"), "" if printable else "  (non-printable)"))

    if not args.run:
        print("[+] (no --run; key recovered by analysis only)")
        return 0

    proc = subprocess.run([sys.executable, args.image], input=key + b"\n",
                          capture_output=True, timeout=30)
    out = proc.stdout.decode("latin-1", "replace").strip()
    print("[+] tool response: %s" % out)
    if out.startswith("zerosecurectf{"):
        print("[+] FLAG =", out)
        return 0
    print("[-] did not get a flag")
    return 1


if __name__ == "__main__":
    sys.exit(main())
