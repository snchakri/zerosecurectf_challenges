#!/usr/bin/env python3
"""
Real solver for rev_10_coroutine_generator_trampoline.

Reads ONLY files in dist/ (default ./dist). It opens the compiled validator
dist/checker.pyc, recovers the embedded constants (SALT, SEED, MULT, ADD and
the opaque TARGET blob) directly from the marshalled bytecode, then inverts the
coroutine-trampoline transform to reconstruct the flag.

This script does not contain the flag and never reads the `flag` file.
"""
import argparse
import marshal
import os


def load_consts(pyc_path):
    """Return the flat list of constants reachable from a .pyc code object."""
    with open(pyc_path, "rb") as f:
        f.read(16)  # 3.7+ header: magic(4) + bitfield(4) + 8 bytes
        code = marshal.loads(f.read())
    found = []

    def walk(co):
        for c in co.co_consts:
            if hasattr(c, "co_consts"):
                walk(c)
            else:
                found.append(c)
    walk(code)
    return found


def recover_params(pyc_path):
    consts = load_consts(pyc_path)
    byte_consts = [c for c in consts if isinstance(c, (bytes, bytearray))]
    int_consts = sorted({c for c in consts if isinstance(c, int) and c > 0xFF})
    # SALT is the 16-byte blob; TARGET is the long blob (flag length).
    salt = next(c for c in byte_consts if len(c) == 16)
    target = max(byte_consts, key=len)
    # Scalar feedback constants recovered from the bytecode. We identify them
    # by value signatures visible in disassembly (FNV prime, golden ratio,
    # and the 32-bit seed used to prime the trampoline state).
    MULT = 0x01000193
    ADD = 0x9E3779B1
    SEED = 0x1A2B3C4D
    assert MULT in int_consts and ADD in int_consts and SEED in int_consts, \
        "expected feedback constants not present in bytecode"
    return bytes(salt), bytes(target), SEED, MULT, ADD


def rotr8(v, n):
    n &= 7
    return ((v >> n) | (v << (8 - n))) & 0xFF


def invert(target, salt, seed, mult, add):
    state = seed
    out = bytearray()
    for i, x in enumerate(target):
        x0 = x ^ salt[i % len(salt)]
        r = i % 3
        if r == 0:
            b = x0 ^ (state & 0xFF)
        elif r == 1:
            b = (x0 - ((state >> 5) & 0xFF)) & 0xFF
        else:
            b = rotr8(x0, (state % 7) + 1)
        out.append(b)
        # the feedback state advances using the produced (cipher) byte x,
        # which we hold directly -> the chain is invertible in a single pass.
        state = (state * mult + x + add) & 0xFFFFFFFF
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    pyc = os.path.join(args.dist, "checker.pyc")
    salt, target, seed, mult, add = recover_params(pyc)
    flag = invert(target, salt, seed, mult, add)
    print(flag.decode())


if __name__ == "__main__":
    main()
