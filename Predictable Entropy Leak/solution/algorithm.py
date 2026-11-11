#!/usr/bin/env python3
"""
Real solver for crypto_04_mersenne_twister_state_recovery.

Reads ONLY files in dist/ (default ./dist):
  - prng_stream.txt  : 624 consecutive MT19937 outputs (getrandbits(32))
  - sealed_vault.hex : the admin vault sealed with keystream from the MT19937
                       outputs that follow the captured 624.

Attack:
  1. Untemper each of the 624 outputs to invert MT19937's output tempering and
     recover the 624 internal state words.
  2. Load that state into a fresh MT19937 clone (index 624, ready to twist).
  3. Replay the generator forward to regenerate the sealing keystream and XOR it
     back over the sealed vault to recover the flag.

This script does not contain the flag and never reads the ./flag file.
"""
import argparse
import os
import random


def untemper(y):
    """Invert MT19937 output tempering: recover the state word from one output."""
    # invert  y ^= y >> 18
    y ^= y >> 18
    # invert  y ^= (y << 15) & 0xEFC60000
    y ^= (y << 15) & 0xEFC60000
    # invert  y ^= (y << 7) & 0x9D2C5680   (left shift of 7 -> iterate)
    t = y
    for _ in range(5):
        t = y ^ ((t << 7) & 0x9D2C5680)
    y = t
    # invert  y ^= y >> 11                 (right shift of 11 -> iterate)
    t = y
    for _ in range(3):
        t = y ^ (t >> 11)
    return t & 0xFFFFFFFF


def keystream(rng, nbytes):
    out = bytearray()
    while len(out) < nbytes:
        out += rng.getrandbits(32).to_bytes(4, "big")
    return bytes(out[:nbytes])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()

    with open(os.path.join(args.dist, "prng_stream.txt"), "r", encoding="utf-8") as f:
        outputs = [int(line) for line in f if line.strip()]
    with open(os.path.join(args.dist, "sealed_vault.hex"), "r", encoding="utf-8") as f:
        sealed = bytes.fromhex(f.read().strip())

    assert len(outputs) >= 624, "need 624 consecutive outputs to clone the state"
    state = [untemper(v) for v in outputs[:624]]

    clone = random.Random()
    clone.setstate((3, tuple(state + [624]), None))

    ks = keystream(clone, len(sealed))
    flag = bytes(a ^ b for a, b in zip(sealed, ks))
    print(flag.decode())


if __name__ == "__main__":
    main()
