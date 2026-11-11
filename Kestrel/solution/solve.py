#!/usr/bin/env python3
"""
ZSCTF :: Kestrel -- reference solver (standalone; stdlib only; does NOT import
the generator).

Intended path -- pure forensic analysis of THIS file:

  1. `strings kestrel.png` surfaces a flag-shaped string in a plaintext tEXt
     chunk near the top -- but it is `zer0securectf{...}` (a ZERO), which fails
     the published format. That is the decoy.
  2. The real flag is in a COMPRESSED zTXt chunk, so `strings` never shows it.
     Parse the PNG chunks, find every zTXt chunk, inflate its payload, and read
     the flag out of the decompressed text.

     (The same thing any PNG-aware tool does for you:
        exiftool kestrel.png            # prints the zTXt "Comment"
        pngcheck -t -v kestrel.png      # dumps text chunks, decompressing zTXt
      This script just does it with the standard library.)

Only a candidate matching ^zerosecurectf\\{[a-z0-9_]+\\}$ is accepted, so the
decoy is rejected automatically.

Usage:
    python3 solve.py <path-to.png>        # prints the flag (only) to stdout
"""
import re
import struct
import sys
import zlib

PNG_SIG = b"\x89PNG\r\n\x1a\n"
FLAG_RE = re.compile(rb"zerosecurectf\{[a-z0-9_]+\}")


def iter_chunks(raw: bytes):
    """Yield (ctype, data) for each PNG chunk."""
    if raw[:8] != PNG_SIG:
        raise ValueError("not a PNG file")
    pos = 8
    while pos + 8 <= len(raw):
        (length,) = struct.unpack(">I", raw[pos:pos + 4])
        ctype = raw[pos + 4:pos + 8]
        data = raw[pos + 8:pos + 8 + length]
        yield ctype, data
        if ctype == b"IEND":
            break
        pos += 12 + length                    # len(4) + type(4) + data + crc(4)


def ztext(data: bytes) -> bytes:
    """Decode a zTXt chunk payload: keyword \\x00 comp_method(1) zlib(text)."""
    kw, _, rest = data.partition(b"\x00")
    comp_method = rest[0]
    if comp_method != 0:
        raise ValueError("unsupported zTXt compression method %d" % comp_method)
    return zlib.decompress(rest[1:])


def recover(path: str) -> str:
    raw = open(path, "rb").read()
    # Search every zTXt chunk's DECOMPRESSED text for a valid-format flag.
    for ctype, data in iter_chunks(raw):
        if ctype == b"zTXt":
            try:
                text = ztext(data)
            except Exception:
                continue
            m = FLAG_RE.search(text)
            if m:
                return m.group(0).decode("ascii")
    raise ValueError("no valid-format flag found in any zTXt chunk "
                     "(the plaintext tEXt look-alike is the decoy)")


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: solve.py <path-to.png>\n")
        return 2
    try:
        flag = recover(argv[1])
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("[-] recovery failed: %s\n" % e)
        return 1
    sys.stderr.write("[+] inflated zTXt chunk; valid-format flag recovered\n")
    print(flag)              # stdout = exactly the flag
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
