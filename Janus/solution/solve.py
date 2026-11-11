#!/usr/bin/env python3
"""
ZSCTF :: Janus -- reference solver (standalone; does NOT import the generator).

Intended path -- recognise that the ONE file wears two faces and combine them:

  FACE 1 (PNG / image).  Parse the PNG from first principles (stdlib zlib +
     struct): read IHDR for W,H; concatenate IDAT; inflate; every scanline uses
     filter type 0, so drop the leading filter byte per row to recover the raw
     HxWx3 RGB samples. Read the 16-byte KEY from the LSBs of the first 128
     samples (row-major, MSB-first per byte). The scheme is also disclosed in the
     PNG tEXt "Comment" chunk.

  FACE 2 (ZIP / archive).  The SAME file is also a valid ZIP (its End-Of-Central-
     Directory record is at the tail and the PNG is an auto-detected prefix).
     Open it with the standard library's zipfile and read the single entry
     `payload.bin` -- the CIPHERTEXT.

  COMBINE.  Rebuild the keystream from the key:
         ks = SHA256(key || b"janus/xor|" || ctr_be32), ctr = 0,1,2,...
     XOR it into the ciphertext to recover the self-verifying frame
         MAGIC "ZJAN" | VER | LEN(2,BE) | FLAG(LEN) | CRC32(4,BE)
     Validate MAGIC + CRC32; print the flag. Wrong key fails the check -- nothing
     is guessed.

Neither face alone wins: unzipping yields only noise; viewing the image yields
only a picture (and even reading the pixel LSBs yields the key, not the flag).

Usage:
    python3 solve.py <path-to-artifact>      # prints the flag (only) to stdout

Pure standard library: hashlib, io, struct, sys, zipfile, zlib. No numpy, no
Pillow.
"""
import hashlib
import io
import struct
import sys
import zipfile
import zlib

# --- public spec: identical to what the artifact is built to (see writeup) ----
MAGIC     = b"ZJAN"
XOR_LABEL = b"janus/xor|"
PNG_SIG   = b"\x89PNG\r\n\x1a\n"
KEY_LEN   = 16
KEY_BITS  = KEY_LEN * 8
ENTRY     = "payload.bin"


# ==========================================================================
# FACE 1: PNG image parsing (stdlib only; colour type 2, filter 0)
# ==========================================================================
def read_key_from_png(raw: bytes) -> bytes:
    if raw[:8] != PNG_SIG:
        raise ValueError("not a PNG file (bad signature)")
    pos = 8
    W = H = bit_depth = color_type = None
    idat = bytearray()
    while pos + 8 <= len(raw):
        (length,) = struct.unpack(">I", raw[pos:pos + 4])
        ctype = raw[pos + 4:pos + 8]
        data = raw[pos + 8:pos + 8 + length]
        if ctype == b"IHDR":
            W, H, bit_depth, color_type = struct.unpack(">IIBB", data[:10])
        elif ctype == b"IDAT":
            idat += data
        elif ctype == b"IEND":
            break
        pos += 12 + length                         # len(4)+type(4)+data+crc(4)

    if W is None:
        raise ValueError("no IHDR chunk")
    if bit_depth != 8 or color_type != 2:
        raise ValueError("expected 8-bit RGB (depth=8,type=2); got %s/%s"
                         % (bit_depth, color_type))

    raw_pixels = zlib.decompress(bytes(idat))
    stride = W * 3
    if len(raw_pixels) != H * (stride + 1):
        raise ValueError("inflated size mismatch")

    # Flatten samples in row-major order, dropping each row's filter byte.
    samples = bytearray()
    for row in range(H):
        base = row * (stride + 1)
        if raw_pixels[base] != 0:
            raise ValueError("unexpected scanline filter (expected type 0)")
        samples += raw_pixels[base + 1:base + 1 + stride]
        if len(samples) >= KEY_BITS:
            break
    if len(samples) < KEY_BITS:
        raise ValueError("image too small to hold the key")

    # First KEY_BITS sample LSBs -> key bytes, MSB-first per byte.
    bits = [samples[i] & 1 for i in range(KEY_BITS)]
    key = bytearray()
    for i in range(0, KEY_BITS, 8):
        b = 0
        for k in range(8):
            b = (b << 1) | bits[i + k]
        key.append(b)
    return bytes(key)


# ==========================================================================
# FACE 2: ZIP archive parsing (standard library)
# ==========================================================================
def read_cipher_from_zip(raw: bytes) -> bytes:
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        names = zf.namelist()
        if ENTRY not in names:
            raise ValueError("ZIP entry %r not found (have %r)" % (ENTRY, names))
        return zf.read(ENTRY)


# ==========================================================================
# COMBINE
# ==========================================================================
def keystream(key: bytes, nbytes: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < nbytes:
        out += hashlib.sha256(key + XOR_LABEL + struct.pack(">I", ctr)).digest()
        ctr += 1
    return bytes(out[:nbytes])


def recover(path: str) -> str:
    raw = open(path, "rb").read()
    key = read_key_from_png(raw)          # FACE 1
    cipher = read_cipher_from_zip(raw)    # FACE 2
    frame = bytes(a ^ b for a, b in zip(cipher, keystream(key, len(cipher))))

    if frame[:4] != MAGIC:
        raise ValueError("MAGIC mismatch -- wrong key/combine (got %r)" % frame[:4])
    if len(frame) < 7:
        raise ValueError("frame too short")
    ver = frame[4]
    (length,) = struct.unpack(">H", frame[5:7])
    flag = frame[7:7 + length]
    (crc,) = struct.unpack(">I", frame[7 + length:7 + length + 4])
    head = frame[:7 + length]
    if (zlib.crc32(head) & 0xFFFFFFFF) != crc:
        raise ValueError("CRC mismatch -- recovery not validated")
    _ = ver
    return flag.decode("utf-8")


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: solve.py <path-to-artifact>\n")
        return 2
    try:
        flag = recover(argv[1])
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("[-] recovery failed: %s\n" % e)
        return 1
    sys.stderr.write("[+] PNG face -> key; ZIP face -> cipher; "
                     "combined, frame validated (MAGIC+CRC32 ok)\n")
    print(flag)               # stdout = exactly the flag
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
