#!/usr/bin/env python3
"""
ZSCTF :: Bittern -- reference solver (standalone; does NOT import the generator).

Intended path -- pure forensic analysis of THIS file, plus the documented,
discoverable keystream:

  1. Parse the PNG from first principles (stdlib zlib + struct): read IHDR for
     W,H; concatenate IDAT; zlib-inflate; every scanline uses filter type 0, so
     drop the leading filter byte per row to recover the raw HxWx3 RGB bytes.
  2. A plain raster-order LSB dump is noise -- the watermark is KEYED. Read the
     asset id from the PNG tEXt "Comment" chunk (the in-file parameter). The
     same chunk documents the construction.
  3. Rebuild the keyed slot stream:
         ks = SHA256(assetid || b"zswm/pos|" || ctr_be32), ctr = 0,1,2,...
     read 32-bit big-endian words, slot = word mod (3*W*H), skip repeats. The
     j-th distinct slot carries payload bit j (MSB-first within each byte).
  4. Read bits in that keyed order and reassemble the self-verifying frame:
         MAGIC "ZSIM" | VER | LEN(2,BE) | FLAG(LEN) | CRC32(4,BE)
     Wrong key/alignment fails MAGIC/CRC; correct recovery yields the flag.
     Nothing is guessed.

Usage:
    python3 solve.py <path-to.png>        # prints the flag (only) to stdout

Third-party: numpy (array handling for the inflated pixel buffer). No Pillow.
"""
import hashlib
import struct
import sys
import zlib

import numpy as np

# --- public spec: identical to what the artifact is built to (see writeup) ----
MAGIC     = b"ZSIM"
POS_LABEL = b"zswm/pos|"
PNG_SIG   = b"\x89PNG\r\n\x1a\n"


# ==========================================================================
# PNG parsing (stdlib only; filter type 0)
# ==========================================================================
def parse_png(path):
    """Return (W, H, pixels[H,W,3] uint8, {tEXt keyword: text})."""
    raw = open(path, "rb").read()
    if raw[:8] != PNG_SIG:
        raise ValueError("not a PNG file")
    pos = 8
    W = H = bit_depth = color_type = None
    idat = bytearray()
    texts = {}
    while pos + 8 <= len(raw):
        (length,) = struct.unpack(">I", raw[pos:pos + 4])
        ctype = raw[pos + 4:pos + 8]
        data = raw[pos + 8:pos + 8 + length]
        if ctype == b"IHDR":
            W, H, bit_depth, color_type = struct.unpack(">IIBB", data[:10])
        elif ctype == b"IDAT":
            idat += data
        elif ctype == b"tEXt":
            kw, _, txt = data.partition(b"\x00")
            texts[kw.decode("latin-1")] = txt.decode("latin-1")
        elif ctype == b"IEND":
            break
        pos += 12 + length                       # len(4)+type(4)+data+crc(4)

    if W is None:
        raise ValueError("no IHDR chunk")
    if bit_depth != 8 or color_type != 2:
        raise ValueError("expected 8-bit RGB (bit_depth=8, color_type=2), "
                         "got depth=%s type=%s" % (bit_depth, color_type))

    raw_pixels = zlib.decompress(bytes(idat))
    stride = W * 3
    rows = np.frombuffer(raw_pixels, dtype=np.uint8).reshape(H, stride + 1)
    if not np.all(rows[:, 0] == 0):
        raise ValueError("unexpected scanline filter (expected type 0 on all rows)")
    pixels = rows[:, 1:].reshape(H, W, 3)
    return W, H, pixels, texts


def extract_assetid(texts):
    """Pull the asset id (hex) out of the documented tEXt comment."""
    comment = texts.get("Comment", "")
    for tok in comment.replace("|", " ").replace(";", " ").split():
        if tok.startswith("assetid="):
            return bytes.fromhex(tok.split("=", 1)[1])
    raise ValueError("asset id not found in PNG tEXt comment: %r" % comment)


# ==========================================================================
# Keyed de-scatter (mirror of the documented embedding)
# ==========================================================================
def slot_stream(assetid, nslots):
    """Endless deterministic stream of DISTINCT LSB slot indices."""
    seen = set()
    ctr = 0
    while True:
        block = hashlib.sha256(assetid + POS_LABEL + struct.pack(">I", ctr)).digest()
        ctr += 1
        for off in range(0, 32, 4):
            word = struct.unpack(">I", block[off:off + 4])[0]
            slot = word % nslots
            if slot not in seen:
                seen.add(slot)
                yield slot


def read_bytes(gen, flat, nbytes):
    """Pull 8*nbytes keyed slots and reassemble bytes, MSB-first."""
    out = bytearray()
    for _ in range(nbytes):
        b = 0
        for _ in range(8):
            b = (b << 1) | (int(flat[next(gen)]) & 1)
        out.append(b)
    return bytes(out)


def recover(path):
    W, H, pixels, texts = parse_png(path)
    assetid = extract_assetid(texts)
    flat = pixels.reshape(-1)
    nslots = int(flat.shape[0])
    if nslots != W * H * 3:
        raise ValueError("pixel buffer size mismatch")

    gen = slot_stream(assetid, nslots)

    # Bootstrap: read the fixed-size header to learn the flag length.
    header = read_bytes(gen, flat, 7)            # MAGIC(4) | VER(1) | LEN(2,BE)
    if header[:4] != MAGIC:
        raise ValueError("MAGIC mismatch -- wrong key/alignment (got %r)" % header[:4])
    (length,) = struct.unpack(">H", header[5:7])

    body = read_bytes(gen, flat, length + 4)     # FLAG(length) | CRC32(4,BE)
    flag = body[:length]
    (crc,) = struct.unpack(">I", body[length:length + 4])
    if (zlib.crc32(header + flag) & 0xFFFFFFFF) != crc:
        raise ValueError("CRC mismatch -- recovery not validated")
    return flag.decode("utf-8")


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: solve.py <path-to.png>\n")
        return 2
    try:
        flag = recover(argv[1])
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("[-] recovery failed: %s\n" % e)
        return 1
    sys.stderr.write("[+] frame validated (MAGIC+CRC32 ok); flag recovered\n")
    print(flag)              # stdout = exactly the flag
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
