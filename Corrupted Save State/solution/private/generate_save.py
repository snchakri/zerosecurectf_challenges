#!/usr/bin/env python3
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "public" / "corrupted_slot.sav"

FLAG = "ZeroSecure_CTF{corrupted_save_recovery_9}"
KEY = b"checkpoint9"
PLAYER = b"AoiRunner"
SEED = 0x1337C0DE


def xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def swap_nibbles(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        out.append(((b & 0x0F) << 4) | ((b & 0xF0) >> 4))
    return bytes(out)


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)

    xored = xor_bytes(FLAG.encode("ascii"), KEY)
    packed = swap_nibbles(xored)

    real_crc = zlib.crc32(xored) & 0xFFFFFFFF
    corrupted_crc = real_crc ^ 0xDEADBEEF

    blob = bytearray()
    blob.extend(b"SVST")
    blob.extend(struct.pack("<B", 1))
    blob.extend(struct.pack("<B", len(PLAYER)))
    blob.extend(PLAYER)
    blob.extend(struct.pack("<I", SEED))
    blob.extend(struct.pack("<H", len(packed)))
    blob.extend(packed)
    blob.extend(struct.pack("<I", corrupted_crc))
    blob.extend(b"SAVE_SLOT_03")

    OUT.write_bytes(bytes(blob))
    print(f"[ok] wrote {OUT}")


if __name__ == "__main__":
    main()
