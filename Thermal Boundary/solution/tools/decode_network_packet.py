#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from pathlib import Path


def decode_packet(path: Path) -> str:
    raw = path.read_bytes()
    if len(raw) < 8:
        raise ValueError("packet too short")

    magic, seq, text_len, _reserved = struct.unpack_from("<HHHH", raw, 0)
    if magic != 0xDEAD:
        raise ValueError(f"unexpected magic: 0x{magic:04x}")

    bits = struct.unpack_from("<16I", raw, 8)
    out = bytearray()
    for i in range(text_len):
        v = 0
        for b in range(8):
            bit_index = i * 8 + b
            word = bit_index // 32
            shift = bit_index % 32
            v |= ((bits[word] >> shift) & 1) << b
        out.append(v)

    _ = seq
    return out.decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Decode Thermal Boundary network mirage packet")
    parser.add_argument("packet", help="Path to binary packet log")
    args = parser.parse_args()

    result = decode_packet(Path(args.packet))
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
