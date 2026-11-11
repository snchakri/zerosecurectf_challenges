#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "dist" / "forgotten_eeprom.bin"

SSID = "Natsuki_Subaru_Network"
FLAG = "ZeroSecure_CTF{eeprom_xor_walk_9}"


def xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def build_blob() -> bytes:
    key = SSID.encode("ascii")
    enc = xor_bytes(FLAG.encode("ascii"), key)

    header = bytearray()
    header.extend(b"ZSFWv1\x00\x00")
    header.extend(b"CONFIG_START\n")
    header.extend(f"SSID:{SSID}\n".encode("ascii"))
    header.extend(b"MODE:SMART_LOCK\n")
    header.extend(f"FLAG_XOR_LEN:{len(enc):03d}\n".encode("ascii"))
    header.extend(b"FLAG_XOR:")
    header.extend(enc)
    header.extend(b"\nCONFIG_END\n")

    if len(header) < 2048:
        header.extend(b"\xff" * (2048 - len(header)))

    return bytes(header)


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(build_blob())
    print(f"[ok] wrote {OUT}")


if __name__ == "__main__":
    main()
