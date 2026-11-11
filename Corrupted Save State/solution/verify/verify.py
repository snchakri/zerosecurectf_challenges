#!/usr/bin/env python3
import struct
import subprocess
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "public" / "corrupted_slot.sav"
EXPECTED = "ZeroSecure_CTF{corrupted_save_recovery_9}"
KEY = b"checkpoint9"


def xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def unswap_nibbles(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        out.append(((b & 0x0F) << 4) | ((b & 0xF0) >> 4))
    return bytes(out)


def main():
    if not ART.exists():
        raise SystemExit("Missing artifact: public/corrupted_slot.sav")

    strings_out = subprocess.check_output(["strings", str(ART)], text=True)
    if "ZeroSecure_CTF{" in strings_out:
        raise SystemExit("Plaintext flag leaked")

    blob = ART.read_bytes()
    if len(blob) < 24 or blob[:4] != b"SVST":
        raise SystemExit("Invalid save header")

    offset = 4
    version = blob[offset]
    offset += 1
    if version != 1:
        raise SystemExit("Unexpected version")

    name_len = blob[offset]
    offset += 1
    player = blob[offset:offset + name_len]
    offset += name_len

    _seed = struct.unpack("<I", blob[offset:offset + 4])[0]
    offset += 4

    data_len = struct.unpack("<H", blob[offset:offset + 2])[0]
    offset += 2
    packed = blob[offset:offset + data_len]
    offset += data_len

    stored_crc = struct.unpack("<I", blob[offset:offset + 4])[0]

    xored = unswap_nibbles(packed)
    recovered = xor_bytes(xored, KEY).decode("ascii")

    if recovered != EXPECTED:
        raise SystemExit("Recovered flag mismatch")

    real_crc = zlib.crc32(xored) & 0xFFFFFFFF
    if stored_crc == real_crc:
        raise SystemExit("Checksum was expected to be corrupted but matched")

    if player != b"AoiRunner":
        raise SystemExit("Unexpected player metadata")

    print("[ok] ch5_corrupted_save_state passed")


if __name__ == "__main__":
    main()
