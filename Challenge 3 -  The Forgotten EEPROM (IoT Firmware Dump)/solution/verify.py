#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN = ROOT / "dist" / "forgotten_eeprom.bin"
EXPECTED_FLAG = "ZeroSecure_CTF{eeprom_xor_walk_9}"


def xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def main():
    if not BIN.exists():
        raise SystemExit("Missing artifact: dist/forgotten_eeprom.bin")

    strings_out = subprocess.check_output(["strings", str(BIN)], text=True)
    if "SSID:Natsuki_Subaru_Network" not in strings_out:
        raise SystemExit("SSID marker not discoverable")
    if "FLAG_XOR:" not in strings_out:
        raise SystemExit("FLAG_XOR marker not discoverable")
    if "ZeroSecure_CTF{" in strings_out:
        raise SystemExit("Flag leaked in plaintext")

    blob = BIN.read_bytes()

    m_ssid = re.search(br"SSID:([^\n]+)\n", blob)
    m_len = re.search(br"FLAG_XOR_LEN:(\d{3})\n", blob)
    m_marker = blob.find(b"FLAG_XOR:")
    if not (m_ssid and m_len and m_marker != -1):
        raise SystemExit("Missing required firmware markers")

    ssid = m_ssid.group(1).decode("ascii")
    xor_len = int(m_len.group(1).decode("ascii"))
    start = m_marker + len(b"FLAG_XOR:")
    enc = blob[start:start + xor_len]

    decoded = xor_bytes(enc, ssid.encode("ascii")).decode("ascii")
    if decoded != EXPECTED_FLAG:
        raise SystemExit("XOR solver did not recover expected flag")

    print("[ok] challenge_3 verification passed")


if __name__ == "__main__":
    main()
