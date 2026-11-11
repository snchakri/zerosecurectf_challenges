#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "public" / "polyglot_payload.dat"
EXPECTED = "ZeroSecure_CTF{polyglot_layers_resolve_9}"


def xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def main():
    if not ART.exists():
        raise SystemExit("Missing artifact: public/polyglot_payload.dat")

    text = ART.read_text(encoding="utf-8")

    if "KEY =" not in text or "BLOB_HEX =" not in text:
        raise SystemExit("Missing required polyglot markers")

    if "ZeroSecure_CTF{" in text:
        raise SystemExit("Plaintext flag leaked in artifact")

    strings_out = subprocess.check_output(["strings", str(ART)], text=True)
    if "ZeroSecure_CTF{" in strings_out:
        raise SystemExit("Plaintext flag leaked in strings output")

    m_key = re.search(r"KEY = '([^']+)'", text)
    m_blob = re.search(r"BLOB_HEX = '([0-9a-f]+)'", text)
    if not (m_key and m_blob):
        raise SystemExit("Could not parse key/blob fields")

    key = m_key.group(1).encode("ascii")
    enc = bytes.fromhex(m_blob.group(1))
    flag = xor_bytes(enc, key).decode("ascii")

    if flag != EXPECTED:
        raise SystemExit("Decoded flag did not match expected")

    print("[ok] ch3_polyglots_dilemma passed")


if __name__ == "__main__":
    main()
