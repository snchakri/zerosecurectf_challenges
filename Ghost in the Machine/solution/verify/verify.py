#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "public" / "ghost_machine.dis"
EXPECTED = "ZeroSecure_CTF{ghost_opcode_trace_9}"


def decode_payload(payload):
    stage = payload[::-1]
    return "".join(chr(ord(ch) + 2) for ch in stage)


def main():
    if not ART.exists():
        raise SystemExit("Missing artifact: public/ghost_machine.dis")

    text = ART.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or not lines[0].startswith("# Python version: "):
        raise SystemExit("Missing Python version header")

    if "3.10" not in lines[0] and "3.9" not in lines[0]:
        raise SystemExit("Transcript not generated with Python 3.10/3.9")

    if "ZeroSecure_CTF{" in text:
        raise SystemExit("Plaintext flag leaked in transcript")

    m = re.search(r"LOAD_CONST\s+\d+\s+\('([^']+)'\)", text)
    if not m:
        raise SystemExit("Could not locate encoded payload constant")

    solved = decode_payload(m.group(1))
    if solved != EXPECTED:
        raise SystemExit("Decoded payload did not match expected flag")

    print("[ok] ch4_ghost_in_the_machine passed")


if __name__ == "__main__":
    main()
