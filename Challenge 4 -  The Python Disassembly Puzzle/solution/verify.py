#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TRANSCRIPT = ROOT / "dist" / "python_disassembly.txt"
EXPECTED = "ZeroSecure_CTF{bytecode_trace_9}"


def decode_payload(payload):
    stage_one = payload[::-1]
    return "".join(chr(ord(ch) - 2) for ch in stage_one)


def main():
    if not TRANSCRIPT.exists():
        raise SystemExit("Missing artifact: dist/python_disassembly.txt")

    content = TRANSCRIPT.read_text(encoding="utf-8")
    first = content.splitlines()[0] if content.splitlines() else ""

    if not first.startswith("# Python version: "):
        raise SystemExit("Missing version header")
    if not ("3.10" in first or "3.9" in first):
        raise SystemExit("Transcript was not generated with Python 3.10/3.9")

    if "ZeroSecure_CTF{" in content:
        raise SystemExit("Flag leaked in plaintext transcript")

    m = re.search(r"LOAD_CONST\s+\d+\s+\('([^']+)'\)", content)
    if not m:
        raise SystemExit("Could not find encoded payload constant")

    solved = decode_payload(m.group(1))
    if solved != EXPECTED:
        raise SystemExit("Disassembly puzzle decode did not match expected flag")

    print("[ok] challenge_4 verification passed")


if __name__ == "__main__":
    main()
