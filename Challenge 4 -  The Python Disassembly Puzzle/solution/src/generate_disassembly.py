#!/usr/bin/env python3
import dis
import platform
import sys
from pathlib import Path

from puzzle_logic import recover_flag

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "dist" / "python_disassembly.txt"

ALLOWED = {(3, 10), (3, 9)}


def main():
    if platform.system() != "Linux":
        raise SystemExit("Challenge 4 build must run in Linux/WSL.")

    if (sys.version_info.major, sys.version_info.minor) not in ALLOWED:
        raise SystemExit(
            "Challenge 4 transcript must be generated with Python 3.10 "
            "(or 3.9 fallback)."
        )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        f.write(f"# Python version: {sys.version.split()[0]}\n")
        f.write("# Function: recover_flag\n\n")
        dis.dis(recover_flag, file=f)

    print(f"[ok] wrote {OUT}")


if __name__ == "__main__":
    main()
