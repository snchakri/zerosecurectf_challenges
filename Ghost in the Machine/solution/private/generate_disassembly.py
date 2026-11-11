#!/usr/bin/env python3
import dis
import sys
from pathlib import Path

from puzzle_logic import recover_flag

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "public" / "ghost_machine.dis"


def main():
    if (sys.version_info.major, sys.version_info.minor) not in {(3, 10), (3, 9)}:
        raise SystemExit("Use Python 3.10 or 3.9 to generate this transcript.")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        f.write(f"# Python version: {sys.version.split()[0]}\n")
        f.write("# Function: recover_flag\n\n")
        dis.dis(recover_flag, file=f)

    print(f"[ok] wrote {OUT}")


if __name__ == "__main__":
    main()
