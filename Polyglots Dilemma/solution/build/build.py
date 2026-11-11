#!/usr/bin/env python3
import platform
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "private" / "generate_polyglot.py"


def main():
    if platform.system() != "Linux":
        raise SystemExit("ch3 build must run in Linux/WSL.")

    uname = subprocess.check_output(["uname", "-a"], text=True).strip()
    if "Linux" not in uname:
        raise SystemExit("ch3 build requires uname -a to report Linux.")

    subprocess.run(["python3", str(GEN)], check=True)


if __name__ == "__main__":
    main()
