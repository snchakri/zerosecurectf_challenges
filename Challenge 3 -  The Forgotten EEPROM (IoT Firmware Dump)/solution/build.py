#!/usr/bin/env python3
import platform
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GEN = ROOT / "src" / "generate_firmware.py"


def main():
    if platform.system() != "Linux":
        raise SystemExit("Challenge 3 build must run in Linux/WSL.")

    uname = subprocess.check_output(["uname", "-a"], text=True).strip()
    if "Linux" not in uname:
        raise SystemExit("Challenge 3 build requires uname -a to report Linux.")

    subprocess.run(["python3", str(GEN)], check=True)


if __name__ == "__main__":
    main()
