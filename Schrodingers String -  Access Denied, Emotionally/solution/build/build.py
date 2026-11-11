#!/usr/bin/env python3
import platform
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "private" / "schrodingers_string.c"
OUT = ROOT / "public" / "schrodingers_string"


def run(cmd):
    print(f"[run] {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def main():
    if platform.system() != "Linux":
        raise SystemExit("ch1 build must run in Linux/WSL.")

    uname = subprocess.check_output(["uname", "-a"], text=True).strip()
    if "Linux" not in uname:
        raise SystemExit("ch1 build requires uname -a to report Linux.")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    run([
        "gcc",
        "-O0",
        "-fno-stack-protector",
        "-fno-inline",
        "-fno-lto",
        "-fno-pie",
        "-no-pie",
        "-o",
        str(OUT),
        str(SRC),
    ])


if __name__ == "__main__":
    main()
