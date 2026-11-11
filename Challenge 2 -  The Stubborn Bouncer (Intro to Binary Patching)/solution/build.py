#!/usr/bin/env python3
import platform
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src" / "stubborn_bouncer.c"
OUT = ROOT / "dist" / "stubborn_bouncer"


def run(cmd):
    print(f"[run] {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def main():
    if platform.system() != "Linux":
        raise SystemExit("Challenge 2 build must run in Linux/WSL.")

    uname = subprocess.check_output(["uname", "-a"], text=True).strip()
    if "Linux" not in uname:
        raise SystemExit("Challenge 2 build requires uname -a to report Linux.")

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
