#!/usr/bin/env python3
import platform
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "private" / "generate_disassembly.py"
FALLBACK = ROOT / "private" / "ghost_machine_3_10.dis"
OUT = ROOT / "public" / "ghost_machine.dis"


def main():
    if platform.system() != "Linux":
        raise SystemExit("ch4 build must run in Linux/WSL.")

    uname = subprocess.check_output(["uname", "-a"], text=True).strip()
    if "Linux" not in uname:
        raise SystemExit("ch4 build requires uname -a to report Linux.")

    interpreter = None
    for candidate in ("python3.10", "python3.9"):
        if shutil.which(candidate):
            interpreter = candidate
            break

    if interpreter is None:
        if not FALLBACK.exists():
            raise SystemExit(
                "Missing python3.10/python3.9 and no fallback transcript found."
            )
        OUT.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(FALLBACK, OUT)
        print(f"[ok] copied fallback transcript to {OUT}")
        return

    subprocess.run([interpreter, str(GEN)], check=True)


if __name__ == "__main__":
    main()
