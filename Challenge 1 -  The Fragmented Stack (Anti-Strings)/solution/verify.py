#!/usr/bin/env python3
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN = ROOT / "dist" / "fragmented_stack"


def out(cmd):
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)


def main():
    if not BIN.exists():
        raise SystemExit("Missing artifact: dist/fragmented_stack")

    header = out(["readelf", "-h", str(BIN)])
    if "ELF64" not in header:
        raise SystemExit("Artifact is not ELF64")

    s = out(["strings", str(BIN)])
    if "ZeroSecure_CTF{" in s:
        raise SystemExit("Flag leaked to strings output")

    sym = out(["nm", str(BIN)])
    if "hidden_flag_builder" not in sym:
        raise SystemExit("hidden_flag_builder symbol missing")

    run_out = out([str(BIN)])
    if "Access Denied." not in run_out:
        raise SystemExit("Unexpected runtime output for challenge 1")

    print("[ok] challenge_1 verification passed")


if __name__ == "__main__":
    main()
