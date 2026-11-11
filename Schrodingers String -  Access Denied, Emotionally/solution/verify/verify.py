#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "public" / "schrodingers_string"


def out(cmd):
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)


def main():
    if not BIN.exists():
        raise SystemExit("Missing artifact: public/schrodingers_string")

    header = out(["readelf", "-h", str(BIN)])
    if "ELF64" not in header:
        raise SystemExit("Artifact is not ELF64")

    strings_out = out(["strings", str(BIN)])
    if "ZeroSecure_CTF{" in strings_out:
        raise SystemExit("Flag leaked via strings")

    symbols = out(["nm", str(BIN)])
    if "hidden_flag_builder" not in symbols:
        raise SystemExit("hidden_flag_builder symbol missing")

    dis = out(["objdump", "-d", str(BIN)])
    hidden_lines = [ln for ln in dis.splitlines() if "hidden_flag_builder" in ln]
    if not hidden_lines:
        raise SystemExit("No disassembly entry for hidden_flag_builder")

    movb_count = len(re.findall(r"\bmovb\b", dis))
    if movb_count < 20:
        raise SystemExit("Not enough bytewise moves; challenge may be over-optimized")

    run_out = out([str(BIN)])
    if "Access denied." not in run_out:
        raise SystemExit("Unexpected runtime output")

    print("[ok] ch1_schrodingers_string passed")


if __name__ == "__main__":
    main()
