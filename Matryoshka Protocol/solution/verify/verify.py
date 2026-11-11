#!/usr/bin/env python3
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "public" / "matryoshka_protocol"
PATCHED = ROOT / "verify" / ".matryoshka_protocol.patched"


def out(cmd):
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)


def run_binary(path, user_input):
    cp = subprocess.run(
        [str(path)],
        input=user_input,
        text=True,
        capture_output=True,
        check=False,
    )
    return cp.stdout + cp.stderr


def parse_text_section(binary_path):
    section_dump = out(["readelf", "-S", "-W", str(binary_path)])
    rx = re.compile(r"\[\s*\d+\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)")
    m = rx.search(section_dump)
    if not m:
        raise SystemExit("Could not locate .text section")
    text_addr = int(m.group(1), 16)
    text_off = int(m.group(2), 16)
    return text_addr, text_off


def parse_main_instructions(binary_path):
    dis = out(["objdump", "-d", "-M", "intel", str(binary_path)])
    lines = dis.splitlines()

    in_main = False
    instructions = []
    func_header = re.compile(r"^([0-9a-fA-F]+)\s+<([^>]+)>:")
    insn = re.compile(r"^\s*([0-9a-fA-F]+):\s*([0-9a-fA-F ]+)\s+([a-zA-Z][a-zA-Z0-9]+)\s*(.*)$")

    for line in lines:
        hdr = func_header.match(line)
        if hdr:
            name = hdr.group(2)
            if name == "main":
                in_main = True
                continue
            if in_main:
                break
        if not in_main:
            continue

        m = insn.match(line)
        if not m:
            continue

        addr = int(m.group(1), 16)
        raw = [int(x, 16) for x in m.group(2).split()]
        mnemonic = m.group(3).lower()
        operands = m.group(4)
        instructions.append((addr, raw, mnemonic, operands))

    if not instructions:
        raise SystemExit("Could not parse main instructions")

    return instructions


def find_jump_before_print_flag(instructions):
    call_idx = None
    for i, (_, _, mnemonic, operands) in enumerate(instructions):
        if mnemonic.startswith("call") and "print_flag" in operands:
            call_idx = i
            break

    if call_idx is None:
        raise SystemExit("Could not find call to print_flag")

    for i in range(call_idx - 1, -1, -1):
        _, raw, mnemonic, _ = instructions[i]
        if mnemonic in {"je", "jne", "jz", "jnz"}:
            return instructions[i]
        if raw and raw[0] == 0x0F and len(raw) >= 2 and raw[1] in {0x84, 0x85}:
            return instructions[i]

    raise SystemExit("No conditional jump found before print_flag call")


def patch_jump(src, dst, jump_addr, jump_raw):
    text_addr, text_off = parse_text_section(src)
    file_off = (jump_addr - text_addr) + text_off

    data = bytearray(src.read_bytes())

    if jump_raw[0] == 0x74:
        data[file_off] = 0x75
    elif jump_raw[0] == 0x75:
        data[file_off] = 0x74
    elif jump_raw[0] == 0x0F and len(jump_raw) >= 2 and jump_raw[1] == 0x84:
        data[file_off + 1] = 0x85
    elif jump_raw[0] == 0x0F and len(jump_raw) >= 2 and jump_raw[1] == 0x85:
        data[file_off + 1] = 0x84
    else:
        raise SystemExit("Unsupported jump encoding")

    dst.write_bytes(data)


def main():
    if not BIN.exists():
        raise SystemExit("Missing artifact: public/matryoshka_protocol")

    h = out(["readelf", "-h", str(BIN)])
    if "ELF64" not in h:
        raise SystemExit("Artifact is not ELF64")

    symbols = out(["nm", str(BIN)])
    if "print_flag" not in symbols:
        raise SystemExit("print_flag symbol missing")

    strings_out = out(["strings", str(BIN)])
    if "ZeroSecure_CTF{" in strings_out:
        raise SystemExit("Flag leaked in strings output")

    baseline = run_binary(BIN, "abc\n")
    if "Protocol rejected." not in baseline:
        raise SystemExit("Baseline behavior unexpected")
    if "ZeroSecure_CTF{" in baseline:
        raise SystemExit("Flag leaked pre-patch")

    if PATCHED.exists():
        PATCHED.unlink()

    try:
        shutil.copy2(BIN, PATCHED)

        ins = parse_main_instructions(BIN)
        jump_addr, jump_raw, _, _ = find_jump_before_print_flag(ins)
        patch_jump(BIN, PATCHED, jump_addr, jump_raw)

        patched = run_binary(PATCHED, "abc\n")
        if "ZeroSecure_CTF{" not in patched:
            raise SystemExit("Patched flow did not reveal flag")
    finally:
        if PATCHED.exists():
            PATCHED.unlink()

    print("[ok] ch2_matryoshka_protocol passed")


if __name__ == "__main__":
    main()
