#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

OP_RTYPE = 0x33
OP_LUI = 0x37
OP_ITYPE = 0x13
OP_LOAD = 0x03
OP_STORE = 0x23
OP_BRANCH = 0x63
OP_JAL = 0x6F
OP_CUSTOM = 0x0B

REGS: Dict[str, int] = {f"r{i}": i for i in range(8)}

R_FUNCS: Dict[str, Tuple[int, int]] = {
    "ADD": (0x0, 0x00),
    "SUB": (0x0, 0x20),
    "XOR": (0x4, 0x00),
    "OR": (0x6, 0x00),
    "AND": (0x7, 0x00),
}


class AsmError(Exception):
    pass


@dataclass(frozen=True)
class Instruction:
    pc: int
    line_no: int
    op: str
    operands: List[str]


def parse_reg(tok: str) -> int:
    key = tok.strip().lower()
    if key not in REGS:
        raise AsmError(f"unknown register: {tok}")
    return REGS[key]


def parse_int(tok: str) -> int:
    try:
        return int(tok, 0)
    except ValueError as exc:
        raise AsmError(f"invalid integer: {tok}") from exc


def parse_mem(tok: str) -> Tuple[int, int]:
    tok = tok.strip()
    if "(" not in tok or not tok.endswith(")"):
        raise AsmError(f"invalid memory operand: {tok}")
    off, base = tok.split("(", 1)
    base = base[:-1]
    return parse_int(off.strip()), parse_reg(base.strip())


def check_range_signed(value: int, bits: int, what: str) -> None:
    lo = -(1 << (bits - 1))
    hi = (1 << (bits - 1)) - 1
    if value < lo or value > hi:
        raise AsmError(f"{what} out of range ({value}) for {bits}-bit signed field")


def enc_r(rd: int, rs1: int, rs2: int, funct3: int, funct7: int) -> int:
    return (
        ((funct7 & 0x7F) << 25)
        | ((rs2 & 0x1F) << 20)
        | ((rs1 & 0x1F) << 15)
        | ((funct3 & 0x07) << 12)
        | ((rd & 0x1F) << 7)
        | OP_RTYPE
    )


def enc_i(rd: int, rs1: int, imm: int, funct3: int, opcode: int) -> int:
    check_range_signed(imm, 12, "imm12")
    imm_u = imm & 0xFFF
    return (
        (imm_u << 20)
        | ((rs1 & 0x1F) << 15)
        | ((funct3 & 0x07) << 12)
        | ((rd & 0x1F) << 7)
        | (opcode & 0x7F)
    )


def enc_s(rs1: int, rs2: int, imm: int, funct3: int) -> int:
    check_range_signed(imm, 12, "store offset")
    imm_u = imm & 0xFFF
    imm_11_5 = (imm_u >> 5) & 0x7F
    imm_4_0 = imm_u & 0x1F
    return (
        (imm_11_5 << 25)
        | ((rs2 & 0x1F) << 20)
        | ((rs1 & 0x1F) << 15)
        | ((funct3 & 0x07) << 12)
        | (imm_4_0 << 7)
        | OP_STORE
    )


def enc_b(rs1: int, rs2: int, offset: int, funct3: int) -> int:
    if offset % 2 != 0:
        raise AsmError(f"branch offset must be 2-byte aligned: {offset}")
    check_range_signed(offset, 13, "branch offset")
    imm = offset & 0x1FFF
    bit12 = (imm >> 12) & 0x1
    bit11 = (imm >> 11) & 0x1
    bits10_5 = (imm >> 5) & 0x3F
    bits4_1 = (imm >> 1) & 0x0F
    return (
        (bit12 << 31)
        | (bits10_5 << 25)
        | ((rs2 & 0x1F) << 20)
        | ((rs1 & 0x1F) << 15)
        | ((funct3 & 0x07) << 12)
        | (bits4_1 << 8)
        | (bit11 << 7)
        | OP_BRANCH
    )


def enc_jal(rd: int, offset: int) -> int:
    if offset % 2 != 0:
        raise AsmError(f"jal offset must be 2-byte aligned: {offset}")
    check_range_signed(offset, 21, "jal offset")
    imm = offset & 0x1FFFFF
    bit20 = (imm >> 20) & 0x1
    bits10_1 = (imm >> 1) & 0x3FF
    bit11 = (imm >> 11) & 0x1
    bits19_12 = (imm >> 12) & 0xFF
    return (
        (bit20 << 31)
        | (bits19_12 << 12)
        | (bit11 << 20)
        | (bits10_1 << 21)
        | ((rd & 0x1F) << 7)
        | OP_JAL
    )


def enc_custom(rd: int, rs1: int, funct3: int) -> int:
    return ((rs1 & 0x1F) << 15) | ((funct3 & 0x7) << 12) | ((rd & 0x1F) << 7) | OP_CUSTOM


def enc_lui(rd: int, imm20: int) -> int:
    if imm20 < -(1 << 19) or imm20 > ((1 << 19) - 1):
        raise AsmError(f"lui immediate out of range: {imm20}")
    return ((imm20 & 0xFFFFF) << 12) | ((rd & 0x1F) << 7) | OP_LUI


def normalize_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    if value >= 0x80000000:
        value -= 0x100000000
    return value


def estimate_size(op: str, operands: List[str]) -> int:
    if op == "LI":
        if len(operands) != 2:
            raise AsmError("LI requires 2 operands")
        imm = normalize_i32(parse_int(operands[1]))
        if -2048 <= imm <= 2047:
            return 4
        return 8
    return 4


def emit_li(rd: int, imm: int) -> List[int]:
    imm = normalize_i32(imm)
    if -2048 <= imm <= 2047:
        return [enc_i(rd, 0, imm, 0x0, OP_ITYPE)]

    upper = (imm + 0x800) >> 12
    lower = imm - (upper << 12)
    return [enc_lui(rd, upper), enc_i(rd, rd, lower, 0x0, OP_ITYPE)]


def tokenize_line(raw: str) -> Tuple[Optional[str], Optional[Tuple[str, List[str]]]]:
    text = raw.split("#", 1)[0].strip()
    if not text:
        return None, None

    label = None
    if ":" in text:
        before, after = text.split(":", 1)
        if before.strip():
            label = before.strip()
        text = after.strip()
        if not text:
            return label, None

    parts = text.split(None, 1)
    op = parts[0].upper()
    operands = []
    if len(parts) > 1:
        operands = [x.strip() for x in parts[1].split(",") if x.strip()]

    return label, (op, operands)


def resolve_target(tok: str, labels: Dict[str, int], pc: int) -> int:
    if tok in labels:
        return labels[tok] - pc
    return parse_int(tok)


def assemble(lines: List[str], entry_label: Optional[str]) -> Tuple[bytes, int]:
    labels: Dict[str, int] = {}
    insns: List[Instruction] = []
    pc = 0

    for line_no, raw in enumerate(lines, 1):
        label, parsed = tokenize_line(raw)
        if label is not None:
            if label in labels:
                raise AsmError(f"duplicate label at line {line_no}: {label}")
            labels[label] = pc
        if parsed is None:
            continue
        op, operands = parsed
        step = estimate_size(op, operands)
        insns.append(Instruction(pc=pc, line_no=line_no, op=op, operands=operands))
        pc += step

    out = bytearray()

    for insn in insns:
        pc = insn.pc
        line_no = insn.line_no
        op = insn.op
        operands = insn.operands
        try:
            if op in R_FUNCS:
                if len(operands) != 3:
                    raise AsmError("R-type requires 3 operands")
                rd = parse_reg(operands[0])
                rs1 = parse_reg(operands[1])
                rs2 = parse_reg(operands[2])
                funct3, funct7 = R_FUNCS[op]
                inst = enc_r(rd, rs1, rs2, funct3, funct7)

            elif op == "LUI":
                if len(operands) != 2:
                    raise AsmError("LUI requires 2 operands")
                rd = parse_reg(operands[0])
                imm20 = parse_int(operands[1])
                inst = enc_lui(rd, imm20)

            elif op == "ADDI":
                if len(operands) != 3:
                    raise AsmError("ADDI requires 3 operands")
                rd = parse_reg(operands[0])
                rs1 = parse_reg(operands[1])
                imm = parse_int(operands[2])
                inst = enc_i(rd, rs1, imm, 0x0, OP_ITYPE)

            elif op == "LD":
                if len(operands) != 2:
                    raise AsmError("LD requires 2 operands")
                rd = parse_reg(operands[0])
                imm, rs1 = parse_mem(operands[1])
                inst = enc_i(rd, rs1, imm, 0x2, OP_LOAD)

            elif op == "ST":
                if len(operands) != 2:
                    raise AsmError("ST requires 2 operands")
                rs2 = parse_reg(operands[0])
                imm, rs1 = parse_mem(operands[1])
                inst = enc_s(rs1, rs2, imm, 0x2)

            elif op == "BEQ" or op == "BNE":
                if len(operands) != 3:
                    raise AsmError(f"{op} requires 3 operands")
                rs1 = parse_reg(operands[0])
                rs2 = parse_reg(operands[1])
                offset = resolve_target(operands[2], labels, pc)
                funct3 = 0x0 if op == "BEQ" else 0x1
                inst = enc_b(rs1, rs2, offset, funct3)

            elif op == "JAL":
                if len(operands) != 2:
                    raise AsmError("JAL requires 2 operands")
                rd = parse_reg(operands[0])
                offset = resolve_target(operands[1], labels, pc)
                inst = enc_jal(rd, offset)

            elif op == "RDTSC":
                if len(operands) != 1:
                    raise AsmError("RDTSC requires 1 operand")
                rd = parse_reg(operands[0])
                inst = enc_custom(rd, 0, 0x0)

            elif op == "CLFLUSH":
                if len(operands) != 1:
                    raise AsmError("CLFLUSH requires 1 operand")
                rs1 = parse_reg(operands[0])
                inst = enc_custom(0, rs1, 0x1)

            elif op == "TRIGGER_SECRET":
                if operands:
                    raise AsmError("TRIGGER_SECRET takes no operands")
                inst = enc_custom(0, 0, 0x2)

            elif op == "PRINT":
                if len(operands) != 1:
                    raise AsmError("PRINT requires 1 operand")
                rs1 = parse_reg(operands[0])
                inst = enc_custom(0, rs1, 0x3)

            elif op == "HALT":
                if operands:
                    raise AsmError("HALT takes no operands")
                inst = 0

            elif op == "NOP":
                if operands:
                    raise AsmError("NOP takes no operands")
                inst = enc_i(0, 0, 0, 0x0, OP_ITYPE)

            elif op == "LI":
                if len(operands) != 2:
                    raise AsmError("LI requires 2 operands")
                rd = parse_reg(operands[0])
                imm = parse_int(operands[1])
                emitted = emit_li(rd, imm)
                for e in emitted:
                    out += struct.pack("<I", e)
                continue

            else:
                raise AsmError(f"unknown opcode: {op}")

        except AsmError as exc:
            raise AsmError(f"line {line_no}: {exc}") from exc

        out += struct.pack("<I", inst)

    if entry_label:
        if entry_label not in labels:
            raise AsmError(f"entry label not found: {entry_label}")
        entry_offset = labels[entry_label]
    else:
        entry_offset = 0

    return bytes(out), entry_offset


def main() -> None:
    parser = argparse.ArgumentParser(description="Thermal Boundary assembler")
    parser.add_argument("input", help="Input assembly file")
    parser.add_argument("output", help="Output bytecode file")
    parser.add_argument("--entry", default=None, help="Optional entry label")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        lines = f.readlines()

    code, entry_offset = assemble(lines, args.entry)

    header = b"TBVM" + struct.pack("<III", 1, len(code), entry_offset)

    with open(args.output, "wb") as f:
        f.write(header)
        f.write(code)

    print(f"wrote {args.output} ({len(code)} code bytes, entry={entry_offset})")


if __name__ == "__main__":
    try:
        main()
    except AsmError as exc:
        print(f"assembler error: {exc}", file=sys.stderr)
        sys.exit(1)
