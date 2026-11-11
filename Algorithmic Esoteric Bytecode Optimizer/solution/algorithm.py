#!/usr/bin/env python3
"""
Real solver for misc_12_esoteric_brainfuck_jit_transpiler.

Reads ONLY dist/program.bf. A naive per-instruction interpreter would have to
execute several million operations (the program is padded with a large
multiply/clear "dead-weight" loop). This solver instead performs the classic
Brainfuck peephole optimisations before running:

  1. run-length collapse of +, -, <, > runs        (+++++  ->  add 5)
  2. clear-loop folding   [-] / [+]                 ->  set cell = 0
  3. multiply/copy-loop folding   [ >+++ <- ] etc.  ->  cell += n*k ; cell = 0

With these folds every loop in the program becomes straight-line arithmetic, so
the whole thing evaluates in microseconds and prints the flag.

It does not contain the flag and never reads the ./flag file.
"""
import argparse
import os
import sys


# IR ops: 'add'(delta), 'move'(delta), 'out', 'in',
#   'clear'            -> cell = 0
#   'mul'(dict off->k) -> for each off: cell[p+off]+=k*cell[p]; cell[p]=0
#   'loop'(body)       -> generic while cell[p]!=0 run body
def tokenize(src):
    return [c for c in src if c in "+-<>[].,"]


def parse(code, i=0, top=True):
    ops = []
    n = len(code)
    while i < n:
        c = code[i]
        if c in "+-":
            delta = 0
            while i < n and code[i] in "+-":
                delta += 1 if code[i] == "+" else -1
                i += 1
            ops.append(("add", delta))
        elif c in "<>":
            delta = 0
            while i < n and code[i] in "<>":
                delta += 1 if code[i] == ">" else -1
                i += 1
            ops.append(("move", delta))
        elif c == ".":
            ops.append(("out", 0)); i += 1
        elif c == ",":
            ops.append(("in", 0)); i += 1
        elif c == "[":
            body, i = parse(code, i + 1, top=False)
            ops.append(optimize_loop(body))
        elif c == "]":
            return ops, i + 1
        else:
            i += 1
    return ops if top else (ops, i)


def optimize_loop(body):
    if body == [("add", -1)] or body == [("add", 1)]:
        return ("clear", 0)
    net_move = 0
    base_delta = 0
    offsets = {}
    flat = True
    for op, arg in body:
        if op == "add":
            offsets[net_move] = offsets.get(net_move, 0) + arg
            if net_move == 0:
                base_delta += arg
        elif op == "move":
            net_move += arg
        else:
            flat = False
            break
    if flat and net_move == 0 and base_delta == -1:
        coeffs = {off: d for off, d in offsets.items() if off != 0 and d != 0}
        return ("mul", coeffs)
    return ("loop", body)


def run(ops, tape, ptr, out):
    for op, arg in ops:
        if op == "add":
            tape[ptr] = (tape[ptr] + arg) & 0xFF
        elif op == "move":
            ptr += arg
        elif op == "out":
            out.append(tape[ptr])
        elif op == "in":
            tape[ptr] = 0
        elif op == "clear":
            tape[ptr] = 0
        elif op == "mul":
            n = tape[ptr]
            if n:
                for off, coeff in arg.items():
                    tape[ptr + off] = (tape[ptr + off] + coeff * n) & 0xFF
                tape[ptr] = 0
        elif op == "loop":
            guard = 0
            while tape[ptr] != 0:
                ptr = run(arg, tape, ptr, out)
                guard += 1
                if guard > 2_000_000:
                    raise RuntimeError("loop budget exceeded (non-foldable)")
    return ptr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    src = open(os.path.join(args.dist, "program.bf"), "r", encoding="utf-8").read()
    ops = parse(tokenize(src))
    tape = bytearray(1 << 16)
    out = bytearray()
    run(ops, tape, 0, out)
    sys.stdout.write(out.decode())
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
