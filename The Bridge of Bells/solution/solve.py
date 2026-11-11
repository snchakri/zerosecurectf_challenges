#!/usr/bin/env python3
from pathlib import Path
import json, math, hashlib, struct, re, sys
HERE = Path(__file__).resolve().parent
CHALLENGE = HERE.parent / "challenge"
def artifact(name):
    p = CHALLENGE / name
    return p if p.exists() else HERE / "unlocked" / name
def load(name):
    return json.loads(artifact(name).read_text())
def flag_bytes(n):
    return n.to_bytes(max(1,(n.bit_length()+7)//8), "big")
def emit(value):
    if isinstance(value,bytes): value=value.decode()
    if not re.fullmatch(r"zerosecurectf\{[^}]+\}",value):
        raise RuntimeError("recovered value is not a flag: " + repr(value))
    print(value)


from z3 import BitVec, BitVecVal, Solver, sat
program=artifact("program.bin").read_bytes();ip=0;stack=[];inputs=[];solver=Solver()
while ip<len(program):
    op=program[ip];ip+=1
    if op==0:break
    if op==1:stack.append(BitVecVal(program[ip],8));ip+=1
    elif op==2:
        x=BitVec("input_%d"%len(inputs),8);inputs.append(x);stack.append(x)
    elif op in [3,4,5,7]:
        a,b=stack.pop(),stack.pop()
        if op==3:stack.append(a^b)
        elif op==4:stack.append(a+b)
        elif op==5:stack.append(b-a)
        else:solver.add(a==b)
    elif op==8:assert program[ip]==len(inputs);ip+=1
    else:raise ValueError(op)
assert solver.check()==sat
model=solver.model();out=bytes(model.eval(x).as_long() for x in inputs)
emit(out)
