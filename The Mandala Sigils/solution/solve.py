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


h=load("states.json");out=bytearray()
for states in h["states"]:
    common=set(map(tuple,states[0]))
    for graph in states[1:]:common &= set(map(tuple,graph))
    assert len(common)==1
    hi,lo=common.pop();out.append(16*hi+lo)
emit(bytes(out))
