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


import runpy
h=load("containers.json")
def prime(n):return n>=2 and all(n%d for d in range(2,math.isqrt(n)+1))
chosen=sorted([c for c in h["containers"] if prime(c["temp"])],key=lambda c:c["temp"])
assert len(chosen)==h["fragments"]
module=runpy.run_path(str(artifact("orchestrator.py")));answer=module["render"](str(artifact("containers.json")),[c["id"] for c in chosen])
assert answer.startswith("FLAG ");emit(answer[5:])
