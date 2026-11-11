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


import subprocess,tempfile
h=load("params.json");p,q,g,y=h["p"],h["q"],h["g"],h["y"]
c=int.from_bytes(hashlib.sha256(h["message"].encode()).digest(),"big")%q
s=1;t=pow(g,s,p)*pow(pow(y,c,p),-1,p)%p
assert pow(g,s,p)==t*pow(y,c,p)%p
proof={"t":t,"s":s};(HERE/"forged_proof.json").write_text(json.dumps(proof,indent=2)+"\n")
print("Forged proof:",json.dumps(proof))
reply=subprocess.check_output([sys.executable,str(artifact("verifier.py")),str(artifact("params.json")),str(HERE/"forged_proof.json"),str(HERE/"accepted_flags.txt")],text=True)
print(reply.strip())
