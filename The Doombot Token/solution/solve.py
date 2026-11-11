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


h=load("token.json");token=bytearray.fromhex(h["token_hex"])
old,new=b"peasant;",b"overlord"
for i,(a,b) in enumerate(zip(old,new)):token[16+5+i]^=a^b
out=token.hex();(HERE/"forged_token.hex").write_text(out+"\n")
print(out)
print("Submit forged_token.hex to the token verifier. The change rewrites role=peasant; to role=overlord while corrupting only the ignored preceding block.")
