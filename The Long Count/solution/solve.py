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


h=load("challenge.json");key=hashlib.sha256(h["root"].encode()).digest();stream=bytearray()
limit=1<<(256-h["bits"])
for step in range(h["steps"]):
    nonce=0
    while True:
        digest=hashlib.sha256(key+nonce.to_bytes(8,"big")).digest()
        if int.from_bytes(digest,"big")<limit:break
        nonce+=1
    print("block",step,"nonce",nonce,file=sys.stderr)
    key=digest;stream.extend(key[:h["per"]])
ct=bytes.fromhex(h["ct"]);emit(bytes(a^b for a,b in zip(ct,stream)))
