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


h=load("handout.json");n=h["n"];a=math.isqrt(n)
if a*a<n:a+=1
while True:
    b2=a*a-n;b=math.isqrt(b2)
    if b*b==b2:break
    a+=1
p,q=a-b,a+b
assert p*q==n
d=pow(h["e"],-1,(p-1)*(q-1))
emit(flag_bytes(pow(h["c"],d,n)))
