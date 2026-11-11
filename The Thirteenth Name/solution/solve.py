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


from fpylll import IntegerMatrix, LLL, CVP
h=load("handout.json");n=h["n"];B=1<<h["nonce_bound_bits"];sigs=h["signatures"];L=len(sigs)
a=[s["r"]*pow(s["s"],-1,n)%n for s in sigs]
b=[s["h"]*pow(s["s"],-1,n)%n for s in sigs]
rows=[]
for i in range(L):
    row=[0]*(L+1);row[i]=n*n;rows.append(row)
rows.append([v*n for v in a]+[B])
M=IntegerMatrix.from_matrix(rows);LLL.reduction(M)
target=tuple([(B//2-v)*n for v in b]+[B*n//2])
v=CVP.closest_vector(M,target);d=(v[-1]//B)%n
for s,aa,bb in zip(sigs,a,b):
    k=(aa*d+bb)%n;assert 0<k<B
    assert (s["s"]*k-s["h"]-s["r"]*d)%n==0
emit(flag_bytes(d))
