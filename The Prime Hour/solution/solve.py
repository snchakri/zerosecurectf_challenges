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
h=load("handout.json");m,a,c=h["m"],h["a"],h["c"];low=h["low_bits"]
H=[x<<low for x in h["outputs_high"]];N=len(H);B=1<<low
powers=[1];offsets=[0]
for i in range(1,N):
    powers.append(powers[-1]*a%m);offsets.append((a*offsets[-1]+c)%m)
d=[(powers[i]*H[0]+offsets[i]-H[i])%m for i in range(N)]
rows=[[powers[i] for i in range(N)]]
for j in range(1,N):
    row=[0]*N;row[j]=m;rows.append(row)
M=IntegerMatrix.from_matrix(rows);LLL.reduction(M)
v=CVP.closest_vector(M,tuple(B//2-d[i] for i in range(N)))
x=[v[i]+d[i] for i in range(N)]
assert all(0<=t<B for t in x)
state=H[0]+x[0];seed=((state-c)*pow(a,-1,m))%m
s=seed
for hi in h["outputs_high"]:
    s=(a*s+c)%m;assert s>>low==hi
emit(flag_bytes(state))
