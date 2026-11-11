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


import sympy as sp
from fpylll import IntegerMatrix, LLL
h=load("handout.json");N=h["N"];X=1<<(8*h["flag_len_bytes"]);x=sp.Symbol("x")
H=int.from_bytes(h["header"].encode(),"big")*X
f=sp.Poly((H+x)**h["e"]-h["c"],x)
f=sp.Poly(sum((int(f.nth(i))%N)*x**i for i in range(f.degree()+1)),x)
m=2;t=1;degree=f.degree();polys=[]
for i in range(m):
    for j in range(degree):polys.append(sp.Poly(x**j*N**(m-i)*f.as_expr()**i,x))
for j in range(t):polys.append(sp.Poly(x**j*f.as_expr()**m,x))
D=len(polys);rows=[[int(p.nth(j))*X**j for j in range(D)] for p in polys]
M=IntegerMatrix.from_matrix(rows);LLL.reduction(M)
answer=None
for row in M:
    g=sp.Poly(sum((int(row[j])//X**j)*x**j for j in range(D)),x)
    for value in sp.polys.polytools.ground_roots(g):
        z=int(value)
        if 0<=z<X and pow(H+z,h["e"],N)==h["c"]:answer=z;break
    if answer is not None:break
if answer is None:raise RuntimeError("small root not recovered")
emit(answer.to_bytes(h["flag_len_bytes"],"big"))
