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


from fpylll import IntegerMatrix, LLL
h=load("handout.json");A,b,q=h["A"],h["b"],h["q"];n=h["n"];m=h["m"]
prefix=b"zerosecurectf{";fixed={i:v for i,v in enumerate(prefix)};fixed[n-1]=ord("}")
unknown=[j for j in range(n) if j not in fixed];u=len(unknown);center=96
base=[fixed.get(j,center) for j in range(n)]
res=[(b[i]-sum(A[i][j]*base[j] for j in range(n)))%q for i in range(m)]
D=m+u+1;rows=[]
for i in range(m):
    row=[0]*D;row[i]=q;rows.append(row)
for k,j in enumerate(unknown):
    row=[0]*D
    for i in range(m):row[i]=A[i][j]
    row[m+k]=1;rows.append(row)
rows.append(res+[0]*u+[1]);M=IntegerMatrix.from_matrix(rows);LLL.reduction(M)
for row in M:
    if abs(row[-1])!=1:continue
    sign=-1 if row[-1]>0 else 1;s=base[:]
    for k,j in enumerate(unknown):s[j]+=sign*int(row[m+k])
    if not all(0<=v<256 for v in s):continue
    errs=[(b[i]-sum(A[i][j]*s[j] for j in range(n))+q//2)%q-q//2 for i in range(m)]
    if max(map(abs,errs))<=1:emit(bytes(s));break
else:raise RuntimeError("bounded-error LWE solution not found")
