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


code=artifact("program.bin").read_bytes();ip=0;registers={};rows=[];targets=[];n=None
while ip<len(code):
    op=code[ip];ip+=1
    if op==0:break
    if op==5:n=int.from_bytes(code[ip:ip+2],"little");ip+=2
    elif op==1:
        r=code[ip];v=int.from_bytes(code[ip+1:ip+3],"little");ip+=3;registers[r]=({},v)
    elif op==2:
        r,j=code[ip:ip+2];c=int.from_bytes(code[ip+2:ip+4],"little");ip+=4
        terms,const=registers[r];terms[j]=(terms.get(j,0)+c)%257
    elif op==3:
        r=code[ip];v=int.from_bytes(code[ip+1:ip+3],"little");ip+=3
        terms,const=registers[r];rows.append(dict(terms));targets.append((v-const)%257)
    else:raise ValueError(op)
rows=[[r.get(j,0) for j in range(n)] for r in rows]
M=[r+[v] for r,v in zip(rows,targets)];row=0;pivots=[]
for col in range(n):
    k=next(i for i in range(row,len(M)) if M[i][col]%257)
    M[row],M[k]=M[k],M[row];inv=pow(M[row][col],-1,257);M[row]=[v*inv%257 for v in M[row]]
    for i in range(len(M)):
        if i==row:continue
        c=M[i][col];M[i]=[(a-c*b)%257 for a,b in zip(M[i],M[row])]
    pivots.append((row,col));row+=1
out=[0]*n
for row,col in pivots:out[col]=M[row][-1]
assert all(sum(a*b for a,b in zip(r,out))%257==v for r,v in zip(rows,targets))
emit(bytes(out))
