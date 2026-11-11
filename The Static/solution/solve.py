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


h=load("consensus.json");q=h["q"];infected=set(h["worm_seed"])
while True:
    bloom={int(i) for i,adj in h["gossip_adjacency"].items() if len(set(adj)&infected)>=h["threshold_percolation"]}
    if bloom<=infected:break
    infected |= bloom
assert len(infected)>=h["quorum"]
shares=[]
for i in sorted(infected):
    sigs=h["signatures"][str(i)]
    if len(sigs)<2 or sigs[0]["r"]!=sigs[1]["r"]:continue
    a,b=sigs[:2];ha=h["blocks"][str(a["block"])]["h"];hb=h["blocks"][str(b["block"])]["h"]
    k=(ha-hb)*pow(a["s"]-b["s"],-1,q)%q
    d=(a["s"]*k-ha)*pow(a["r"],-1,q)%q
    assert pow(h["g"],d,h["P"])==h["public_keys"][str(i)]
    shares.append((i,d))
assert len(shares)>=h["shamir_threshold"]
for shift in [1,0]:
    pts=[(i+shift,d) for i,d in shares[:h["shamir_threshold"]]];secret=0
    for i,(xi,yi) in enumerate(pts):
        num=den=1
        for j,(xj,_) in enumerate(pts):
            if i!=j:num=num*(-xj)%q;den=den*(xi-xj)%q
        secret=(secret+yi*num*pow(den,-1,q))%q
    b=flag_bytes(secret)
    if b.startswith(b"zerosecurectf{"):emit(b);break
else:raise RuntimeError("Shamir reconstruction did not produce a flag")
