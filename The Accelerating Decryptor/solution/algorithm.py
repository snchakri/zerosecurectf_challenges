import json
import math

def continued_fractions(n, d):
    while d:
        q = n // d
        yield q
        n, d = d, n - q * d

def convergents(cf):
    h0, h1 = 0, 1
    k0, k1 = 1, 0
    for q in cf:
        h = q * h1 + h0
        k = q * k1 + k0
        yield h, k
        h0, h1 = h1, h
        k0, k1 = k1, k

with open("pubkey.json", "r") as f:
    data = json.load(f)

n = int(data["n"])
e = int(data["e"])
c = int(data["c"])

for k_cand, d_cand in convergents(continued_fractions(e, n)):
    m = pow(c, d_cand, n)
    try:
        txt = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8')
        if "zerosecure{" in txt:
            print(txt)
            break
    except Exception:
        pass
