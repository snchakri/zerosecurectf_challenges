import json

with open("shares.json", "r") as f:
    data = json.load(f)

p = int(data["p"])
shares = data["shares"]

k_shares = [(s[0], int(s[1])) for s in shares[:5]]

secret = 0
for j in range(len(k_shares)):
    xj, yj = k_shares[j]
    num = 1
    den = 1
    for m in range(len(k_shares)):
        if m == j:
            continue
        xm = k_shares[m][0]
        num = (num * (-xm)) % p
        den = (den * (xj - xm)) % p
    lj = (num * pow(den, -1, p)) % p
    secret = (secret + yj * lj) % p

flag = secret.to_bytes((secret.bit_length() + 7) // 8, 'big').decode('utf-8')
print(flag)
