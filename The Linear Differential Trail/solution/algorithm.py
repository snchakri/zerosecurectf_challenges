#!/usr/bin/env python3
"""
Real solver for crypto_12_feal4_cryptanalysis.

Reads ONLY dist/ (default ./dist): cipher_spec.py (the reduced-width FEAL-4
definition) and plaintext_pairs.json (chosen-plaintext differential transcript +
the CTR-encrypted flag). Performs differential cryptanalysis:

  * alpha = 0x8080 gives a ~0.12 three-round differential. Pre-filter "right
    pairs" by the observable round-output difference and rank the last round key
    K3 by the modal recovered difference; keep the top candidates.
  * Peel round 4, repeat for K2.
  * Reduced to a 2-round cipher with known plaintext, solve K0 and K1 directly
    from the FEAL round-function relations.
  * Validate the full key against the whole transcript (an equivalent key is
    fine: it is the identical permutation), then CTR-decrypt the flag.

This script does not contain the flag and never reads the ./flag file.
"""
import argparse
import importlib.util
import json
import os
import sys
from collections import Counter, defaultdict

sys.dont_write_bytecode = True  # do not create __pycache__ in dist/


def load_cipher(dist):
    spec = importlib.util.spec_from_file_location("cipher_spec", os.path.join(dist, "cipher_spec.py"))
    cs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cs)
    return cs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()

    cs = load_cipher(args.dist)
    with open(os.path.join(args.dist, "plaintext_pairs.json"), "r", encoding="utf-8") as f:
        D = json.load(f)
    alpha = int(D["alpha"])
    nonce = int(D["nonce"])
    flag_ct = bytes.fromhex(D["flag_ct_hex"])

    FT = [cs.F16(i) for i in range(1 << 16)]
    FINV = defaultdict(list)
    for x, y in enumerate(FT):
        FINV[y].append(x)

    def enc(pt, K):
        return cs.encrypt_block(pt, K)

    def inv_round(Lo, Ro, k):
        return (Ro ^ FT[Lo ^ k], Lo)

    def peel(pairs, k):
        return [(inv_round(La, Ra, k), inv_round(Lb, Rb, k)) for (La, Ra), (Lb, Rb) in pairs]

    def top_last_keys(pairs, topm, rp_cap=60):
        target = Counter((La ^ Lb) for (La, Ra), (Lb, Rb) in pairs).most_common(1)[0][0]
        rp = [p for p in pairs if (p[0][0] ^ p[1][0]) == target][:rp_cap]
        if not rp:
            return []
        La = [p[0][0] for p in rp]; Ra = [p[0][1] for p in rp]
        Lb = [p[1][0] for p in rp]; Rb = [p[1][1] for p in rp]
        Rd = [Ra[i] ^ Rb[i] for i in range(len(rp))]
        scores = []
        for k in range(1 << 16):
            c = Counter()
            for i in range(len(rp)):
                c[Rd[i] ^ FT[La[i] ^ k] ^ FT[Lb[i] ^ k]] += 1
            scores.append((c.most_common(1)[0][1], k))
        scores.sort(reverse=True)
        return [k for _, k in scores[:topm]]

    def recover_k0_k1(knowns, pairs2):
        def solve(getbase, gett):
            cand = None
            for (p, cp), ((L2, R2), _) in zip(knowns, pairs2):
                L0 = (p >> 16) & 0xFFFF; R0 = p & 0xFFFF
                s = set(getbase(L0, R0, L2, R2) ^ x for x in FINV.get(gett(L0, R0, L2, R2), []))
                cand = s if cand is None else (cand & s)
                if not cand:
                    return []
                if len(cand) == 1:
                    break
            return list(cand)
        k0 = solve(lambda L0, R0, L2, R2: R0, lambda L0, R0, L2, R2: L2 ^ L0)
        k1 = solve(lambda L0, R0, L2, R2: L2, lambda L0, R0, L2, R2: R2 ^ R0)
        return k0, k1

    pairs = D["pairs"]
    knowns = [(p, c1) for p, c1, c2 in pairs]
    pairs4 = [(((c1 >> 16) & 0xFFFF, c1 & 0xFFFF), ((c2 >> 16) & 0xFFFF, c2 & 0xFFFF))
              for p, c1, c2 in pairs]
    sample = knowns[:8]

    def attack(M3=12, M2=12):
        for k3 in top_last_keys(pairs4, M3):
            pairs3 = peel(pairs4, k3)
            for k2 in top_last_keys(pairs3, M2):
                pairs2 = peel(pairs3, k2)
                k0s, k1s = recover_k0_k1(knowns, pairs2)
                for k0 in k0s:
                    for k1 in k1s:
                        K = [k0, k1, k2, k3]
                        if all(enc(p, K) == c for p, c in sample) and all(enc(p, K) == c for p, c in knowns):
                            return K
        return None

    K = attack()
    if K is None:
        raise SystemExit("differential attack failed")

    out = bytearray()
    i = 0
    while len(out) < len(flag_ct):
        out += enc((nonce + i) & 0xFFFFFFFF, K).to_bytes(4, "big")
        i += 1
    flag = bytes(a ^ b for a, b in zip(flag_ct, out[:len(flag_ct)]))
    print(flag.decode())


if __name__ == "__main__":
    main()
