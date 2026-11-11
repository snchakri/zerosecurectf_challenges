#!/usr/bin/env python3
"""
Real solver for rev_12_non_deterministic_finite_automaton_nfa.

Reads ONLY the ELF in dist/ (default --dist ./dist). Steps:
  1. Scan the binary for the magic-delimited NFA table (Z5NFA_v1 .. Z5NFAEND).
  2. Parse states, epsilon transitions, symbol transitions, start/accept, and
     the acc-chain constants (A0, K, C).
  3. Compute which states can still reach the accept state (reverse reachability
     over epsilon + symbol edges). Decoy "trap" targets cannot.
  4. Walk the automaton with epsilon-closure: at each step exactly one symbol
     moves an accept-reachable state to another accept-reachable state -> that
     byte is the next Y byte. This yields the unique accepted string Y.
  5. Invert the position-chained transform to recover the flag.

Does not contain the flag and never reads the `flag` file.
"""
import argparse
import glob
import os
import struct

MAGIC = b"Z5NFA_v1"
MAGICEND = b"Z5NFAEND"


def find_blob(data):
    i = data.index(MAGIC)
    j = data.index(MAGICEND, i)
    return data[i:j + len(MAGICEND)]


def parse(blob):
    assert blob[:8] == MAGIC
    off = 8
    n_states, start, accept = struct.unpack_from("<HHH", blob, off); off += 6
    A0, K, C = struct.unpack_from("<BBB", blob, off); off += 3
    (n_eps,) = struct.unpack_from("<H", blob, off); off += 2
    eps = []
    for _ in range(n_eps):
        f, t = struct.unpack_from("<HH", blob, off); off += 4
        eps.append((f, t))
    (n_sym,) = struct.unpack_from("<H", blob, off); off += 2
    sym = []
    for _ in range(n_sym):
        f, b, t = struct.unpack_from("<HBH", blob, off); off += 5
        sym.append((f, b, t))
    return dict(n=n_states, start=start, accept=accept,
               A0=A0, K=K, C=C, eps=eps, sym=sym)


def eclose(states, eps, n):
    seen = set(states)
    stack = list(states)
    while stack:
        s = stack.pop()
        for f, t in eps:
            if f == s and t not in seen:
                seen.add(t); stack.append(t)
    return seen


def reach_accept(nfa):
    # reverse edges, BFS from accept
    radj = {}
    for f, t in nfa["eps"]:
        radj.setdefault(t, []).append(f)
    for f, b, t in nfa["sym"]:
        radj.setdefault(t, []).append(f)
    seen = {nfa["accept"]}
    stack = [nfa["accept"]]
    while stack:
        s = stack.pop()
        for p in radj.get(s, ()):
            if p not in seen:
                seen.add(p); stack.append(p)
    return seen


def recover_Y(nfa):
    eps, sym, n = nfa["eps"], nfa["sym"], nfa["n"]
    live = reach_accept(nfa)
    cur = eclose({nfa["start"]}, eps, n)
    Y = []
    while nfa["accept"] not in cur:
        # candidate bytes that move an accept-reachable state to one
        cand = set()
        for f, b, t in sym:
            if f in cur and f in live and t in live:
                cand.add(b)
        assert len(cand) == 1, f"ambiguous next symbol: {sorted(cand)}"
        b = cand.pop()
        Y.append(b)
        nxt = {t for (f, bb, t) in sym if f in cur and bb == b}
        cur = eclose(nxt, eps, n)
        cur = {s for s in cur if s in live}  # prune dead
        if len(Y) > 4096:
            raise RuntimeError("no accept path found")
    return bytes(Y)


def invert(Y, A0, K, C):
    acc = A0
    out = bytearray()
    for yi in Y:
        out.append((yi - acc) & 0xFF)
        acc = (acc * K + yi + C) & 0xFF
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    cands = [p for p in glob.glob(os.path.join(args.dist, "*"))
             if os.path.isfile(p)]
    data = None
    for p in cands:
        d = open(p, "rb").read()
        if MAGIC in d:
            data = d; break
    assert data is not None, "NFA table not found in dist/"
    nfa = parse(find_blob(data))
    Y = recover_Y(nfa)
    flag = invert(Y, nfa["A0"], nfa["K"], nfa["C"])
    print(flag.decode())


if __name__ == "__main__":
    main()
