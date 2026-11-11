#!/usr/bin/env python3
"""
Real solver for rev_11_trie_prefix_tree_graph_validator.

Reads ONLY dist/validator.pyc (default --dist ./dist). Steps:
  1. Pull the embedded GRAPH blob out of the marshalled bytecode.
  2. Parse the binary trie (per-node salt, accept bit, salted edge hashes).
  3. Find the unique accepting node and walk parent links to the root.
  4. Invert each salted edge hash over the transition alphabet to read the
     character, giving the accepted string = the flag.

Does not contain the flag and never reads the `flag` file.
"""
import argparse
import marshal
import os
import struct
import hashlib

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_{}" \
           "ABCDEFGHIJKLMNOPQRSTUVWXYZ-!@#$%^&*()+=."  # superset, for safety


def extract_graph(pyc_path):
    with open(pyc_path, "rb") as f:
        f.read(16)
        code = marshal.loads(f.read())
    blobs = []

    def walk(co):
        for c in co.co_consts:
            if hasattr(c, "co_consts"):
                walk(c)
            elif isinstance(c, (bytes, bytearray)):
                blobs.append(bytes(c))
    walk(code)
    # GRAPH is by far the largest bytes constant
    return max(blobs, key=len)


def parse(graph):
    off = 0
    (n_nodes,) = struct.unpack_from("<I", graph, off); off += 4
    salts, accepts, edges, parent = [], [], [], {}
    for idx in range(n_nodes):
        salt = graph[off:off+4]; off += 4
        (accept,) = struct.unpack_from("<B", graph, off); off += 1
        (ne,) = struct.unpack_from("<B", graph, off); off += 1
        elist = []
        for _ in range(ne):
            h = graph[off:off+8]; off += 8
            (child,) = struct.unpack_from("<I", graph, off); off += 4
            elist.append((h, child))
            parent[child] = (idx, h)       # trie: each child has one parent
        salts.append(salt); accepts.append(accept); edges.append(elist)
    return salts, accepts, edges, parent


def recover_char(salt, h):
    for ch in ALPHABET:
        if hashlib.sha256(salt + ch.encode()).digest()[:8] == h:
            return ch
    raise ValueError("edge hash not invertible over alphabet")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default="./dist")
    args = ap.parse_args()
    graph = extract_graph(os.path.join(args.dist, "validator.pyc"))
    salts, accepts, edges, parent = parse(graph)

    term = next(i for i, a in enumerate(accepts) if a == 1)
    # walk back to root collecting (parent_salt, edge_hash)
    chain = []
    cur = term
    while cur in parent:
        p, h = parent[cur]
        chain.append((salts[p], h))
        cur = p
    chain.reverse()
    flag = "".join(recover_char(salt, h) for salt, h in chain)
    print(flag)


if __name__ == "__main__":
    main()
