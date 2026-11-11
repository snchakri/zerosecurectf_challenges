# Trie Prefix Tree Graph Traversal — solution

Run from this challenge's title directory:

```bash
python solution/solve.py
```

The solver uses the supplied artifacts in a temporary working directory. Service models, where necessary, are confined to `solution/runtime/`. They represent the challenge's local oracle or verifier.

The source artifact uses `zerosecure{...}`; the event also accepted the corresponding answer listed in `accepted_flags.txt`. Preserve the recovered spelling when comparing source results.

# Writeup: Trie Prefix Tree Graph Traversal (Salted Radix Graph Navigation)


## 1. Analysis & Theoretical Foundations
`dist/validator.pyc` embeds one `GRAPH` byte-blob encoding a prefix trie whose
accepted language is a single string (the flag). The trie is padded with ~600
decoy phrases (many sharing the flag's prefixes) so the graph has thousands of
nodes and heavy branching. `check()` walks from node 0 consuming one input byte
per step; a step follows the edge whose salted hash matches
`sha256(node_salt || byte)[:8]`. Acceptance requires ending on the single node
whose accept bit is set.


## 2. Binary layout of GRAPH (little-endian)
```
u32  n_nodes
repeat n_nodes:
     4 bytes  node salt
     u8       accept flag (1 on exactly one node)
     u8       edge count
     repeat edge count:
         8 bytes  edge hash = sha256(node_salt || char)[:8]
         u32      child node index
```
No transition character is stored in the clear; only its salted fingerprint.


## 3. Step-by-Step Walkthrough
1. Extract the `GRAPH` blob from the `.pyc` (strip 16-byte header,
   `marshal.loads`, pick the largest `bytes` constant).
2. Parse the nodes. While parsing, record `parent[child] = (parent_idx, hash)`
   — valid because a trie is a tree (one parent per node).
3. Locate the unique node with `accept == 1`.
4. Walk from that node up to the root via `parent[...]`, collecting
   `(parent_salt, edge_hash)` pairs; reverse the list to get root→leaf order.
5. For each pair, recover the character by testing the small alphabet
   `[a-z0-9_{}]` (plus a safety superset) until
   `sha256(parent_salt || char)[:8] == edge_hash`. Concatenate to get the flag.


## 4. Why it resists shortcuts
- `strings`/grep find nothing: edge labels are 8-byte salted hashes, the flag is
  never stored as text.
- One-shot LLM solving fails: the answer is a *path* hidden among thousands of
  decoy-filled branches with hashed edges; you must parse the binary graph,
  isolate the unique accepting node, and invert salted hashes.
- Still tractable for humans: the up-walk is O(path length) and each hash
  inversion is a ~40-symbol lookup — far below any brute-force concern.


## 5. Exploit Script & Verification
`solve.py` reads only `dist/validator.pyc`:
```bash
python solve.py --dist ./dist
```
It prints the recovered `zerosecure{...}` key, byte-identical to the `flag` file.


## 6. Citations & References
- Fredkin, E. (1960). *Trie memory.* Communications of the ACM, 3(9), 490–499.
- Knuth, D. E. (1998). *The Art of Computer Programming, Vol. 3: Sorting and
  Searching* (digital trees / tries).
- NIST FIPS 180-4, *Secure Hash Standard* (SHA-256).


## 7. Defense Engineering & Remediation
Salted-hash edge labels raise the reversing cost but are not a KDF: the alphabet
is small and brute-forceable. For real authentication, verify a passphrase with a
slow, salted password hash (Argon2id/scrypt) server-side, never a client-side
reachability graph.
