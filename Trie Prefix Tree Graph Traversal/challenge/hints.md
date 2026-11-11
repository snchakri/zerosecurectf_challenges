# Staged Hint Ladder: Trie Prefix Tree Graph Traversal

### Hint Level 1 (Orientation)
Decompile `dist/validator.pyc`. It holds a single large `GRAPH` byte-blob and a
`check()` that walks it from node 0, one input byte per step. Reverse the blob's
binary layout: a node count, then per node a 4-byte salt, an accept flag, and a
list of outgoing edges. Each edge stores an 8-byte hash and a child index — not
the character itself.

### Hint Level 2 (Reframe)
The structure is a tree: every node has exactly one parent. Exactly one node has
its accept flag set. An edge's hash is `sha256(parent_salt || char)[:8]`. You do
not need to understand every decoy branch — you only need the single path from
the accepting node back up to the root.

### Hint Level 3 (Strong Nudge)
Build a child→(parent, edge_hash) map while parsing, find the one accepting node,
and walk upward to the root collecting edge hashes. For each edge, brute-force
the one printable character whose `sha256(parent_salt || char)[:8]` equals the
stored hash (the alphabet is tiny, ~40 symbols). Reverse the collected
characters to read the key. No path search over the decoys is required.

---
*Note: Crux Floor invariant: The core reverse engineering insight is never handed out completely; each hint restores a reasoning handle.*
