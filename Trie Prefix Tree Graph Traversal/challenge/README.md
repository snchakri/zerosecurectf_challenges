# Trie Prefix Tree Graph Traversal

**Category:** Reverse Engineering

The Latverian authentication daemon does not store passphrases. Doom considers
stored secrets a weakness a spy could read. Instead the citadel's gatekeeper
holds a vast branching map — thousands of nodes of a prefix tree — and a
submitted phrase is accepted only if it traces an exact route through that map
to the single sealed chamber at the end.

The map is deliberately choked with false corridors: hundreds of decoy phrases
share openings with the true one, so the tree forks constantly, and almost every
branch dead-ends against Doombot garrisons. Worse, the daemon never writes the
letter that opens each door. Each edge is marked only by a salted fingerprint of
the character that unlocks it, so you cannot simply read the path off the map.

CICADA3301 exfiltrated the compiled gatekeeper. Your objective: find the one
chamber that bears the acceptance seal, trace the route that reaches it, and
read back the phrase that route spells — the master license key.

**Download the attached file** (CPython 3.13 bytecode) and recover the flag.
