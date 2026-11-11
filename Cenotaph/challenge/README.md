# Cenotaph

**Category:** Final Chain

**Doombot CN-01 · the empty tomb**

> *"Here lies the key to my archive. Dig, if you like. My tombs are patient."*
>
> — Victor von Doom

A crackme guarding Doom's archive: a key check, a `grant()` that prints a flag, a buried `reconstruct()`. Every flag it can give you is forged (the wrong case, a `zer0` prefix, or broken with hyphens), and its own integrity seal is the hash of nothing at all.

**CICADA3301 field note:** every corridor here looks like a painted wall. Some of those walls are doors. Whatever you pull from Doom's vaults by real work counts.

**Connect:** `nc <challenge-host> 30003`

Flag format: `zerosecurectf{...}` — and Doom's forgers mint a look-alike, `zer0securectf{...}`. Every vault this target guards pays out: each sealed secret you truly recover is a valid flag.

The event connection above is an archived address placeholder. For local review, follow the local service instructions in the solution folder.
