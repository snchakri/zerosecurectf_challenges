# Multi-Stage Dynamic Runtime Code Decryption

**Category:** Reverse Engineering

Doom's armorers never ship a weapon that reveals itself at rest. The citadel's
key-vault loader, lifted by CICADA3301, arrives as an opaque block: nothing in it
reads as a key, nor even as the code that checks one. It wakes in layers. The
first layer peels a sealed payload into a page of live memory; the contents of
*that* payload — not any stored constant — become the seed that unseals the next
layer; and only the final layer, assembled entirely at runtime, knows what the
gate demands.

Break the chain anywhere and everything downstream stays encrypted garbage. The
loader gives nothing away: it simply grants or denies. There is no key written in
the file, and no single key either — the true value only exists for an instant,
after every stage has fed the next.

Your objective: reproduce the loader's staged derivation, reconstruct the value
that only ever lives in memory, and read out the master key.

**Download the attached file** (Linux x86-64 ELF) and recover the flag.
